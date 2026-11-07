#!/usr/bin/env python3
"""Disposable Vault + real containerized Proxmox API authorization integration.

WARNING: Creates real Proxmox users/tokens only inside the test-only, privileged
container started in the SAME GitHub-hosted runner. Never point this at a live
server. No host passwords, API secrets, or Vault credentials are printed.
"""
import argparse
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ISSUER_USER = "ci-issuer@pve"
TARGET_USER = "ci-workload@pve"
IMAGE_USER = "ci-images@pve"


class TestError(Exception):
    pass


def check(condition, message):
    if not condition:
        raise TestError(message)
    print(f"PASS: {message}", flush=True)


def docker(*args):
    # Do not print stdout: pveum token creation displays one-time secrets.
    proc = subprocess.run(
        ["docker", "exec", "pve-test", *args], capture_output=True,
        text=True, timeout=40, check=False,
    )
    if proc.returncode:
        raise TestError(f"Proxmox container command {args[:3]!r} failed with exit {proc.returncode}")
    return proc.stdout


def vault(*args, input_text=None, expect_success=True):
    proc = subprocess.run(
        ["vault", *args], input=input_text, capture_output=True,
        text=True, timeout=45, check=False,
    )
    if proc.returncode != 0 and expect_success:
        # Do not echo API errors; some SDKs include full authorization headers.
        raise TestError(f"Vault command {args[0]} failed (exit {proc.returncode})")
    if proc.returncode == 0 and not expect_success:
        raise TestError(f"Vault unexpectedly permitted {args[0]}")
    return proc.stdout if expect_success else None


def vjson(*args, **kwargs):
    return json.loads(vault(*args, **kwargs))


class PVE:
    def __init__(self, url, ca, root_auth):
        self.url = url.rstrip("/")
        self.root_auth = root_auth
        self.context = ssl.create_default_context(cafile=str(ca))
        # The test-only PVE image may not export its generated cluster CA.
        # Treat the observed leaf as a local trust anchor (still enforce
        # signature verification and hostname matching for this CI host).
        self.context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN

    def call(self, method, path, auth=None, fields=None):
        body = None
        headers = {"Authorization": auth or self.root_auth}
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(
            self.url + path, headers=headers, data=body, method=method,
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=20) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            parsed = {}
        return status, parsed

    def token(self, method, user, token_id, auth=None, fields=None):
        user_q = urllib.parse.quote(user, safe="")
        token_q = urllib.parse.quote(token_id, safe="")
        return self.call(
            method, f"/access/users/{user_q}/token/{token_q}", auth=auth, fields=fields,
        )

    def permissions(self, auth):
        return self.call("GET", "/access/permissions", auth=auth)


def token_header(identifier, secret):
    return f"PVEAPIToken={identifier}={secret}"


def setup_vault(plugin, pve, ca_path, issuer_user, mount, *,
                password=None, token=None):
    checksum = hashlib.sha256(Path(plugin).read_bytes()).hexdigest()
    version = "v0.0.0-real-pve-ci"
    plugin_name = "vault-plugin-secrets-proxmox"
    # Vault plugin catalog registration is idempotent across separate mounts.
    if not getattr(setup_vault, "_registered", False):
        vault("plugin", "register", f"-sha256={checksum}",
              f"-command={plugin_name}", f"-version={version}",
              "secret", plugin_name)
        setup_vault._registered = True
    vault("secrets", "enable", f"-path={mount}",
          f"-plugin-version={version}", plugin_name)
    name, realm = issuer_user.split("@", 1)
    options = [
        f"user={name}", f"realm={realm}",
        f"proxmox_url={pve.url}",
        f"ca_cert_pem=@{ca_path}",
        "insecure_skip_tls_verify=false",
    ]
    if password is not None and token is None:
        options += ["auth_method=password", "password=-"]
        secret = password
    elif token is not None and password is None:
        options += ["auth_method=token", f"token_id={token[0]}",
                    "token_secret=-"]
        secret = token[1]
    else:
        raise TestError("issuer must have exactly one authentication method")
    vault("write", f"{mount}/config", *options, input_text=secret)
    config = vjson("read", "-format=json", f"{mount}/config")["data"]
    check(config.get("auth_method") == ("password" if password is not None else "token")
          and "password" not in config and "token_secret" not in config,
          "issuer configuration persisted without exposing its authentication secret")


def role(mount, name, user, ttl="2m"):
    uname, realm = user.split("@", 1)
    vault("write", f"{mount}/role/{name}",
          f"user={uname}", f"realm={realm}", f"ttl={ttl}",
          "max_ttl=5m", "inherit_user_privileges=true")


def issue(mount, role_name):
    response = vjson("read", "-format=json", f"{mount}/creds/{role_name}")
    token = response.get("data") or {}
    check(bool(response.get("lease_id")) and not response.get("renewable", True)
          and token.get("token_id_full") and token.get("secret"),
          f"Vault issues a nonrenewable credential for {role_name}")
    return response, token_header(token["token_id_full"], token["secret"])


def run(args):
    report = []
    bootstrap = json.loads(Path(args.credentials).read_text())
    root_identifier = bootstrap["token_id"].removeprefix("PVEAPIToken=")
    if not bootstrap["token_id"].startswith("PVEAPIToken=root@pam!"):
        raise TestError("unexpected container bootstrap identity")
    pve = PVE(args.url, args.ca,
              token_header(root_identifier, bootstrap["token_value"]))
    status, version = pve.call("GET", "/version")
    check(status == 200 and bool(version.get("data")),
          "verified HTTPS connection to real Proxmox VE API")
    report.append("- Proxmox version: " + str(version["data"].get("version")))

    # Passwords are disposable fixtures generated per-run, never logged.
    workload_password = secrets.token_urlsafe(30)
    image_password = secrets.token_urlsafe(30)
    docker("pveum", "user", "add", ISSUER_USER,
           "--comment", "Disposable negative-permission probe")
    docker("pveum", "user", "add", TARGET_USER,
           "--password", workload_password,
           "--comment", "Disposable Vault workload issuer")
    docker("pveum", "user", "add", IMAGE_USER,
           "--password", image_password,
           "--comment", "Disposable Vault image issuer")
    docker("pveum", "acl", "modify", "/", "--user", TARGET_USER,
           "--role", "PVEAuditor")
    docker("pveum", "acl", "modify", "/storage", "--user", IMAGE_USER,
           "--role", "PVEDatastoreUser")

    # Two independent mounts, each with same-user ticket authentication.
    # No root or globally privileged token is supplied to Vault.
    workloads = "pve-workloads-ci"
    images = "pve-images-ci"
    setup_vault(args.plugin, pve, args.ca, TARGET_USER, workloads,
                password=workload_password)
    setup_vault(args.plugin, pve, args.ca, IMAGE_USER, images,
                password=image_password)
    role(workloads, "deployment", TARGET_USER)
    role(images, "image", IMAGE_USER)

    # Fail before attempting the Proxmox API if a role targets any other user.
    role(workloads, "cross-user", IMAGE_USER)
    vault("read", f"{workloads}/creds/cross-user", expect_success=False)
    vault("write", f"{workloads}/role/privileged",
          "user=root", "realm=pam", "ttl=2m", "max_ttl=5m",
          "inherit_user_privileges=true", expect_success=False)
    check(True, "plugin rejects cross-user issuance and root@pam roles")

    img, image_auth = issue(images, "image")
    check(img["data"]["token_id_full"].startswith(IMAGE_USER + "!"),
          "image credential belongs to its dedicated same-user issuer")
    check(pve.permissions(image_auth)[0] == 200,
          "image token authenticates under its restricted identity")
    vault("lease", "revoke", "-sync", img["lease_id"])
    check(pve.permissions(image_auth)[0] in (401, 403),
          "Vault revokes image token using dedicated user's ticket")

    dep, generated_auth = issue(workloads, "deployment")
    token = dep["data"]
    check(token["token_id_full"].startswith(TARGET_USER + "!"),
          "deploy credential belongs to its dedicated same-user issuer")
    check(pve.permissions(generated_auth)[0] == 200,
          "workload token authenticates against real Proxmox")
    meta_status, meta = pve.token("GET", TARGET_USER, token["token_id"])
    check(meta_status == 200 and int(meta["data"].get("expire", 0)) > time.time(),
          "real Proxmox enforces finite native expiration")
    check(int(meta["data"].get("privsep", -1)) == 0,
          "temporary token inherits only dedicated restricted user's permissions")

    # A limited token must not be able to renew itself by creating a sibling.
    bypass = pve.token(
        "POST", TARGET_USER, "ci-self-mint-escape",
        auth=generated_auth,
        fields={"expire": int(time.time()) + 3600, "privsep": 0},
    )
    if bypass[0] == 200:
        pve.token("DELETE", TARGET_USER, "ci-self-mint-escape")
        raise TestError("CRITICAL: workload token can mint a longer-lived replacement")
    check(bypass[0] in (401, 403),
          f"restricted temporary token cannot self-mint (HTTP {bypass[0]})")

    # A role update must not redirect the already-issued lease revocation.
    role(workloads, "deployment", IMAGE_USER)
    vault("lease", "revoke", "-sync", dep["lease_id"])
    check(pve.permissions(generated_auth)[0] in (401, 403),
          "original target token is revoked despite role modification")
    user_path = urllib.parse.quote(TARGET_USER, safe="")
    status, inventory = pve.call("GET", f"/access/users/{user_path}/token")
    check(status == 200 and isinstance(inventory.get("data"), list),
          "authorized administrator can inspect PVE token inventory")
    check(not any(
        entry.get("tokenid") == token["token_id"]
        for entry in inventory["data"] if isinstance(entry, dict)
    ), "revoked token is absent from Proxmox inventory")
    # Changed role must not be used to issue credentials for another user.
    vault("read", f"{workloads}/creds/deployment", expect_success=False)
    check(True, "updated cross-user role cannot issue new credentials")

    # Demonstrate why the previously proposed global PVEUserAdmin issuer is
    # dangerous. Direct Proxmox access is still broad, but the plugin's
    # self-only issuance check must prevent that issuer being used for others.
    issuer_info = json.loads(
        docker("pveum", "user", "token", "add", ISSUER_USER,
               "bootstrap", "--privsep", "0", "--output-format", "json")
    )
    risky_auth = token_header(f"{ISSUER_USER}!bootstrap", issuer_info["value"])
    safe_probe = pve.token(
        "POST", TARGET_USER, "ci-probe-no-acl", auth=risky_auth,
        fields={"expire": int(time.time()) + 90, "privsep": 0},
    )
    check(safe_probe[0] in (401, 403),
          "issuer without global user administration cannot mint for another user")
    docker("pveum", "acl", "modify", "/access",
           "--user", ISSUER_USER, "--role", "PVEUserAdmin")
    root_probe_id = "ci-root-escalation"
    root_probe = pve.token(
        "POST", "root@pam", root_probe_id, auth=risky_auth,
        fields={"expire": int(time.time()) + 90, "privsep": 0},
    )
    if root_probe[0] == 200:
        root_secret = (root_probe[1].get("data") or {}).get("value")
        check(bool(root_secret), "broad issuer receives root token secret")
        try:
            root_auth = token_header("root@pam!" + root_probe_id, root_secret)
            check(pve.permissions(root_auth)[0] == 200,
                  "broad Proxmox issuer can mint an authenticating root@pam token")
        finally:
            check(pve.token("DELETE", "root@pam", root_probe_id)[0] == 200,
                  "disposed of privileged test token")
        report.append("- Inherent Proxmox risk: global PVEUserAdmin can mint root@pam token")
    else:
        report.append(f"- Global PVEUserAdmin root-token probe: HTTP {root_probe[0]}")
    unsafe_mount = "pve-unsafe-issuer-ci"
    setup_vault(args.plugin, pve, args.ca, ISSUER_USER, unsafe_mount,
                token=("bootstrap", issuer_info["value"]))
    role(unsafe_mount, "workload", TARGET_USER)
    vault("read", f"{unsafe_mount}/creds/workload", expect_success=False)
    check(True, "plugin rejects a broadly privileged cross-user token issuer")
    # No root-backed Vault mount exists at any point.

    # Prove PVE native expiry independently of Vault lease revoke.
    short_id = "ci-native-expiry"
    resp_status, short = pve.token(
        "POST", TARGET_USER, short_id,
        fields={"expire": int(time.time()) + 8, "privsep": 0},
    )
    check(resp_status == 200 and (short.get("data") or {}).get("value"),
          "created genuinely short-expiring Proxmox token")
    auth = token_header(f"{TARGET_USER}!{short_id}", short["data"]["value"])
    check(pve.permissions(auth)[0] == 200, "native token authenticates before deadline")
    time.sleep(10)
    check(pve.permissions(auth)[0] in (401, 403),
          "native expiry rejects token without Vault intervention")
    check(pve.token("DELETE", TARGET_USER, short_id)[0] == 200,
          "expired token removed from Proxmox inventory")

    report.extend([
        "- Vault issuer authentication: **per-user password ticket**",
        "- Workload/image mounts: **separate restricted identities**",
        "- Same-user issuance and revocation: **passed**",
        "- Cross-user API issuance through plugin: **blocked**",
        "- Dangerous global /access issuer exposure: **blocked at plugin boundary**",
        "- Restricted workload self-minting: **denied**",
        "- Native expiration independent of Vault: **passed**",
        "- Existing role-change revocation: **passed**",
        "- TLS verification: **passed**",
    ])
    Path(args.report).write_text(
        "## Real Proxmox VE container security integration\n\n"
        + "\n".join(report) + "\n"
    )
    print("SUCCESS: same-user Vault issuers pass real Proxmox authorization tests",
          flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--url", default="https://pve-test.local:8006/api2/json")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as exc:
        with Path(args.report).open("a") as summary:
            summary.write(f"\n**Test result: FAILED / GATE BLOCKED** — {type(exc).__name__}: {exc}\n")
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
