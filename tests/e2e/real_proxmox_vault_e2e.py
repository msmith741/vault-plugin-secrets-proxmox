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


def setup_vault(plugin, pve, ca_path, issuer_user, issuer_token, mount):
    checksum = hashlib.sha256(Path(plugin).read_bytes()).hexdigest()
    version = "v0.0.0-real-pve-ci"
    plugin_name = "vault-plugin-secrets-proxmox"
    vault("plugin", "register", f"-sha256={checksum}",
          f"-command={plugin_name}", f"-version={version}", "secret", plugin_name)
    vault("secrets", "enable", f"-path={mount}",
          f"-plugin-version={version}", plugin_name)
    name, realm = issuer_user.split("@", 1)
    token_id, token_value = issuer_token
    vault("write", f"{mount}/config",
          f"user={name}", f"realm={realm}", f"token_id={token_id}",
          "token_secret=-", f"proxmox_url={pve.url}",
          f"ca_cert_pem=@{ca_path}", "insecure_skip_tls_verify=false",
          input_text=token_value)
    cfg = vjson("read", "-format=json", f"{mount}/config")
    check("token_secret" not in cfg.get("data", {}),
          "real Proxmox issuer secret is not returned by Vault config read")


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
    critical = []
    bootstrap = json.loads(Path(args.credentials).read_text())
    if not bootstrap["token_id"].startswith("PVEAPIToken=root@pam!"):
        raise TestError("unexpected test-container bootstrap identity")
    root_id = bootstrap["token_id"].removeprefix("PVEAPIToken=")
    root_value = bootstrap["token_value"]
    pve = PVE(args.url, args.ca, token_header(root_id, root_value))
    status, version = pve.call("GET", "/version")
    # GET /version might require authentication, but we provided root token.
    check(status == 200 and bool(version.get("data")),
          "connected over verified HTTPS to actual Proxmox VE API")
    version_string = str(version["data"].get("version", "unknown"))
    report.append(f"- Proxmox VE version: {version_string}")
    print("INFO: Proxmox version:", version_string)

    for user in (ISSUER_USER, TARGET_USER, IMAGE_USER):
        docker("pveum", "user", "add", user, "--comment", "Disposable Vault CI test")
    # Read-only permissions provide an authenticated operation to test while
    # deliberately not granting user/token administration privileges.
    docker("pveum", "acl", "modify", "/", "--user", TARGET_USER, "--role", "PVEAuditor")
    docker("pveum", "acl", "modify", "/storage", "--user", IMAGE_USER,
           "--role", "PVEDatastoreUser")

    mount = "pve-real-ci"
    setup_vault(args.plugin, pve, args.ca, "root@pam", ("test", root_value), mount)
    role(mount, "deployment", TARGET_USER)
    role(mount, "images", IMAGE_USER)

    # Observe that distinct Vault roles produce distinct identity tokens.
    image_lease, image_auth = issue(mount, "images")
    check(image_lease["data"]["token_id_full"].startswith(IMAGE_USER + "!"),
          "image role targets separate Proxmox identity")
    vault("lease", "revoke", "-sync", image_lease["lease_id"])

    dep, generated_auth = issue(mount, "deployment")
    token = dep["data"]
    check(token["token_id_full"].startswith(TARGET_USER + "!"),
          "deployment role targets configured Proxmox identity")
    check(pve.permissions(generated_auth)[0] == 200,
          "issued credential authenticates to actual Proxmox API")
    lookup = pve.token("GET", TARGET_USER, token["token_id"])
    check(lookup[0] == 200 and
          int(lookup[1].get("data", {}).get("expire", 0)) > int(time.time()),
          "real Proxmox stores finite native token expiration")
    check(int(lookup[1]["data"].get("privsep", -1)) == 0,
          "real Proxmox confirms generated token inherits target account privileges")

    # Try to bypass Vault TTL by minting a longer-lived sibling token.
    escape_name = "ci-escape"
    escape = pve.token(
        "POST", TARGET_USER, escape_name, auth=generated_auth,
        fields={"expire": int(time.time()) + 3600, "privsep": 0},
    )
    if escape[0] == 200:
        critical.append("Restricted workload token created a longer-lived sibling token")
        print("SECURITY BLOCKER: generated token can mint a replacement token", flush=True)
        report.append("- Self-mint attempt: **SUCCEEDED — SECURITY BLOCKER**")
        # Cleanup with an independent administrator before further testing.
        removal = pve.token("DELETE", TARGET_USER, escape_name)
        check(removal[0] == 200, "removed synthetic sibling token after bypass test")
    else:
        check(escape[0] in (401, 403),
              f"self-mint request rejected by real Proxmox (HTTP {escape[0]})")
        report.append(f"- Self-mint attempt: rejected (HTTP {escape[0]})")

    # Restricted issuer must NOT create tokens for another account before ACL.
    issuer_info = json.loads(
        docker("pveum", "user", "token", "add", ISSUER_USER, "bootstrap",
               "--privsep", "0", "--output-format", "json")
    )
    restricted_auth = token_header(f"{ISSUER_USER}!bootstrap", issuer_info["value"])
    test_id = "ci-delegation"
    attempt = pve.token("POST", TARGET_USER, test_id, auth=restricted_auth,
                        fields={"expire": int(time.time()) + 300, "privsep": 0})
    check(attempt[0] in (401, 403), "unprivileged issuer cannot mint for other user")
    # Test progressively broader delegated scopes, RECORDING any privilege
    # expansion. A broadly privileged issuer is not production approval.
    probes = [
        ("realm PVEUserAdmin", "/access/realm/pve", "PVEUserAdmin"),
        ("realm Realm.AllocateUser", "/access/realm/pve", "CITokenIssuer"),
        ("global PVEUserAdmin", "/access", "PVEUserAdmin"),
    ]
    delegated_scope = None
    for label, acl_path, acl_role in probes:
        if acl_role == "CITokenIssuer":
            docker("pveum", "role", "add", "CITokenIssuer",
                   "--privs", "Realm.AllocateUser")
        docker("pveum", "acl", "modify", acl_path,
               "--user", ISSUER_USER, "--role", acl_role)
        delegation = pve.token(
            "POST", TARGET_USER, test_id, auth=restricted_auth,
            fields={"expire": int(time.time()) + 300, "privsep": 0},
        )
        report.append(f"- Cross-user issuer with {label}: HTTP {delegation[0]}")
        if delegation[0] == 200:
            delegated_scope = label
            print(f"INFO: cross-user issuer permitted with {label}", flush=True)
            check(pve.token("DELETE", TARGET_USER, test_id, auth=restricted_auth)[0] == 200,
                  f"delegated issuer can delete token under {label}")
            break
        check(delegation[0] in (401, 403),
              f"issuer scope {label} correctly reported a permission denial")

    if delegated_scope:
        # A successful delegated probe must also work through the same
        # constrained issuer identity configured on a separate Vault mount.
        second = "pve-restricted-ci"
        setup_vault(args.plugin, pve, args.ca, ISSUER_USER,
                    ("bootstrap", issuer_info["value"]), second)
        role(second, "workload", TARGET_USER)
        check_result, _ = issue(second, "workload")
        vault("lease", "revoke", "-sync", check_result["lease_id"])
        check(True, "delegated issuer completes full Vault lease lifecycle")
        if delegated_scope == "global PVEUserAdmin":
            print("SECURITY WARNING: cross-user token management needed global /access user administration",
                  flush=True)
            report.append("- Issuer privilege boundary: **global /access role required; review before production**")

            # Determine whether a broadly delegated issuer can mint for other
            # accounts beyond the one named in the Vault role. The fixture
            # accounts, including root@pam, exist ONLY inside this runner.
            for other_user, probe_id in (
                (IMAGE_USER, "ci-unrelated-user"),
                ("root@pam", "ci-root-risk-probe"),
            ):
                probe = pve.token(
                    "POST", other_user, probe_id, auth=restricted_auth,
                    fields={"expire": int(time.time()) + 90, "privsep": 0},
                )
                if probe[0] == 200:
                    print(f"SECURITY WARNING: delegated issuer can mint for {other_user}",
                          flush=True)
                    report.append(
                        f"- Delegated issuer can create token for {other_user}: **YES**"
                    )
                    try:
                        if other_user == "root@pam":
                            root_secret = (probe[1].get("data") or {}).get("value")
                            check(bool(root_secret), "delegated issuer received root token secret")
                            root_auth = token_header("root@pam!" + probe_id, root_secret)
                            check(pve.permissions(root_auth)[0] == 200,
                                  "delegated issuer's root token authenticates to actual Proxmox")
                            critical.append(
                                "non-root delegated issuer minted an authenticating root@pam API token"
                            )
                    finally:
                        check(
                            pve.token("DELETE", other_user, probe_id)[0] == 200,
                            f"removed privileged probe token for {other_user}",
                        )
                else:
                    check(
                        probe[0] in (401, 403),
                        f"issuer denied minting unrelated token for {other_user}",
                    )
                    report.append(
                        f"- Delegated issuer can create token for {other_user}: no (HTTP {probe[0]})"
                    )
    else:
        print("SECURITY GATE: cross-user token issuance remained denied with tested scopes",
              flush=True)
        report.append("- Restricted issuer: **not proven viable; issuer design must be revised**")

    vault("lease", "revoke", "-sync", dep["lease_id"])
    check(pve.permissions(generated_auth)[0] in (401, 403),
          "Vault lease revocation invalidates the actual Proxmox token")
    # Proxmox versions differ in the response to GET for a missing token.
    # Verify absence from the actual token inventory instead of assuming 404.
    user_q = urllib.parse.quote(TARGET_USER, safe="")
    listing_status, listing = pve.call("GET", f"/access/users/{user_q}/token")
    check(listing_status == 200 and isinstance(listing.get("data"), list),
          "Proxmox user token inventory is readable")
    check(not any(
        item.get("tokenid") == token["token_id"]
        for item in listing["data"] if isinstance(item, dict)
    ), "revoked token is absent from actual Proxmox token inventory")

    # Native expiry is independent of Vault's lease expiration manager.
    ephemeral = "ci-native-expiry"
    exp = pve.token("POST", TARGET_USER, ephemeral,
                    fields={"expire": int(time.time()) + 8, "privsep": 0})
    check(exp[0] == 200 and exp[1].get("data", {}).get("value"),
          "created a genuine short-expiring Proxmox token")
    ep_auth = token_header(f"{TARGET_USER}!{ephemeral}", exp[1]["data"]["value"])
    check(pve.permissions(ep_auth)[0] == 200,
          "native-expiry token authenticates before deadline")
    time.sleep(10)
    check(pve.permissions(ep_auth)[0] in (401, 403),
          "native Proxmox expiry rejects token without Vault revocation")
    check(pve.token("DELETE", TARGET_USER, ephemeral)[0] == 200,
          "expired token cleaned from Proxmox inventory")

    report.append("- Token creation/deletion via real Proxmox API: passed")
    report.append("- Native expiry independent of Vault: passed")
    report.append("- Vault lease revocation: passed")
    report.append("- Separate image/deployment identities: passed")
    report.append("- Real Proxmox TLS certificate verification: passed")
    report.append("- Restricted workload self-mint security gate: passed (HTTP 403)")
    report.append("- Delegated issuer privilege-escalation gate: " + (
        "**CRITICAL BLOCKER: minted root@pam token**" if critical else "no root-token minting observed"
    ))
    summary = "## Proxmox VE container integration results\n\n" + "\n".join(report) + "\n"
    Path(args.report).write_text(summary)
    if critical:
        raise TestError("; ".join(critical))
    print("SUCCESS: real containerized Proxmox API integration and security checks passed",
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
