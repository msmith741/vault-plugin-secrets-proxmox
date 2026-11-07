#!/usr/bin/env python3
"""Black-box test: a real ephemeral Vault process + a local fake Proxmox API.

Creates no external resources. All Vault auth tokens and Proxmox tokens are
synthetic and scoped to this CI job. Never echo returned credentials.
"""
import argparse
import hashlib
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def vault(*args, input_text=None, token=None, expect_success=True):
    env = os.environ.copy()
    if token is not None:
        env["VAULT_TOKEN"] = token
    result = subprocess.run(
        ["vault", *args], input=input_text, capture_output=True,
        text=True, env=env, check=False, timeout=45,
    )
    if expect_success and result.returncode != 0:
        # Errors are sanitized: never print arguments or response bodies that
        # may contain secrets, issuer values, or generated token material.
        raise AssertionError(
            f"Vault command failed: command={args[0]} exit={result.returncode}; "
            f"message={result.stderr[:250]!r}"
        )
    if not expect_success and result.returncode == 0:
        raise AssertionError(f"Expected Vault command to be denied: {args[0]}")
    return result.stdout if expect_success else None


def vault_json(*args, **kwargs):
    return json.loads(vault(*args, **kwargs))


def mock_get(base, ca, path, auth=None, expected=200):
    headers = {}
    if auth is not None:
        headers["Authorization"] = auth
    request = urllib.request.Request(base + path, headers=headers)
    context = ssl.create_default_context(cafile=str(ca))
    try:
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    if status != expected:
        raise AssertionError(f"Mock API returned HTTP {status}, expected {expected}")
    return json.loads(body)


def check(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--mock-url", default="https://localhost:8843")
    args = parser.parse_args()

    binary = Path(args.plugin)
    cert = Path(args.ca)
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    plugin_name = "vault-plugin-secrets-proxmox"
    version = "v0.0.0-ci"
    mount = "ci-proxmox"

    vault(
        "plugin", "register", f"-sha256={sha}",
        f"-command={plugin_name}", f"-version={version}", "secret", plugin_name,
    )
    details = vault_json("plugin", "info", "-format=json", "secret", plugin_name)
    check(details.get("name") == plugin_name, "plugin registers in Vault catalog")

    vault(
        "secrets", "enable", f"-path={mount}",
        f"-plugin-version={version}", plugin_name,
    )
    mounts = vault_json("secrets", "list", "-format=json")
    check(f"{mount}/" in mounts, "external secrets engine mounts successfully")

    # Intentionally absent CA test: Vault must reject untrusted endpoints.
    ca_params = ["ca_cert_pem=@" + str(cert)]
    issuer_params = [
        "user=issuer", "realm=pve", "token_id=bootstrap",
        "token_secret=-", f"proxmox_url={args.mock_url}/api2/json",
        "timeout=20", "insecure_skip_tls_verify=false",
    ]
    vault(
        "write", f"{mount}/config",
        *issuer_params, *ca_params, input_text="ci-only-issuer-secret",
    )
    read_config = vault_json("read", "-format=json", f"{mount}/config")
    check(
        read_config["data"].get("token_id") == "bootstrap"
        and "token_secret" not in read_config["data"],
        "issuer config persists without exposing the bootstrap secret",
    )

    vault(
        "write", f"{mount}/role/deployer",
        "user=workload", "realm=pve", "ttl=2m", "max_ttl=5m",
        "inherit_user_privileges=true",
    )
    roles = vault_json("read", "-format=json", f"{mount}/role/deployer")
    check(
        roles["data"]["inherit_user_privileges"] is True,
        "role enforces explicit privilege inheritance acknowledgement",
    )

    bad = vault(
        "write", f"{mount}/role/unsafe",
        "user=root", "realm=pam", "inherit_user_privileges=true",
        expect_success=False,
    )
    check(bad is None, "root@pam role is refused")

    policy = f'path "{mount}/creds/deployer" {{ capabilities = ["read"] }}\n'
    vault("policy", "write", "e2e-consumer", "-", input_text=policy)
    vault_token = vault_json(
        "token", "create", "-format=json", "-policy=e2e-consumer",
        "-no-default-policy", "-ttl=10m",
    )["auth"]["client_token"]
    vault("read", f"{mount}/config", token=vault_token, expect_success=False)
    vault(
        "write", f"{mount}/role/unauthorized",
        "user=other", "realm=pve", token=vault_token,
        expect_success=False,
    )
    check(True, "Vault ACLs deny consumer issuer and role management")

    result = vault_json(
        "read", "-format=json", f"{mount}/creds/deployer", token=vault_token,
    )
    lease = result.get("lease_id")
    data = result.get("data") or {}
    check(
        isinstance(lease, str) and lease.startswith(mount + "/creds/deployer/")
        and result.get("renewable", result.get("lease_renewable")) is False
        and result.get("lease_duration", 0) > 0
        and data.get("token_id_full", "").startswith("workload@pve!")
        and data.get("secret") == "ci-only-generated-token-value",
        "real Vault lease contains a non-renewable temporary Proxmox token",
    )
    combined = "PVEAPIToken=" + data["token_id_full"] + "=" + data["secret"]
    mock = mock_get(args.mock_url, cert, "/__test__/authenticate", auth=combined)
    check(mock.get("authorized") is True, "issued token authenticates with the Proxmox mock")
    state = mock_get(args.mock_url, cert, "/__test__/state")
    check(
        state["created"] == 1 and state["deleted"] == 0
        and len(state["active"]) == 1
        and state["active"][0]["privsep"] == "0",
        "Proxmox mock records one finite-expiry, inheritance-mode token",
    )

    # Revoke after changing the role's target; revocation must use the identity
    # stored with the lease instead of the newly configured role.
    vault(
        "write", f"{mount}/role/deployer",
        "user=changed-account", "realm=pve", "ttl=2m", "max_ttl=5m",
        "inherit_user_privileges=true",
    )
    vault("lease", "revoke", "-sync", lease)
    state = mock_get(args.mock_url, cert, "/__test__/state")
    check(
        state["created"] == 1 and state["deleted"] == 1
        and len(state["active"]) == 0,
        "Vault synchronous revoke deletes original token after role modification",
    )
    mock_get(args.mock_url, cert, "/__test__/authenticate", auth=combined, expected=401)
    check(True, "revoked token no longer authenticates")

    # Simulated Proxmox permission denial is a failed issuance, not a
    # successful-looking Vault lease or an automatic permissions escalation.
    vault(
        "write", f"{mount}/role/denied",
        "user=forbidden", "realm=pve", "ttl=2m", "max_ttl=5m",
        "inherit_user_privileges=true",
    )
    vault("read", f"{mount}/creds/denied", expect_success=False)
    state = mock_get(args.mock_url, cert, "/__test__/state")
    check(
        state["rejected"] >= 1 and len(state["active"]) == 0,
        "simulated Proxmox 403 fails issuance without leaving active credentials",
    )

    # Distinct mount uses no CA certificate. The fake Proxmox endpoint has an
    # ephemeral self-signed cert; a verified client must fail without the CA.
    vault("secrets", "enable", "-path=ci-no-ca", f"-plugin-version={version}", plugin_name)
    vault(
        "write", "ci-no-ca/config",
        *issuer_params, input_text="ci-only-issuer-secret",
    )
    vault(
        "write", "ci-no-ca/role/tls-check",
        "user=workload", "realm=pve", "ttl=2m", "max_ttl=5m",
        "inherit_user_privileges=true",
    )
    vault("read", "ci-no-ca/creds/tls-check", expect_success=False)
    check(True, "untrusted Proxmox TLS certificate is rejected without configured CA")

    print("SUCCESS: ephemeral Vault external-plugin E2E passed, with no real Proxmox connection", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Test credentials above are fixtures, never print token response.
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
