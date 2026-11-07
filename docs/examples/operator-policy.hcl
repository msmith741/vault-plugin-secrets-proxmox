# Example Vault ACL policy for an operator responsible for ONE mount.
# REVIEW BEFORE GRANTING. A holder can rotate/replace the privileged
# Proxmox issuer token, redirect issuer API settings, and change target
# Proxmox users on roles. This is NOT a consumer policy.
#
# Plugin catalog registration and system-level mount management are
# intentionally excluded; those require separate Vault administrator ACLs.
path "proxmox/config" {
  capabilities = ["create", "read", "update"]
}

path "proxmox/role/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "proxmox/role" {
  capabilities = ["list"]
}
