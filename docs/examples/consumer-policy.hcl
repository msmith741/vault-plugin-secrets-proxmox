# Example Vault ACL policy for a single Proxmox workload role.
# Assign only to the authenticated machine or user that needs this token.
# Every successful read creates a new Proxmox API token.
path "proxmox/creds/workload" {
  capabilities = ["read"]
}
