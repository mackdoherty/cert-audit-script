# cert.ps1 — TLS Certificate Audit for CA Migrations

Parallel TLS certificate auditing tool for Windows DNS environments. Enumerates all servers in a DNS zone, probes each one for TLS certificates, and classifies them as migrated to a new CA or still on the old one. Results are exported to CSV.

Designed for use during internal CA migrations (e.g. replacing an old issuing CA with a new one).

## Requirements

- PowerShell 7+
- RSAT DNS Server Tools (`DnsServer` module) — typically installed on Domain Controllers or admin workstations
- Network access to the target hosts on the ports being checked
- Read access to the DNS zone via the specified DNS server

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-DnsServer` | Yes | — | FQDN or IP of the DNS server to query |
| `-DnsZone` | Yes | — | DNS zone to enumerate (e.g. `megacorp.corp`) |
| `-NewCA_Name` | Yes | — | Display name of the new CA (substring matched against cert issuer) |
| `-NewCA_IssuerThumbprint` | No | — | Thumbprint of the new CA cert — enables exact chain matching (recommended) |
| `-NewCA_IssuerDN` | No | — | Full Distinguished Name of the new CA — used for DN-level matching |
| `-PortsToCheck` | No | `443, 8443` | Ports to probe on each host |
| `-ExportPath` | No | Desktop or `%TEMP%` | Full path for the output CSV |
| `-Concurrency` | No | `20` | Number of parallel connections (5–50) |
| `-ConnectTimeoutMs` | No | `4000` | TCP connect timeout in milliseconds |
| `-HandshakeTimeoutMs` | No | `6000` | TLS handshake timeout in milliseconds |
| `-MaxRetries` | No | `2` | Retry attempts per host:port on failure (0–5) |
| `-HostnameFilter` | No | Excludes `pc`, `laptop`, `workstation`, `test`, `dev-`, `backup` | Regex applied to hostnames — only matching hosts are probed |
| `-SslProtocols` | No | OS default | TLS protocol version(s) to negotiate |
| `-RequireTrustedChain` | No | Off | Perform real chain validation instead of bypassing. Use after the new root is trusted locally. |
| `-CheckRevocation` | No | Off | Enable online CRL/OCSP revocation checking (adds latency) |

## Issuer Matching

The script determines whether a cert was issued by the new CA using the following priority order:

1. **Thumbprint** — checks if the new CA's thumbprint appears anywhere in the certificate chain (most reliable)
2. **Distinguished Name** — normalized DN comparison against the cert's direct issuer
3. **Name substring** — fallback match of `-NewCA_Name` against the issuer string

Providing `-NewCA_IssuerThumbprint` is strongly recommended for accurate results.

## Output

The CSV contains one row per host:port with the following columns:

| Column | Description |
|---|---|
| `Hostname` | FQDN of the host |
| `Port` | Port probed |
| `Status` | `Updated (New CA)`, `OLD / Other CA`, `Updated (New CA) - Chain Invalid`, or `Error` |
| `Issuer` | Certificate issuer DN |
| `Subject` | Certificate subject DN |
| `SANs` | Subject Alternative Names |
| `Thumbprint` | Certificate thumbprint |
| `ExpiryDate` | Expiry date (`yyyy-MM-dd`) |
| `DaysLeft` | Days until expiry |
| `TlsVersion` | Negotiated TLS protocol |
| `Cipher` | Cipher suite and key strength |
| `ChainValid` | Whether the chain built successfully against the local trust store |
| `ChainStatus` | Chain status details, or `OK` |
| `Error` | Error message if the connection failed |

## Usage Examples

**Dry run — see what would be probed without making any connections:**
```powershell
.\cert.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
    -NewCA_Name "MegaCorp Enterprise CA 2025" -WhatIf
```

**Standard audit with thumbprint matching:**
```powershell
.\cert.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
    -NewCA_Name "MegaCorp Enterprise CA 2025" `
    -NewCA_IssuerThumbprint "A1B2C3D4E5F67890ABCDEF1234567890ABCDEF12"
```

**Audit additional ports with revocation checking:**
```powershell
.\cert.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
    -NewCA_Name "MegaCorp Enterprise CA 2025" `
    -NewCA_IssuerThumbprint "A1B2C3D4E5F67890ABCDEF1234567890ABCDEF12" `
    -PortsToCheck 443,636,8443 -CheckRevocation
```

**After deploying the new root to the local trust store — use real chain validation:**
```powershell
.\cert.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
    -NewCA_Name "MegaCorp Enterprise CA 2025" `
    -NewCA_IssuerThumbprint "A1B2C3D4E5F67890ABCDEF1234567890ABCDEF12" `
    -RequireTrustedChain
```

## Notes

- **Chain validity vs. issuer match are independent.** A cert can be classified as `Updated (New CA)` but still show `ChainValid = False` if the new root isn't trusted on the machine running the script. This is expected early in a migration. The warning at the end of the run will flag this.
- **The hostname filter excludes workstations and dev machines by default.** Adjust `-HostnameFilter` if your naming conventions differ.
- **`-RequireTrustedChain` will cause connection failures** for new-CA certs if the root isn't trusted locally yet. Leave it off until the root has been distributed.
- **Revocation checking adds significant latency** on large zones. Leave `-CheckRevocation` off for initial sweeps.
- The script requires permission to remotely query the DNS zone. Run as an account with DNS read access.
