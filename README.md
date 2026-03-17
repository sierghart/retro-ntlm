# RETRO-NTLM — NTLMv1 GPO Detection via LDAP + SYSVOL

> Active Directory NTLMv1 policy auditing tool using only a standard domain user account.

RETRO-NTLM replicates the detection method used by PingCastle to identify whether NTLMv1 is enabled across an Active Directory domain. It connects via LDAP to enumerate all GPOs, then reads `GptTmpl.inf` files directly from the SYSVOL share to parse the `LmCompatibilityLevel` registry value — the definitive indicator of NTLMv1 being allowed.

---

## How It Works

1. **LDAP** — connects to the Domain Controller and enumerates all Group Policy Objects (GPOs), collecting their names, GUIDs and SYSVOL paths
2. **SYSVOL (SMB)** — for each GPO, reads the file:
   ```
   \\DOMAIN\SYSVOL\domain\Policies\{GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
   ```
3. **Parsing** — extracts `LmCompatibilityLevel` from the `[Registry Values]` section, handling both formats:
   ```ini
   ; Format 1 (most common)
   MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,0

   ; Format 2 (older GPOs)
   LmCompatibilityLevel = 0
   ```
4. **Report** — outputs findings per GPO with risk level and exports to CSV if requested

---

## Features

- Works with a **standard domain user** — no local admin required
- Enumerates all GPOs in the domain, not just the Default Domain Policy
- Handles both UTF-16-LE (BOM) and UTF-8 encoded `GptTmpl.inf` files
- Pass-the-hash support via Impacket
- CSV export for reporting
- Reuses a single SMB connection for all GPO reads (performance)
- Warns when `LmCompatibilityLevel` is not explicitly set in any GPO (Windows default applies)

---

## Requirements

- Python 3.8+
- [ldap3](https://github.com/cannatag/ldap3)
- [Impacket](https://github.com/fortra/impacket)
- Network access to the Domain Controller on ports **389 (LDAP)** and **445 (SMB/SYSVOL)**

> ⚠️ **No local admin required.** Any valid domain user account is sufficient.

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/youruser/retro-ntlm.git
cd retro-ntlm
```

**Install dependencies:**
```bash
pip install ldap3 impacket --break-system-packages
```

---

## Usage

### Password authentication
```bash
python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -p Password123 --dc 192.168.1.10
```

### Pass-the-hash
```bash
python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -H aad3b435b51404ee:5f4dcc3b5aa765d6 --dc 192.168.1.10
```

### Export results to CSV
```bash
python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -p Password123 --dc 192.168.1.10 -o results.csv
```

---

## Options

| Argument | Description |
|---|---|
| `--dc` | Domain Controller IP or hostname (**required**) |
| `-d`, `--domain` | Domain FQDN, e.g. `CORP.LOCAL` (**required**) |
| `-u`, `--user` | Username (**required**) |
| `-p`, `--pass` | Password |
| `-H`, `--hash` | NT Hash (`LMHASH:NTHASH` or `NTHASH` only) |
| `-o`, `--output` | Save results to CSV file |

---

## LmCompatibilityLevel Reference

| Value | Status | Meaning |
|---|---|---|
| 0 | ✅ NTLMv1 ACTIVE | Sends LM + NTLMv1 (no ESS) |
| 1 | ✅ NTLMv1 ACTIVE | Sends LM + NTLMv1 (ESS if negotiated) |
| 2 | ✅ NTLMv1 ACTIVE | Sends NTLMv1 only |
| 3 | ❌ NTLMv2 only | Sends NTLMv2 only |
| 4 | ❌ NTLMv2 only | Refuses NTLMv1, accepts NTLMv2 |
| 5 | ❌ NTLMv2 only | Refuses LM + NTLMv1, NTLMv2 only |

> ⚠️ **If `LmCompatibilityLevel` is not explicitly defined in any GPO**, Windows applies its default value (typically `0` or `1` on older systems), which means **NTLMv1 may be active** even without an explicit policy setting.

---

## Requirements per Account Type

| Requirement | Details |
|---|---|
| Domain user account | ✅ Required — any valid domain user |
| Local admin on target | ❌ Not required |
| LDAP access (port 389) | ✅ Required to enumerate GPOs |
| SMB access (port 445) | ✅ Required to read SYSVOL |

---

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Usage against systems without explicit written permission is illegal. The author assumes no liability for misuse.

