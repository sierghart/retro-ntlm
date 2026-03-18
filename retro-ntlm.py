#!/usr/bin/env python3
# =============================================================================
# ldap_ntlmv1.py — NTLMv1 GPO Detection via LDAP + SYSVOL
#
# Detects NTLMv1 policy (LmCompatibilityLevel) by:
#   1. Querying Active Directory via LDAP for GPOs
#   2. Reading GptTmpl.inf files from SYSVOL share
#   3. Parsing LmCompatibilityLevel from Security Options
#
# Requirements:
#   pip install ldap3 impacket --break-system-packages
#
# Usage:
#   python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -p Password123 --dc 192.168.1.10
#   python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -H aad3b435:5f4dcc3b5aa -dc 192.168.1.10
# =============================================================================

import argparse
import sys
import re
from datetime import datetime

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

LM_LEVEL_MEANING = {
    0: ("NTLMv1 ACTIVE",   RED,   "Sends LM + NTLMv1 (no ESS)"),
    1: ("NTLMv1 ACTIVE",   RED,   "Sends LM + NTLMv1 (ESS if negotiated)"),
    2: ("NTLMv1 ACTIVE",   RED,   "Sends NTLMv1 only"),
    3: ("NTLMv2 only",     GREEN, "Sends NTLMv2 only"),
    4: ("NTLMv2 only",     GREEN, "Refuses NTLMv1, accepts NTLMv2"),
    5: ("NTLMv2 only",     GREEN, "Refuses LM + NTLMv1, NTLMv2 only"),
}


def banner():
    print(f"""{CYAN}{BOLD}
  ██████╗ ███████╗████████╗██████╗  ██████╗       ███╗   ██╗████████╗██╗     ███╗   ███╗
  ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗      ████╗  ██║╚══██╔══╝██║     ████╗ ████║
  ██████╔╝█████╗     ██║   ██████╔╝██║   ██║█████╗██╔██╗ ██║   ██║   ██║     ██╔████╔██║
  ██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║╚════╝██║╚██╗██║   ██║   ██║     ██║╚██╔╝██║
  ██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝      ██║ ╚████║   ██║   ███████╗██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝       ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
{RESET}  {BOLD}RETRO-NTLM{RESET} — NTLMv1 GPO Detection via LDAP + SYSVOL
  ──────────────────────────────────────────────────────────────────────────
""")


# ─── LDAP: Query GPOs from Active Directory ───────────────────────────────────

def get_gpos_ldap(server, domain, username, password, nthash):
    """Connects to AD via LDAP using impacket (same stack as netexec) and retrieves all GPOs"""
    try:
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1 as ldapasn1_impacket
    except ImportError:
        print(f"  {RED}[!]{RESET} impacket not installed. Run: pip install impacket --break-system-packages")
        sys.exit(1)

    # Build base DN from domain (CORP.LOCAL → DC=CORP,DC=LOCAL)
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    print(f"  {CYAN}[*]{RESET} Connecting to LDAP: {server}")
    print(f"  {CYAN}[*]{RESET} Base DN: {base_dn}")

    # Parse hash
    lmhash = ""
    nthash_val = ""
    if nthash:
        parts      = nthash.split(":")
        lmhash     = parts[0] if len(parts) == 2 else "aad3b435b51404eeaad3b435b51404ee"
        nthash_val = parts[-1]
        print(f"  {CYAN}[*]{RESET} Auth method: NTLM (pass-the-hash)")
    else:
        print(f"  {CYAN}[*]{RESET} Auth method: NTLM (password)")

    try:
        conn = impacket_ldap.LDAPConnection(
            f"ldap://{server}",
            base_dn,
            server
        )
        if nthash:
            conn.login(username, "", domain, lmhash, nthash_val)
        else:
            conn.login(username, password, domain)
    except Exception as e:
        print(f"  {RED}[!]{RESET} LDAP connection failed: {e}")
        sys.exit(1)

    print(f"  {GREEN}[+]{RESET} LDAP connected successfully\n")

    # Search for all GPOs
    gpos = []
    try:
        resp = conn.search(
            searchBase=f"CN=Policies,CN=System,{base_dn}",
            searchFilter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "cn", "whenChanged", "flags"]
        )

        for item in resp:
            if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                continue

            name    = ""
            path    = ""
            guid    = ""
            changed = ""
            flags   = "0"

            for attr in item["attributes"]:
                attr_name = str(attr["type"])
                val       = str(attr["vals"][0]) if attr["vals"] else ""

                if attr_name == "displayName":
                    name = val
                elif attr_name == "gPCFileSysPath":
                    path = val
                elif attr_name == "cn":
                    guid = val
                elif attr_name == "whenChanged":
                    changed = val
                elif attr_name == "flags":
                    flags = val

            gpos.append({
                "name":    name or "Unknown",
                "path":    path,
                "guid":    guid,
                "changed": changed,
                "flags":   flags,
            })

    except Exception as e:
        print(f"  {RED}[!]{RESET} LDAP search failed: {e}")
        sys.exit(1)

    print(f"  {CYAN}[*]{RESET} Found {BOLD}{len(gpos)}{RESET} GPOs in the domain\n")
    return gpos


# ─── SYSVOL: Read GptTmpl.inf files ──────────────────────────────────────────

def parse_sysvol_path(sysvol_path):
    r"""
    Parses a UNC SYSVOL path into (share, relative_path).

    Input examples:
      \\CORP.LOCAL\SysVol\corp.local\Policies\{GUID}
      \\192.168.1.10\SYSVOL\corp.local\Policies\{GUID}

    Returns:
      share     = "SYSVOL"
      rel_path  = "corp.local\\Policies\\{GUID}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
    """
    # Normalize slashes and strip leading backslashes
    clean = sysvol_path.replace("/", "\\").lstrip("\\")

    # Split: [host, share, rest...]
    parts = clean.split("\\", 2)

    if len(parts) < 2:
        return None, None

    share    = parts[1].upper()   # SYSVOL or NETLOGON
    rel_rest = parts[2] if len(parts) == 3 else ""

    # Append the GptTmpl.inf subpath — use explicit double backslashes (Windows UNC)
    suffix  = "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
    gpttmpl = rel_rest.rstrip("\\") + "\\" + suffix

    return share, gpttmpl


def smb_login(conn, username, password, domain, nthash):
    """Handles both password and pass-the-hash login"""
    if nthash:
        parts  = nthash.split(":")
        lmhash = parts[0] if len(parts) == 2 else "aad3b435b51404eeaad3b435b51404ee"
        nth    = parts[-1]
        conn.login(username, "", domain, lmhash, nth)
    else:
        conn.login(username, password, domain)


# Reuse a single SMB connection per scan to avoid reconnecting for every GPO
_smb_conn_cache = {}

def get_smb_conn(dc, domain, username, password, nthash):
    """Returns a cached SMB connection to the DC"""
    from impacket.smbconnection import SMBConnection
    key = dc
    if key not in _smb_conn_cache:
        conn = SMBConnection(dc, dc, timeout=10)
        smb_login(conn, username, password, domain, nthash)
        _smb_conn_cache[key] = conn
    return _smb_conn_cache[key]


def read_gpttmpl_smb(dc, domain, username, password, nthash, sysvol_path):
    """Reads GptTmpl.inf from SYSVOL via SMB using impacket"""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print(f"  {RED}[!]{RESET} impacket not installed. Run: pip install impacket --break-system-packages")
        return None

    share, gpttmpl_path = parse_sysvol_path(sysvol_path)

    if not share or not gpttmpl_path:
        return None

    try:
        conn = get_smb_conn(dc, domain, username, password, nthash)

        buf = []
        conn.getFile(share, gpttmpl_path, buf.append)

        raw = b"".join(buf)

        # GptTmpl.inf is typically UTF-16-LE with BOM
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            content = raw.decode("utf-16", errors="ignore")
        else:
            content = raw.decode("utf-8", errors="ignore")

        return content if content.strip() else None

    except Exception as e:
        # Connection may have been reset — clear cache and retry once
        if dc in _smb_conn_cache:
            try: _smb_conn_cache[dc].logoff()
            except: pass
            del _smb_conn_cache[dc]
        try:
            conn = get_smb_conn(dc, domain, username, password, nthash)
            buf  = []
            conn.getFile(share, gpttmpl_path, buf.append)
            raw  = b"".join(buf)
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                return raw.decode("utf-16", errors="ignore")
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return None


def parse_lm_level(content):
    r"""
    Parses LmCompatibilityLevel from GptTmpl.inf content.

    Handles both formats:
      Format 1 (Registry Values section):
        MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,0
        where 4 = REG_DWORD type, 0 = actual value

      Format 2 (plain System Access section):
        LmCompatibilityLevel = 0
    """
    if not content:
        return None

    # Format 1 — registry path with type,value  (most common in GptTmpl.inf)
    match = re.search(
        r"LmCompatibilityLevel\s*=\s*\d+,\s*(\d+)",
        content,
        re.IGNORECASE
    )
    if match:
        return int(match.group(1))

    # Format 2 — plain value (fallback)
    match = re.search(
        r"LmCompatibilityLevel\s*=\s*(\d+)",
        content,
        re.IGNORECASE
    )
    if match:
        return int(match.group(1))

    return None


# ─── LDAP fallback: check Default Domain Policy security settings ─────────────

def check_ldap_security_policy(server, domain, username, password, nthash):
    """
    Fallback: searches for domain info via impacket LDAP.
    Not as accurate as SYSVOL but works without SMB access.
    """
    try:
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1 as ldapasn1_impacket
    except ImportError:
        return []

    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    lmhash    = ""
    nthash_val = ""
    if nthash:
        parts      = nthash.split(":")
        lmhash     = parts[0] if len(parts) == 2 else "aad3b435b51404eeaad3b435b51404ee"
        nthash_val = parts[-1]

    results = []
    try:
        conn = impacket_ldap.LDAPConnection(f"ldap://{server}", base_dn, server)
        if nthash:
            conn.login(username, "", domain, lmhash, nthash_val)
        else:
            conn.login(username, password, domain)

        resp = conn.search(
            searchBase=base_dn,
            searchFilter="(objectClass=domain)",
            attributes=["msDS-Behavior-Version", "ms-DS-MachineAccountQuota",
                        "minPwdLength", "lockoutThreshold", "pwdProperties"]
        )

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry):
                results.append({
                    "type":    "Domain Info",
                    "details": str(item)
                })

    except Exception:
        pass

    return results


# ─── Main scan logic ──────────────────────────────────────────────────────────

def scan(dc, domain, username, password, nthash, output_file):
    print(f"  {CYAN}[*]{RESET} Target DC  : {dc}")
    print(f"  {CYAN}[*]{RESET} Domain     : {domain}")
    print(f"  {CYAN}[*]{RESET} Username   : {username}@{domain}")
    print(f"  {CYAN}[*]{RESET} Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {'─'*70}\n")

    # Step 1: Get all GPOs via LDAP
    gpos = get_gpos_ldap(dc, domain, username, password, nthash)

    if not gpos:
        print(f"  {YELLOW}[?]{RESET} No GPOs found. Check credentials and domain.")
        return

    # Step 2: For each GPO, read GptTmpl.inf from SYSVOL
    findings = []
    not_defined = []
    errors      = []

    print(f"  {CYAN}[*]{RESET} Reading GptTmpl.inf from SYSVOL for each GPO...\n")

    for gpo in gpos:
        name = gpo["name"]
        path = gpo["path"]

        if not path:
            errors.append({"gpo": name, "reason": "No SYSVOL path"})
            continue

        # Show parsed path for debugging
        share, gpttmpl_path = parse_sysvol_path(path)
        print(f"  {GRAY}[~]{RESET} {name}")
        print(f"       Share: {share} | Path: {gpttmpl_path}")

        content = read_gpttmpl_smb(dc, domain, username, password, nthash, path)

        if content is None:
            errors.append({"gpo": name, "reason": "Could not read GptTmpl.inf"})
            print(f"  {GRAY}[-]{RESET} {name} — could not read GptTmpl.inf")
            continue

        lm_level = parse_lm_level(content)

        if lm_level is not None:
            label, color, meaning = LM_LEVEL_MEANING.get(lm_level, ("Unknown", YELLOW, "Unknown level"))
            findings.append({
                "gpo":      name,
                "path":     path,
                "level":    lm_level,
                "label":    label,
                "meaning":  meaning,
                "changed":  gpo["changed"],
            })
            vuln_str = f"{color}{BOLD}[!] {label}{RESET}" if lm_level <= 2 else f"{GREEN}[+] {label}{RESET}"
            print(f"  {vuln_str} — GPO: {BOLD}{name}{RESET}")
            print(f"       LmCompatibilityLevel = {lm_level} → {meaning}")
            print(f"       Last modified: {gpo['changed']}")
            print(f"       Path: {path}\n")
        else:
            not_defined.append(name)
            print(f"  {GRAY}[~]{RESET} {name} — LmCompatibilityLevel not defined in this GPO")

    # Step 3: Summary
    vuln_gpos  = [f for f in findings if f["level"] <= 2]
    safe_gpos  = [f for f in findings if f["level"] > 2]

    print(f"\n  {'─'*70}")
    print(f"  {CYAN}[*]{RESET} GPOs scanned          : {len(gpos)}")
    print(f"  {CYAN}[*]{RESET} GPOs with LM setting  : {len(findings)}")
    print(f"  {GREEN}[+]{RESET} NTLMv2 enforced       : {len(safe_gpos)}")
    print(f"  {RED}{BOLD}[!] NTLMv1 ACTIVE          : {len(vuln_gpos)}{RESET}")
    print(f"  {GRAY}[~]{RESET} Not defined in GPO    : {len(not_defined)}")
    print(f"  {YELLOW}[-]{RESET} Read errors           : {len(errors)}")

    if not findings and not errors:
        print(f"\n  {YELLOW}[!]{RESET} LmCompatibilityLevel not explicitly set in any GPO.")
        print(f"       This means the {BOLD}Windows default is used (level 0 or 1 on older systems){RESET}.")
        print(f"       Without explicit policy, NTLMv1 may be active.")

    if vuln_gpos:
        print(f"\n  {RED}{BOLD}GPOs with NTLMv1 ACTIVE:{RESET}")
        for f in vuln_gpos:
            print(f"    {RED}→{RESET} {f['gpo']} [Level {f['level']}] — {f['meaning']}")

    # Step 4: Save to file
    if output_file:
        save_results(findings, not_defined, errors, output_file)

    # Close cached SMB connection
    for conn in _smb_conn_cache.values():
        try: conn.logoff()
        except: pass
    _smb_conn_cache.clear()


def save_results(findings, not_defined, errors, filename):
    import csv
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "gpo", "path", "level", "label", "meaning", "changed"
        ])
        writer.writeheader()
        for r in findings:
            writer.writerow(r)
        for name in not_defined:
            writer.writerow({
                "gpo": name, "path": "", "level": "N/A",
                "label": "Not defined", "meaning": "LmCompatibilityLevel not set in this GPO", "changed": ""
            })
    print(f"\n  {CYAN}[*]{RESET} Results saved to: {filename}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Detects NTLMv1 policy via LDAP GPO enumeration + SYSVOL parsing",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -p Password123 --dc 192.168.1.10
  python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -H aad3b435:5f4dcc3b5aa --dc 192.168.1.10
  python3 ldap_ntlmv1.py -d CORP.LOCAL -u jsmith -p Password123 --dc 192.168.1.10 -o results.csv

Notes:
  - Requires a valid domain user account (no admin needed)
  - SYSVOL must be accessible (port 445)
  - LDAP must be accessible (port 389)
  - If LmCompatibilityLevel is not set in any GPO, Windows default applies (usually level 0-1)
        """
    )

    parser.add_argument("--dc",        required=True, help="Domain Controller IP or hostname")
    parser.add_argument("-d", "--domain", required=True, help="Domain FQDN (e.g. CORP.LOCAL)")
    parser.add_argument("-u", "--user",   required=True, help="Username")
    parser.add_argument("-p", "--pass",   dest="password", default="", help="Password")
    parser.add_argument("-H", "--hash",   dest="nthash",   default="", help="NT Hash (LMHASH:NTHASH or NTHASH)")
    parser.add_argument("-o", "--output", help="Save results to CSV")

    args = parser.parse_args()

    if not args.password and not args.nthash:
        print(f"  {RED}[!]{RESET} Provide either -p <password> or -H <nthash>")
        sys.exit(1)

    scan(
        dc=args.dc,
        domain=args.domain,
        username=args.user,
        password=args.password,
        nthash=args.nthash,
        output_file=args.output,
    )

    print()


if __name__ == "__main__":
    main()
