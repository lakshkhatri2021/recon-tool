#!/usr/bin/env python3
"""
recon.py — automated external attack surface recon
usage: python3 recon.py <domain> [-o output_file]
"""

import subprocess  # lets python run terminal commands
import sys         # lets us read command line arguments
import os          # used to build the path to the wordlist file
import re          # regex — used to strip colour codes from output
import argparse    # handles command line arguments cleanly
import shutil      # used to check if tools are installed
from datetime import datetime  # for timestamps

# list of tools that need to be installed before the script runs
REQUIRED_BINS = ["subfinder", "httpx", "naabu", "tlsx", "nuclei", "ffuf"]

# ── port risk catalog ───────────────────────────────────────────────────────
# maps a port number to (service name, risk level, note explaining why it matters)
# this turns raw port numbers into something a non-technical reader understands
PORT_RISK_CATALOG = {
    21:    ("FTP",          "HIGH",   "often allows anonymous login; credentials sent in plaintext"),
    22:    ("SSH",          "MEDIUM", "ensure key-based auth and disable root login"),
    23:    ("Telnet",       "HIGH",   "unencrypted remote access; should never be internet-facing"),
    25:    ("SMTP",         "MEDIUM", "check for open mail relay"),
    53:    ("DNS",          "LOW",    "normal for DNS servers"),
    80:    ("HTTP",         "LOW",    "normal; check for redirect to HTTPS"),
    110:   ("POP3",         "MEDIUM", "often unencrypted"),
    135:   ("MSRPC",        "HIGH",   "Windows RPC endpoint; common attack vector"),
    139:   ("NetBIOS",      "HIGH",   "legacy Windows file sharing; common attack vector"),
    143:   ("IMAP",         "MEDIUM", "often unencrypted"),
    443:   ("HTTPS",        "LOW",    "normal"),
    445:   ("SMB",          "HIGH",   "Windows file sharing; target of EternalBlue and similar exploits"),
    1433:  ("MSSQL",        "HIGH",   "database should not be internet-facing"),
    1521:  ("Oracle DB",    "HIGH",   "database should not be internet-facing"),
    2049:  ("NFS",          "HIGH",   "network file system; often has misconfigured permissions"),
    3306:  ("MySQL",        "HIGH",   "database should not be internet-facing"),
    3389:  ("RDP",          "HIGH",   "common ransomware entry point; ensure MFA/NLA enabled"),
    5432:  ("PostgreSQL",   "HIGH",   "database should not be internet-facing"),
    5900:  ("VNC",          "HIGH",   "remote desktop; often has weak or no authentication"),
    6379:  ("Redis",        "HIGH",   "frequently exposed without authentication by default"),
    8080:  ("HTTP-alt",     "MEDIUM", "often an admin panel or proxy"),
    8443:  ("HTTPS-alt",    "MEDIUM", "often an admin panel"),
    9200:  ("Elasticsearch","HIGH",   "frequently exposed without authentication"),
    11211: ("Memcached",    "HIGH",   "frequently exposed without auth; can be abused for DDoS amplification"),
}

# order used to sort findings so the scariest stuff shows up first
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "wordlists", "common.txt")


def check_deps():
    missing = [b for b in REQUIRED_BINS if not shutil.which(b)]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        print("    Install: brew install " + " ".join(missing))
        print("    Also needed: pip3 install dnstwist checkdmarc --break-system-packages")
        sys.exit(1)


def clean(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text or "").strip()


def run(cmd, stdin_data=None, timeout=300):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            input=stdin_data,
            timeout=timeout,
        )
        stdout = clean(result.stdout)
        stderr = clean(result.stderr) if result.returncode != 0 else None
        return stdout, stderr
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except Exception as e:
        return "", str(e)


def section(title, f):
    bar = "=" * 60
    msg = f"\n{bar}\n  {title}\n{bar}"
    print(msg)
    f.write(msg + "\n")


def log(text, f):
    print(text)
    f.write(text + "\n")


# ── each function below is one stage of the recon ──────────────────

def run_subfinder(domain, f):
    section("1/8  subfinder — passive subdomain enumeration", f)
    out, err = run(f"subfinder -d {domain} -silent")
    if err:
        log(f"[!] subfinder error: {err}", f)
    subdomains = [s for s in out.splitlines() if s.strip()]
    log(f"Found {len(subdomains)} subdomain(s)\n{out}", f)
    return subdomains


def run_httpx(domain, subdomains, f):
    section("2/8  httpx — live host probing", f)
    all_hosts = [domain] + subdomains
    out, err = run("httpx -silent", stdin_data="\n".join(all_hosts))
    if err:
        log(f"[!] httpx error: {err}", f)
    live = [s for s in out.splitlines() if s.strip()]
    log(f"Live hosts ({len(live)}):\n{out}", f)
    return live


def run_naabu(domain, subdomains, f):
    # naabu scans for open ports across the root domain + all subdomains
    section("3/8  naabu — port scanning + risk classification", f)
    all_hosts = "\n".join([domain] + subdomains)
    out, err = run("naabu -silent", stdin_data=all_hosts)
    if err:
        log(f"[!] naabu error: {err}", f)

    if not out:
        log("(no open ports found)", f)
        return

    # naabu output is one "host:port" pair per line
    # naabu can report the same host:port twice (once per IPv4/IPv6 address)
    # so we use a set to drop exact duplicates
    seen = set()
    findings = []  # list of (host, port) tuples
    for line in out.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        if line in seen:
            continue
        seen.add(line)

        # split "host:port" from the right, in case the host itself
        # contains a colon (shouldn't for domains, but safe either way)
        host, _, port_str = line.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            continue
        findings.append((host, port))

    # sort findings so HIGH risk ports appear first, then by port number
    def sort_key(item):
        _, port = item
        _, risk, _ = PORT_RISK_CATALOG.get(port, ("Unknown", "UNKNOWN", ""))
        return (RISK_ORDER[risk], port)

    findings.sort(key=sort_key)

    high_risk_count = 0
    for host, port in findings:
        service, risk, note = PORT_RISK_CATALOG.get(
            port, ("Unknown", "UNKNOWN", "not in risk catalog — manually review")
        )
        if risk == "HIGH":
            high_risk_count += 1
        # left-pad risk to 6 chars and service to 15 chars so columns line up
        log(f"  [{risk:<6}] {host}:{port:<5} {service:<15} — {note}", f)

    if high_risk_count:
        log(f"\n  ⚠ {high_risk_count} high-risk port(s) found — review immediately", f)


def run_tlsx(domain, f):
    section("4/8  tlsx — TLS certificate inspection", f)
    out, err = run(f"tlsx -u {domain} -silent")
    if err:
        log(f"[!] tlsx error: {err}", f)
    log(out or "(no TLS data returned)", f)


def run_dnstwist(domain, f):
    section("5/8  dnstwist — typosquatting detection", f)
    out, err = run(f"dnstwist {domain}")
    if err:
        log(f"[!] dnstwist error: {err}", f)
    log(out or "(no results)", f)


def run_checkdmarc(domain, f):
    section("6/8  checkdmarc — DMARC / SPF / DKIM", f)
    out, err = run(f"checkdmarc {domain}")
    if err:
        log(f"[!] checkdmarc error: {err}", f)
    log(out or "(no results)", f)


def run_nuclei(live_hosts, f):
    section("7/8  nuclei — vulnerability template scanning", f)
    if not live_hosts:
        log("Skipped — no live hosts to scan.", f)
        return
    out, err = run("nuclei -silent", stdin_data="\n".join(live_hosts))
    if err:
        log(f"[!] nuclei error: {err}", f)
    log(out or "(no findings)", f)

def run_ffuf(live_hosts, f):
    section("8/8  ffuf — directory & file brute-forcing", f)

    if not live_hosts:
        log("Skipped — no live hosts to scan.", f)
        return

    if not os.path.exists(WORDLIST_PATH):
        log(f"[!] wordlist not found at {WORDLIST_PATH}", f)
        return

    any_findings = False

    for host in live_hosts:
        log(f"\n  Target: {host}", f)
        cmd = (
            f"ffuf -u {host}/FUZZ -w {WORDLIST_PATH} "
            f"-mc 200,204,301,302,307,401,403 -t 40 -s"
        )
        out, err = run(cmd, timeout=180)
        if err:
            log(f"  [!] ffuf error: {err}", f)
            continue

        if out:
            any_findings = True
            log(out, f)
        else:
            log("  (nothing found)", f)

    if any_findings:
        log("\n  ⚠ ffuf found accessible paths above — review each manually,"
            " some may expose sensitive files or admin interfaces", f)


def main():
    parser = argparse.ArgumentParser(
        description="Automated external attack surface recon tool"
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "-o", "--output", help="Output file (default: <domain>_report.txt)"
    )
    args = parser.parse_args()

    domain = args.domain
    output_file = args.output or f"{domain}_report.txt"

    check_deps()

    start = datetime.now()

    with open(output_file, "w") as f:
        log(f"Started : {start.strftime('%Y-%m-%d %H:%M:%S')}", f)
        log(f"Target  : {domain}", f)
        log(f"Output  : {output_file}\n", f)

        subdomains = run_subfinder(domain, f)
        live_hosts = run_httpx(domain, subdomains, f)
        run_naabu(domain, subdomains, f)
        run_tlsx(domain, f)
        run_dnstwist(domain, f)
        run_checkdmarc(domain, f)
        run_nuclei(live_hosts, f)
        run_ffuf(live_hosts, f)

        elapsed = int((datetime.now() - start).total_seconds())
        bar = "=" * 60
        summary = (
            f"\n{bar}\n  RECON COMPLETE\n{bar}\n"
            f"  Target     : {domain}\n"
            f"  Subdomains : {len(subdomains)}\n"
            f"  Live hosts : {len(live_hosts)}\n"
            f"  Elapsed    : {elapsed}s\n"
            f"  Report     : {output_file}\n"
            f"{bar}"
        )
        log(summary, f)

    print(f"\nReport saved → {output_file}")


if __name__ == "__main__":
    main()