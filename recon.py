#!/usr/bin/env python3
"""
recon.py — automated external attack surface recon
usage: python3 recon.py <domain> [-o output_file]
"""

import subprocess  # lets python run terminal commands
import sys         # lets us read command line arguments
import os          # not used anymore but kept for compatibility
import re          # regex — used to strip colour codes from output
import argparse    # handles command line arguments cleanly
import shutil      # used to check if tools are installed
from datetime import datetime  # for timestamps

# list of tools that need to be installed before the script runs
REQUIRED_BINS = ["subfinder", "httpx", "naabu", "tlsx", "nuclei"]


def check_deps():
    # loops through each tool and checks if it exists on the system
    # shutil.which() is like typing "which subfinder" in terminal
    missing = [b for b in REQUIRED_BINS if not shutil.which(b)]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        print("    Install: brew install " + " ".join(missing))
        print("    Also needed: pip3 install dnstwist checkdmarc --break-system-packages")
        sys.exit(1)  # exit the script if anything is missing


def clean(text):
    # terminal output often has colour codes like \x1b[32m (green text)
    # this strips them out so the report file is plain readable text
    return re.sub(r'\x1b\[[0-9;]*m', '', text or "").strip()


def run(cmd, stdin_data=None, timeout=300):
    # runs a terminal command and returns its output
    # stdin_data lets us pipe input into the command (instead of using echo)
    # timeout=300 means if a command takes over 5 minutes, kill it
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,  # capture both stdout and stderr
            text=True,
            input=stdin_data,
            timeout=timeout,
        )
        stdout = clean(result.stdout)
        # only return stderr if the command actually failed
        stderr = clean(result.stderr) if result.returncode != 0 else None
        return stdout, stderr
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except Exception as e:
        return "", str(e)


def section(title, f):
    # prints and writes a section header to the report
    bar = "=" * 60
    msg = f"\n{bar}\n  {title}\n{bar}"
    print(msg)
    f.write(msg + "\n")


def log(text, f):
    # prints to terminal AND writes to the report file at the same time
    print(text)
    f.write(text + "\n")


# ── each function below is one stage of the recon ──────────────────

def run_subfinder(domain, f):
    # subfinder finds subdomains passively (no direct scanning)
    # e.g. for google.com it might find mail.google.com, drive.google.com etc
    section("1/7  subfinder — passive subdomain enumeration", f)
    out, err = run(f"subfinder -d {domain} -silent")
    if err:
        log(f"[!] subfinder error: {err}", f)
    subdomains = [s for s in out.splitlines() if s.strip()]
    log(f"Found {len(subdomains)} subdomain(s)\n{out}", f)
    return subdomains  # returns the list so the next stages can use it


def run_httpx(domain, subdomains, f):
    # httpx checks which subdomains are actually alive/responding
    # we also include the root domain itself (the fix)
    # e.g. subdomain might exist in DNS but the server is down
    section("2/7  httpx — live host probing", f)
    all_hosts = [domain] + subdomains  # root domain + all subdomains
    out, err = run("httpx -silent", stdin_data="\n".join(all_hosts))
    if err:
        log(f"[!] httpx error: {err}", f)
    live = [s for s in out.splitlines() if s.strip()]
    log(f"Live hosts ({len(live)}):\n{out}", f)
    return live  # returns only the live ones for nuclei to scan later


def run_naabu(domain, subdomains, f):
    # naabu scans for open ports on the domain and all subdomains
    # e.g. port 22 = SSH, port 80 = HTTP, port 443 = HTTPS
    section("3/7  naabu — port scanning (root domain + subdomains)", f)
    all_hosts = "\n".join([domain] + subdomains)
    out, err = run("naabu -silent", stdin_data=all_hosts)
    if err:
        log(f"[!] naabu error: {err}", f)
    log(out or "(no open ports found)", f)


def run_tlsx(domain, f):
    # tlsx inspects the TLS/SSL certificate on the domain
    # tells you cert expiry, issuer, SANs (other domains on same cert) etc
    section("4/7  tlsx — TLS certificate inspection", f)
    out, err = run(f"tlsx -u {domain} -silent")
    if err:
        log(f"[!] tlsx error: {err}", f)
    log(out or "(no TLS data returned)", f)


def run_dnstwist(domain, f):
    # dnstwist generates typo variations of the domain and checks if they're registered
    # e.g. g00gle.com, gooogle.com — attackers register these for phishing
    section("5/7  dnstwist — typosquatting detection", f)
    out, err = run(f"dnstwist {domain}")
    if err:
        log(f"[!] dnstwist error: {err}", f)
    log(out or "(no results)", f)


def run_checkdmarc(domain, f):
    # checks email security records: SPF, DMARC, DKIM
    # if these are missing, attackers can send fake emails pretending to be from this domain
    section("6/7  checkdmarc — DMARC / SPF / DKIM", f)
    out, err = run(f"checkdmarc {domain}")
    if err:
        log(f"[!] checkdmarc error: {err}", f)
    log(out or "(no results)", f)


def run_nuclei(live_hosts, f):
    # nuclei runs 10,000+ vulnerability checks against all live hosts
    # checks for misconfigs, exposed panels, known CVEs etc
    section("7/7  nuclei — vulnerability template scanning", f)
    if not live_hosts:
        log("Skipped — no live hosts to scan.", f)
        return
    out, err = run("nuclei -silent", stdin_data="\n".join(live_hosts))
    if err:
        log(f"[!] nuclei error: {err}", f)
    log(out or "(no findings)", f)


def main():
    # argparse handles the command line input properly
    # instead of crashing with an error, it shows a help message
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

    check_deps()  # check all tools are installed before doing anything

    start = datetime.now()

    # "with open" automatically closes the file even if the script crashes
    with open(output_file, "w") as f:
        log(f"Started : {start.strftime('%Y-%m-%d %H:%M:%S')}", f)
        log(f"Target  : {domain}", f)
        log(f"Output  : {output_file}\n", f)

        # run each stage in order, passing results to the next stage
        subdomains = run_subfinder(domain, f)
        live_hosts = run_httpx(domain, subdomains, f)  # fixed: passes domain too
        run_naabu(domain, subdomains, f)
        run_tlsx(domain, f)
        run_dnstwist(domain, f)
        run_checkdmarc(domain, f)
        run_nuclei(live_hosts, f)

        # final summary at the bottom of the report
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