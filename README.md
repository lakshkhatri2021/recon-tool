# recon-tool

Automated external attack surface recon tool. Give it a domain, and it chains
through subfinder, httpx, naabu, tlsx, dnstwist, checkdmarc, and nuclei
automatically, saving a clean, timestamped report.

## Install dependencies

```bash
brew install subfinder httpx naabu tlsx nuclei
pip3 install dnstwist checkdmarc --break-system-packages
```

The script checks for these tools on startup and tells you exactly what's
missing if anything isn't installed.

## Usage

```bash
python3 recon.py target.com
```

Output is saved to `target.com_report.txt` by default. To set a custom
output file:

```bash
python3 recon.py target.com -o myreport.txt
```

## What it does

1. **subfinder** — passive subdomain enumeration
2. **httpx** — probes the root domain and all subdomains to find live hosts
3. **naabu** — port scanning across the root domain and subdomains
4. **tlsx** — TLS certificate inspection
5. **dnstwist** — typosquatting / lookalike domain detection
6. **checkdmarc** — email security checks (DMARC/SPF/DKIM/BIMI)
7. **nuclei** — runs vulnerability templates against all live hosts

The report includes timestamps, a per-stage breakdown, and a summary at the
end (subdomain count, live host count, elapsed time).

## Notes

- Each stage is wrapped in error handling — if one tool isn't installed or
  errors out, the rest of the recon still runs and the error is logged in
  the report.
- `nuclei` has a 5-minute timeout per run since it checks against thousands
  of templates. On larger targets it may time out before finishing — this is
  logged in the report rather than crashing the script.
- Only run this against domains you own or have explicit permission to test
  (e.g. bug bounty programs, your own infrastructure).

## Example output

See `scanme.nmap.org_report.txt` for a sample run against nmap's official
test target.
