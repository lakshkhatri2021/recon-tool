# recon-tool

automated external attack surface recon tool. give it a domain, it chains through subfinder, httpx, naabu, tlsx, dnstwist, checkdmarc and nuclei automatically and saves a clean report.

## install dependencies

```bash
brew install subfinder httpx naabu tlsx nuclei
pip3 install dnstwist checkdmarc --break-system-packages
```

## usage

```bash
python3 recon.py target.com
```

output saved to `target.com_report.txt`

## what it does

1. finds all subdomains via passive sources
2. filters to live ones
3. scans open ports
4. inspects TLS certificates
5. detects typosquatting domains
6. checks email security (DMARC/SPF/DKIM)
7. runs 10,000+ vulnerability templates against live subdomains
