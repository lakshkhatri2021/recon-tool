import subprocess
import sys
import os
os.environ["PATH"] += ":/Users/lakshkhatri/Library/Python/3.12/bin"

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

domain = sys.argv[1]
report = open(f"{domain}_report.txt", "w")

def log(text):
    print(text)
    report.write(text + "\n")

log(f"\nStarting recon on {domain}...\n")

log("[+] Running subfinder...")
subdomains = run_command(f"subfinder -d {domain} -silent")
log(subdomains)

log("[+] Running httpx to find live subdomains...")
live_subdomains = run_command(f"echo '{subdomains}' | httpx -silent")
log(live_subdomains)

log("[+] Running naabu for port scanning...")
ports = run_command(f"naabu -host {domain} -silent")
log(ports)

log("[+] Running tlsx for TLS inspection...")
tls = run_command(f"tlsx -u {domain} -silent")
log(tls)

log("[+] Running dnstwist for typosquatting...")
dnstwist = run_command(f"dnstwist {domain}")
log(dnstwist)

log("[+] Running checkdmarc for email security...")
dmarc = run_command(f"checkdmarc {domain}")
log(dmarc)

log("[+] Running nuclei on live subdomains...")
nuclei = run_command(f"echo '{live_subdomains}' | nuclei -silent")
log(nuclei)

log("\nRecon complete.")
report.close()
print(f"\nReport saved to {domain}_report.txt")