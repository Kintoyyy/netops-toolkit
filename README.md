# NetOps Toolkit

Browser-based OSINT and IT utilities for ISP operators, DNS admins and security teams. Static site — no backend, no tracking. Host it on GitHub Pages.

| Tool | Mode | What it does |
|---|---|---|
| Lookalike Domain Detector | offline | Punycode homographs, mixed scripts, typosquats, brand impersonation |
| Domain & IP Intel | online | RDAP for domains / IPs / ASNs, geolocation, PTR |
| DNS Lookup | online | DNS-over-HTTPS queries, resolver compare, DNSSEC |
| Subdomain Finder | online | Certificate Transparency (crt.sh / CertSpotter) + DNS resolve |
| Bulk HTTP Checker | online | Mass DNS + reachability + response time, CSV, curl/PowerShell script for exact status codes |
| Email Security Check | online | MX, SPF lookup count, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI |
| Email Header Analyzer | offline | Hop trace, delays, auth verdicts, phishing flags |
| IOC Extractor & Defanger | offline | IPs, domains, URLs, hashes, CVEs, ATT&CK IDs |
| Subnet Calculator | offline | IPv4/IPv6 math, VLSM split, CIDR aggregation |
| Blocklist Converter | offline | RPZ, Unbound, dnsmasq, MikroTik, AdGuard, Squid, ipset |
| MAC Address Lookup | online | OUI vendor, formats, randomized MAC, EUI-64 |
| Encode / Decode Toolbox | offline | Base64, URL, hex, JWT, hashes, timestamps, generators |

**Offline** tools never send data anywhere. **Online** tools call public APIs (Cloudflare/Google DoH, rdap.org, crt.sh, CertSpotter, ipwho.is, maclookup.app) directly from the visitor's browser.

## Deploy
Push this folder to a repo → Settings → Pages → Deploy from branch → `main` / root.

## Structure
```
index.html          homepage — tool registry is the TOOLS array near the bottom
assets/             shared style.css + common.js (theme, DoH, IP helpers)
src/<slug>.html     tool source fragments
build.py            wraps src/*.html into tools/<slug>/index.html
tools/<slug>/       built pages (commit these — Pages serves them)
```

## Add a tool
1. Create `src/my-tool.html` starting with `<!-- title: My Tool | desc: One-line description -->`, then your HTML and `<script>`.
2. Run `python3 build.py`.
3. Add an entry to `TOOLS` in `index.html`.

Tools accept `?q=` in the URL, so they can link to each other (e.g. `tools/domain-intel/?q=8.8.8.8`).
