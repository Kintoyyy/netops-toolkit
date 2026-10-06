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
| Recursive Decoder | offline | Recursive auto-decoding (Base64/32/58/85, hex, binary, Morse, ROT, gzip…) until readable text appears |
| Classical Cipher Solver | offline | Caesar, Vigenère auto-crack, Affine, Rail fence, Bacon, Polybius, Morse, A1Z26, IoC |
| XOR Cracker | offline | Single-byte brute force, repeating-key recovery, known-plaintext key derivation + completion, keys from context text |
| File Analyzer | offline | Magic bytes, embedded-file carving, EXIF/GPS/XMP metadata (spots hex/base64 → XOR Cracker), PNG CRC/dimension fix, JPEG/ZIP structure, strings, entropy |
| Image Steganography | offline | Bit planes, channel views, LSB extraction and auto-scan |
| RSA Toolkit | offline | d / decrypt, factoring (Fermat, Pollard rho, multi-prime), small-e and Wiener attacks |

**Offline** tools never send data anywhere. **Online** tools call public APIs (Cloudflare/Google DoH, rdap.org, crt.sh, CertSpotter, ipwho.is, maclookup.app) directly from the visitor's browser.

## Deploy
Push this folder to a repo → Settings → Pages → Deploy from branch → `main` / root.

## Structure
```
index.html          homepage — tool registry is the TOOLS array near the bottom
assets/             style.css, common.js (theme, DoH, IP helpers), decoders.js (encodings, scoring, pattern highlighting)
src/<slug>.html     tool source fragments
build.py            wraps src/*.html into tools/<slug>/index.html
tools/<slug>/       built pages (commit these — Pages serves them)
```

## Add a tool
1. Create `src/my-tool.html` starting with `<!-- title: My Tool | desc: One-line description -->` (add `| js: decoders` to also load decoders.js), then your HTML and `<script>`.
2. Run `python3 build.py`.
3. Add an entry to `TOOLS` in `index.html`.

Tools accept `?q=` in the URL, so they can link to each other (e.g. `tools/domain-intel/?q=8.8.8.8`).
