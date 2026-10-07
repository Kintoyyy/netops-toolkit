# NetOps Toolkit

A browser-based toolbox for ISP operators, network engineers, DNS admins and security teams. Static site — no backend, no tracking. Host it on GitHub Pages.

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
| My IP & Connection | online | Public IPv4/IPv6, ISP/ASN, DNS resolver, latency, speed test, Path MTU tools, WebRTC leak check |
| Subnet Calculator | offline | IPv4/IPv6 math, VLSM planner, aggregation, subtraction, overlap finder, cheat sheet |
| Subnet Visualizer | offline | Split/join address plans with notes, colors, block map and shareable links |
| BGP Toolkit | online | ASN/prefix lookup, RPKI, looking-glass AS paths and path / neighbour graphs (RIPEstat), prefix lists, communities, AS-path regex |
| MikroTik Burst Calculator | offline | Queue burst duration / re-arm time per the RouterOS algorithm, misconfiguration checks, playable speed simulation vs max-limit only, simple queue / PPP / Hotspot / queue tree config, import from rate-limit strings |
| MikroTik CGNAT Generator | offline | Deterministic CGNAT (RFC 6598 / RFC 7422): aggregated netmap blocks — one rule per block (32 rules for 1,024 subscribers behind a /27, fixed public IP per subscriber) or TCP/UDP port blocks for exact per-subscriber tracing, capacity and port-exhaustion checks, safe edge filters, blackhole route, mapping CSV and abuse IP:port lookup |
| Traceroute Analyzer | online | Parses tracert / traceroute / mtr / tracepath / Cisco / Juniper / MikroTik output; hop owner (ASN, prefix), IXP (PeeringDB), location, PTR, private/CGNAT hops, ICMP deprioritisation vs real latency and loss |
| Blocklist Converter | offline | RPZ, Unbound, dnsmasq, MikroTik, AdGuard, Squid, ipset |
| PCAP Analyzer | offline | pcap/pcapng triage: port scans, DNS/DGA/tunneling, ICMP channels, follow stream, HTTP export, credentials |
| MAC Address Lookup | online | OUI vendor, formats, randomized MAC, EUI-64 |
| Encode / Decode Toolbox | offline | Base64, URL, hex, JWT, hashes, timestamps, generators |
| Recursive Decoder | offline | Recursive auto-decoding (Base64/32/58/85, hex, binary, Morse, ROT, gzip…) until readable text appears |
| Classical Cipher Solver | offline | Caesar, Vigenère auto-crack, Affine, Rail fence, Bacon, Polybius, Morse, A1Z26, IoC |
| XOR Cracker | offline | Single-byte brute force, repeating-key recovery, known-plaintext key derivation + completion, keys from context text |
| File Analyzer | offline | Magic bytes, embedded-file carving, EXIF/GPS/XMP metadata (spots hex/base64 → XOR Cracker), PNG CRC/dimension fix, JPEG/ZIP structure, strings, entropy |
| Image Steganography | offline | Bit planes, channel views, LSB extraction and auto-scan |
| RSA Toolkit | offline | d / decrypt, factoring (Fermat, Pollard rho, multi-prime), small-e and Wiener attacks |

**Split view** (`split/`, or the *Split view* button on any tool) puts up to six tools side by side — columns, rows or a grid, with draggable dividers. Each pane can switch tool, reload, pop out or maximise, and links to another tool (an IP in the traceroute, an ASN in Domain Intel…) open in the next pane. The layout is saved locally and in the URL, so it can be bookmarked or shared.

**Recently used tools** show on the homepage, and every tool remembers its last inputs plus a **History** of recent runs (header menu → click an entry to restore and re-run it). This is stored only in your browser's localStorage and can be switched off (which also clears it) from the History menu.

**Offline** tools never send data anywhere. **Online** tools call public APIs (Cloudflare/Google DoH, rdap.org, RIPEstat, ipify, Cloudflare speed test, crt.sh, CertSpotter, ipwho.is, maclookup.app, PeeringDB) directly from the visitor's browser.

On a visitor's first visit, a short notice asks them to accept the [disclaimer](disclaimer/) (provided as is, no liability, authorized use only). Acceptance is stored in their browser; bump `VERSION` in `assets/consent.js` to ask again after a material change.

## Deploy
Push this folder to a repo → Settings → Pages → Deploy from branch → `main` / root.

## Structure
```
index.html          homepage
split/              split view — several tools side by side in resizable panes
disclaimer/         terms of use (as is, no liability) with the accept / withdraw control
favicon.ico, site.webmanifest, assets/icons/   favicon (icon.svg is the master), touch and install icons
assets/og-image.png 1200×630 social preview used by every page
sitemap.xml, robots.txt   generated by build.py
assets/             tools.js (tool registry: the TOOLS array), style.css, common.js (theme, DoH, IP helpers), history.js (recent tools, saved inputs, History menu), consent.js (first-visit disclaimer notice), netcalc.js (prefix math), decoders.js (encodings, scoring, pattern highlighting)
src/<slug>.html     tool source fragments
build.py            wraps src/*.html into tools/<slug>/index.html, refreshes every page's <head> metadata, writes the sitemap
tools/<slug>/       built pages (commit these — Pages serves them)
```

## Add a tool
1. Create `src/my-tool.html` starting with `<!-- title: My Tool | desc: One-line description -->` (add `| js: decoders` to also load decoders.js), then your HTML and `<script>`.
2. Add an entry to `TOOLS` in `assets/tools.js` (the homepage, split view and sitemap read it).
3. Run `python3 build.py` — it also adds the favicon, canonical URL, Open Graph / Twitter tags and JSON-LD to the page.

Metadata is generated from the page title and description. The public URL lives in `SITE` at the top of `build.py` (it matches `CNAME`); change it there if the domain changes. Hand-written pages keep their generated block between `<!-- meta:start -->` and `<!-- meta:end -->`.

Tools accept `?q=` in the URL, so they can link to each other (e.g. `tools/domain-intel/?q=8.8.8.8`).

## License
[MIT](LICENSE) — free for anyone to use, modify and share, provided as is without warranty. See the [disclaimer](disclaimer/).
