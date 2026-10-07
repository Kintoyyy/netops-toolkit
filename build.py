#!/usr/bin/env python3
"""Wraps src/<slug>.html fragments into tools/<slug>/index.html with the shared shell. 
Fragment format: first line  <!-- title: ... | desc: ... [| js: decoders] -->  then body HTML + <script>."""
import pathlib, re, html

ROOT = pathlib.Path(__file__).parent
TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · NetOps Toolkit</title>
<meta name="description" content="{desc}">
<link rel="stylesheet" href="../../assets/style.css">
</head>
<body>
<div class="wrap">
  <a class="back" href="../../">← All tools</a>
  <header class="top">
    <div><h1>{title}</h1><p class="sub">{desc}</p></div>
    <div class="hdr-actions"><a class="btn split-link" href="../../split/?add={slug}" title="Use this tool side by side with others"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-3px"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M12 4v16"/></svg> Split view</a><button id="themeBtn" title="Toggle theme"></button></div>
  </header>
<script src="../../assets/common.js"></script>
<script src="../../assets/history.js"></script>
<script src="../../assets/consent.js"></script>
{extra}{body}
<footer>Free and open source under the <a href="https://github.com/Kintoyyy/netops-toolkit/blob/main/LICENSE" target="_blank" rel="noopener">MIT License</a> · provided as is, without warranty · <a href="../../disclaimer/">Disclaimer</a></footer>
</div>
</body>
</html>
"""

for src in sorted((ROOT / "src").glob("*.html")):
    text = src.read_text()
    m = re.match(r"<!--\s*title:\s*(.*?)\s*\|\s*desc:\s*(.*?)\s*(?:\|\s*js:\s*(.*?)\s*)?-->\n", text)
    assert m, f"missing header in {src}"
    out = ROOT / "tools" / src.stem / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(TEMPLATE.format(title=html.escape(m[1]), desc=html.escape(m[2]), slug=src.stem, body=text[m.end():],
        extra=''.join(f'<script src="../../assets/{j.strip()}.js"></script>\n' for j in (m[3] or '').split(',') if j.strip())))
    print("built", out.relative_to(ROOT))
