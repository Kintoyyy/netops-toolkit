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
    <button id="themeBtn" title="Toggle theme"></button>
  </header>
<script src="../../assets/common.js"></script>
{extra}{body}
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
    out.write_text(TEMPLATE.format(title=html.escape(m[1]), desc=html.escape(m[2]), body=text[m.end():],
        extra=''.join(f'<script src="../../assets/{j.strip()}.js"></script>\n' for j in (m[3] or '').split(',') if j.strip())))
    print("built", out.relative_to(ROOT))
