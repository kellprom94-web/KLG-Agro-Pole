import json, gzip, base64, re, subprocess
html = open("web/index.html", encoding="utf-8").read().replace("__MAPTILER_KEY__", "xEJHv5v4Ll7BYEmGWWMH")
src = open("worker/src.js", encoding="utf-8").read().replace("__HTML__", json.dumps(html, ensure_ascii=False))
open("worker/worker.js", "w", encoding="utf-8").write(src)
js = re.search(r"<script>(.*)</script>", html, re.S).group(1)
open("/tmp/page.js", "w", encoding="utf-8").write(js)


print("worker bytes", len(src.encode()))
