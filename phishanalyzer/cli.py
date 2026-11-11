"""phish-analyzer: python -m phishanalyzer.cli samples/*.eml"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from .analyzer import Report, analyze_file
from .indicators import defang

COLORS = {"phishing": "#c92a2a", "suspicious": "#e67700", "clean": "#2b8a3e"}
RU = {"phishing": "ФИШИНГ", "suspicious": "ПОДОЗРИТЕЛЬНО", "clean": "ЧИСТО"}

TEMPLATE = Template("""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>Анализ писем</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#222;max-width:1100px}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0 18px}
th,td{border:1px solid #ddd;padding:6px 9px;text-align:left;vertical-align:top}th{background:#f3f3f3}
.v{color:#fff;padding:3px 9px;border-radius:4px;font-weight:700;font-size:13px}
.mail{border:1px solid #ddd;border-radius:8px;padding:4px 20px 8px;margin:18px 0}
code{font-size:12px;word-break:break-all} .meta td:first-child{width:130px;color:#666}
</style></head><body>
<h1>Анализ подозрительных писем</h1>
<p style="color:#666">{{ generated }} · писем: {{ items|length }}</p>
<table><tr><th>Файл</th><th>Тема</th><th>Отправитель</th><th>Скор</th><th>Вердикт</th></tr>
{% for name, r in items %}<tr><td>{{ name }}</td><td>{{ r.subject }}</td><td>{{ r.from_addr }}</td><td>{{ r.score }}</td>
<td><span class="v" style="background:{{ colors[r.verdict] }}">{{ ru[r.verdict] }}</span></td></tr>{% endfor %}
</table>
{% for name, r in items %}<div class="mail">
<h2>{{ r.subject }} <span class="v" style="background:{{ colors[r.verdict] }}">{{ ru[r.verdict] }} · {{ r.score }}</span></h2>
<table class="meta">
<tr><td>От</td><td>{{ r.from_name }} &lt;{{ r.from_addr }}&gt;</td></tr>
{% if r.reply_to %}<tr><td>Reply-To</td><td>{{ r.reply_to }}</td></tr>{% endif %}
<tr><td>SPF / DKIM / DMARC</td><td>{{ r.auth.get("spf","—") }} / {{ r.auth.get("dkim","—") }} / {{ r.auth.get("dmarc","—") }}</td></tr>
<tr><td>Файл</td><td>{{ name }}</td></tr></table>
{% if r.findings %}<table><tr><th>Код</th><th>Признак</th><th>Вес</th><th>Детали</th></tr>
{% for f in r.findings %}<tr><td>{{ f.code }}</td><td>{{ f.title }}</td><td>+{{ f.weight }}</td><td><code>{{ f.detail }}</code></td></tr>{% endfor %}
</table>{% else %}<p>Признаков фишинга не найдено.</p>{% endif %}
{% set ioc = r.iocs() %}{% if r.verdict != "clean" and (ioc.urls or ioc.sha256) %}<p><b>IOC</b> (обезврежены):
{% for u in ioc.urls %}<br><code>{{ defang(u) }}</code>{% endfor %}
{% for d in ioc.domains %}<br><code>{{ defang(d) }}</code>{% endfor %}
{% for a in r.attachments %}<br><code>{{ a.filename }} · SHA-256 {{ a.sha256 }}</code>{% endfor %}</p>{% endif %}
</div>{% endfor %}
</body></html>""", autoescape=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Офлайн-анализ писем (.eml) на признаки фишинга")
    parser.add_argument("emails", nargs="+", type=Path)
    parser.add_argument("-o", "--out-dir", type=Path, default=Path("out"))
    args = parser.parse_args()

    items: list[tuple[str, Report]] = [(p.name, analyze_file(p)) for p in args.emails]
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for name, r in items:
        print(f"\n{name}\n  Тема: {r.subject}\n  От:   {r.from_name} <{r.from_addr}>")
        print(f"  Вердикт: {RU[r.verdict]} (скор {r.score})")
        for f in r.findings:
            print(f"   +{f.weight:<3} {f.code:18} {f.title}: {f.detail}")

    (args.out_dir / "report.html").write_text(
        TEMPLATE.render(items=items, colors=COLORS, ru=RU, defang=defang,
                        generated=datetime.now().strftime("%Y-%m-%d %H:%M")), encoding="utf-8")
    (args.out_dir / "report.json").write_text(json.dumps(
        [{"file": n, "verdict": r.verdict, "score": r.score, "subject": r.subject, "from": r.from_addr,
          "auth": r.auth, "findings": [asdict(f) for f in r.findings], "iocs": r.iocs()} for n, r in items],
        ensure_ascii=False, indent=2), encoding="utf-8")
    with open(args.out_dir / "iocs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "type", "value", "defanged"])
        for name, r in items:
            if r.verdict == "clean":
                continue
            for kind, values in r.iocs().items():
                for v in values:
                    w.writerow([name, kind, v, defang(v) if kind in ("urls", "domains", "emails") else v])
    print(f"\nОтчёт: {args.out_dir / 'report.html'} · IOC: {args.out_dir / 'iocs.csv'}")


if __name__ == "__main__":
    main()
