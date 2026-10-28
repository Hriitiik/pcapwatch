import html
import json
from dataclasses import asdict
from datetime import datetime, timezone

CSS = """
body{font-family:systen-ui,sans-serif;margin:2rem;color:#1a1a1a}
h1{font-size:1.4rem}
.meta{color:#555;margin-bottom:1.5rem}
table{border-collapse:collapse;border-width:100%}
th,td{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top;font-size:.9rem}
th{background:#f4f4f4}
pre{margin:.5rem 0 0;white-space:pre-wrap;word-break:break-all;font-size:.8rem}
summary{cursor:pointer;color:#0a6}
"""


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def attack_url(attack_id):
    return "https://attack.mitre.org/techniques/" + attack_id.replace(".", "/") + "/"


def to_dict(result):
    return {
        "pcap": result.pcap,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "packets": result.packets,
        "flows": len(result.flows),
        "findings": [
            dict(asdict(f), start_iso=iso(f.start), end_iso=iso(f.end))
            for f in result.findings
        ],
    }


def to_json(result):
    return json.dumps(to_dict(result), indent=2)


def to_html(result):
    d = to_dict(result)
    esc = html.escape

    rows = []
    for f in d["findings"]:
        evidence = esc(json.dumps(f["evidence"], indent=2))
        rows.append(
            "<tr>"
            f"<td>{esc(f['start_iso'])}</td>"
            f'<td><a href="{esc(attack_url(f["attack_id"]))}">{esc(f["attack_id"])}</a></td>'
            f"<td>{esc(f['rule'])}</td>"
            f"<td>{esc(f['src'])}</td>"
            f"<td>{esc(f['summary'])}"
            f"<details><summary>evidence</summary><pre>{evidence}</pre></details></td>"
            "</tr>"
        )

    if rows:
        body = (
            "<table><tr><th>Time (UTC)</th><th>ATT&amp;CK</th><th>Rule</th>"
            "<th>Source</th><th>Details</th></tr>" + "".join(rows) + "</table>"
        )
    else:
        body = "<p>No findings.</p>"

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>pcapwatch report</title><style>{CSS}</style></head><body>"
        "<h1>pcapwatch report</h1>"
        f'<div class="meta">{esc(d["pcap"])} &middot; {d["packets"]} packets '
        f"&middot; {d['flows']} flows &middot; {len(d['findings'])} findings "
        f"&middot; generated {esc(d['generated'])}</div>"
        f"{body}</body></html>"
    )
