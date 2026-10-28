import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine import analyze
from .report import to_html, to_json


def stamp(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    print(f"wrote {p}")


def main():
    ap = argparse.ArgumentParser(
        prog="pcapwatch", description="Hunt for attacker behavior in PCAP files"
    )
    ap.add_argument("pcap", help="path to a .pcap file")
    ap.add_argument("--json", metavar="FILE", help="write a JSON report")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report")
    args = ap.parse_args()

    try:
        result = analyze(args.pcap)
    except FileNotFoundError:
        print(f"error: {args.pcap} not found", file=sys.stderr)
        sys.exit(1)

    print(f"pcapwatch: {args.pcap}")
    print(
        f"Packets: {result.packets}   Flows: {len(result.flows)}   "
        f"Findings: {len(result.findings)}"
    )
    print()
    if not result.findings:
        print("  no findings")
    for f in result.findings:
        print(f"  [{f.attack_id}] {stamp(f.start)}  {f.summary}")

    if args.json:
        write(args.json, to_json(result))
    if args.html:
        write(args.html, to_html(result))


if __name__ == "__main__":
    main()
