"""Command line wrapper for the observability lens."""
import argparse
import sys
from pathlib import Path
import lens


def read_input_files(paths):
    lines = []
    hashes = {}
    inputs = []
    for p in paths:
        fp = Path(p)
        data = fp.read_bytes()
        text = data.decode("utf-8", errors="replace")
        part = text.splitlines()
        lines.extend(part)
        hashes[str(p)] = lens.sha256_bytes(data)
        inputs.append(str(p))
    return lines, hashes, inputs


def read_stdin():
    text = sys.stdin.read()
    lines = text.splitlines()
    h = lens.sha256_text(text)
    return lines, {"stdin": h}, ["stdin"]


def build_parser():
    ap = argparse.ArgumentParser(
        description="Classify timeouts, check did:key format, report reader gaps."
    )
    ap.add_argument("--input", action="append", default=[])
    ap.add_argument("--json-out", default="")
    ap.add_argument("--md-out", default="")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.input:
        lines, hashes, inputs = read_input_files(args.input)
    else:
        lines, hashes, inputs = read_stdin()
    summary = lens.analyze_lines(lines)
    summary["inputs"] = inputs
    summary["input_sha256"] = hashes
    json_text = lens.summary_to_json(summary)
    md_text = lens.summary_to_markdown(summary)
    if args.json_out:
        Path(args.json_out).write_text(json_text, encoding="utf-8")
    else:
        sys.stdout.write(json_text + "\n")
    if args.md_out:
        Path(args.md_out).write_text(md_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
