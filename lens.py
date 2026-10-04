"""Public timeout and DID format observability lens."""
import hashlib
import json
import re

PARSER_VERSION = "1.0.0"

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

DID_RE = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]+")
HOUR_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):\d{2}")
TIME_RE = re.compile(r"\b(\d{2}):\d{2}:\d{2}\b")
SEQ_RE = re.compile(r"\bseq(?:uence)?\s*[:=#\-]*\s*(\d+)", re.IGNORECASE)
DIGIT_RE = re.compile(r"\d+")
SPACE_RE = re.compile(r"\s+")


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    pad = 0
    for b in raw:
        if b == 0:
            pad = pad + 1
        else:
            break
    if n == 0:
        enc = ""
    else:
        enc = ""
        while n > 0:
            n, rem = divmod(n, 58)
            enc = BASE58_ALPHABET[rem] + enc
    return "1" * pad + enc


def b58decode(text):
    n = 0
    for ch in text:
        idx = BASE58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError("bad base58 char")
        n = n * 58 + idx
    pad = 0
    for ch in text:
        if ch == "1":
            pad = pad + 1
        else:
            break
    if n == 0:
        body = b""
    else:
        h = hex(n)[2:]
        if len(h) % 2 == 1:
            h = "0" + h
        body = bytes.fromhex(h)
    return b"\x00" * pad + body


def classify_http_line(line):
    s = line.strip()
    if s == "":
        return "unknown"
    low = s.lower()
    if "408" in s:
        return "timeout_408"
    has_timeout = ("timeout" in low) or ("timed out" in low)
    has_timer = ("timer" in low) or ("elapsed" in low) or ("deadline" in low)
    if has_timeout and has_timer:
        return "timeout_408"
    if has_timeout and ("poll" in low):
        return "timeout_408"
    if ("refus" in low) or ("no timer" in low) or ("without timer" in low):
        return "refusal_no_timer"
    if ("connection reset" in low) and ("timer" not in low):
        return "refusal_no_timer"
    return "other"


def parse_hour(line):
    m = HOUR_RE.search(line)
    if m:
        return m.group(1) + " " + m.group(2) + ":00"
    m2 = TIME_RE.search(line)
    if m2:
        return m2.group(1) + ":00"
    return "unknown_hour"


def count_http_by_hour(lines):
    out = {}
    for line in lines:
        b = classify_http_line(line)
        h = parse_hour(line)
        if h not in out:
            out[h] = {"timeout_408": 0, "refusal_no_timer": 0, "other": 0, "unknown": 0}
        out[h][b] = out[h][b] + 1
    return out


def validate_did_key(did):
    res = {"did": did, "valid": False, "reason": "", "codec": "unknown"}
    prefix = "did:key:z"
    if not isinstance(did, str):
        res["reason"] = "not a string"
        return res
    if not did.startswith(prefix):
        res["reason"] = "must start with did:key:z"
        return res
    payload = did[len(prefix):]
    if payload == "":
        res["reason"] = "missing multibase payload"
        return res
    for ch in payload:
        if ch not in BASE58_ALPHABET:
            res["reason"] = "bad base58 char"
            return res
    try:
        raw = b58decode(payload)
    except ValueError:
        res["reason"] = "base58 decode failed"
        return res
    if len(raw) != 34:
        res["reason"] = "decoded length must be 34 got " + str(len(raw))
        return res
    head = raw[0:2]
    if head == b"\xed\x01":
        res["valid"] = True
        res["codec"] = "ed25519"
        res["reason"] = "ok ed25519"
        return res
    if head == b"\xec\x01":
        res["valid"] = True
        res["codec"] = "x25519"
        res["reason"] = "ok x25519"
        return res
    res["reason"] = "bad multicodec prefix"
    return res


def find_did_keys(text):
    return DID_RE.findall(text)


def parse_seq(line):
    m = SEQ_RE.search(line)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def analyze_sequences(nums):
    total = len(nums)
    gaps = []
    restarts = 0
    if total == 0:
        return {
            "count": 0,
            "gaps": [],
            "gap_count": 0,
            "restart_count": 0,
            "max_gap": 0,
            "continuity": 0.0,
        }
    for i in range(1, total):
        prev = nums[i - 1]
        cur = nums[i]
        if cur <= prev:
            restarts = restarts + 1
        elif cur > prev + 1:
            missing = cur - prev - 1
            gaps.append({"prev": prev, "next": cur, "missing": missing})
    max_gap = 0
    for g in gaps:
        if g["missing"] > max_gap:
            max_gap = g["missing"]
    if total <= 1:
        score = 1.0
    else:
        good = 0
        for i in range(1, total):
            if nums[i] == nums[i - 1] + 1:
                good = good + 1
        score = good / (total - 1)
    return {
        "count": total,
        "gaps": gaps,
        "gap_count": len(gaps),
        "restart_count": restarts,
        "max_gap": max_gap,
        "continuity": round(score, 3),
    }


def is_heartbeat(line):
    low = line.lower()
    if "heartbeat" in low:
        return True
    if "still online" in low:
        return True
    if "agent online" in low:
        return True
    if low.strip() == "online":
        return True
    if "online" in low and ("uptime" in low or "load" in low or "ram:" in low):
        return True
    return False


def is_signal(line):
    low = line.lower()
    if "408" in line:
        return True
    if "timeout" in low:
        return True
    if "refus" in low:
        return True
    if "did:key:" in low:
        return True
    if "error" in low:
        return True
    if "warn" in low:
        return True
    return False


def heartbeat_stats(lines):
    hb = 0
    sig = 0
    other = 0
    for line in lines:
        h = is_heartbeat(line)
        s = is_signal(line)
        if s:
            sig = sig + 1
        elif h:
            hb = hb + 1
        else:
            other = other + 1
    total = len(lines)
    if total == 0:
        ratio = 0.0
    else:
        ratio = hb / total
    return {
        "heartbeat": hb,
        "signal": sig,
        "other": other,
        "total": total,
        "heartbeat_ratio": round(ratio, 3),
    }


def template_of(line):
    t = DIGIT_RE.sub("#", line)
    t = SPACE_RE.sub(" ", t).strip()
    if t == "":
        return "<empty>"
    if len(t) > 120:
        t = t[:120]
    return t


def top_templates(lines, limit=5):
    counts = {}
    for line in lines:
        t = template_of(line)
        counts[t] = counts.get(t, 0) + 1
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    out = []
    for tmpl, cnt in items[:limit]:
        out.append({"template": tmpl, "count": cnt})
    return out


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def analyze_lines(lines):
    total = len(lines)
    buckets = {"timeout_408": 0, "refusal_no_timer": 0, "other": 0, "unknown": 0}
    for line in lines:
        b = classify_http_line(line)
        buckets[b] = buckets[b] + 1
    by_hour = count_http_by_hour(lines)
    dids = []
    for line in lines:
        for d in find_did_keys(line):
            dids.append(validate_did_key(d))
    valid = 0
    for d in dids:
        if d["valid"]:
            valid = valid + 1
    seqs = []
    for line in lines:
        n = parse_seq(line)
        if n is not None:
            seqs.append(n)
    seq_info = analyze_sequences(seqs)
    hb = heartbeat_stats(lines)
    tops = top_templates(lines, limit=5)
    return {
        "parser_version": PARSER_VERSION,
        "total_lines": total,
        "http_buckets": buckets,
        "http_by_hour": by_hour,
        "did_checks": {
            "total_found": len(dids),
            "valid": valid,
            "invalid": len(dids) - valid,
            "details": dids,
        },
        "reader": seq_info,
        "reader_sequences": seqs,
        "heartbeat": hb,
        "top_templates": tops,
    }


def summary_to_json(summary):
    return json.dumps(summary, sort_keys=True, indent=2)


def summary_to_markdown(summary):
    parts = []
    parts.append("# Technocore Observability Lens")
    parts.append("")
    parts.append("Parser: " + str(summary.get("parser_version", "")))
    parts.append("Total lines: " + str(summary.get("total_lines", 0)))
    parts.append("")
    parts.append("## HTTP buckets")
    buckets = summary.get("http_buckets", {})
    for k in sorted(buckets.keys()):
        parts.append("- " + str(k) + ": " + str(buckets[k]))
    parts.append("")
    parts.append("## HTTP by hour")
    by_hour = summary.get("http_by_hour", {})
    if not by_hour:
        parts.append("- none")
    for h in sorted(by_hour.keys()):
        row = by_hour[h]
        line = "- " + str(h) + ": "
        line = line + "408=" + str(row.get("timeout_408", 0))
        line = line + " refusal=" + str(row.get("refusal_no_timer", 0))
        line = line + " other=" + str(row.get("other", 0))
        line = line + " unknown=" + str(row.get("unknown", 0))
        parts.append(line)
    parts.append("")
    parts.append("## DID checks")
    did = summary.get("did_checks", {})
    parts.append("- found: " + str(did.get("total_found", 0)))
    parts.append("- valid: " + str(did.get("valid", 0)))
    parts.append("- invalid: " + str(did.get("invalid", 0)))
    parts.append("")
    parts.append("## Reader")
    reader = summary.get("reader", {})
    parts.append("- count: " + str(reader.get("count", 0)))
    parts.append("- gaps: " + str(reader.get("gap_count", 0)))
    parts.append("- restarts: " + str(reader.get("restart_count", 0)))
    parts.append("- max gap: " + str(reader.get("max_gap", 0)))
    parts.append("- continuity: " + str(reader.get("continuity", 0)))
    parts.append("")
    parts.append("## Heartbeat")
    hb = summary.get("heartbeat", {})
    parts.append("- heartbeat: " + str(hb.get("heartbeat", 0)))
    parts.append("- signal: " + str(hb.get("signal", 0)))
    parts.append("- other: " + str(hb.get("other", 0)))
    parts.append("- ratio: " + str(hb.get("heartbeat_ratio", 0)))
    parts.append("")
    parts.append("## Top templates")
    tops = summary.get("top_templates", [])
    if not tops:
        parts.append("- none")
    for item in tops:
        parts.append("- " + str(item.get("count", 0)) + " x " + str(item.get("template", "")))
    hashes = summary.get("input_sha256", None)
    if hashes is not None:
        parts.append("")
        parts.append("## Input SHA256")
        for k in sorted(hashes.keys()):
            parts.append("- " + str(k) + ": " + str(hashes[k]))
    parts.append("")
    return "\n".join(parts)
