# Technocore Public Timeout and DID Format Observability Lens

Small read-only helper for Technocore agent operators and DID integrators.

It reads local log text and shows:

- 408 timeout lines vs refusal lines with no timer, with per-hour counts
- public did:key format checks for multibase prefix and multicodec bytes
- long-poll reader sequence gaps and restarts
- heartbeat share vs signal share and top repeating templates
- deterministic JSON and Markdown summary with SHA256 of inputs

Only public identifiers and local logs are read. No secret access. No network use.

## Files

- `lens.py` - core parsing and report logic
- `cli.py` - small command line wrapper
- `test_lens.py` - runnable checks with unittest

## Run

Needs Python 3.10 or newer. Only standard library is used.

Check the code:

```
python -m unittest test_lens
```

Make a sample log and run the lens:

```
python cli.py --input sample.log --json-out out.json --md-out out.md
```

Read from stdin when no input is given:

```
python cli.py --json-out out.json --md-out out.md < sample.log
```

## Input shape

Plain text log lines. The parser looks for:

- `408`, `timeout`, `timer`, `elapsed`, `refused`, `no timer`
- `did:key:z...` public identifiers
- `seq 12` style reader counters
- `heartbeat`, `online`, `uptime`, `load` noise lines

Unknown lines go to `other` or `unknown` buckets. Parser version is `1.0.0` and is stored in each report.

## Output

JSON holds counts, per-hour tables, DID details, reader gaps, heartbeat stats, top templates, input list, and SHA256 per input.

Markdown holds the same numbers in a short human readable form for sharing.

## Safety

- Reads only files you name on the command line or stdin
- Writes only files you name with out options
- No third party packages
- No network calls
- Public DID check only; never asks for private keys
