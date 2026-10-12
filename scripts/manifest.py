#!/usr/bin/env python3
"""The authority manifest (cancho-tools' pattern, cancho docs/agent-toolbox.md D12): derived by the compiler,
embedded by the build, gated against the ceiling.

1. pass 1: `cancho authority <sources> --std --output json`, without the generated file;
2. write manifests/server.authority.json (the committed record) and generated/built.cho, which holds the
   report and the compiler pin as string literals (cli.cho's `authority()` reads the first; a string
   constant adds no label, so the manifest can describe the program that contains it -- the fixed point);
3. pass 2: derive again WITH the generated file and require the same report -- the fixed point, or the
   embedding is refused;
4. require every derived label to be within authority/server.ceiling and `bounded` true.

    python3 scripts/manifest.py            # regenerate, then check
    python3 scripts/manifest.py --check    # change nothing; exit 1 on drift

`--check` also compares what the built binary prints (`build/server introspect`) with the fresh derivation
when the binary exists, so a stale build is caught as well as a stale file. The compiler is $CANCHO, or
`cancho` on PATH.
"""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent

# The server's sources, the order ci.yml builds them in.
SOURCES = [
    "src/server.cho", "src/dns.cho", "src/stub.cho", "src/cache.cho", "src/store.cho",
    "src/rng.cho", "src/forward.cho", "src/upstreams.cho", "src/limit.cho", "src/access.cho",
    "src/local.cho", "src/localtab.cho", "src/cli.cho", "src/rules.cho", "src/log.cho",
]

GENERATED = "generated/built.cho"

TEMPLATE = '''edition 5;

module built;

// `built` -- what the build embeds: the compiler's authority report for this server at a fixed point
// (`scripts/manifest.py`, cancho docs/agent-toolbox.md D12). Generated; do not edit by hand. The report
// is the one the compiler derives from the sources WITHOUT this file, and pass 2 derives again with it
// and requires the same report: a string constant adds no label, so the manifest describes the program
// that contains it.

pub fn authority() -> [] &static [byte] {
    return %s;
}

pub fn compiler() -> [] &static [byte] {
    return "%s";
}
'''


def compiler():
    return os.environ.get("CANCHO", "cancho")


def pin():
    """The compiler pin, from ci.yml (the file the CI builds with; the revision is part of the contract)."""
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("CANCHO_REV:"):
            return line.split(":", 1)[1].strip()
    sys.exit("no CANCHO_REV in .github/workflows/ci.yml")


def sources():
    return [str(ROOT / s) for s in SOURCES]


def derive():
    if not (ROOT / GENERATED).exists():
        sys.exit("%s does not exist; run scripts/manifest.py once to bootstrap it" % GENERATED)
    files = sources() + [str(ROOT / GENERATED)]
    out = subprocess.run([compiler(), "authority", *files, "--std", "--output", "json"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("cancho authority failed:\n" + out.stdout + out.stderr)
    return json.loads(out.stdout)


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def literal(text):
    """A cancho string literal: six escapes, no others, one line."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 32:
            sys.exit("a control character cannot be written in a cancho literal")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def label_text(label):
    if label["argument"] is None:
        return label["name"]
    return '%s("%s")' % (label["name"], label["argument"])


def ceiling():
    return [l.strip() for l in (ROOT / "authority/server.ceiling").read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")]


def gate(authority):
    problems = []
    allowed = set(ceiling())
    if not authority.get("bounded", False):
        problems.append("bounded is false")
    if authority.get("foreign_symbols"):
        problems.append("foreign symbols %s" % authority["foreign_symbols"])
    for label in authority["labels"]:
        text = label_text(label)
        if text not in allowed:
            problems.append("%s is not within authority/server.ceiling" % text)
    return problems


def introspected():
    binary = ROOT / "build" / "server"
    if not binary.exists():
        return None
    out = subprocess.run([str(binary), "introspect"], capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        return "introspect exited %d" % out.returncode
    return json.loads(out.stdout)["authority"]


def main():
    check = "--check" in sys.argv[1:]
    record = ROOT / "manifests" / "server.authority.json"
    built = ROOT / GENERATED
    first = derive()
    record_text = json.dumps(first, indent=2) + "\n"
    built_text = TEMPLATE % (literal(compact(first)), pin())

    if check:
        problems = []
        if not record.exists() or record.read_text() != record_text:
            problems.append("manifests/server.authority.json is not the compiler's report (stale)")
        if not built.exists() or built.read_text() != built_text:
            problems.append("generated/built.cho is stale")
        embedded = introspected()
        if embedded is not None and embedded != first:
            problems.append("build/server's introspect prints an authority that is not the compiler's "
                            "(a stale build?)")
        problems += gate(first)
        # The fixed point: with the generated file, the same report.
        second = derive()
        if second != first:
            problems.append("the report is not at a fixed point: with the generated file the compiler "
                            "derives %s" % [label_text(l) for l in second["labels"]])
        for p in problems:
            print("FAIL: " + p)
        sys.exit(1 if problems else 0)

    record.write_text(record_text)
    built.write_text(built_text)
    second = derive()
    problems = gate(first)
    if second != first:
        problems.append("not at a fixed point")
    for p in problems:
        print("FAIL: " + p)
    print("wrote %s and %s; the report is at a fixed point and within the ceiling"
          % (record.relative_to(ROOT), built.relative_to(ROOT)))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
