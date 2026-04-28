"""Command-line interface for ContainerWatch."""

import argparse
import json
import sys
from pathlib import Path

from containerwatch import __version__
from containerwatch.checks import audit_many
from containerwatch.output import print_json, print_text


def _load_offline(path: Path) -> list[dict]:
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        print(f"error: expected JSON array (or single object), got {type(data).__name__}", file=sys.stderr)
        sys.exit(2)
    return data


def _load_live() -> list[dict]:
    import docker

    try:
        client = docker.from_env()
        return [c.attrs for c in client.containers.list()]
    except Exception as e:
        print(f"error: could not query Docker daemon: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_audit(args: argparse.Namespace) -> int:
    if args.offline:
        if not args.inspect_file:
            print("error: --offline requires --inspect-file PATH", file=sys.stderr)
            return 2
        containers = _load_offline(args.inspect_file)
    else:
        containers = _load_live()

    findings = audit_many(containers)
    color = not args.no_color and sys.stdout.isatty()
    if args.json:
        print_json(findings, container_count=len(containers))
    else:
        print_text(findings, container_count=len(containers), color=color)
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    """Stream Docker events in real time, audit every started container."""
    import docker

    try:
        client = docker.from_env()
    except Exception as e:
        print(f"error: could not connect to Docker daemon: {e}", file=sys.stderr)
        return 2

    print(f"ContainerWatch monitoring Docker events (Ctrl-C to stop)\n", flush=True)
    try:
        for event in client.events(decode=True, filters={"type": "container", "event": "start"}):
            cid = event.get("id", "")
            try:
                attrs = client.containers.get(cid).attrs
            except Exception as e:
                print(f"  failed to inspect {cid[:12]}: {e}", file=sys.stderr)
                continue
            findings = audit_many([attrs])
            name = attrs.get("Name", cid[:12]).lstrip("/")
            if not findings:
                print(f"OK    {name} — no findings")
                continue
            for f in findings:
                print(f"{f.severity.upper():>8}  {name}  {f.rule}  {f.detail}", flush=True)
    except KeyboardInterrupt:
        print("\nstopped.", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="container-watch",
        description="Docker runtime security monitor.",
    )
    p.add_argument("--version", action="version", version=f"container-watch {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Audit currently running containers")
    a.add_argument("--offline", action="store_true", help="Read inspect data from file")
    a.add_argument("--inspect-file", type=Path, help="JSON file with one or many container inspect objects")
    a.add_argument("--json", action="store_true", help="JSON output")
    a.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    a.set_defaults(func=cmd_audit)

    m = sub.add_parser("monitor", help="Tail Docker events and audit each new container")
    m.set_defaults(func=cmd_monitor)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
