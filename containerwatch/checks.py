"""Security checks against a single normalized container inspect dict.

The inspect dict is what `docker inspect <container>` returns — same shape
whether you got it from the docker SDK (`container.attrs`) or from a saved
JSON file. Every check is pure: takes a dict, returns zero or more findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    severity: str  # critical / high / medium / low
    rule: str
    container: str
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)


# Host paths that, when bind-mounted into a container, give it dangerous reach.
SENSITIVE_HOST_PATHS = {
    "/": "container can read or modify the entire host filesystem",
    "/etc": "container can read host configuration including credentials",
    "/var/run/docker.sock": "container can drive the Docker daemon — full host takeover via container escape",
    "/var/run": "container can interact with host runtime sockets",
    "/proc": "container can inspect host processes and kernel state",
    "/sys": "container can interact with host kernel via sysfs",
    "/root": "container can read root's home directory",
    "/var/lib/docker": "container can read other containers' filesystems",
    "/etc/shadow": "container can read host password hashes",
}

# Linux capabilities that should never be added back without a strong reason.
DANGEROUS_CAPS = {
    "SYS_ADMIN": "near-equivalent to root on the host",
    "NET_ADMIN": "can manipulate host networking from inside the container",
    "DAC_READ_SEARCH": "bypasses file read permission checks",
    "DAC_OVERRIDE": "bypasses file read/write/execute permission checks",
    "SYS_PTRACE": "can attach to and inspect host processes",
    "SYS_MODULE": "can load and unload kernel modules",
    "SYS_RAWIO": "raw access to device memory and ports",
    "NET_RAW": "can craft arbitrary network packets",
}


def _name(container: dict) -> str:
    name = container.get("Name", "")
    return name.lstrip("/") or container.get("Id", "(unknown)")[:12]


def check_privileged(container: dict) -> list[Finding]:
    if container.get("HostConfig", {}).get("Privileged"):
        return [
            Finding(
                severity="critical",
                rule="privileged_container",
                container=_name(container),
                detail="container started with --privileged — equivalent to root on the host",
            )
        ]
    return []


def check_host_pid(container: dict) -> list[Finding]:
    if container.get("HostConfig", {}).get("PidMode") == "host":
        return [
            Finding(
                severity="high",
                rule="pid_host",
                container=_name(container),
                detail="--pid=host — container shares the host's PID namespace",
            )
        ]
    return []


def check_host_network(container: dict) -> list[Finding]:
    if container.get("HostConfig", {}).get("NetworkMode") == "host":
        return [
            Finding(
                severity="high",
                rule="net_host",
                container=_name(container),
                detail="--network=host — container shares the host network stack",
            )
        ]
    return []


def check_sensitive_mounts(container: dict) -> list[Finding]:
    out: list[Finding] = []
    for mount in container.get("Mounts", []) or []:
        src = mount.get("Source", "")
        mode = mount.get("Mode", "rw")
        # `Mode` is a raw, label-laden string (e.g. "ro,Z" or "rprivate") and
        # substring-matching it misclassifies mounts ("rprivate" contains no
        # "ro" token but is read-write; "shared" etc.). The mount's `RW`
        # boolean is docker's authoritative read/write flag — prefer it, and
        # only fall back to the legacy Mode parse when RW is absent.
        if "RW" in mount:
            rw = bool(mount["RW"])
        else:
            rw = "ro" not in mode.split(",")
        for sensitive, why in SENSITIVE_HOST_PATHS.items():
            if src == sensitive or src.startswith(sensitive + "/"):
                # docker.sock is critical even read-only because socket access = control
                ro = not rw
                if "docker.sock" in src:
                    severity = "critical"
                elif ro:
                    severity = "medium"
                else:
                    severity = "high"
                out.append(
                    Finding(
                        severity=severity,
                        rule="sensitive_mount",
                        container=_name(container),
                        detail=f"bind-mount of {src} ({mode}) — {why}",
                        extra={"source": src, "destination": mount.get("Destination"), "mode": mode},
                    )
                )
                break
    return out


def check_dangerous_capabilities(container: dict) -> list[Finding]:
    caps_added = container.get("HostConfig", {}).get("CapAdd") or []
    out: list[Finding] = []
    for cap in caps_added:
        # docker may or may not include the CAP_ prefix; normalize it off.
        cap_name = cap.upper().removeprefix("CAP_")
        if cap_name in DANGEROUS_CAPS:
            out.append(
                Finding(
                    severity="high",
                    rule="dangerous_capability",
                    container=_name(container),
                    detail=f"--cap-add {cap} — {DANGEROUS_CAPS[cap_name]}",
                    extra={"capability": cap_name},
                )
            )
    return out


def check_security_opt(container: dict) -> list[Finding]:
    sec_opts = container.get("HostConfig", {}).get("SecurityOpt") or []
    out: list[Finding] = []
    for opt in sec_opts:
        opt_lower = opt.lower()
        if "apparmor=unconfined" in opt_lower:
            out.append(
                Finding(
                    severity="high",
                    rule="apparmor_unconfined",
                    container=_name(container),
                    detail="--security-opt apparmor=unconfined disables AppArmor MAC",
                )
            )
        if "seccomp=unconfined" in opt_lower:
            out.append(
                Finding(
                    severity="high",
                    rule="seccomp_unconfined",
                    container=_name(container),
                    detail="--security-opt seccomp=unconfined disables seccomp syscall filtering",
                )
            )
    return out


def check_running_as_root(container: dict) -> list[Finding]:
    cfg = container.get("Config", {}) or {}
    user = cfg.get("User", "") or ""
    is_root = user in ("", "0", "root", "0:0")
    if not is_root:
        return []
    # Bare 'running as root' is medium; root + privileged or root + sensitive mount
    # is already covered by other checks at higher severity.
    return [
        Finding(
            severity="medium",
            rule="root_user",
            container=_name(container),
            detail="container process runs as root inside the container — drop with --user",
        )
    ]


def check_exposed_docker_api(container: dict) -> list[Finding]:
    # Containers that expose port 2375 are usually exposing the Docker API unencrypted
    out: list[Finding] = []
    ports = container.get("NetworkSettings", {}).get("Ports") or {}
    for port_proto in ports:
        if port_proto.startswith("2375"):
            out.append(
                Finding(
                    severity="critical",
                    rule="docker_api_exposed",
                    container=_name(container),
                    detail=f"port {port_proto} mapped — looks like Docker API exposed without TLS",
                )
            )
    return out


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def audit(container: dict) -> list[Finding]:
    """Run every check on one container's inspect dict."""
    findings: list[Finding] = []
    for check in (
        check_privileged,
        check_host_pid,
        check_host_network,
        check_sensitive_mounts,
        check_dangerous_capabilities,
        check_security_opt,
        check_exposed_docker_api,
        check_running_as_root,
    ):
        findings.extend(check(container))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return findings


def audit_many(containers: list[dict]) -> list[Finding]:
    """Run audit() against many containers, return one combined sorted list."""
    all_findings: list[Finding] = []
    for c in containers:
        all_findings.extend(audit(c))
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.container, f.rule))
    return all_findings
