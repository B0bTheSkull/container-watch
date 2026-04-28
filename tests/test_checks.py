import json
from pathlib import Path

from containerwatch.checks import (
    audit,
    audit_many,
    check_dangerous_capabilities,
    check_exposed_docker_api,
    check_host_network,
    check_host_pid,
    check_privileged,
    check_running_as_root,
    check_security_opt,
    check_sensitive_mounts,
)

SAMPLE = Path(__file__).parent.parent / "examples" / "sample_inspect.json"


def _records():
    return json.loads(SAMPLE.read_text())


def _by_name(records: list[dict], name: str) -> dict:
    return next(r for r in records if r["Name"] == name)


def test_safe_container_no_critical_or_high():
    findings = audit(_by_name(_records(), "/safe-nginx"))
    assert all(f.severity in ("low", "medium") for f in findings)


def test_privileged_detected():
    findings = check_privileged(_by_name(_records(), "/privileged-tool"))
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_host_pid_detected():
    findings = check_host_pid(_by_name(_records(), "/host-net-tool"))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_host_network_detected():
    findings = check_host_network(_by_name(_records(), "/host-net-tool"))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_dangerous_capability_detected():
    findings = check_dangerous_capabilities(_by_name(_records(), "/host-net-tool"))
    assert any(f.extra.get("capability") == "NET_ADMIN" for f in findings)


def test_security_opt_seccomp_unconfined():
    findings = check_security_opt(_by_name(_records(), "/host-net-tool"))
    assert any(f.rule == "seccomp_unconfined" for f in findings)


def test_security_opt_apparmor_unconfined():
    findings = check_security_opt(_by_name(_records(), "/etc-reader"))
    assert any(f.rule == "apparmor_unconfined" for f in findings)


def test_docker_socket_mount_critical():
    findings = check_sensitive_mounts(_by_name(_records(), "/dind-runner"))
    assert findings
    assert findings[0].severity == "critical"
    assert "docker.sock" in findings[0].detail


def test_etc_mount_readonly_medium():
    findings = check_sensitive_mounts(_by_name(_records(), "/etc-reader"))
    etc_finding = next(f for f in findings if "/etc" in f.detail)
    assert etc_finding.severity == "medium"  # ro mount


def test_root_user_detected():
    findings = check_running_as_root(_by_name(_records(), "/privileged-tool"))
    assert findings and findings[0].severity == "medium"


def test_non_root_user_not_flagged():
    findings = check_running_as_root(_by_name(_records(), "/safe-nginx"))
    assert not findings


def test_docker_api_port_exposed_critical():
    findings = check_exposed_docker_api(_by_name(_records(), "/exposed-docker-api"))
    assert findings and findings[0].severity == "critical"


def test_audit_many_sorts_by_severity():
    findings = audit_many(_records())
    severities = [f.severity for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=order.get)


def test_audit_many_finds_critical_in_full_dataset():
    findings = audit_many(_records())
    assert any(f.severity == "critical" for f in findings)
    rules = {f.rule for f in findings}
    # Spot-check that representative findings show up
    assert "privileged_container" in rules
    assert "sensitive_mount" in rules
    assert "docker_api_exposed" in rules
