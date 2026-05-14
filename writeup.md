# Runtime before runtime: catching bad Docker configs before they become incidents

> Container security is mostly configuration security. The exploits that matter aren't usually CVEs — they're a forgotten `--privileged`, a CI runner with the Docker socket mounted, or a compose file with `network: host` because someone wanted to make local dev easier.

## TL;DR

ContainerWatch is a Python CLI that audits running Docker containers — or saved inspect snapshots — for dangerous runtime configurations. It checks eleven distinct misconfiguration patterns (privileged mode, socket mounts, host networking, dangerous capabilities, disabled seccomp/AppArmor, exposed Docker API, and more), tags every finding critical/high/medium/low, and outputs either human-readable color text or structured JSON for SIEM forwarding. There's also a live-monitoring mode that tails the Docker events stream and audits each new container the moment it starts.

---

## Why bother

I've been building toward a detection portfolio that covers multiple layers — DNS (pi-hole-lab), log analysis (LogHound), IDS rules (SigmaForge). The missing layer was the container surface. I run Docker on my workstation and in homelab services, and after reading enough post-mortems I noticed a pattern: the attacks that actually succeed against containerized environments are almost never container escapes via runtime CVEs. They're misconfigurations that hand the attacker root from the jump.

The three most common:

1. **`--privileged`** — the operator didn't want to debug a capabilities issue and just gave the container everything. Now it can write to the host filesystem, load kernel modules, and escape trivially.
2. **Docker socket mounted into a container** (`-v /var/run/docker.sock:/var/run/docker.sock`) — almost every CI-in-Docker tutorial shows this. It means the container can call `docker run --rm --privileged -v /:/host alpine chroot /host sh` and own the host in one command.
3. **Port 2375 exposed** — the Docker daemon's unauthenticated TCP API, occasionally left listening "just to test" and never closed.

I wanted something small enough to actually read and audit myself, that I could drop on any Docker host and get a quick yes/no on whether the running environment was sane.

---

## What's new about this build

The existing options are either heavy (Falco — excellent, but needs a kernel module or eBPF, a separate deployment, and a running daemon to process rules) or one-shot scanners that don't integrate easily with a broader pipeline (Docker Bench for Security — thorough, but produces text designed for human reading, not machine parsing). ContainerWatch is intentionally small and composable:

1. **Offline mode.** Feed it a `docker inspect` JSON snapshot and it runs without touching a live daemon. Useful for CI/CD gates: run `docker inspect $(docker ps -q) > snapshot.json` in your pipeline, ship the file somewhere trusted, and audit it there. No daemon access required at audit time.

2. **Structured JSON output.** Every finding is a typed object: `severity`, `rule`, `container`, `detail`, `extra`. Forward it directly to LogHound, ship it to Elasticsearch, or convert it to a Sigma alert with SigmaForge. It doesn't try to be a full SIEM — it just produces output a SIEM can consume without scraping text.

3. **Exit codes that compose.** Exit 0 means clean. Exit 1 means at least one critical or high finding. Exit 2 means configuration error. That means `container-watch audit || alert_oncall` works exactly as you'd expect in a bash pipeline or a GitHub Actions `if:` condition.

4. **Monitor mode.** Long-running watchdog that tails the Docker events socket and audits each new container at start time. Designed to run as a `systemd` unit on a build server or any host where containers come and go.

---

## Architecture in 30 seconds

```
Docker daemon
    │
    ├── [live]    docker SDK → container.attrs (inspect dict)
    └── [offline] docker inspect JSON file

         ↓
   containerwatch/checks.py
   ┌─────────────────────────────────────────────────────────────┐
   │  check_privileged()      → Finding(critical)                │
   │  check_host_pid()        → Finding(high)                    │
   │  check_host_network()    → Finding(high)                    │
   │  check_sensitive_mounts()→ Finding(critical/high/medium)    │
   │  check_dangerous_caps()  → Finding(high)                    │
   │  check_security_opt()    → Finding(high)                    │
   │  check_exposed_docker_api()→ Finding(critical)              │
   │  check_running_as_root() → Finding(medium)                  │
   └─────────────────────────────────────────────────────────────┘
         ↓
   containerwatch/output.py
   ├── print_text()   → color-coded terminal output (human)
   └── print_json()   → structured JSON (SIEM / pipeline)
```

Every check is a pure function: takes one container inspect dict, returns zero or more `Finding` dataclasses. No side effects, no global state, easy to unit test in isolation. The CLI layer (`cli.py`) handles the two sources (live Docker SDK, offline JSON) and the two output formats independently — the check logic never knows or cares how the data arrived.

---

## Things that bit me

### The Docker socket severity question

My first cut treated `/var/run/docker.sock` mounted read-only as `medium` — same as any other sensitive path read-only. That's wrong. A socket isn't a file you read; you interact with it. Read-only permissions on a socket are effectively meaningless — if you can open the socket, you can issue commands to the daemon. I changed the logic so `docker.sock` is always `critical` regardless of the mount mode. The commit diff is two lines in `checks.py` but it took me an hour of thinking through the semantics to get there.

### Capabilities normalization

The Docker SDK sometimes returns capability names with the `CAP_` prefix (`CAP_SYS_ADMIN`) and sometimes without (`SYS_ADMIN`), depending on the Docker version and how the container was started. The check was silently missing matches on older setups because the prefix didn't match the constant in `DANGEROUS_CAPS`. Fixed with a one-liner: `cap_name = cap.upper().removeprefix("CAP_")`. The kind of bug that's invisible unless you test against a real daemon and a real old version.

### Offline mode and the `--inspect-file` UX

The first version required `--offline` and `--inspect-file` as separate flags and gave a confusing error if you provided one without the other. I eventually made `--inspect-file` imply `--offline` — if you gave me a file, you clearly wanted offline mode. Less surprising.

### Running as root is medium, not high

My first instinct was to rate `root_user` as `high`. The problem is that the vast majority of containers run as root because most images don't set a non-root user in the Dockerfile — including official images. If I rated it `high`, `exit 1` would fire on almost every deployment, and the tool would get disabled or ignored immediately. Medium is honest: "this is worth fixing, but it's not a fire." The critical/high findings are the ones that warrant a phone call at 2am.

---

## Findings from the sample environment

Running against `examples/sample_inspect.json` — six containers representing a realistic mix of clean and dangerous configs:

```
$ container-watch audit --offline --inspect-file examples/sample_inspect.json --no-color

ContainerWatch
Containers inspected: 6  |  Findings: 15

────────────────────────────────────────────────────────────────────────────────
[CRITICAL] sensitive_mount  (dind-runner)
  bind-mount of /var/run/docker.sock (rw) — container can drive the Docker daemon — full host takeover via container escape
────────────────────────────────────────────────────────────────────────────────
[CRITICAL] docker_api_exposed  (exposed-docker-api)
  port 2375/tcp mapped — looks like Docker API exposed without TLS
────────────────────────────────────────────────────────────────────────────────
[CRITICAL] privileged_container  (privileged-tool)
  container started with --privileged — equivalent to root on the host
────────────────────────────────────────────────────────────────────────────────
[    HIGH] apparmor_unconfined  (etc-reader)
  --security-opt apparmor=unconfined disables AppArmor MAC
────────────────────────────────────────────────────────────────────────────────
[    HIGH] dangerous_capability  (etc-reader)
  --cap-add SYS_ADMIN — near-equivalent to root on the host
────────────────────────────────────────────────────────────────────────────────
[    HIGH] dangerous_capability  (host-net-tool)
  --cap-add NET_ADMIN — can manipulate host networking from inside the container
────────────────────────────────────────────────────────────────────────────────
[    HIGH] net_host  (host-net-tool)
  --network=host — container shares the host network stack
────────────────────────────────────────────────────────────────────────────────
[    HIGH] pid_host  (host-net-tool)
  --pid=host — container shares the host's PID namespace
────────────────────────────────────────────────────────────────────────────────
[    HIGH] seccomp_unconfined  (host-net-tool)
  --security-opt seccomp=unconfined disables seccomp syscall filtering
────────────────────────────────────────────────────────────────────────────────
[  MEDIUM] root_user  (dind-runner)
  container process runs as root inside the container — drop with --user
────────────────────────────────────────────────────────────────────────────────
... (5 more medium findings)
────────────────────────────────────────────────────────────────────────────────

Summary: [CRITICAL] 3  [    HIGH] 6  [  MEDIUM] 6
```

Exit code `1` — there are critical and high findings. In a CI gate, that's a failed build. In a monitoring setup, that's a PagerDuty page.

The one clean container (`safe-nginx`) was running as UID 101, had only a read-only bind mount of a non-sensitive path, and exposed only port 80. It generated zero findings, which is the correct result.

The JSON output for the same run is machine-ready:

```json
{
  "containers_inspected": 6,
  "total_findings": 15,
  "findings": [
    {
      "severity": "critical",
      "rule": "sensitive_mount",
      "container": "dind-runner",
      "detail": "bind-mount of /var/run/docker.sock (rw) ...",
      "extra": {"source": "/var/run/docker.sock", "destination": "/var/run/docker.sock", "mode": "rw"}
    },
    ...
  ]
}
```

Forward that to LogHound or any SIEM with `container-watch audit --json | logforward`.

---

## Where this fits in a blue-team / cloud-sec workflow

Most container security conversation focuses on the image layer — CVE scanning, SBOM, base image freshness. That work matters. But the runtime layer is where the exploitable misconfigs actually live, and it's chronically under-monitored. A few places ContainerWatch fits naturally:

**CI/CD gate.** Before a container reaches production, snapshot its inspect data and run an offline audit. Fail the pipeline on critical/high. The exit code makes this trivially scriptable in GitHub Actions, GitLab CI, or any other runner.

**Build server watchdog.** CI build servers run dozens of containers per hour — often with elevated permissions because the build system needs them. `container-watch monitor` as a systemd unit on the build server gives you a continuous record of what ran with what permissions. If a malicious build starts a privileged container to try to escape, you see it immediately.

**Incident response triage.** During an IR engagement, getting a fast picture of what Docker configurations were present at the time of compromise matters. A saved `docker inspect` JSON is easy to collect forensically and easy to analyze offline — no daemon access needed, no touching the live system beyond the initial snapshot.

**Cloud environment baselining.** Same offline mode works against inspect data pulled from a cloud control plane. Baseline a clean deployment, re-audit after a change, diff the findings.

---

## What it doesn't do (limits)

Being honest about scope matters more in security tooling than anywhere else.

- **No image scanning.** ContainerWatch doesn't look at image layers, base images, or installed packages. Trivy or Grype do that; they're better at it than this tool will ever be.
- **No Kubernetes support.** Pod specs, DaemonSets, and PSPs have an overlapping but distinct misconfiguration surface. That's on the roadmap but not here yet.
- **No historical trending.** Each run is a point-in-time snapshot. The tool doesn't remember previous state or alert on delta. A `--baseline` mode is planned.
- **No remediation.** Findings tell you what's wrong and why it matters. Fixing it is on you. Some misconfigs (like `--privileged` on a CI runner) have real operational reasons; the tool can't know that and doesn't try to auto-remediate.
- **No behavioral / runtime detection.** ContainerWatch sees configuration, not behavior. If a container starts clean and then a process inside it does something malicious, that's Falco's domain, not this tool's.

---

## What I'd do differently

- **Test against more Docker versions earlier.** The capability prefix normalization bug (`CAP_SYS_ADMIN` vs `SYS_ADMIN`) was invisible until I tested against a specific older daemon. A Docker version matrix in CI from day one would have caught it.
- **Start with the JSON schema.** I designed human output first and retrofitted JSON. The `extra` field ended up as an open dict rather than typed per-rule. Defining the schema first and deriving human output from it would have been cleaner.
- **Add a suppress/allowlist earlier.** Teams have legitimate reasons for privileged containers (Docker-in-Docker, specific hardware access). Without a way to annotate known-safe configs, the tool alerts on things already accepted or gets ignored. A per-container exception list would make this production-deployable rather than advisory-only.

---

## Resources

- [Docker security documentation](https://docs.docker.com/engine/security/) — the official baseline
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) — the full checklist this tool cherry-picks from
- [Falco](https://falco.org/) — behavioral runtime security, the complement to ContainerWatch
- [Trivy](https://aquasecurity.github.io/trivy/) — image and IaC scanning
- The repo: [github.com/B0bTheSkull/container-watch](https://github.com/B0bTheSkull/container-watch)
