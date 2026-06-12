# ContainerWatch

> **Docker runtime security monitor — alerts on privileged containers, sensitive host mounts, host networking, dangerous capabilities, and other dangerous configurations as they happen.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)

---

## What It Does

Two modes:

- **`audit`** — one-shot scan of every running container. Use it as a daily cron, a pre-deploy gate, or a baseline assessment.
- **`monitor`** — streams the Docker events socket and audits each new container as it starts. Use it as a long-running watchdog on a workstation or a build server.

Either mode produces severity-tagged findings — JSON for SIEM ingestion, color text for humans.

---

## What It Catches

| Check | Severity | Why it matters |
|---|---|---|
| `--privileged` container | critical | Equivalent to root on the host |
| Docker socket mounted (`/var/run/docker.sock`) | critical | Container can drive the daemon — escape via `docker run` |
| Bind-mount of `/`, `/etc`, `/proc`, `/sys`, `/root`, `/var/lib/docker` (rw) | high | Read or modify host state |
| Same mounts (ro) | medium | Read-only, but still leaks secrets |
| `--pid=host` | high | Sees and signals every host process |
| `--network=host` | high | Bypasses container network isolation |
| `--cap-add SYS_ADMIN`, `NET_ADMIN`, `DAC_*`, `SYS_PTRACE`, etc. | high | Capability that should never be added without a strong reason |
| `--security-opt seccomp=unconfined` | high | Disables syscall filtering |
| `--security-opt apparmor=unconfined` | high | Disables AppArmor MAC |
| Port `2375/tcp` exposed | critical | Docker API without TLS — usually accidental |
| Container process running as root | medium | Drop with `--user` unless you have a reason |

Findings are sorted critical → low and tagged with the container name.

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/container-watch.git
cd container-watch
pip install -e .
```

You'll need access to the Docker daemon socket — run as a user in the `docker` group, or with `sudo`.

---

## Usage

### Audit running containers

```bash
container-watch audit
```

### Audit a saved inspect file (offline mode — useful for CI / triage)

```bash
docker inspect $(docker ps -q) > snapshot.json
container-watch audit --offline --inspect-file snapshot.json
```

### JSON output

```bash
container-watch audit --json > findings.json
```

### Real-time monitoring

```bash
container-watch monitor
```

Tails the Docker events stream and audits each new container as it starts. Drop into a `systemd` unit on a build server or a workstation that runs containers regularly.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical or high findings |
| `1` | At least one critical or high finding |
| `2` | Configuration / connectivity error |

---

## Example Output

```
ContainerWatch
Containers inspected: 6  |  Findings: 15

────────────────────────────────────────────────────────────────────────
[CRITICAL] sensitive_mount  (dind-runner)
  bind-mount of /var/run/docker.sock (rw) — container can drive the Docker daemon — full host takeover via container escape
────────────────────────────────────────────────────────────────────────
[CRITICAL] docker_api_exposed  (exposed-docker-api)
  port 2375/tcp mapped — looks like Docker API exposed without TLS
────────────────────────────────────────────────────────────────────────
[CRITICAL] privileged_container  (privileged-tool)
  container started with --privileged — equivalent to root on the host
────────────────────────────────────────────────────────────────────────
[    HIGH] dangerous_capability  (host-net-tool)
  --cap-add NET_ADMIN — can manipulate host networking from inside the container
────────────────────────────────────────────────────────────────────────
[    HIGH] net_host  (host-net-tool)
  --network=host — container shares the host network stack
────────────────────────────────────────────────────────────────────────
...
Summary: [CRITICAL] 3  [    HIGH] 6  [  MEDIUM] 6
```

---

## Why I Built This

Container security is mostly *configuration* security. The exploits that matter aren't usually CVEs in the runtime — they're misconfigurations like a forgotten `--privileged`, a `docker.sock` mounted into a CI runner, or a homelab compose file with `network: host` for convenience. Tools like Falco, Trivy, and Docker Bench catch most of this, but they're heavy.

ContainerWatch is small enough to read in a sitting, runs against any Docker daemon you can reach, and pairs cleanly with the rest of my detection portfolio. Findings come out as JSON ready to forward to [LogHound](https://github.com/B0bTheSkull/loghound) or any SIEM.

---

## Roadmap

- [ ] Image-layer scanning (call out FROM with known-vulnerable base images)
- [ ] Docker Compose file static scan (catch misconfig before it runs)
- [ ] Kubernetes mode (Pod / DaemonSet / StatefulSet specs over Docker)
- [ ] Webhook output for Slack / Discord alerting
- [ ] `--baseline` mode — diff against a saved good state, only alert on deltas
- [ ] Detection rule pack as Sigma (so [SigmaForge](https://github.com/B0bTheSkull/sigmaforge) can convert)

---

## License

MIT — see [LICENSE](LICENSE)
