#!/usr/bin/env python3
"""mlc-guard — opbox-side watcher for mlc-utah-1, runs under d-watchdog.

Loop (60s):
  1. GET https://mylittlechart.org/health — 200: all good.
  2. If down: ssh probe — is mlc-server waiting for the SQLCipher key
     (post-reboot state: service active but no listener, or crashed)?
  3. If yes (or service failed/inactive): boot-unlock (push dbkey + server.env
     into box tmpfs, start service), then re-verify health.

Secrets never leave opbox except into box tmpfs over ssh. Box holds no creds.
Logs to stdout — d-watchdog captures them.
"""
import subprocess, sys, time, urllib.request

NEMO = r"C:/Users/VA PC/CODING/ML_TRADING/nemo"
MLCOPS = [r"C:/Users/VA PC/AppData/Local/Programs/Python/Python312/python.exe",
          NEMO + "/mylittlechart-server/ops/mlcops.py"]
SSH = ["ssh", "-i", NEMO + "/env/mlc-utah-box", "-o", "BatchMode=yes",
       "-o", "ConnectTimeout=10", "root@144.172.97.222"]
INTERVAL = 60


def log(msg):
    print(f"[mlc-guard {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def health_ok():
    # curl, not urllib — Cloudflare bot-rules 403 python's default UA
    r = subprocess.run(["curl", "-s", "-o", "NUL", "-w", "%{http_code}", "-m", "15",
                        "https://mylittlechart.org/health"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "200"


def box_state():
    """None = ssh unreachable; else (active_state, waiting_for_key)."""
    try:
        r = subprocess.run(SSH + ["systemctl is-active mlc-server; "
                                  "journalctl -u mlc-server --no-pager -n 30 | grep -c 'waiting for /run/mlc/dbkey' || true"],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None
    lines = r.stdout.splitlines()
    return (lines[0].strip() if lines else "?", any(l.strip() not in ("0", "") for l in lines[1:]))


def main():
    log("started; watching https://mylittlechart.org/health every 60s")
    cooldown = 0
    while True:
        if health_ok():
            if cooldown:
                log("health restored")
            cooldown = 0
        else:
            cooldown += 1
            if cooldown >= 2:  # two consecutive failures before acting
                st = box_state()
                if st is None:
                    log("health FAIL + ssh unreachable — box down/network, no action")
                else:
                    active, waiting = st
                    log(f"health FAIL: service={active}, waiting_for_key={waiting}")
                    if waiting or active in ("failed", "inactive", "activating"):
                        log("running boot-unlock (key + secrets + start)")
                        r = subprocess.run(MLCOPS + ["boot-unlock"], capture_output=True, text=True, timeout=120)
                        log((r.stdout + r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr) else "no output")
                        time.sleep(5)
                        log("post-unlock health: " + ("OK" if health_ok() else "STILL DOWN"))
                cooldown = -300 // INTERVAL  # 5-min backoff after an intervention
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
