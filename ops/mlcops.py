#!/usr/bin/env python3
"""mlcops — opbox control plane for the mylittlechart.org production box (mlc-utah-1).

Thin SSH wrapper — no agent on the box, zero new attack surface there.
Key: env/mlc-utah-box (ed25519, root@144.172.97.222).

Usage:
  mlcops.py status                 # systemd states, health, disk, uptime
  mlcops.py logs [unit] [lines]    # journal tail (default mlc-server, 50)
  mlcops.py restart [unit]         # restart mlc-server (or cloudflared-mlc etc.)
  mlcops.py deploy <binary>        # upload new musl binary, restart, verify health
  mlcops.py backup-now             # consistent DB snapshot into /var/lib/mlc/backups
  mlcops.py backup-pull            # pull latest backup to opbox env/backups/mlc-utah-1/
  mlcops.py key-push [keyfile]    # push SQLCipher key -> tmpfs /run/mlc/dbkey (0600 root, RAM only)
  mlcops.py secrets-push           # push canonical server.env -> tmpfs /run/mlc/server.env
  mlcops.py boot-unlock            # after box reboot: key + secrets + start service
  mlcops.py ssh <cmd...>           # raw passthrough
"""
import os, subprocess, sys, time

NEMO = os.path.dirname(os.path.abspath(__file__))
for _ in range(3):
    if os.path.isdir(os.path.join(NEMO, "env")):
        break
    NEMO = os.path.dirname(NEMO)
HOST = "root@144.172.97.222"
KEY = os.path.join(NEMO, "env", "mlc-utah-box")
SSH = ["ssh", "-i", KEY, "-o", "StrictHostKeyChecking=accept-new",
       "-o", "ConnectTimeout=15", "-o", "BatchMode=yes", HOST]
SCP = ["scp", "-q", "-i", KEY, "-o", "StrictHostKeyChecking=accept-new"]
BACKUP_DIR_OPBOX = os.path.join("E:\\", "backups", "mlc-utah-1")  # key stays on C: (env/backups/backup-key) — E: alone leaks nothing


def sh(cmd, check=True):
    print("$", cmd[:140])
    r = subprocess.run(SSH + [cmd], capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout + r.stderr).strip()
    if out:
        print(out)
    if check and r.returncode != 0:
        sys.exit(f"remote rc={r.returncode}")
    return r.returncode, r.stdout


def cmd_status():
    sh("systemctl is-active mlc-server nginx nftables fail2ban; "
       "curl -s -o /dev/null -w 'app health: %{http_code}\\n' http://127.0.0.1:19200/health; "
       "df -h / | awk 'NR==2{print \"disk: \"$4\" free of \"$2}'; "
       "free -m | awk '/Mem:/{print \"mem: \"$3\"/\"$2\" MB\"}'; uptime -p")


def cmd_logs(unit="mlc-server", lines="50"):
    sh(f"journalctl -u {unit} --no-pager -n {int(lines)}")


def cmd_restart(unit="mlc-server"):
    sh(f"systemctl restart {unit} && sleep 2 && systemctl is-active {unit}")


def cmd_deploy(binary):
    if not os.path.isfile(binary):
        sys.exit(f"no such file: {binary}")
    name = os.path.basename(binary)
    print("uploading…")
    subprocess.run(SCP + [binary, f"{HOST}:/opt/mlc/{name}.new"], check=True)
    sh(f"chmod 755 /opt/mlc/{name}.new && mv /opt/mlc/{name}.new /opt/mlc/{name} "
       f"&& systemctl restart mlc-server && sleep 3 && "
       f"curl -s -o /dev/null -w 'health after deploy: %{{http_code}}\\n' http://127.0.0.1:19200/health")


def cmd_backup_now():
    sh("install -d -o mlc -g mlc -m 750 /var/lib/mlc/backups && "
       "ts=$(date -u +%Y%m%dT%H%M%SZ) && "
       "sqlite3 /var/lib/mlc/data/mylittlechart.db \".backup /var/lib/mlc/backups/mylittlechart-$ts.db\" && "
       "tar -czf /var/lib/mlc/backups/config-$ts.tar.gz -C / etc/nftables.conf etc/nginx/sites-available/mlc etc/nginx/conf.d etc/ssh/sshd_config.d/00-mlc-hardening.conf etc/systemd/system/mlc-server.service 2>/dev/null; "
       "chmod 640 /var/lib/mlc/backups/*-$ts*; ls -la /var/lib/mlc/backups/ | tail -5 && "
       "ls -1t /var/lib/mlc/backups/*.db | tail -n +15 | xargs -r rm -f && echo retention-ok")


def _backup_key():
    """Backup encryption key: 32 random bytes, lives ONLY on opbox (env/backups/backup-key, 0600)."""
    p = os.path.join(NEMO, "env", "backups", "backup-key")
    if not os.path.isfile(p):
        with open(p, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(p, 0o600)
        print("generated new backup key:", p)
    return open(p, "rb").read()


def _encrypt_file(path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, nonce = _backup_key(), os.urandom(12)
    with open(path, "rb") as f:
        ct = AESGCM(key).encrypt(nonce, f.read(), None)
    with open(path + ".gcm", "wb") as f:
        f.write(nonce + ct)
    os.remove(path)
    print("encrypted:", os.path.basename(path) + ".gcm", "(plaintext removed)")


def cmd_backup_pull():
    os.makedirs(BACKUP_DIR_OPBOX, exist_ok=True)
    import re
    rc, out = sh("ls -1t /var/lib/mlc/backups/")
    # whitelist filenames — a compromised box must not inject paths/names
    files = [l for l in out.splitlines() if re.fullmatch(r"[A-Za-z0-9.-]+\.(db|tar\.gz)", l.strip() or "")]
    if not files:
        sys.exit("no backups on box")
    latest_db = next((f for f in files if f.endswith(".db")), None)
    latest_cfg = next((f for f in files if f.endswith(".tar.gz")), None)
    for name in filter(None, (latest_db, latest_cfg)):
        dst = os.path.join(BACKUP_DIR_OPBOX, name)
        subprocess.run(SCP + [f"{HOST}:/var/lib/mlc/backups/{name}", dst], check=True)
        print("pulled:", name)
        _encrypt_file(dst)
    import glob, time
    snaps = sorted(glob.glob(os.path.join(BACKUP_DIR_OPBOX, "*.db.gcm")), key=os.path.getmtime)
    for old in snaps[:-30]:
        os.remove(old)
        print("pruned:", os.path.basename(old))


def cmd_backup_decrypt(name):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    src = os.path.join(BACKUP_DIR_OPBOX, name)
    blob = open(src, "rb").read()
    pt = AESGCM(_backup_key()).decrypt(blob[:12], blob[12:], None)
    out_path = src[:-4] if src.endswith(".gcm") else src + ".out"
    open(out_path, "wb").write(pt)
    print("decrypted ->", out_path)


CANON_KEY = os.path.join(NEMO, "env", "mlc-utah-1", "sqlcipher.key")
CANON_ENV = os.path.join(NEMO, "env", "mlc-utah-1", "server.env")


def _push_tmpfs(local, remote, mode="600"):
    """Push a secret file into box tmpfs (/run/mlc), root-only. Box keeps no copy on disk."""
    with open(local, "rb") as f:
        data = f.read()
    p = subprocess.run(SSH + [f"install -d -m 770 -o root -g mlc /run/mlc && cat > {remote} && chmod {mode} {remote} && echo DELIVERED:{remote}"],
                       input=data, capture_output=True)
    print(p.stdout.decode().strip(), p.stderr.decode().strip())
    if p.returncode != 0 or "DELIVERED" not in p.stdout.decode():
        sys.exit("push failed")


def cmd_key_push(keyfile=None):
    keyfile = keyfile or CANON_KEY
    if not os.path.isfile(keyfile):
        sys.exit(f"no such file: {keyfile}")
    if len(open(keyfile, "rb").read().strip()) < 32:
        sys.exit("key looks too short")
    _push_tmpfs(keyfile, "/run/mlc/dbkey")


def cmd_secrets_push():
    if not os.path.isfile(CANON_ENV):
        sys.exit(f"canonical secrets missing: {CANON_ENV}")
    _push_tmpfs(CANON_ENV, "/run/mlc/server.env")


def cmd_boot_unlock():
    """After box reboot: push db key + secrets, then start the service (it waits for the key)."""
    cmd_key_push()
    cmd_secrets_push()
    sh("systemctl start mlc-server && sleep 3 && curl -s -o /dev/null -w 'health: %{http_code}\\n' http://127.0.0.1:19200/health")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd, rest = args[0], args[1:]
    {"status": lambda: cmd_status(),
     "logs": lambda: cmd_logs(*rest) if rest else cmd_logs(),
     "restart": lambda: cmd_restart(*rest) if rest else cmd_restart(),
     "deploy": lambda: cmd_deploy(*rest),
     "backup-now": cmd_backup_now,
     "backup-pull": cmd_backup_pull,
     "backup-decrypt": lambda: cmd_backup_decrypt(*rest),
     "key-push": lambda: cmd_key_push(*rest) if rest else cmd_key_push(),
     "secrets-push": cmd_secrets_push,
     "boot-unlock": cmd_boot_unlock,
     "ssh": lambda: sh(" ".join(rest), check=False),
     }.get(cmd, lambda: sys.exit(f"unknown: {cmd}"))()


if __name__ == "__main__":
    main()
