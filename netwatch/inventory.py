"""Publisher / signature lookup for executables (used by the Log analysis page).

Windows : Authenticode via PowerShell Get-AuthenticodeSignature (signed = status Valid)
macOS   : codesign
Linux   : binaries are rarely signed individually, so we report the owning package
          (dpkg or rpm) as the publisher and call the file "signed" when its hash still
          matches the package database. `verified_by` always says which method was used.
"""
import hashlib, os, platform, re, subprocess, threading, queue

SYSTEM = platform.system()


def _run(cmd, timeout=20, env=None, input=None):
    kw = {"creationflags": 0x08000000} if SYSTEM == "Windows" else {}   # no console window
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, input=input, **kw)
    except (OSError, subprocess.SubprocessError):
        return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def verify(path):
    """-> dict(publisher, signed 0/1, verified_by, sha256). Never raises."""
    info = {"publisher": "", "signed": 0, "verified_by": "", "sha256": ""}
    p = path[:-10] if path.endswith(" (deleted)") else path
    if not os.path.isfile(p):
        info["verified_by"] = "file no longer on disk"
        return info
    try:
        info["sha256"] = sha256(p)
        fn = {"Windows": _windows, "Darwin": _macos}.get(SYSTEM, _linux)
        info.update(fn(p))
    except Exception as e:                       # permission denied, tool missing, ...
        info["verified_by"] = f"check failed: {e}"
    return info


def _windows(p):
    script = ("$s=Get-AuthenticodeSignature -LiteralPath $env:NW_PATH;"
              "[pscustomobject]@{st=$s.Status.ToString();sub=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress")
    r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 30, {**os.environ, "NW_PATH": p})
    if not r or r.returncode:
        return {"verified_by": "powershell signature check failed"}
    import json
    d = json.loads(r.stdout)
    m = re.search(r"CN=(\"[^\"]+\"|[^,]+)", d["sub"] or "")
    return {"publisher": m.group(1).strip('"') if m else "", "signed": int(d["st"] == "Valid"),
            "verified_by": f"Authenticode: {d['st']}"}


def _macos(p):
    d = _run(["codesign", "-dvv", p])
    auth = re.findall(r"^Authority=(.+)$", (d.stderr if d else ""), re.M)
    ok = _run(["codesign", "--verify", "--strict", p])
    pub = re.sub(r"^(Developer ID Application|Apple Development|Mac Developer): ", "", auth[0]) if auth else ""
    pub = re.sub(r" \([A-Z0-9]{10}\)$", "", pub)
    return {"publisher": pub, "signed": int(bool(ok and ok.returncode == 0 and auth)),
            "verified_by": "codesign" if auth else "codesign: unsigned"}


def _linux(p):
    real = os.path.realpath(p)
    if os.path.exists("/usr/bin/dpkg-query"):
        r = _run(["dpkg-query", "-S", real])
        if r and r.returncode == 0 and r.stdout.strip():
            head = r.stdout.splitlines()[0].rsplit(": ", 1)[0]       # "pkg[:arch]" or "a, b:arch"
            pkg = head.split(",")[0].strip()
            m = _run(["dpkg-query", "-W", "-f=${Maintainer}", pkg])
            pub = re.sub(r"\s*<.*>", "", m.stdout).strip() if m and m.returncode == 0 else ""
            ok = _dpkg_hash_ok(pkg, real)
            return {"publisher": pub or pkg, "signed": int(ok is True),
                    "verified_by": f"dpkg {pkg}: " + {True: "hash matches package", False: "FILE MODIFIED since install",
                                                      None: "no checksum available"}[ok]}
    if os.path.exists("/usr/bin/rpm"):
        r = _run(["rpm", "-qf", "--qf", "%{NAME}|%{VENDOR}|%{PACKAGER}", real])
        if r and r.returncode == 0 and "|" in r.stdout:
            name, vendor, packager = (r.stdout.split("|") + ["", ""])[:3]
            v = _run(["rpm", "-Vf", real])
            ok = bool(v and v.returncode == 0)
            pub = next((x for x in (vendor, packager) if x and x != "(none)"), name)
            return {"publisher": pub, "signed": int(ok),
                    "verified_by": f"rpm {name}: " + ("verified" if ok else "FILE MODIFIED since install")}
    return {"verified_by": "not owned by any installed package; no signature"}


def _dpkg_hash_ok(pkg, real):
    base = "/var/lib/dpkg/info/"
    for name in (pkg + ".md5sums", pkg.split(":")[0] + ".md5sums"):
        if os.path.exists(base + name):
            rel = real.lstrip("/")
            for line in open(base + name, errors="replace"):
                digest, _, f = line.rstrip("\n").partition("  ")
                if f == rel:
                    h = hashlib.md5()
                    with open(real, "rb") as fh:
                        for blk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(blk)
                    return h.hexdigest() == digest
            return None
    return None


class Verifier:
    """Background queue so slow checks (PowerShell, hashing) never block sampling."""
    def __init__(self, on_done):
        self.q, self.on_done = queue.Queue(), on_done
        threading.Thread(target=self._run, daemon=True).start()

    def submit(self, path):
        self.q.put(path)

    def _run(self):
        while True:
            path = self.q.get()
            self.on_done(path, verify(path))
