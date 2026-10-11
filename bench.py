#!/usr/bin/env python3
"""AnyPS5 homebrew test bench.

Fetches free PS5 homebrew, unwraps FSELF containers, relinks with AnyPS5's
relinker, audits imports, and names missing NIDs - producing a console-free
compatibility and coverage report for the AnyPS5 project.

Pipeline per executable:
  container/ELF -> clean ELF -> relinker --windows --registry -> audit
"""
import json
import os
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
from unfself import extract as unfself, MAGICS  # noqa: E402
from nid import load_name_db  # noqa: E402

# --- local configuration (override with ANYPS5_DIR) ----------------------------
ANYPS5 = os.environ.get("ANYPS5_DIR", os.path.normpath(os.path.join(HERE, "..", "Anyps5")))
RELINKER = os.path.join(ANYPS5, "build", "core", "relinker",
                        "relinker.exe" if os.name == "nt" else "relinker")
AUDIT = os.path.join(ANYPS5, "tools", "import_audit.py")
LIBS = os.path.join(ANYPS5, "build", "core", "libs", "libs")
AEROLIB = os.path.join(HERE, "data", "aerolib.csv")
CACHE = os.path.join(HERE, "cache")
WORK = os.path.join(HERE, "work")
REPORT = os.path.join(HERE, "report", "REPORT.md")
# -----------------------------------------------------------------------------


def fetch(url: str) -> str:
    os.makedirs(CACHE, exist_ok=True)
    name = os.path.join(CACHE, url.split("/")[-1].replace("%2F", "_"))
    if not os.path.exists(name):
        print(f"  downloading {url.rsplit('/', 1)[-1]} ...")
        urllib.request.urlretrieve(url, name)
    return name


def elf_kind(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        e_type, = __import__("struct").unpack_from("<H", data, 16)
        return {0xFE00: "ET_SCE_EXEC", 0xFE10: "ET_SCE_DYNAMIC", 0xFE18: "ET_SCE_RELEXEC"}.get(
            e_type, f"ELF type {e_type:#x}")
    magic, = __import__("struct").unpack_from("<I", data, 0)
    if magic in MAGICS:
        return "FSELF container"
    return f"unknown (magic {data[:4].hex()})"


def relink(elf: str, out_dir: str, stem: str):
    os.makedirs(os.path.join(out_dir, "sce_module"), exist_ok=True)
    out_exe = os.path.join(out_dir, stem + ".exe")
    registry = os.path.join(out_dir, stem + ".registry.json")
    for old in (out_exe, registry):
        if os.path.exists(old):
            os.remove(old)
    result = subprocess.run([RELINKER, "--windows", "--registry", elf, out_exe],
                            capture_output=True, text=True, timeout=600)
    guest = os.path.join(out_dir, "app0", "sce_module", stem + ".libc.prx.guest.prx.registry.json")
    registries = [registry]
    if os.path.exists(guest):
        registries.append(guest)
    return result.returncode == 0 and os.path.exists(out_exe), result.stdout + result.stderr, registries


def audit(registries, out_dir):
    cmd = [sys.executable, AUDIT, *registries, "--libs", LIBS,
           "--modules", os.path.join(out_dir, "sce_module")]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.stdout + result.stderr


def parse_audit(text: str) -> dict:
    info = {"implemented": 0, "stub": 0, "absent": 0, "absent_named": []}
    current = None
    for line in text.splitlines():
        parts = line.split()
        if line.strip().startswith("implemented"):
            info["implemented"] = int(parts[1])
        elif line.strip().startswith("stub"):
            info["stub"] = int(parts[1])
        elif line.strip().startswith("absent"):
            info["absent"] = int(parts[1])
        m = line.strip().startswith("[")
        if m and line.strip().endswith("]"):
            current = line.strip()[1:-1]
        elif parts and len(parts[0]) == 11 and current:
            info["absent_named"].append((current, parts[0], parts[1] if len(parts) > 1 else "?"))
    return info


def main():
    db = load_name_db(AEROLIB) if os.path.exists(AEROLIB) else {}
    print(f"name database: {len(db)} NIDs")

    executables = []

    # ps5-payload-sdk samples: individual payload ELFs in a zip
    z = fetch("https://github.com/john-tornblom/ps5-payload-sdk/releases/download/releases%2Fv0.9/Payload.binaries.zip")
    with zipfile.ZipFile(z) as archive:
        for name in archive.namelist():
            if name.endswith(".elf"):
                executables.append((f"payload/{os.path.basename(name)}", archive.read(name), None))

    # RetroArch PS5: title zip, FSELF eboots inside
    z = fetch("https://github.com/mihawk-99/PS5_RetroArch/releases/download/v1.0.0-beta.1/PS5_RetroArch-v1.0.0-beta1.zip")
    with zipfile.ZipFile(z) as archive:
        for name in ("PPSA99169/eboot.bin", "PPSA99169/picker/picker.bin", "PPSA99169/es-de/es-de.bin"):
            data = archive.read(name)
            executables.append((f"retroarch/{name.split('/')[-1]}", data, "PPSA99169"))

    os.makedirs(WORK, exist_ok=True)
    rows = []
    for label, data, title_id in executables:
        print(f"\n== {label}")
        kind = elf_kind(data)
        print(f"    {kind}")
        try:
            if "FSELF" in kind:
                data = unfself(data)
            stem = label.replace("/", "_").rsplit(".", 1)[0]
            out_dir = os.path.join(WORK, stem)
            os.makedirs(out_dir, exist_ok=True)
            # guest libc module for RetroArch-family titles
            if title_id:
                module_dir = os.path.join(out_dir, "sce_module")
                os.makedirs(module_dir, exist_ok=True)
                with zipfile.ZipFile(z) as archive:
                    try:
                        libc = archive.read("PPSA99169/sce_module/libc.prx")
                        open(os.path.join(module_dir, "libc.prx"), "wb").write(unfself(libc))
                    except KeyError:
                        pass
            elf_path = os.path.join(out_dir, "input.elf")
            open(elf_path, "wb").write(data)
            ok, log, registries = relink(elf_path, out_dir, stem)
            if not ok:
                rows.append((label, kind, "relink failed", log.strip().splitlines()[-1] if log.strip() else ""))
                continue
            summary = parse_audit(audit(registries, out_dir))
            named = [(lib, nid, db.get(nid, "?")) for lib, nid, _ in summary["absent_named"]]
            total = summary["implemented"] + summary["stub"] + summary["absent"]
            if summary["absent"] == 0 and total == 0:
                verdict = "converted (imports not audited)"
            elif summary["absent"] == 0:
                verdict = "loads (all imports resolve)"
            else:
                verdict = f"blocked: {summary['absent']} absent NIDs"
            rows.append((label, kind, verdict, summary, named))
        except Exception as error:
            rows.append((label, kind, "error", str(error)))

    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as out:
        out.write("# AnyPS5 homebrew bench report\n\n")
        out.write("Free, console-free test corpus. Generated by `bench.py`.\n\n")
        out.write("| Executable | Format | Status | Implemented | Stub | Absent |\n")
        out.write("|---|---|---|---|---|---|\n")
        for row in rows:
            label, kind, verdict = row[0], row[1], row[2]
            if isinstance(row[3], dict):
                out.write(f"| {label} | {kind} | {verdict} | {row[3]['implemented']} | "
                          f"{row[3]['stub']} | {row[3]['absent']} |\n")
            else:
                out.write(f"| {label} | {kind} | {verdict}: {row[3]} | - | - | - |\n")
        wanted = {}
        for row in rows:
            if len(row) == 5:
                for lib, nid, name in row[4]:
                    wanted.setdefault((lib, nid, name), 0)
                    wanted[(lib, nid, name)] += 1
        if wanted:
            out.write("\n## Most-wanted missing functions (by number of executables)\n\n")
            out.write("| Library | NID | Name | Wanted by |\n|---|---|---|---|\n")
            for (lib, nid, name), count in sorted(wanted.items(), key=lambda kv: -kv[1]):
                out.write(f"| {lib} | `{nid}` | {name} | {count} |\n")
    print(f"\nreport written: {REPORT}")


if __name__ == "__main__":
    main()
