# anyps5-hb — the homebrew test bench for AnyPS5

**Free, legal, console-free testing for [AnyPS5](https://github.com/boykopovar/AnyPS5).**

AnyPS5 turns PS5 executables into native Windows/Linux programs — no emulation.
Its biggest bottleneck is not code, it is **test material**: the compatibility
list is short because every contributor needs a PS5, an exploitable firmware,
and dumped games just to try anything.

Meanwhile the PS5 homebrew scene publishes **free, legally downloadable
executables** every month — real binaries that import real system NIDs:
payload SDK samples, RetroArch PS5 with three executables and 35 cores,
file managers, tools. Nobody had connected that corpus to AnyPS5.

This bench does, automatically:

```
download → unwrap FSELF → relink → audit imports → name missing NIDs
                                                        ↓
                                    report/REPORT.md: a prioritized,
                                    community-facing implementation roadmap
```

## The report

Every run produces `report/REPORT.md`:

| Executable | Format | Status | Implemented | Stub | Absent |
|---|---|---|---|---|---|
| retroarch/picker.bin | FSELF container | loads (all imports resolve) | 348 | 4 | 0 |
| retroarch/es-de.bin | FSELF container | loads (all imports resolve) | 437 | 6 | 0 |
| retroarch/eboot.bin | FSELF container | blocked: 1 absent NIDs | 542 | 13 | 1 |
| payload/list_files.elf | payload ELF | converted | - | - | - |
| payload/hwinfo.elf | payload ELF | relink failed: Invalid dynamic segment size | | | |

...plus the part contributors actually want:

```
## Most-wanted missing functions (by number of executables)

| Library              | NID           | Name                        | Wanted by |
|----------------------|---------------|-----------------------------|-----------|
| libSceSystemService  | JoBqSQt1yyA   | sceSystemServiceLoadExec    | 3         |
| libkernel            | 04AjkP0jO9U   | _umtx_op                    | 3         |
| libkernel            | Jahsnh4KKkg   | madvise                     | 3         |
| libkernel            | QuJYZ2KVGGQ   | shm_open                    | 3         |
```

"Implement these next, in this order — proof of who needs them, from binaries
anyone can download." Each run of the bench is also a regression test: when a
new AnyPS5 commit lands, the report shows exactly which titles moved from
*blocked* to *loads*.

The relinker's structural rejects are valuable too — every `FAIL:` line is a
minimal reproduction for a relinker test case.

## Quickstart

Requirements: Python 3.10+, a built AnyPS5 checkout (see its
`docs/dev/BUILD.md`).

```sh
git clone https://github.com/<you>/anyps5-hb
cd anyps5-hb

export ANYPS5_DIR=/path/to/Anyps5     # default: ../Anyps5
python bench.py

cat report/REPORT.md
```

Artifacts land in `work/<title>/` (converted `.exe`, registries) and the
corpus is cached under `cache/` so reruns are offline.

## Adding titles

Edit `titles.toml` — one entry per upstream release. Anything free and legal
belongs there: payload SDK sample packs, new homebrew releases, open-source
PS5 ports. The bench handles plaintext-FSELF containers and raw ELFs; when a
new container variant appears, extend `tools/unfself.py`.

## How it works

- `tools/unfself.py` — unwraps the plaintext FSELF containers homebrew
  packagers use (segment table, optional per-segment inflate, version
  records) into clean PS5 ELFs the relinker accepts.
- `tools/nid.py` — computes Sony NIDs (SHA1 + fixed suffix, 11-char base64),
  mirroring AnyPS5's own `core/libs/nid/src/NidCompute.cpp`, and matches
  missing imports against the public `aerolib.csv` name database
  (from [SocraticBliss/ps4_module_loader](https://github.com/SocraticBliss/ps4_module_loader/blob/master/aerolib.csv),
  ~97k NID→name pairs).
- `bench.py` — orchestrates everything and renders the report. It calls
  AnyPS5's `relinker --registry` and `tools/import_audit.py` unchanged; all
  compatibility knowledge stays in AnyPS5 where it belongs.

## Provenance and licensing

- `tools/nid.py` mirrors AnyPS5's GPL-2.0 NID computation.
- `tools/unfself.py` was written from the observed container structure; the
  plaintext-SELF geometry is long-public scene knowledge. See the PROVENANCE
  note in the file.
- This repository deliberately lives **outside** the AnyPS5 tree: it consumes
  free GPL-3.0 homebrew releases, and keeping the tooling separate avoids
  mixing license families inside AnyPS5 itself.
- No Sony software, keys, firmware, or copyrighted content is downloaded,
  distributed, or required. Everything the bench fetches is published by its
  authors for free public use.

## Roadmap

- [ ] boot testing: run each converted executable with a timeout and record
      how far it gets (module load → entry → first flip)
- [ ] payload import normalization so payload audits classify name imports
- [ ] per-commit CI history: chart implemented/absent over time
- [ ] auto-open issues for newly named most-wanted NIDs

## Contributing

Add a title to `titles.toml`, improve the unwrapper, or extend the report —
PRs welcome. For AnyPS5 itself (library implementations, relinker fixes),
contribute there and let this bench prove your patch's effect.
