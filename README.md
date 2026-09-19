# MemReader

A Windows process memory scanner and editor — the same idea as Cheat Engine's
memory-scanning core, built from scratch in C#/.NET. Find a value you can see
(health, gold, ammo) or a value you can't (a spawn flag, a hidden timer), edit
it, freeze it, and build a pointer chain that still finds it after the target
restarts.

Two builds share one core: a **GUI** for interactive use, and a **console**
build that scripts from a shell for automation and testing.

![MemReader](docs/screenshot.png)

## What it's for

This is a learning and single-player modding tool, not a multiplayer cheat.
Concretely:

- ✅ Your own single-player games, offline
- ✅ Your own processes, for debugging or learning how memory scanning works
- ✅ Security research and CTFs on software you're authorized to test
- ❌ Online multiplayer games — most run anti-cheat that treats a memory-read
  handle as the thing to detect; using this there risks a ban and, on some
  games, breaks nothing since the server holds the real values anyway
- ❌ Any process or machine you don't own or aren't authorized on

The tool itself only opens a handle and reads/writes bytes — same primitive
`Process.GetProcesses()` and Task Manager use. What makes something a
violation is *where* you point it, not the code.

## Features

| | |
|---|---|
| **Value scan** | Int32, Int64, Float, Double, UTF-8, UTF-16, raw hex bytes |
| **First Scan / Next Scan** | The classic narrow-by-elimination workflow |
| **Unknown-value detector** | Snapshot + filter (`changed`, `went down by N`, ...) — find a value with no visible number |
| **Watch list** | Live values, editable in place, per-row freeze |
| **Change log** | Every write to a watched address, timestamped, with before → after |
| **Pointer chains** | Find a route from a stable module base to a value; save it; reload it after the target restarts and it still resolves |
| **Multi-threaded scan** | Regions scanned in parallel — about 2× faster on multi-GB processes |
| **Console mode** | Full CLI with the same core; scriptable, pipeable, used for this project's own tests |

## Quickstart

**Download:** grab the latest release, unzip, run `MemReaderGui.exe`.

**Or build from source** (.NET 8 SDK required):

```
git clone https://github.com/Even2B/memreader.git
cd memreader
dotnet build MemReader          # console
dotnet build MemReaderGui       # gui
```

Run the GUI, filter for a process, **Attach**, then scan. `Console mode` in
the top-right hands off to the CLI mid-session if you want to script from
there instead.

## How it works

- `ProcessMemory` — thin wrapper around `OpenProcess` / `ReadProcessMemory` /
  `WriteProcessMemory`, read-only unless a writable handle is actually granted
- `Scanner` — the value scan: chunked reads across every committed, readable
  region, parallelized with `Parallel.For`
- `DeltaScanner` — the unknown-value path: snapshot private writable pages,
  then filter by how the value changed rather than what it equals
- `PointerScanner` — indexes every pointer-shaped value in the process, then
  walks backward from an address to something inside a loaded module (the
  only part of a process's layout that's the same across restarts)

The GUI and console projects each reference the same `.cs` files from the
other's folder rather than duplicating logic — one core, two front ends.

## Known limitations

- **Java/.NET/managed targets are unreliable.** A garbage collector physically
  relocates objects, so an address found a moment ago can be invalid after a
  GC pass. Native (C/C++) games are the reliable case; a JVM or CLR process
  will drop scan chains after 2–3 narrowing steps. This isn't a bug to fix —
  it's what happens when you scan a moving target.
- **Your antivirus may flag this.** Any tool that opens `PROCESS_VM_READ` /
  `PROCESS_VM_WRITE` handles looks identical to a game trainer to heuristic
  AV — because that's exactly what it is. Cheat Engine gets flagged for the
  same reason. If you built it yourself from this source, you know what's in
  it.
- **No 64-bit-only assumption** — 32-bit target processes are detected
  (`IsWow64Process`) and their address space is scanned correctly, but this
  hasn't been exercised as heavily as the 64-bit path.

## Roadmap

Not yet built, in rough priority order:

- **Event-correlation detector** — mark a moment (hotkey) across several
  repetitions and rank addresses by how tightly their changes correlate with
  your markers, instead of manual snapshot/filter cycles
- **Self-healing offsets** — fingerprint a found address by its surrounding
  byte pattern so a saved chain can re-find itself after a game patch shifts
  offsets, not just after a restart
- **Write journal + undo** — every write logged with a one-click revert
- **Value timeline graphs** — plot a watched address over time instead of
  reading a scrolling number

## License

MIT — see [LICENSE](LICENSE).
