<img src="docs/mascot.jpg" alt="MemReader mascot" width="140" align="right">

# MemReader

A Windows process memory scanner and editor — the same idea as Cheat Engine's
memory-scanning core, built from scratch in C#/.NET. Find a value you can see
(health, gold, ammo) or a value you can't (a spawn flag, a hidden timer), edit
it, freeze it, and build a pointer chain that still finds it after the target
restarts.

Three builds share one core: a **GUI** for interactive use, a **console**
build that scripts from a shell for automation and testing, and a
**standalone trainer** template the GUI compiles on demand from whatever you
select on the watch list.

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
| **Self-healing offsets** | A chain's module-level entry point is fingerprinted by the code that references it; if a patch shifts it, a rescan of the module's code re-finds the pointer instead of the chain just breaking |
| **Correlation detector** | Mark a moment (a global hotkey) across a few repetitions and rank candidates by how tightly they track your marks — finds a value with no visible number, fast, without a scan chain that a GC can break |
| **Write journal** | Every deliberate write (a manual edit, "write to all results") logged with before/after; undo one entry or every write this session |
| **Disassembler** | Real x86-64 instructions at any address (via Iced), not just raw hex — see the code that touches a value, not only the value itself |
| **Standalone trainer** | Build a self-contained .exe from selected watch-list values — no MemReader install needed to run it, and it inherits the self-healing chains behind those values |
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
dotnet build MemReaderTrainer   # standalone trainer template (built for you by the GUI)
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
- `ChainFingerprint` — the self-healing half of a pointer chain: decodes the
  module's code (via Iced) to find the instruction that loads the chain's
  static holder, and fingerprints it as a wildcarded byte pattern so a patch
  that moves the holder can still be found by rescanning for that instruction

The GUI, console, and trainer projects each reference the same `.cs` files
from one another's folders rather than duplicating logic — one core, three
front ends.

A saved chain only carries a fingerprint once it's been resolved onto a watch
list — that's the point where a chain has been kept rather than just found,
so it's the point worth paying to fingerprint. A `.chains` file saved before
that step won't have one; resolve it once and it will.

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

- **A real breakpoint** — catch the exact instruction that writes an address
  (`DebugActiveProcess` + a hardware or software breakpoint) instead of
  finding a value only by narrowing a scan
- **Value timeline graphs** — plot a watched address over time instead of
  reading a scrolling number

## License

MIT — see [LICENSE](LICENSE).
