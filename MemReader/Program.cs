using System.Diagnostics;
using System.Globalization;
using MemReader;

// Process memory scanner and editor. Interactive REPL over the shared scanner core.

Console.OutputEncoding = System.Text.Encoding.UTF8;
bool debugPriv = Native.TryEnableDebugPrivilege();

Console.WriteLine("MemReader - process memory scanner and editor");
Console.WriteLine(debugPriv
    ? "SeDebugPrivilege: enabled"
    : "SeDebugPrivilege: not available (run as Administrator to reach more processes)");
Console.WriteLine("Type 'help' for commands.\n");

ProcessMemory? target = null;
List<IntPtr> results = new();
DeltaScan? deltaScan = null;
PointerScanner? pointers = null;
List<PointerChain> chains = new();
CorrelationDetector? correlation = null;
var journal = new WriteJournal();

// A PID on the command line attaches straight away, so handing over from the GUI
// continues the same session instead of starting from nothing. This has to sit after
// the state above is declared, or those declarations overwrite what Open sets.
if (args.Length > 0 && int.TryParse(args[0], out _))
{
    try { Open(args[0]); }
    catch (Exception ex) { Console.WriteLine($"error: {ex.Message}"); }
}

try
{
    while (true)
    {
        Console.Write(target is null ? "memreader> " : $"{target.Process.ProcessName}:{target.Process.Id}> ");
        var line = Console.ReadLine();
        if (line is null) break;
        line = line.Trim();
        if (line.Length == 0) continue;

        var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        var cmd = parts[0].ToLowerInvariant();
        var rest = parts.Length > 1 ? parts[1].Trim() : "";

        try
        {
            switch (cmd)
            {
                case "help" or "?": PrintHelp(); break;
                case "ps": ListProcesses(rest); break;
                case "open": Open(rest); break;
                case "info": Info(); break;
                case "regions": Regions(rest); break;
                case "scan": Scan(rest, first: true); break;
                case "next": Scan(rest, first: false); break;
                case "list": ListResults(rest); break;
                case "read": ReadAt(rest); break;
                case "write": WriteAt(rest); break;
                case "writeall": WriteAll(rest); break;
                case "journal": ShowJournal(rest); break;
                case "undo": Undo(rest); break;
                case "undoall": UndoAll(); break;
                case "snapshot": Snapshot(rest); break;
                case "filter": FilterDelta(rest); break;
                case "ptrindex": BuildPointerIndex(); break;
                case "ptrscan": PointerScan(rest); break;
                case "ptrlist": ListChains(); break;
                case "ptrresolve": ResolveChains(); break;
                case "ptrsave": SaveChains(rest); break;
                case "ptrload": LoadChains(rest); break;
                case "addaddr": AddAddr(rest); break;
                case "corrstart": CorrStart(rest); break;
                case "corrmark": CorrMark(); break;
                case "corrstop": CorrStop(rest); break;
                case "exit" or "quit": return;
                default: Console.WriteLine($"Unknown command '{cmd}'. Try 'help'."); break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"error: {ex.Message}");
        }
    }
}
finally { target?.Dispose(); }

void PrintHelp() => Console.WriteLine("""
  ps [filter]            list processes, optionally filtered by name
  open <pid|name>        attach to a process (read/write when permitted)
  info                   show the attached process
  regions [n]            list committed memory regions (default 40)
  scan <type> <value>    fresh scan of the whole address space
  next <value>           re-scan current results for a new value
  list [n]               show current result addresses (default 20)
  addaddr <hex>          add one known address to the results (e.g. from a hex dump)
  read <addr> [len]      hex dump at an address (hex ok: 0x7ff...), default 128 bytes
  write <addr> <value>   write one address, using the last scan's type
  writeall <value>       write every current result
  journal [n]            show recent writes (default 15) - address, before -> after
  undo <n>                revert entry n from 'journal' (1 = most recent)
  undoall                 revert every write this session, oldest state per address

  pointer chains (survive a restart)
  ptrindex               index every pointer in the process (do this once)
  ptrscan <addr> [depth] find chains that lead to an address (default depth 4)
  ptrlist                show the chains found
  ptrresolve             resolve each chain against the process right now
  ptrsave <file>         write chains to a file
  ptrload <file>         read chains back in a later session

  correlation detector (find a value with no visible number, fast)
  corrstart <type> [ms]   watch the current results, polling every [ms] (default 100)
  corrmark                record that an event just happened - press this at the moment
  corrstop [n]            stop, rank candidates by hits vs noise, show top n (default 15)

  don't know the value?
  snapshot [type]        copy the target's private memory as a baseline (default i32)
  filter <op> [amount]   keep addresses that moved: changed | same | up | down
                         | upby <n> | downby <n>
  exit                   quit

  types: i32 i64 f32 f64 str wstr hex
  example: open notepad / scan i32 100 / next 99 / list / read 0x1A2B3C4D0 64
""");

void ListProcesses(string filter)
{
    var all = Process.GetProcesses()
        .Where(p => filter.Length == 0 || p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase))
        .OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase);

    Console.WriteLine($"{"PID",8}  {"WORKING SET",14}  NAME");
    foreach (var p in all)
    {
        string ws;
        try { ws = $"{p.WorkingSet64 / 1024 / 1024:N0} MB"; } catch { ws = "n/a"; }
        Console.WriteLine($"{p.Id,8}  {ws,14}  {p.ProcessName}");
        p.Dispose();
    }
}

void Open(string arg)
{
    if (arg.Length == 0) { Console.WriteLine("usage: open <pid|name>"); return; }

    if (!int.TryParse(arg, out int pid))
    {
        var matches = Process.GetProcessesByName(arg.Replace(".exe", "", StringComparison.OrdinalIgnoreCase));
        if (matches.Length == 0) { Console.WriteLine($"no process named '{arg}'"); return; }
        if (matches.Length > 1)
        {
            Console.WriteLine($"{matches.Length} processes named '{arg}' - pick a PID:");
            foreach (var m in matches) Console.WriteLine($"  {m.Id}");
            return;
        }
        pid = matches[0].Id;
    }

    target?.Dispose();
    target = ProcessMemory.Open(pid);
    results.Clear();
    Info();
}

void Info()
{
    if (target is null) { Console.WriteLine("not attached - use 'open <pid|name>'"); return; }
    Console.WriteLine($"attached: {target.Process.ProcessName} (PID {target.Process.Id}), " +
                      $"{(target.Is32Bit ? "32-bit" : "64-bit")}, {results.Count} result(s) held");
}

void Regions(string arg)
{
    var mem = Require();
    int limit = arg.Length > 0 ? int.Parse(arg) : 40;
    long total = 0; int shown = 0;

    foreach (var r in mem.Regions())
    {
        total += r.RegionSize.ToInt64();
        if (shown++ < limit)
            Console.WriteLine($"{r.BaseAddress.ToInt64():X16}  {r.RegionSize.ToInt64() / 1024,10:N0} KB  " +
                              $"prot={r.Protect:X4} type={r.Type:X}");
    }
    Console.WriteLine($"{shown} readable region(s), {total / 1024 / 1024:N0} MB total" +
                      (shown > limit ? $" ({shown - limit} not shown)" : ""));
}

void Scan(string arg, bool first)
{
    var mem = Require();
    Needle needle;

    if (first)
    {
        var bits = arg.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (bits.Length < 2) { Console.WriteLine("usage: scan <type> <value>"); return; }
        needle = Needle.Parse(KindOf(bits[0]), bits[1]);
    }
    else
    {
        if (results.Count == 0) { Console.WriteLine("no previous results - run 'scan' first"); return; }
        if (arg.Length == 0) { Console.WriteLine("usage: next <value>"); return; }
        needle = Needle.Parse(Program.LastKind, arg);
    }

    var sw = Stopwatch.StartNew();
    if (first)
    {
        long lastReport = 0;
        results = Scanner.FirstScan(mem, needle, scanned =>
        {
            if (scanned - lastReport < 64 * 1024 * 1024) return;
            lastReport = scanned;
            Console.Write($"\r  scanned {scanned / 1024 / 1024:N0} MB...");
        });
        Console.Write("\r".PadRight(40) + "\r");
        Program.LastKind = needle.Kind;
    }
    else
    {
        results = Scanner.Refine(mem, results, needle);
    }

    sw.Stop();
    Console.WriteLine($"{results.Count:N0} match(es) for {needle.Display} in {sw.ElapsedMilliseconds:N0} ms");
    if (results.Count is > 0 and <= 10) ListResults("");
    else if (results.Count > 10) Console.WriteLine("narrow it down with 'next <new value>', or 'list' to see addresses");
}

void ListResults(string arg)
{
    int limit = arg.Length > 0 ? int.Parse(arg) : 20;
    foreach (var a in results.Take(limit)) Console.WriteLine($"  {a.ToInt64():X16}");
    if (results.Count > limit) Console.WriteLine($"  ... {results.Count - limit:N0} more");
}

void ReadAt(string arg)
{
    var mem = Require();
    var bits = arg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    if (bits.Length == 0) { Console.WriteLine("usage: read <addr> [len]"); return; }

    ulong addr = ParseAddress(bits[0]);
    int len = bits.Length > 1 ? int.Parse(bits[1]) : 128;

    var data = mem.Read((IntPtr)(long)addr, len);
    if (data is null) { Console.WriteLine($"could not read {len} bytes at {addr:X}"); return; }

    Console.Write(Scanner.HexDump(data, addr));
    if (len >= 4) Console.WriteLine($"  as i32={BitConverter.ToInt32(data)}  f32={BitConverter.ToSingle(data)}");
    if (len >= 8) Console.WriteLine($"  as i64={BitConverter.ToInt64(data)}  f64={BitConverter.ToDouble(data)}");
}

void WriteAt(string arg)
{
    var mem = Require();
    var bits = arg.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
    if (bits.Length < 2) { Console.WriteLine("usage: write <addr> <value>"); return; }
    if (!mem.CanWrite) { Console.WriteLine("process opened read-only - rerun as Administrator"); return; }

    var addr = (IntPtr)(long)ParseAddress(bits[0]);
    var needle = Needle.Parse(Program.LastKind, bits[1].Trim());
    Console.WriteLine(journal.RecordedWrite(mem, addr, needle.Pattern, "write")
        ? $"wrote {needle.Display} to {addr.ToInt64():X}"
        : $"write to {addr.ToInt64():X} was refused");
}

void WriteAll(string arg)
{
    var mem = Require();
    if (arg.Length == 0) { Console.WriteLine("usage: writeall <value>"); return; }
    if (results.Count == 0) { Console.WriteLine("no results - run 'scan' first"); return; }
    if (!mem.CanWrite) { Console.WriteLine("process opened read-only - rerun as Administrator"); return; }

    var needle = Needle.Parse(Program.LastKind, arg);
    int ok = results.Count(a => journal.RecordedWrite(mem, a, needle.Pattern, "writeall"));
    Console.WriteLine($"wrote {needle.Display} to {ok:N0} of {results.Count:N0} address(es)");
}

void Snapshot(string arg)
{
    var mem = Require();
    var kind = arg.Length > 0 ? KindOf(arg) : ValueKind.Int32;
    if (!DeltaScan.Supports(kind)) { Console.WriteLine("unknown-value scans need a number type"); return; }

    var sw = Stopwatch.StartNew();
    deltaScan = DeltaScan.Start(mem, kind);
    Program.LastKind = kind;
    sw.Stop();

    Console.WriteLine($"snapshot: {deltaScan.SnapshotBytes / 1024 / 1024:N0} MB, " +
                      $"~{deltaScan.Count:N0} candidates in {sw.ElapsedMilliseconds:N0} ms" +
                      (deltaScan.SnapshotIncomplete ? " (hit the 1 GB cap)" : ""));
    Console.WriteLine("now make the value change in the target, then: filter down / filter downby 50");
}

void FilterDelta(string arg)
{
    if (deltaScan is null) { Console.WriteLine("no snapshot - run 'snapshot' first"); return; }
    var bits = arg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    if (bits.Length == 0) { Console.WriteLine("usage: filter <changed|same|up|down|upby N|downby N>"); return; }

    var (delta, needsAmount) = bits[0].ToLowerInvariant() switch
    {
        "changed" => (Delta.Changed, false),
        "same" or "unchanged" => (Delta.Unchanged, false),
        "up" or "increased" => (Delta.Increased, false),
        "down" or "decreased" => (Delta.Decreased, false),
        "upby" => (Delta.IncreasedBy, true),
        "downby" => (Delta.DecreasedBy, true),
        _ => throw new ArgumentException($"unknown filter '{bits[0]}'"),
    };

    double amount = 0;
    if (needsAmount && (bits.Length < 2 || !double.TryParse(bits[1], NumberStyles.Float,
            CultureInfo.InvariantCulture, out amount)))
    {
        Console.WriteLine($"usage: filter {bits[0]} <amount>");
        return;
    }

    var sw = Stopwatch.StartNew();
    deltaScan.Filter(delta, amount);
    sw.Stop();

    results = deltaScan.Addresses.ToList();
    Program.LastKind = deltaScan.Kind;
    Console.WriteLine($"{results.Count:N0} address(es) survived in {sw.ElapsedMilliseconds:N0} ms" +
                      (deltaScan.Truncated ? $" (capped at {DeltaScan.MaxCandidates:N0} - use a sharper filter)" : ""));
    if (results.Count is > 0 and <= 10) ListResults("");
}

void BuildPointerIndex()
{
    var mem = Require();
    var sw = Stopwatch.StartNew();
    pointers = new PointerScanner(mem);
    pointers.BuildIndex();
    sw.Stop();
    Console.WriteLine($"indexed {pointers.PointerCount:N0} pointers over " +
                      $"{pointers.IndexedBytes / 1024 / 1024:N0} MB in {sw.ElapsedMilliseconds:N0} ms");
}

void PointerScan(string arg)
{
    if (pointers is null) { Console.WriteLine("no index - run 'ptrindex' first"); return; }
    var bits = arg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    if (bits.Length == 0) { Console.WriteLine("usage: ptrscan <addr> [depth]"); return; }

    var addr = (IntPtr)(long)ParseAddress(bits[0]);
    int depth = bits.Length > 1 ? int.Parse(bits[1]) : 4;

    var sw = Stopwatch.StartNew();
    chains = pointers.Find(addr, depth);
    sw.Stop();

    Console.WriteLine($"{chains.Count:N0} chain(s) in {sw.ElapsedMilliseconds:N0} ms");
    ListChains();
}

void ListChains()
{
    foreach (var c in chains.Take(15)) Console.WriteLine($"  {c}");
    if (chains.Count > 15) Console.WriteLine($"  ... {chains.Count - 15:N0} more");
}

void ResolveChains()
{
    if (pointers is null) { Console.WriteLine("no index - run 'ptrindex' first"); return; }
    foreach (var c in chains.Take(15))
    {
        var addr = pointers.Resolve(c);
        Console.WriteLine(addr is null
            ? $"  BROKEN  {c}"
            : $"  {addr.Value.ToInt64():X16}  {c}");
    }
}

void SaveChains(string path)
{
    if (path.Length == 0) { Console.WriteLine("usage: ptrsave <file>"); return; }
    File.WriteAllText(path, PointerScanner.Save(chains));
    Console.WriteLine($"saved {chains.Count:N0} chain(s) to {path}");
}

void LoadChains(string path)
{
    if (path.Length == 0) { Console.WriteLine("usage: ptrload <file>"); return; }
    chains = PointerScanner.Load(File.ReadAllText(path));
    Console.WriteLine($"loaded {chains.Count:N0} chain(s)");
    ListChains();
}

void AddAddr(string arg)
{
    if (arg.Length == 0) { Console.WriteLine("usage: addaddr <hex address>"); return; }
    var addr = (IntPtr)(long)ParseAddress(arg.Trim());
    results.Add(addr);
    Console.WriteLine($"added {addr.ToInt64():X16} - now {results.Count:N0} result(s)");
}

void CorrStart(string arg)
{
    var mem = Require();
    if (results.Count == 0) { Console.WriteLine("no candidates - run 'scan' or 'snapshot'+'filter' first"); return; }
    if (correlation is not null) { Console.WriteLine("already capturing - 'corrstop' first"); return; }

    var bits = arg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var kind = bits.Length > 0 ? KindOf(bits[0]) : ValueKind.Int32;
    int ms = bits.Length > 1 ? int.Parse(bits[1]) : 100;
    int size = kind is ValueKind.Int64 or ValueKind.Double ? 8 : 4;

    correlation = new CorrelationDetector(mem, results, size);
    correlation.StartCapture(ms);
    Program.LastKind = kind;
    Console.WriteLine($"capturing {results.Count:N0} candidate(s) every {ms} ms - " +
                      "run 'corrmark' at each event, then 'corrstop' when done");
}

void CorrMark()
{
    if (correlation is null) { Console.WriteLine("not capturing - run 'corrstart' first"); return; }
    correlation.Mark();
    Console.WriteLine($"marked ({correlation.MarkCount} so far)");
}

void CorrStop(string arg)
{
    if (correlation is null) { Console.WriteLine("not capturing - run 'corrstart' first"); return; }
    int show = arg.Length > 0 ? int.Parse(arg) : 15;

    var ranked = correlation.StopAndScore();
    int totalMarks = ranked.Count > 0 ? ranked[0].TotalMarks : 0;
    correlation = null;

    Console.WriteLine($"{ranked.Count:N0} candidate(s) scored against {totalMarks} mark(s):");
    foreach (var r in ranked.Take(show))
        Console.WriteLine($"  {r.Address.ToInt64():X16}  hits {r.Hits}/{r.TotalMarks}  noise {r.NoiseChanges}");

    results = ranked.Take(show).Select(r => r.Address).ToList();
}

void ShowJournal(string arg)
{
    int n = arg.Length > 0 ? int.Parse(arg) : 15;
    var recent = journal.Entries.Reverse().Take(n).ToList();
    if (recent.Count == 0) { Console.WriteLine("no writes recorded this session"); return; }

    for (int i = 0; i < recent.Count; i++)
    {
        var e = recent[i];
        Console.WriteLine($"  {i + 1,3}. {e.When:HH:mm:ss}  {e.Address.ToInt64():X16}  " +
                          $"{BitConverter.ToString(e.Before)} -> {BitConverter.ToString(e.After)}  [{e.Source}]");
    }
}

void Undo(string arg)
{
    var mem = Require();
    if (!int.TryParse(arg, out int n) || n < 1) { Console.WriteLine("usage: undo <n>  (n from 'journal', 1 = most recent)"); return; }

    var recent = journal.Entries.Reverse().ToList();
    if (n > recent.Count) { Console.WriteLine($"only {recent.Count} entries recorded"); return; }

    var entry = recent[n - 1];
    Console.WriteLine(journal.Undo(mem, entry)
        ? $"reverted {entry.Address.ToInt64():X16} to {BitConverter.ToString(entry.Before)}"
        : $"undo failed for {entry.Address.ToInt64():X16}");
}

void UndoAll()
{
    var mem = Require();
    int count = journal.Entries.Select(e => e.Address).Distinct().Count();
    int ok = journal.UndoAll(mem);
    Console.WriteLine($"reverted {ok} of {count} address(es) to their pre-session state");
}

ulong ParseAddress(string s)
{
    s = s.Trim();
    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
    return ulong.Parse(s, NumberStyles.HexNumber);
}

ValueKind KindOf(string t) => t.ToLowerInvariant() switch
{
    "i32" or "int" => ValueKind.Int32,
    "i64" or "long" => ValueKind.Int64,
    "f32" or "float" => ValueKind.Float,
    "f64" or "double" => ValueKind.Double,
    "str" or "utf8" => ValueKind.Utf8,
    "wstr" or "utf16" => ValueKind.Utf16,
    "hex" or "bytes" => ValueKind.Bytes,
    _ => throw new ArgumentException($"unknown type '{t}' (i32 i64 f32 f64 str wstr hex)"),
};

ProcessMemory Require() => target ?? throw new InvalidOperationException("not attached - use 'open <pid|name>'");

/// <summary>Remembers the type of the last fresh scan so 'next' can reuse it.</summary>
internal partial class Program { internal static ValueKind LastKind = ValueKind.Int32; }
