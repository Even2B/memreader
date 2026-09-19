using System.Text;

namespace MemReader;

/// <summary>
/// A route to a value that survives a restart: start at a fixed offset inside a
/// loaded module, then follow pointers, adding an offset at each hop.
/// Resolves as: addr = module + ModuleOffset; foreach off: addr = [addr] + off.
/// </summary>
internal sealed record PointerChain(string Module, ulong ModuleOffset, int[] Offsets)
{
    public int Depth => Offsets.Length;

    /// <summary>
    /// A code signature for the instruction that loads the module-level holder, when
    /// one has been captured. Lets <see cref="PointerScanner.Resolve"/> re-find the
    /// holder after a patch shifts <see cref="ModuleOffset"/> instead of trusting it.
    /// </summary>
    public ChainFingerprint? Fingerprint { get; init; }

    public override string ToString() =>
        $"{Module}+0x{ModuleOffset:X}" + string.Concat(Offsets.Select(o => $" -> +0x{o:X}")) +
        (Fingerprint is null ? "" : " (self-healing)");
}

/// <summary>
/// Finds pointer chains leading to an address.
///
/// A scan result is just an address, and the game allocates its objects somewhere new
/// every launch, so the address is worthless tomorrow. What does not move is the game's
/// own code and globals: a module always sits at a known offset from its base. So the
/// job is to walk backwards from the value to something inside a module.
/// </summary>
internal sealed class PointerScanner
{
    /// <summary>How far before a pointer's target the value may sit (a struct field offset).</summary>
    public const int DefaultMaxOffset = 0x800;

    /// <summary>Guards against a combinatorial blowup on a large process.</summary>
    private const int MaxNodesPerLevel = 400_000;

    private readonly ProcessMemory _mem;

    // Every aligned pointer-sized value in the process that points at committed memory,
    // sorted by the value so "who points near X?" is a binary search.
    private long[] _holders = Array.Empty<long>();
    private long[] _targets = Array.Empty<long>();

    private List<(string Name, ulong Base, ulong Size)> _modules = new();

    public int PointerCount => _holders.Length;
    public long IndexedBytes { get; private set; }

    public PointerScanner(ProcessMemory mem) => _mem = mem;

    /// <summary>
    /// Builds the pointer index. This is the expensive part - one pass over the whole
    /// address space - so it is done once and reused for every chain search after.
    /// </summary>
    public void BuildIndex(Action<long>? progress = null)
    {
        _modules = _mem.Modules();

        var regions = _mem.Regions().ToArray();
        var ranges = regions
            .Select(r => ((ulong)r.BaseAddress.ToInt64(), (ulong)r.RegionSize.ToInt64()))
            .OrderBy(r => r.Item1)
            .ToArray();

        var holders = new List<long>(1 << 20);
        var targets = new List<long>(1 << 20);
        long done = 0;
        var buffer = new byte[1 << 20];

        foreach (var region in regions)
        {
            ulong regionBase = (ulong)region.BaseAddress.ToInt64();
            ulong regionSize = (ulong)region.RegionSize.ToInt64();

            for (ulong offset = 0; offset < regionSize; offset += (ulong)buffer.Length)
            {
                int want = (int)Math.Min((ulong)buffer.Length, regionSize - offset);
                if (!_mem.ReadInto((IntPtr)(long)(regionBase + offset), buffer, want)) continue;

                for (int i = 0; i + 8 <= want; i += 8)
                {
                    long value = BitConverter.ToInt64(buffer, i);
                    // User-space addresses only; this drops the flood of small ints and flags.
                    if (value < 0x10000 || value > 0x7FFF_FFFF_FFFF) continue;
                    if (!InAnyRange(ranges, (ulong)value)) continue;

                    holders.Add((long)(regionBase + offset) + i);
                    targets.Add(value);
                }

                done += want;
                progress?.Invoke(done);
            }
        }

        IndexedBytes = done;

        _holders = holders.ToArray();
        _targets = targets.ToArray();
        Array.Sort(_targets, _holders); // sort both, keyed on the pointed-to address
    }

    /// <summary>
    /// Walks backwards from <paramref name="target"/> until it reaches something inside
    /// a module, which is the only part of the route that is the same next launch.
    /// </summary>
    public List<PointerChain> Find(IntPtr target, int maxDepth = 4,
        int maxOffset = DefaultMaxOffset, int maxChains = 200)
    {
        var found = new List<PointerChain>();
        var seen = new HashSet<long>();

        // Each frontier entry is "reach this address, and these offsets finish the walk".
        var frontier = new List<(long Addr, List<int> Tail)> { ((long)target, new List<int>()) };

        for (int depth = 0; depth < maxDepth && frontier.Count > 0; depth++)
        {
            var next = new List<(long, List<int>)>();

            foreach (var (addr, tail) in frontier)
            {
                foreach (var (holder, offset) in HoldersPointingNear(addr, maxOffset))
                {
                    var chain = new List<int>(tail.Count + 1) { offset };
                    chain.AddRange(tail);

                    if (ModuleOf((ulong)holder) is { } hit)
                    {
                        found.Add(new PointerChain(hit.Name, (ulong)holder - hit.Base, chain.ToArray()));
                        if (found.Count >= maxChains) return Rank(found);
                        continue; // a static start is the end of the road
                    }

                    if (next.Count < MaxNodesPerLevel && seen.Add(holder))
                        next.Add((holder, chain));
                }
            }

            frontier = next;
        }

        return Rank(found);
    }

    /// <summary>Resolves a chain against the process as it is right now.</summary>
    public IntPtr? Resolve(PointerChain chain) => ResolveDirect(_mem, _modules, chain);

    /// <summary>
    /// Resolves a chain without a prebuilt index - just this one walk. Used by a
    /// generated trainer, which needs to re-find a single address on attach and
    /// has no reason to pay for a full-process pointer scan to do it.
    /// </summary>
    public static IntPtr? ResolveDirect(ProcessMemory mem, PointerChain chain) =>
        ResolveDirect(mem, mem.Modules(), chain);

    private static IntPtr? ResolveDirect(
        ProcessMemory mem, List<(string Name, ulong Base, ulong Size)> modules, PointerChain chain)
    {
        // A fingerprint re-finds the holder by its code, not by an offset that assumed
        // the old binary - prefer it, since a stale offset can still read *something*
        // without failing outright. Fall back to the plain offset if there's no
        // fingerprint yet, or the module hasn't actually been patched since it was made.
        ulong? addr = chain.Fingerprint?.Locate(mem, chain.Module);

        if (addr is null)
        {
            var module = modules.FirstOrDefault(m =>
                string.Equals(m.Name, chain.Module, StringComparison.OrdinalIgnoreCase));
            if (module.Base == 0) return null;
            addr = module.Base + chain.ModuleOffset;
        }

        foreach (int offset in chain.Offsets)
        {
            var buf = mem.Read((IntPtr)(long)addr.Value, 8);
            if (buf is null) return null;

            long next = BitConverter.ToInt64(buf, 0) + offset;
            if (next < 0x10000) return null;
            addr = (ulong)next;
        }

        return (IntPtr)(long)addr.Value;
    }

    /// <summary>Shortest chains with the smallest offsets are the most reliable across runs.</summary>
    private static List<PointerChain> Rank(List<PointerChain> chains) => chains
        .OrderBy(c => c.Depth)
        .ThenBy(c => c.Offsets.Length == 0 ? 0 : c.Offsets.Max())
        .ToList();

    /// <summary>
    /// Every stored pointer whose value lands in [addr - maxOffset, addr], i.e. anything
    /// pointing at the start of a struct that contains our value.
    /// </summary>
    private IEnumerable<(long Holder, int Offset)> HoldersPointingNear(long addr, int maxOffset)
    {
        int lo = LowerBound(addr - maxOffset);
        for (int i = lo; i < _targets.Length && _targets[i] <= addr; i++)
            yield return (_holders[i], (int)(addr - _targets[i]));
    }

    private int LowerBound(long value)
    {
        int lo = 0, hi = _targets.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (_targets[mid] < value) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    private (string Name, ulong Base, ulong Size)? ModuleOf(ulong addr)
    {
        foreach (var m in _modules)
            if (addr >= m.Base && addr < m.Base + m.Size)
                return m;
        return null;
    }

    private static bool InAnyRange((ulong Base, ulong Size)[] ranges, ulong addr)
    {
        int lo = 0, hi = ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (addr < ranges[mid].Base) hi = mid - 1;
            else if (addr >= ranges[mid].Base + ranges[mid].Size) lo = mid + 1;
            else return true;
        }
        return false;
    }

    /// <summary>
    /// Chains are worth keeping between sessions, so they serialise to one line each.
    /// A chain with a captured fingerprint gets three extra fields; older files and
    /// chains without one just stop after the offsets, and load back with none.
    /// </summary>
    public static string Save(IEnumerable<PointerChain> chains)
    {
        var sb = new StringBuilder();
        foreach (var c in chains)
        {
            sb.Append($"{c.Module}|{c.ModuleOffset:X}|{string.Join(",", c.Offsets.Select(o => o.ToString("X")))}");
            if (c.Fingerprint is { } fp)
            {
                string wildcard = new(fp.Wildcard.Select(w => w ? '1' : '0').ToArray());
                sb.Append($"|{Convert.ToHexString(fp.Pattern)}|{wildcard}|{fp.InstructionOffset}");
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static List<PointerChain> Load(string text)
    {
        var chains = new List<PointerChain>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split('|');
            if (parts.Length != 3 && parts.Length != 6) continue;

            var offsets = parts[2].Length == 0
                ? Array.Empty<int>()
                : parts[2].Split(',').Select(o => Convert.ToInt32(o, 16)).ToArray();

            ChainFingerprint? fingerprint = parts.Length == 6
                ? new ChainFingerprint(
                    Convert.FromHexString(parts[3]),
                    parts[4].Select(c => c == '1').ToArray(),
                    int.Parse(parts[5]))
                : null;

            chains.Add(new PointerChain(parts[0], Convert.ToUInt64(parts[1], 16), offsets) { Fingerprint = fingerprint });
        }
        return chains;
    }
}
