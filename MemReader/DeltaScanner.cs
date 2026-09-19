using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>How a candidate's current value must relate to its previous value.</summary>
internal enum Delta
{
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,
    DecreasedBy,
}

/// <summary>
/// Finds a value you cannot name. Snapshot the process, let the number move in the
/// app, then keep only the addresses that moved the way you say it moved. Spending
/// 50 gold and filtering "decreased by 50" usually lands on the real address in one
/// or two passes, without ever knowing what the starting number was.
/// </summary>
internal sealed class DeltaScan
{
    /// <summary>Snapshotting every region would cost gigabytes; game state lives in private writable pages.</summary>
    private const long MaxSnapshotBytes = 2L << 30;

    /// <summary>A partial capture smaller than this is not worth keeping.</summary>
    private const long Chunk = 1L << 20;

    /// <summary>Beyond this the address list costs more than it is worth - the user needs a sharper filter.</summary>
    public const int MaxCandidates = 4_000_000;

    private readonly ProcessMemory _mem;
    public ValueKind Kind { get; }
    public int Size { get; }
    public int Stride { get; }

    // Phase 1: raw region copies, before any filter has run.
    private List<(IntPtr Base, byte[] Data)>? _snapshot;

    // Phase 2: a concrete address list plus each address's previous bytes.
    private IntPtr[]? _addrs;
    private byte[]? _prev;

    /// <summary>True when the last filter produced more candidates than we keep.</summary>
    public bool Truncated { get; private set; }

    public long SnapshotBytes { get; private set; }
    public bool SnapshotIncomplete { get; private set; }

    public long Count => _addrs?.LongLength ?? EstimateFromSnapshot();

    public IReadOnlyList<IntPtr> Addresses => _addrs ?? (IReadOnlyList<IntPtr>)Array.Empty<IntPtr>();

    /// <summary>Only numbers have a meaningful "went up" - text and byte patterns do not.</summary>
    public static bool Supports(ValueKind kind) =>
        kind is ValueKind.Int32 or ValueKind.Int64 or ValueKind.Float or ValueKind.Double;

    private DeltaScan(ProcessMemory mem, ValueKind kind)
    {
        _mem = mem;
        Kind = kind;
        Size = kind switch
        {
            ValueKind.Int32 or ValueKind.Float => 4,
            _ => 8,
        };
        Stride = Size;
    }

    /// <summary>Takes the baseline copy of every private writable region.</summary>
    public static DeltaScan Start(ProcessMemory mem, ValueKind kind, Action<long>? progress = null)
    {
        if (!Supports(kind))
            throw new ArgumentException("Unknown-value scans work on numbers only.", nameof(kind));

        var scan = new DeltaScan(mem, kind) { _snapshot = new List<(IntPtr, byte[])>() };
        long taken = 0;

        foreach (var region in mem.Regions())
        {
            if (!IsCandidateRegion(region)) continue;

            long size = region.RegionSize.ToInt64();

            // A JVM heap is one region larger than the whole budget. Capturing part of
            // it beats skipping it, since that is exactly where the values live.
            long take = Math.Min(size, MaxSnapshotBytes - taken);
            if (take < size) scan.SnapshotIncomplete = true;
            if (take < Chunk) break;

            var data = mem.Read(region.BaseAddress, (int)take);
            if (data is null) continue;

            scan._snapshot.Add((region.BaseAddress, data));
            taken += take;
            progress?.Invoke(taken);
            if (taken >= MaxSnapshotBytes) break;
        }

        scan.SnapshotBytes = taken;
        return scan;
    }

    /// <summary>
    /// Private, writable, committed pages: heap and stack, where a game keeps the
    /// numbers it mutates. Skipping mapped images cuts the snapshot by an order of
    /// magnitude and drops constants that could never be the value you are hunting.
    /// </summary>
    private static bool IsCandidateRegion(Native.MEMORY_BASIC_INFORMATION mbi)
    {
        const uint MEM_PRIVATE = 0x20000;
        uint p = mbi.Protect & 0xFF;
        bool writable = p is 0x04 or 0x08 or 0x40 or 0x80;
        return mbi.Type == MEM_PRIVATE && writable && mbi.RegionSize.ToInt64() >= 8;
    }

    /// <summary>Applies one filter, replacing the candidate set with whatever survived.</summary>
    public void Filter(Delta delta, double amount, Action<long>? progress = null)
    {
        Truncated = false;
        if (_snapshot is not null) FilterFromSnapshot(delta, amount, progress);
        else FilterFromList(delta, amount, progress);
    }

    private void FilterFromSnapshot(Delta delta, double amount, Action<long>? progress)
    {
        var addrs = new List<IntPtr>();
        var prev = new List<byte>();
        long done = 0;

        foreach (var (base_, old) in _snapshot!)
        {
            var now = _mem.Read(base_, old.Length);
            if (now is null) continue;

            for (int off = 0; off + Size <= old.Length; off += Stride)
            {
                if (!Passes(delta, amount, old.AsSpan(off, Size), now.AsSpan(off, Size))) continue;

                if (addrs.Count >= MaxCandidates) { Truncated = true; break; }
                addrs.Add((IntPtr)(base_.ToInt64() + off));
                prev.AddRange(now.AsSpan(off, Size));
            }

            done += old.Length;
            progress?.Invoke(done);
            if (Truncated) break;
        }

        _addrs = addrs.ToArray();
        _prev = prev.ToArray();
        _snapshot = null; // the address list supersedes it
    }

    private void FilterFromList(Delta delta, double amount, Action<long>? progress)
    {
        if (_addrs is null || _prev is null) return;

        var keptAddr = new List<IntPtr>();
        var keptPrev = new List<byte>();
        var current = ReadCurrent(progress);

        for (int i = 0; i < _addrs.Length; i++)
        {
            if (current[i] is not { } now) continue;
            var old = _prev.AsSpan(i * Size, Size);
            if (!Passes(delta, amount, old, now)) continue;

            keptAddr.Add(_addrs[i]);
            keptPrev.AddRange(now);
        }

        _addrs = keptAddr.ToArray();
        _prev = keptPrev.ToArray();
    }

    /// <summary>
    /// Reads every candidate, coalescing addresses that share a block into one call.
    /// A per-address read costs a syscall each, which is ruinous at millions of hits.
    /// </summary>
    private byte[]?[] ReadCurrent(Action<long>? progress)
    {
        const int Block = 64 * 1024;
        var result = new byte[]?[_addrs!.Length];

        int i = 0;
        while (i < _addrs.Length)
        {
            long start = _addrs[i].ToInt64();
            int j = i;
            while (j < _addrs.Length && _addrs[j].ToInt64() + Size - start <= Block) j++;

            int span = (int)(_addrs[j - 1].ToInt64() + Size - start);
            var buf = _mem.Read((IntPtr)start, span);

            if (buf is not null)
                for (int k = i; k < j; k++)
                {
                    int off = (int)(_addrs[k].ToInt64() - start);
                    result[k] = buf.AsSpan(off, Size).ToArray();
                }

            i = j;
            progress?.Invoke(i);
        }

        return result;
    }

    private bool Passes(Delta delta, double amount, ReadOnlySpan<byte> old, ReadOnlySpan<byte> now)
    {
        double a = ToDouble(old), b = ToDouble(now);

        return delta switch
        {
            Delta.Changed => a != b,
            Delta.Unchanged => a == b,
            Delta.Increased => b > a,
            Delta.Decreased => b < a,
            // Floats never land exactly, so allow a hair of slack on the difference.
            Delta.IncreasedBy => Math.Abs(b - a - amount) < Tolerance,
            Delta.DecreasedBy => Math.Abs(a - b - amount) < Tolerance,
            _ => false,
        };
    }

    private double Tolerance => Kind is ValueKind.Float or ValueKind.Double ? 1e-3 : 0.5;

    private double ToDouble(ReadOnlySpan<byte> b) => Kind switch
    {
        ValueKind.Int32 => MemoryMarshal.Read<int>(b),
        ValueKind.Int64 => MemoryMarshal.Read<long>(b),
        ValueKind.Float => MemoryMarshal.Read<float>(b),
        _ => MemoryMarshal.Read<double>(b),
    };

    private long EstimateFromSnapshot() =>
        _snapshot?.Sum(r => (r.Data.Length - Size) / Stride + 1L) ?? 0;
}
