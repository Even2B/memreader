using System.Text;

namespace MemReader;

internal enum ValueKind { Int32, Int64, Float, Double, Utf8, Utf16, Bytes }

/// <summary>A needle to look for, plus the comparison that decides a hit.</summary>
internal sealed class Needle
{
    public required ValueKind Kind { get; init; }
    public required byte[] Pattern { get; init; }
    public required string Display { get; init; }

    public int Size => Pattern.Length;

    /// <summary>Alignment to step by. Numerics sit on their own size; text can start anywhere.</summary>
    public int Stride => Kind switch
    {
        ValueKind.Int32 or ValueKind.Float => 4,
        ValueKind.Int64 or ValueKind.Double => 8,
        _ => 1,
    };

    public static Needle Parse(ValueKind kind, string input) => kind switch
    {
        ValueKind.Int32 => new Needle { Kind = kind, Pattern = BitConverter.GetBytes(int.Parse(input)), Display = input },
        ValueKind.Int64 => new Needle { Kind = kind, Pattern = BitConverter.GetBytes(long.Parse(input)), Display = input },
        ValueKind.Float => new Needle { Kind = kind, Pattern = BitConverter.GetBytes(float.Parse(input)), Display = input },
        ValueKind.Double => new Needle { Kind = kind, Pattern = BitConverter.GetBytes(double.Parse(input)), Display = input },
        ValueKind.Utf8 => new Needle { Kind = kind, Pattern = Encoding.UTF8.GetBytes(input), Display = $"\"{input}\"" },
        ValueKind.Utf16 => new Needle { Kind = kind, Pattern = Encoding.Unicode.GetBytes(input), Display = $"\"{input}\"" },
        ValueKind.Bytes => new Needle { Kind = kind, Pattern = HexToBytes(input), Display = input },
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static byte[] HexToBytes(string s)
    {
        s = s.Replace(" ", "").Replace("-", "");
        if (s.Length % 2 != 0) throw new FormatException("Hex needs an even number of digits.");
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }
}

internal static class Scanner
{
    private const int ChunkSize = 1 << 20; // 1 MiB reads keep memory flat on huge regions.

    /// <summary>Full sweep of the address space. Returns every address holding the needle.</summary>
    public static List<IntPtr> FirstScan(ProcessMemory mem, Needle needle, Action<long>? progress = null)
    {
        // Regions are independent, so they fan out across cores. Each worker keeps its
        // own hit list and buffer; merging once at the end beats locking per match.
        var regions = mem.Regions().ToArray();
        var perRegion = new List<IntPtr>[regions.Length];
        long scanned = 0;

        Parallel.For(0, regions.Length,
            () => new byte[ChunkSize + needle.Size],
            (r, _, buffer) =>
            {
                perRegion[r] = ScanRegion(mem, regions[r], needle, buffer, ref scanned, progress);
                return buffer;
            },
            _ => { });

        var hits = new List<IntPtr>(perRegion.Sum(h => h?.Count ?? 0));
        foreach (var regionHits in perRegion)
            if (regionHits is not null) hits.AddRange(regionHits);

        // Callers (and the coalesced re-reads) expect ascending addresses.
        hits.Sort((a, b) => a.ToInt64().CompareTo(b.ToInt64()));
        return hits;
    }

    private static List<IntPtr> ScanRegion(
        ProcessMemory mem, Native.MEMORY_BASIC_INFORMATION region, Needle needle,
        byte[] buffer, ref long scanned, Action<long>? progress)
    {
        var hits = new List<IntPtr>();
        int overlap = needle.Size - 1;

        ulong regionBase = (ulong)region.BaseAddress.ToInt64();
        ulong regionSize = (ulong)region.RegionSize.ToInt64();
        ulong offset = 0;

        while (offset < regionSize)
        {
            int want = (int)Math.Min((ulong)ChunkSize, regionSize - offset);
            // Read a little past the chunk so a match straddling the boundary is not lost.
            int padded = (int)Math.Min((ulong)(want + overlap), regionSize - offset);

            if (mem.ReadInto((IntPtr)(long)(regionBase + offset), buffer, padded))
            {
                int limit = Math.Min(want, padded - needle.Size);
                // Keep numeric scans on their natural alignment across chunk boundaries.
                ulong misalign = (regionBase + offset) % (ulong)needle.Stride;
                int start = misalign == 0 ? 0 : needle.Stride - (int)misalign;

                for (int i = start; i <= limit; i += needle.Stride)
                    if (Matches(buffer, i, needle.Pattern))
                        hits.Add((IntPtr)(long)(regionBase + offset + (ulong)i));

                long done = Interlocked.Add(ref scanned, want);
                progress?.Invoke(done);
            }

            offset += (ulong)want;
        }

        return hits;
    }

    /// <summary>Re-checks known addresses against a new value. This is what narrows a scan down.</summary>
    public static List<IntPtr> Refine(ProcessMemory mem, IEnumerable<IntPtr> candidates, Needle needle)
    {
        var kept = new List<IntPtr>();
        foreach (var addr in candidates)
        {
            var buf = mem.Read(addr, needle.Size);
            if (buf != null && Matches(buf, 0, needle.Pattern)) kept.Add(addr);
        }
        return kept;
    }

    private static bool Matches(byte[] haystack, int offset, byte[] pattern)
    {
        for (int i = 0; i < pattern.Length; i++)
            if (haystack[offset + i] != pattern[i]) return false;
        return true;
    }

    /// <summary>Classic hex+ASCII dump for eyeballing what actually lives at an address.</summary>
    public static string HexDump(byte[] data, ulong baseAddress)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append($"{baseAddress + (ulong)i:X16}  ");
            for (int j = 0; j < 16; j++)
                sb.Append(i + j < data.Length ? $"{data[i + j]:X2} " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                byte b = data[i + j];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
