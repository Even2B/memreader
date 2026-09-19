namespace MemReader;

/// <summary>One candidate's outcome after a capture session finishes.</summary>
internal sealed record CorrelationResult(IntPtr Address, int Hits, int TotalMarks, int NoiseChanges)
{
    /// <summary>Perfect hits with zero unrelated noise sort first - the strongest possible evidence.</summary>
    public static readonly IComparer<CorrelationResult> ByStrength =
        Comparer<CorrelationResult>.Create((a, b) =>
            b.Hits != a.Hits ? b.Hits.CompareTo(a.Hits) : a.NoiseChanges.CompareTo(b.NoiseChanges));
}

/// <summary>
/// Finds a value by how it moves relative to marked moments, instead of by narrowing
/// on a typed number. Watch a pile of candidates, press a hotkey at the instant an
/// event happens (damage taken, an item bought) a handful of times, and stop: the
/// address that changed at every mark and nowhere else is the one you want.
///
/// This does not survive a garbage collector relocating the object mid-capture - no
/// address-based technique can. What it fixes is the cost of finding out: one capture
/// that takes a few seconds, instead of the slow multi-round-trip scan/filter cycle
/// where each step is a fresh chance for the GC to invalidate everything found so far.
/// </summary>
internal sealed class CorrelationDetector : IDisposable
{
    private readonly ProcessMemory _mem;
    private readonly IntPtr[] _addresses; // must stay sorted ascending for ReadMany
    private readonly int _size;

    private readonly List<DateTime> _ticks = new();
    private readonly List<byte[]?[]> _samples = new(); // [tick][addressIndex]
    private readonly List<DateTime> _marks = new();
    private readonly object _lock = new();

    private CancellationTokenSource? _pollLoop;
    private Task? _pollTask;

    public bool Capturing => _pollLoop is not null;
    public int TickCount { get { lock (_lock) return _ticks.Count; } }
    public int MarkCount { get { lock (_lock) return _marks.Count; } }

    public CorrelationDetector(ProcessMemory mem, IEnumerable<IntPtr> addresses, int size)
    {
        _mem = mem;
        _size = size;
        // Sorted once up front - ReadMany's block-coalescing assumes ascending order,
        // and every poll tick reuses this same order rather than re-sorting each time.
        _addresses = addresses.Distinct().OrderBy(a => a.ToInt64()).ToArray();
    }

    /// <summary>Begins polling every candidate in the background at the given interval.</summary>
    public void StartCapture(int pollIntervalMs)
    {
        if (Capturing) throw new InvalidOperationException("already capturing");
        lock (_lock) { _ticks.Clear(); _samples.Clear(); _marks.Clear(); }

        _pollLoop = new CancellationTokenSource();
        var token = _pollLoop.Token;

        _pollTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                var now = _mem.ReadMany(_addresses, _size);
                lock (_lock) { _ticks.Add(DateTime.UtcNow); _samples.Add(now); }
                try { await Task.Delay(pollIntervalMs, token); }
                catch (TaskCanceledException) { break; }
            }
        }, token);
    }

    /// <summary>Records that an event happened right now. Call this at the moment you notice it.</summary>
    public void Mark()
    {
        if (!Capturing) throw new InvalidOperationException("not capturing - call StartCapture first");
        lock (_lock) _marks.Add(DateTime.UtcNow);
    }

    /// <summary>Stops polling and scores every candidate against the recorded marks.</summary>
    public List<CorrelationResult> StopAndScore()
    {
        if (!Capturing) throw new InvalidOperationException("not capturing");
        _pollLoop!.Cancel();
        try { _pollTask?.Wait(); } catch (AggregateException) { /* cancellation, expected */ }
        _pollLoop.Dispose();
        _pollLoop = null;

        List<DateTime> ticks;
        List<byte[]?[]> samples;
        List<DateTime> marks;
        lock (_lock) { ticks = _ticks.ToList(); samples = _samples.ToList(); marks = _marks.ToList(); }

        var results = new List<CorrelationResult>(_addresses.Length);
        for (int a = 0; a < _addresses.Length; a++)
            results.Add(Score(a, ticks, samples, marks));

        results.Sort((x, y) => CorrelationResult.ByStrength.Compare(x, y));
        return results;
    }

    /// <summary>
    /// A mark fires human reaction time after the real change, not at the same instant
    /// - you see the hit, then you press the key. So a "hit" isn't "did the value
    /// change in the exact tick straddling the mark"; it's "did the value change
    /// somewhere in the second or so leading up to the mark." Noise is any change
    /// that falls outside every mark's window - movement with no event to explain it.
    /// </summary>
    private static readonly TimeSpan ReactionWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MarkTailBuffer = TimeSpan.FromMilliseconds(250);

    private CorrelationResult Score(
        int addressIndex, List<DateTime> ticks, List<byte[]?[]> samples, List<DateTime> marks)
    {
        var windows = marks.Select(m => (Start: m - ReactionWindow, End: m + MarkTailBuffer)).ToList();
        int hits = 0, noise = 0;

        foreach (var (start, end) in windows)
            if (ChangedBetween(addressIndex, ticks, samples, start, end))
                hits++;

        for (int t = 1; t < ticks.Count; t++)
        {
            var prev = samples[t - 1][addressIndex];
            var curr = samples[t][addressIndex];
            if (prev is null || curr is null) continue;
            if (prev.AsSpan().SequenceEqual(curr)) continue;

            // A change inside any mark's window already counted as a hit above;
            // only changes that fall in none of them are unexplained movement.
            bool insideAWindow = windows.Any(w => ticks[t - 1] < w.End && ticks[t] > w.Start);
            if (!insideAWindow) noise++;
        }

        return new CorrelationResult(_addresses[addressIndex], hits, marks.Count, noise);
    }

    /// <summary>Compares the value at the tick just before the window opens to the value
    /// at the tick just before it closes - true if the window contains any change at all.</summary>
    private static bool ChangedBetween(
        int addressIndex, List<DateTime> ticks, List<byte[]?[]> samples, DateTime start, DateTime end)
    {
        byte[]? before = null, after = null;
        for (int t = 0; t < ticks.Count; t++)
        {
            if (ticks[t] <= start) before = samples[t][addressIndex] ?? before;
            if (ticks[t] <= end) after = samples[t][addressIndex] ?? after;
        }
        return before is not null && after is not null && !before.AsSpan().SequenceEqual(after);
    }

    public void Dispose()
    {
        if (Capturing) { _pollLoop!.Cancel(); try { _pollTask?.Wait(); } catch { /* shutting down */ } }
        _pollLoop?.Dispose();
    }
}
