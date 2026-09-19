namespace MemReader;

/// <summary>One deliberate write: what changed, when, and where it came from.</summary>
internal sealed record WriteJournalEntry(IntPtr Address, byte[] Before, byte[] After, DateTime When, string Source);

/// <summary>
/// A safety net for deliberate writes - a manual edit, a "write to all results" pass -
/// so a mistake is one click to undo instead of a reason to restart the target.
///
/// Freeze intentionally never goes through here: it corrects the same address many
/// times a second, and journaling every correction would bury the handful of writes a
/// user actually meant to make. Freeze already has its own instant undo - untick the
/// box - so it doesn't need this one too.
/// </summary>
internal sealed class WriteJournal
{
    private const int MaxEntries = 500;
    private readonly List<WriteJournalEntry> _entries = new();

    public IReadOnlyList<WriteJournalEntry> Entries => _entries;

    /// <summary>
    /// The only path a caller should use for a write worth being able to undo. Reads
    /// the old value first so the entry is self-contained even if nothing else in the
    /// app still remembers what was there before.
    /// </summary>
    public bool RecordedWrite(ProcessMemory mem, IntPtr address, byte[] newBytes, string source)
    {
        var before = mem.Read(address, newBytes.Length);
        if (!mem.Write(address, newBytes)) return false;

        // A write that changes nothing (already had this value) isn't worth undoing.
        if (before is not null && !before.AsSpan().SequenceEqual(newBytes))
        {
            _entries.Add(new WriteJournalEntry(address, before, newBytes, DateTime.Now, source));
            while (_entries.Count > MaxEntries) _entries.RemoveAt(0);
        }
        return true;
    }

    /// <summary>Reverts one entry by writing its recorded "before" bytes back.</summary>
    public bool Undo(ProcessMemory mem, WriteJournalEntry entry) => mem.Write(entry.Address, entry.Before);

    /// <summary>
    /// Reverts every write this session, as if none of them had happened. For each
    /// address this restores the value from its EARLIEST entry rather than replaying
    /// the whole history backwards - for a single address those are equivalent, and
    /// this is simpler: a later write to the same address just gets skipped over.
    /// </summary>
    public int UndoAll(ProcessMemory mem)
    {
        int ok = 0;
        foreach (var group in _entries.GroupBy(e => e.Address))
        {
            var earliest = group.OrderBy(e => e.When).First();
            if (mem.Write(earliest.Address, earliest.Before)) ok++;
        }
        _entries.Clear();
        return ok;
    }

    public void Clear() => _entries.Clear();
}
