namespace MemReader;

/// <summary>
/// One value the trainer knows how to find and, optionally, hold. Baked in at build
/// time by MainForm's trainer generator from whatever the watch list looked like then.
/// </summary>
internal sealed record TrainerTarget(
    string Label,
    ValueKind Kind,
    int Size,
    string? Module,
    ulong ModuleOffset,
    int[] Offsets,
    long StaticAddress,
    byte[]? FrozenValue,
    byte[]? FingerprintPattern,
    bool[]? FingerprintWildcard,
    int FingerprintInstructionOffset)
{
    /// <summary>
    /// Resolves this target against the attached process: a pointer chain when one was
    /// captured (survives a restart - and, with a fingerprint, a patch too), otherwise
    /// the exact address seen at build time (only good for the same run of the target).
    /// </summary>
    public IntPtr? Resolve(ProcessMemory mem)
    {
        if (Module is null) return (IntPtr)StaticAddress;

        var chain = new PointerChain(Module, ModuleOffset, Offsets)
        {
            Fingerprint = FingerprintPattern is null
                ? null
                : new ChainFingerprint(FingerprintPattern, FingerprintWildcard!, FingerprintInstructionOffset),
        };
        return PointerScanner.ResolveDirect(mem, chain);
    }
}
