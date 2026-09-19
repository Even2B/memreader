using Iced.Intel;

namespace MemReader;

/// <summary>
/// A code signature for the instruction that loads a pointer chain's module-level
/// static holder. A saved chain's <c>ModuleOffset</c> is only correct for the exact
/// binary it was found in - a patch that recompiles the module can shift the holder
/// to a new offset even though nothing about the chain conceptually changed. The
/// instruction that reads the holder is what's actually stable: its opcode and
/// surrounding bytes usually survive a patch even when the address it points at
/// doesn't, so re-finding that instruction re-finds the holder.
/// </summary>
internal sealed record ChainFingerprint(byte[] Pattern, bool[] Wildcard, int InstructionOffset)
{
    private const int ContextBefore = 8;
    private const int ContextAfter = 8;

    /// <summary>
    /// Finds the instruction in <paramref name="moduleName"/> that references
    /// <paramref name="targetAddress"/> (module base + a chain's saved offset) and
    /// fingerprints it: its own bytes with the address-bearing bytes wildcarded, plus
    /// a little literal context on each side so the pattern isn't just a bare opcode.
    /// </summary>
    public static ChainFingerprint? Capture(ProcessMemory mem, string moduleName, ulong targetAddress)
    {
        var module = ModuleOf(mem, moduleName);
        if (module is null) return null;

        foreach (var (regionBase, regionSize) in ExecutableRegionsOf(mem, module.Value.Base, module.Value.Size))
        {
            var code = mem.Read((IntPtr)(long)regionBase, (int)regionSize);
            if (code is null) continue;

            var decoder = Decoder.Create(64, new ByteArrayCodeReader(code));
            decoder.IP = regionBase;
            ulong end = regionBase + (ulong)code.Length;

            while (decoder.IP < end)
            {
                ulong insnStart = decoder.IP;
                var insn = decoder.Decode();
                if (insn.IsInvalid) break; // ran past real code into data - this region is done

                if (!insn.IsIPRelativeMemoryOperand || insn.IPRelativeMemoryAddress != targetAddress)
                    continue;

                var built = Build(code, (int)(insnStart - regionBase), insn.Length,
                    insn.IPRelativeMemoryAddress, insn.NextIP);
                if (built is not null) return built;
            }
        }

        return null;
    }

    /// <summary>Rescans a module's code for this signature and returns the address it now points to.</summary>
    public ulong? Locate(ProcessMemory mem, string moduleName)
    {
        var module = ModuleOf(mem, moduleName);
        if (module is null) return null;

        foreach (var (regionBase, regionSize) in ExecutableRegionsOf(mem, module.Value.Base, module.Value.Size))
        {
            var code = mem.Read((IntPtr)(long)regionBase, (int)regionSize);
            if (code is null) continue;

            int at = IndexOf(code, Pattern, Wildcard);
            if (at < 0) continue;

            ulong insnAddr = regionBase + (ulong)(at + InstructionOffset);
            if (DecodeOne(mem, insnAddr) is { IsIPRelativeMemoryOperand: true } insn)
                return insn.IPRelativeMemoryAddress;
        }

        return null;
    }

    private static ChainFingerprint? Build(byte[] code, int insnOffset, int insnLength, ulong target, ulong nextIp)
    {
        long displacement = (long)target - (long)nextIp;
        if (FindDisplacement(code, insnOffset, insnLength, displacement) is not (int dispOffset, int dispLength))
            return null;

        int start = Math.Max(0, insnOffset - ContextBefore);
        int end = Math.Min(code.Length, insnOffset + insnLength + ContextAfter);

        var pattern = code[start..end];
        var wildcard = new bool[pattern.Length];
        for (int i = 0; i < dispLength; i++)
            wildcard[dispOffset - start + i] = true;

        return new ChainFingerprint(pattern, wildcard, insnOffset - start);
    }

    /// <summary>
    /// Locates the displacement's own bytes inside the instruction by matching its
    /// little-endian encoding - disp32 first (the common case for RIP-relative
    /// addressing), disp8 if that comes up empty.
    /// </summary>
    private static (int Offset, int Length)? FindDisplacement(byte[] code, int insnOffset, int insnLength, long displacement)
    {
        var asInt32 = BitConverter.GetBytes((int)displacement);
        for (int i = insnOffset; i <= insnOffset + insnLength - 4; i++)
            if (code.AsSpan(i, 4).SequenceEqual(asInt32)) return (i, 4);

        byte asSByte = unchecked((byte)(sbyte)displacement);
        for (int i = insnOffset; i < insnOffset + insnLength; i++)
            if (code[i] == asSByte) return (i, 1);

        return null;
    }

    private static int IndexOf(byte[] haystack, byte[] pattern, bool[] wildcard)
    {
        for (int i = 0; i <= haystack.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (wildcard[j]) continue;
                if (haystack[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static Instruction? DecodeOne(ProcessMemory mem, ulong address)
    {
        var buf = mem.Read((IntPtr)(long)address, 16); // longest possible x86-64 instruction
        if (buf is null) return null;

        var decoder = Decoder.Create(64, new ByteArrayCodeReader(buf));
        decoder.IP = address;
        var insn = decoder.Decode();
        return insn.IsInvalid ? null : insn;
    }

    private static (ulong Base, ulong Size)? ModuleOf(ProcessMemory mem, string moduleName)
    {
        var module = mem.Modules().FirstOrDefault(m =>
            string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));
        return module.Base == 0 ? null : (module.Base, module.Size);
    }

    /// <summary>The executable portion of a module's address range - code lives here, not data.</summary>
    private static IEnumerable<(ulong Base, ulong Size)> ExecutableRegionsOf(
        ProcessMemory mem, ulong moduleBase, ulong moduleSize)
    {
        ulong moduleEnd = moduleBase + moduleSize;
        const uint executable = Native.PAGE_EXECUTE | Native.PAGE_EXECUTE_READ |
                                 Native.PAGE_EXECUTE_READWRITE | Native.PAGE_EXECUTE_WRITECOPY;

        foreach (var region in mem.Regions())
        {
            ulong regionBase = (ulong)region.BaseAddress.ToInt64();
            ulong regionSize = (ulong)region.RegionSize.ToInt64();
            if (regionBase >= moduleEnd || regionBase + regionSize <= moduleBase) continue;
            if ((region.Protect & executable) == 0) continue;

            ulong start = Math.Max(regionBase, moduleBase);
            ulong stop = Math.Min(regionBase + regionSize, moduleEnd);
            yield return (start, stop - start);
        }
    }
}
