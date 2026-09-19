using Iced.Intel;

namespace MemReader;

/// <summary>One decoded instruction, formatted for display.</summary>
internal sealed record DisassembledInstruction(ulong Address, int Length, string Bytes, string Text);

/// <summary>
/// Turns raw bytes at an address into x86-64 assembly. This is the difference between
/// a scanner ("this value changed") and a reverse-engineering tool ("this instruction
/// changed it") - the hex dump shows data, this shows the code that produces it.
/// </summary>
internal static class Disassembler
{
    /// <summary>
    /// Reads and decodes instructions starting at an address. Stops at the requested
    /// count or as soon as a read fails - a bad address should show what it could,
    /// not nothing at all.
    /// </summary>
    public static List<DisassembledInstruction> Decode(ProcessMemory mem, IntPtr address, int count)
    {
        // x86-64 instructions run up to 15 bytes; over-reading a little is cheaper
        // than under-reading and cutting the last instruction in half.
        const int BytesPerInstruction = 16;
        var buffer = mem.Read(address, count * BytesPerInstruction);
        if (buffer is null) return new List<DisassembledInstruction>();

        var results = new List<DisassembledInstruction>(count);
        var codeReader = new ByteArrayCodeReader(buffer);
        var decoder = Iced.Intel.Decoder.Create(64, codeReader);
        decoder.IP = (ulong)address.ToInt64();
        var formatter = new NasmFormatter();
        var output = new StringOutput();

        while (results.Count < count && decoder.IP < (ulong)address.ToInt64() + (ulong)buffer.Length)
        {
            var insn = decoder.Decode();
            if (insn.IsInvalid) break; // ran into data or the buffer's tail - stop rather than show garbage

            output.Reset();
            formatter.Format(insn, output);

            int offset = (int)(insn.IP - (ulong)address.ToInt64());
            string bytes = BitConverter.ToString(buffer, offset, insn.Length).Replace('-', ' ');
            results.Add(new DisassembledInstruction(insn.IP, insn.Length, bytes, output.ToString()));
        }

        return results;
    }
}
