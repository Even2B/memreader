using System.Globalization;
using System.Text;

namespace MemReader;

/// <summary>
/// One address the user is tracking: what it is, what it should read, and whether
/// MemReader should keep forcing it back to that value.
/// </summary>
internal sealed class WatchEntry
{
    public required IntPtr Address { get; init; }
    public required ValueKind Kind { get; set; }
    public required int Size { get; set; }

    /// <summary>The bytes rewritten on every freeze tick. Null until the value is set or frozen.</summary>
    public byte[]? Locked { get; set; }

    public bool Frozen { get; set; }

    /// <summary>Last value the monitor saw, used to notice the next write.</summary>
    public byte[]? Seen { get; set; }

    /// <summary>How many times this address has changed since it was added.</summary>
    public int Changes { get; set; }

    /// <summary>When it last changed, used to highlight rows that just moved.</summary>
    public DateTime ChangedAt { get; set; }

    public string TypeName => Kind switch
    {
        ValueKind.Int32 => "Int 32",
        ValueKind.Int64 => "Int 64",
        ValueKind.Float => "Float",
        ValueKind.Double => "Double",
        ValueKind.Utf8 => "UTF-8",
        ValueKind.Utf16 => "UTF-16",
        _ => "Bytes",
    };

    /// <summary>Turns raw bytes into the text shown in the grid.</summary>
    public string Format(byte[] data) => Kind switch
    {
        ValueKind.Int32 => BitConverter.ToInt32(data).ToString(),
        ValueKind.Int64 => BitConverter.ToInt64(data).ToString(),
        ValueKind.Float => BitConverter.ToSingle(data).ToString(CultureInfo.InvariantCulture),
        ValueKind.Double => BitConverter.ToDouble(data).ToString(CultureInfo.InvariantCulture),
        ValueKind.Utf8 => Encoding.UTF8.GetString(data).TrimEnd('\0'),
        ValueKind.Utf16 => Encoding.Unicode.GetString(data).TrimEnd('\0'),
        _ => BitConverter.ToString(data).Replace('-', ' '),
    };

    /// <summary>
    /// Turns typed text back into bytes. Text is padded or trimmed to the original
    /// length so a shorter string cannot run past the buffer it was found in.
    /// </summary>
    public byte[] ParseToBytes(string text)
    {
        var bytes = Needle.Parse(Kind, text).Pattern;

        if (Kind is ValueKind.Utf8 or ValueKind.Utf16 or ValueKind.Bytes)
        {
            var fitted = new byte[Size];
            Array.Copy(bytes, fitted, Math.Min(bytes.Length, Size));
            return fitted;
        }

        return bytes;
    }
}
