using System.Drawing;

namespace MemReader;

/// <summary>Dark palette shared by every control, so the app reads as one surface.</summary>
internal static class Theme
{
    public static readonly Color Bg = Color.FromArgb(24, 24, 27);
    public static readonly Color Panel = Color.FromArgb(32, 32, 36);
    public static readonly Color Field = Color.FromArgb(42, 42, 47);
    public static readonly Color Border = Color.FromArgb(58, 58, 64);
    public static readonly Color Text = Color.FromArgb(228, 228, 231);
    public static readonly Color Muted = Color.FromArgb(150, 150, 158);
    public static readonly Color Accent = Color.FromArgb(96, 165, 250);
    public static readonly Color Good = Color.FromArgb(74, 222, 128);
    public static readonly Color Warn = Color.FromArgb(251, 146, 60);

    public static readonly Font Ui = new("Segoe UI", 9F);
    public static readonly Font Mono = new("Consolas", 9.5F);
}
