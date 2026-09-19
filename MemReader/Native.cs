using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>Raw Win32 surface needed to read another process's address space.</summary>
internal static class Native
{
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_OPERATION = 0x0008;

    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesRead);

    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess, IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQueryEx(
        IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi, IntPtr length);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO info);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

    // --- Elevation helpers: SeDebugPrivilege lets us open processes we otherwise couldn't. ---

    public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const int TOKEN_QUERY = 0x0008;
    public const int SE_PRIVILEGE_ENABLED = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        int bufferLength, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    // --- Module enumeration: a chain is only durable if it starts inside a module. ---

    public const uint LIST_MODULES_ALL = 0x03;

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr BaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(
        IntPtr hProcess, [Out] IntPtr[]? modules, int cb, out int needed, uint filter);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(
        IntPtr hProcess, IntPtr module, out MODULEINFO info, int cb);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetModuleBaseNameW(
        IntPtr hProcess, IntPtr module, System.Text.StringBuilder name, int size);

    // --- Global hotkey: lets "Mark" fire while the game, not this app, has focus. ---

    public const int WM_HOTKEY = 0x0312;
    public const uint MOD_NOREPEAT = 0x4000;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    /// <summary>Best-effort enable of SeDebugPrivilege. Silently no-ops without admin.</summary>
    public static bool TryEnableDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            return false;
        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }
}
