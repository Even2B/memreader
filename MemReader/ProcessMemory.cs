using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>A read-only handle onto one process's address space.</summary>
internal sealed class ProcessMemory : IDisposable
{
    private readonly IntPtr _handle;
    public Process Process { get; }
    public bool Is32Bit { get; }

    /// <summary>True when the handle carries write rights, so edits are possible.</summary>
    public bool CanWrite { get; }

    private ProcessMemory(Process p, IntPtr handle, bool is32Bit, bool canWrite)
    {
        Process = p; _handle = handle; Is32Bit = is32Bit; CanWrite = canWrite;
    }

    public static ProcessMemory Open(int pid)
    {
        var p = Process.GetProcessById(pid);

        // Ask for write rights, but fall back to read-only rather than failing outright:
        // plenty of processes will hand over a read handle and refuse a writable one.
        const int read = Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ;
        const int write = read | Native.PROCESS_VM_WRITE | Native.PROCESS_VM_OPERATION;

        bool canWrite = true;
        var h = Native.OpenProcess(write, false, pid);
        if (h == IntPtr.Zero)
        {
            canWrite = false;
            h = Native.OpenProcess(read, false, pid);
        }

        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(err == 5
                ? $"Access denied opening PID {pid}. Run as Administrator; protected system processes stay off-limits."
                : $"OpenProcess failed for PID {pid} (Win32 error {err}).");
        }

        Native.IsWow64Process(h, out bool wow64);
        return new ProcessMemory(p, h, wow64, canWrite);
    }

    /// <summary>
    /// Writes bytes at an address, lifting page protection for the duration if the
    /// page is read-only, then putting the original protection back.
    /// </summary>
    public bool Write(IntPtr address, byte[] data)
    {
        if (!CanWrite) return false;

        bool reprotected = Native.VirtualProtectEx(
            _handle, address, data.Length, Native.PAGE_EXECUTE_READWRITE, out uint old);

        try
        {
            return Native.WriteProcessMemory(_handle, address, data, data.Length, out var wrote)
                   && (int)wrote == data.Length;
        }
        finally
        {
            if (reprotected)
                Native.VirtualProtectEx(_handle, address, data.Length, old, out _);
        }
    }

    /// <summary>Reads exactly <paramref name="size"/> bytes, or returns null if the read was refused.</summary>
    public byte[]? Read(IntPtr address, int size)
    {
        var buf = new byte[size];
        return Native.ReadProcessMemory(_handle, address, buf, size, out var got) && (int)got == size
            ? buf : null;
    }

    /// <summary>
    /// Reads into a caller-owned buffer. The parallel scan reuses one buffer per worker,
    /// so a multi-GB sweep does not allocate a fresh megabyte for every chunk.
    /// </summary>
    public bool ReadInto(IntPtr address, byte[] buffer, int size) =>
        Native.ReadProcessMemory(_handle, address, buffer, size, out var got) && (int)got == size;

    /// <summary>
    /// Reads many addresses efficiently by coalescing ones that share a small block of
    /// memory into a single call - a per-address read costs a syscall each, which adds
    /// up fast once a watch list or correlation capture reaches thousands of entries.
    /// </summary>
    /// <param name="ascendingAddresses">Must already be sorted ascending - the caller
    /// (a scan result, a watch list snapshot) typically already is.</param>
    /// <param name="sizeAt">Byte width of the value at index i - a plain scan reads every
    /// address at one uniform size, but a mixed watch list needs this per entry.</param>
    public byte[]?[] ReadMany(IReadOnlyList<IntPtr> ascendingAddresses, Func<int, int> sizeAt)
    {
        const int Block = 64 * 1024;
        var result = new byte[]?[ascendingAddresses.Count];

        int i = 0;
        while (i < ascendingAddresses.Count)
        {
            long start = ascendingAddresses[i].ToInt64();
            int j = i;
            while (j < ascendingAddresses.Count &&
                   ascendingAddresses[j].ToInt64() + sizeAt(j) - start <= Block) j++;

            int span = (int)(ascendingAddresses[j - 1].ToInt64() + sizeAt(j - 1) - start);
            var buf = Read((IntPtr)start, span);

            if (buf is not null)
                for (int k = i; k < j; k++)
                {
                    int off = (int)(ascendingAddresses[k].ToInt64() - start);
                    result[k] = buf.AsSpan(off, sizeAt(k)).ToArray();
                }

            i = j;
        }

        return result;
    }

    /// <summary>Convenience for the common case: every address holds the same value size.</summary>
    public byte[]?[] ReadMany(IReadOnlyList<IntPtr> ascendingAddresses, int size) =>
        ReadMany(ascendingAddresses, _ => size);

    /// <summary>
    /// The loaded modules, with the address range each occupies. An address inside a
    /// module is the same offset from that module every run, which is what makes a
    /// pointer chain survive a restart.
    /// </summary>
    public List<(string Name, ulong Base, ulong Size)> Modules()
    {
        var list = new List<(string, ulong, ulong)>();

        Native.EnumProcessModulesEx(_handle, null, 0, out int needed, Native.LIST_MODULES_ALL);
        if (needed == 0) return list;

        var handles = new IntPtr[needed / IntPtr.Size];
        if (!Native.EnumProcessModulesEx(_handle, handles, needed, out _, Native.LIST_MODULES_ALL))
            return list;

        var name = new StringBuilder(260);
        foreach (var h in handles)
        {
            if (h == IntPtr.Zero) continue;
            if (!Native.GetModuleInformation(_handle, h, out var info, Marshal.SizeOf<Native.MODULEINFO>()))
                continue;

            name.Clear();
            Native.GetModuleBaseNameW(_handle, h, name, name.Capacity);
            list.Add((name.ToString(), (ulong)info.BaseOfDll.ToInt64(), info.SizeOfImage));
        }

        return list;
    }

    /// <summary>Walks every committed, readable, non-guard region in the address space.</summary>
    public IEnumerable<Native.MEMORY_BASIC_INFORMATION> Regions()
    {
        Native.GetSystemInfo(out var si);
        ulong addr = (ulong)si.MinimumApplicationAddress.ToInt64();
        ulong max = Is32Bit
            ? 0x7FFF_FFFFUL
            : (ulong)si.MaximumApplicationAddress.ToInt64();
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();

        while (addr < max)
        {
            if (Native.VirtualQueryEx(_handle, (IntPtr)(long)addr, out var mbi, mbiSize) == IntPtr.Zero)
                break;

            ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
            if (regionSize == 0) break;

            bool readable = mbi.State == Native.MEM_COMMIT
                            && (mbi.Protect & Native.PAGE_GUARD) == 0
                            && (mbi.Protect & Native.PAGE_NOACCESS) == 0;
            if (readable) yield return mbi;

            addr += regionSize;
        }
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero) Native.CloseHandle(_handle);
        Process.Dispose();
    }
}
