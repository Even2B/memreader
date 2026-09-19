using System.Drawing;
using System.Windows.Forms;

namespace MemReader;

/// <summary>
/// A generated, standalone trainer: waits for one process, resolves the targets baked
/// in at build time, and lets the user view, edit, or freeze each one - the same
/// watch-list behavior as MemReaderGui, just for a fixed, pre-picked set of addresses.
/// </summary>
internal sealed class TrainerForm : Form
{
    private readonly Label _status = new();
    private readonly DataGridView _grid = new();
    private readonly System.Windows.Forms.Timer _timer = new();

    private ProcessMemory? _mem;
    private readonly List<WatchEntry?> _live = new();

    public TrainerForm()
    {
        Text = $"{GeneratedTargets.ProcessName} trainer - built with MemReader";
        Width = 640;
        Height = 420;
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        Font = Theme.Ui;
        Icon = SystemIcons.Application;

        _status.Dock = DockStyle.Top;
        _status.Height = 28;
        _status.Padding = new Padding(8, 6, 8, 0);
        _status.ForeColor = Theme.Muted;
        Controls.Add(_status);

        _grid.Dock = DockStyle.Fill;
        _grid.VirtualMode = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.BackgroundColor = Theme.Field;
        _grid.BorderStyle = BorderStyle.FixedSingle;
        _grid.GridColor = Theme.Border;
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        _grid.DefaultCellStyle.BackColor = Theme.Field;
        _grid.DefaultCellStyle.ForeColor = Theme.Text;
        _grid.DefaultCellStyle.SelectionBackColor = Theme.Accent;
        _grid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _grid.DefaultCellStyle.Font = Theme.Mono;

        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Value", ReadOnly = true, Width = 220 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Current", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.Columns.Add(new DataGridViewCheckBoxColumn
        { HeaderText = "Freeze", Width = 56 });
        Controls.Add(_grid);
        _grid.BringToFront();

        _grid.CellValueNeeded += OnValueNeeded;
        _grid.CellValuePushed += OnValuePushed;
        _grid.CurrentCellDirtyStateChanged += (_, _) =>
        {
            if (_grid.IsCurrentCellDirty && _grid.CurrentCell?.ColumnIndex == 2)
                _grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
        };
        _grid.DataError += (_, e) => e.ThrowException = false;

        _grid.RowCount = GeneratedTargets.Targets.Length;
        for (int i = 0; i < GeneratedTargets.Targets.Length; i++) _live.Add(null);

        SetStatus($"Waiting for {GeneratedTargets.ProcessName}...", Theme.Muted);

        _timer.Interval = 100;
        _timer.Tick += (_, _) => Tick();
        _timer.Start();

        FormClosed += (_, _) => { _timer.Stop(); _mem?.Dispose(); };
    }

    private void Tick()
    {
        if (_mem is null || _mem.Process.HasExited)
        {
            _mem?.Dispose();
            _mem = null;
            for (int i = 0; i < _live.Count; i++) _live[i] = null;
            TryAttach();
            _grid.Invalidate();
            return;
        }

        foreach (var entry in _live)
            if (entry is { Frozen: true, Locked: { } bytes })
                _mem.Write(entry.Address, bytes);

        _grid.Invalidate();
    }

    private void TryAttach()
    {
        var proc = System.Diagnostics.Process.GetProcessesByName(GeneratedTargets.ProcessName).FirstOrDefault();
        if (proc is null)
        {
            SetStatus($"Waiting for {GeneratedTargets.ProcessName}...", Theme.Muted);
            return;
        }

        try
        {
            _mem = ProcessMemory.Open(proc.Id);
        }
        catch (Exception ex)
        {
            SetStatus($"Attach failed: {ex.Message}", Theme.Warn);
            return;
        }

        int resolved = 0;
        for (int i = 0; i < GeneratedTargets.Targets.Length; i++)
        {
            var target = GeneratedTargets.Targets[i];
            var addr = target.Resolve(_mem);
            if (addr is null) { _live[i] = null; continue; }

            _live[i] = new WatchEntry { Address = addr.Value, Kind = target.Kind, Size = target.Size };
            if (target.FrozenValue is { } frozen)
            {
                _live[i]!.Locked = frozen;
                _live[i]!.Frozen = true;
            }
            resolved++;
        }

        SetStatus(!_mem.CanWrite
            ? $"Attached to {GeneratedTargets.ProcessName} read-only - restart as Administrator to edit or freeze."
            : $"Attached to {GeneratedTargets.ProcessName} (pid {proc.Id}). " +
              $"{resolved}/{GeneratedTargets.Targets.Length} target(s) found.",
            !_mem.CanWrite ? Theme.Warn : Theme.Good);
    }

    private void OnValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= GeneratedTargets.Targets.Length) return;
        var target = GeneratedTargets.Targets[e.RowIndex];
        var entry = _live[e.RowIndex];

        switch (e.ColumnIndex)
        {
            case 0: e.Value = target.Label; break;
            case 2: e.Value = entry?.Frozen ?? false; break;
            default:
                if (entry is null) { e.Value = "<not found>"; break; }
                var data = _mem?.Read(entry.Address, entry.Size);
                e.Value = data is null ? "<unreadable>" : entry.Format(data);
                break;
        }
    }

    private void OnValuePushed(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _live.Count) return;
        var entry = _live[e.RowIndex];
        if (entry is null || _mem is null) return;

        if (e.ColumnIndex == 2)
        {
            entry.Frozen = e.Value is true;
            if (entry.Frozen) entry.Locked ??= _mem.Read(entry.Address, entry.Size);
            return;
        }

        if (e.ColumnIndex != 1) return;
        if (!_mem.CanWrite) { SetStatus("This process was opened read-only.", Theme.Warn); return; }

        try
        {
            var bytes = entry.ParseToBytes(Convert.ToString(e.Value) ?? "");
            if (_mem.Write(entry.Address, bytes)) entry.Locked = bytes;
            else SetStatus("Write was refused by the target.", Theme.Warn);
        }
        catch (Exception ex)
        {
            SetStatus($"Cannot parse that value: {ex.Message}", Theme.Warn);
        }
    }

    private void SetStatus(string text, Color color)
    {
        _status.Text = text;
        _status.ForeColor = color;
    }
}
