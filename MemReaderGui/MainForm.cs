using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace MemReader;

/// <summary>
/// Memory scanner and editor: pick a process, scan for a value, narrow the hits,
/// then edit or freeze the addresses that survive.
/// </summary>
internal sealed class MainForm : Form
{
    private ProcessMemory? _target;
    private List<IntPtr> _results = new();
    private ValueKind _lastKind = ValueKind.Int32;
    private int _lastSize = 4;

    // --- process picker ---
    private readonly SplitContainer _mainSplit = new();
    private readonly TextBox _filter = new();
    private readonly ListView _procList = new();
    private readonly Button _refreshBtn = new();
    private readonly Button _attachBtn = new();
    private readonly Label _procCount = new();
    private int _sortColumn = 2;
    private SortOrder _sortOrder = SortOrder.Descending;

    // --- scan controls ---
    private readonly Label _attached = new();
    private readonly ComboBox _type = new();
    private readonly TextBox _value = new();
    private readonly Button _firstScan = new();
    private readonly Button _nextScan = new();
    private readonly Button _reset = new();
    private readonly ProgressBar _progress = new();
    private readonly Label _status = new();

    // --- unknown-value ("what is the money?") scanning ---
    private readonly Button _unknownScan = new();
    private readonly ComboBox _delta = new();
    private readonly TextBox _deltaAmount = new();
    private readonly Button _applyDelta = new();
    private readonly Label _deltaInfo = new();
    private DeltaScan? _deltaScan;

    // --- results + dump ---
    private readonly DataGridView _grid = new();
    private readonly RichTextBox _dump = new();
    private readonly System.Windows.Forms.Timer _live = new();

    // --- watch list (edit + freeze) ---
    private readonly SplitContainer _rightSplit = new();
    private readonly DataGridView _watchGrid = new();
    private readonly List<WatchEntry> _watch = new();
    private readonly Button _addWatch = new();
    private readonly Button _writeAll = new();
    private readonly Button _dropWatch = new();
    private readonly System.Windows.Forms.Timer _freeze = new();

    // --- change log: what writes to a watched address, and when ---
    private readonly TabControl _tabs = new();
    private readonly ListBox _log = new();
    private readonly CheckBox _logging = new();
    private readonly Button _clearLog = new();
    private readonly ComboBox _rate = new();
    private readonly Label _monitorCost = new();

    private readonly Button _consoleMode = new();

    // --- pointer chains: routes that still work after the game restarts ---
    private readonly ListBox _chainList = new();
    private readonly Button _findPtr = new();
    private readonly Button _resolvePtr = new();
    private readonly Button _savePtr = new();
    private readonly Button _loadPtr = new();
    private PointerScanner? _ptrScan;
    private List<PointerChain> _chains = new();

    // --- correlation detector: find a value by marking moments, not typing numbers ---
    private const int MarkHotkeyId = 0xC077; // arbitrary id, just needs to be unique to this app
    private const uint MarkHotkeyVk = 0x77;  // VK_F8 - rarely bound in games or Windows itself
    private readonly Button _corrStart = new();
    private readonly Button _corrMark = new();
    private readonly Button _corrStop = new();
    private readonly Label _corrStatus = new();
    private readonly DataGridView _corrGrid = new();
    private readonly Button _corrAddToWatch = new();
    private CorrelationDetector? _correlation;
    private List<CorrelationResult> _corrResults = new();
    private bool _hotkeyRegistered;

    // --- write journal: a safety net for deliberate edits and batch writes ---
    private readonly WriteJournal _journal = new();
    private readonly DataGridView _journalGrid = new();
    private readonly Button _undoSelected = new();
    private readonly Button _undoAll = new();
    private readonly Label _journalStatus = new();

    // --- disassembly: what code actually touches an address, not just its bytes ---
    private readonly TextBox _disasmAddr = new();
    private readonly Button _disasmGo = new();
    private readonly RichTextBox _disasmOutput = new();
    private readonly Label _disasmStatus = new();
    private readonly System.Windows.Forms.Timer _monitor = new();
    private int _tickCost;
    private const int MaxLogEntries = 500;

    /// <summary>Past this, even a slow poll costs more than the answer is worth.</summary>
    private const int MaxWatched = 50_000;

    /// <summary>Watch entries ordered by address, so neighbours share one read. Rebuilt on edit.</summary>
    private int[] _watchOrder = Array.Empty<int>();
    private bool _watchOrderStale = true;

    public MainForm()
    {
        Text = "MemReader - process memory scanner and editor";
        MinimumSize = new Size(900, 560);
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        Font = Theme.Ui;
        StartPosition = FormStartPosition.Manual;
        SizeToScreen();

        BuildLayout();
        WireEvents();

        bool priv = Native.TryEnableDebugPrivilege();
        SetStatus(priv
            ? "SeDebugPrivilege enabled - most user processes are reachable."
            : "Running without SeDebugPrivilege - restart as Administrator for wider access.",
            priv ? Theme.Good : Theme.Warn);

        RefreshProcesses();
    }

    // ---------------------------------------------------------------- layout

    /// <summary>
    /// Fills most of the desktop rather than guessing a pixel size - a fixed 1400px
    /// window is either cramped or off-screen depending on the display.
    /// </summary>
    private void SizeToScreen()
    {
        var work = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 800);
        int w = Math.Max(MinimumSize.Width, (int)(work.Width * 0.92));
        int h = Math.Max(MinimumSize.Height, (int)(work.Height * 0.92));
        Size = new Size(w, h);
        Location = new Point(work.X + (work.Width - w) / 2, work.Y + (work.Height - h) / 2);
    }

    private void BuildLayout()
    {
        // A splitter rather than a fixed column: the process list is the first thing
        // you read, and how much room it needs depends on the machine.
        var host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Padding = new Padding(10) };
        Controls.Add(host);

        _mainSplit.Dock = DockStyle.Fill;
        _mainSplit.Orientation = Orientation.Vertical;
        _mainSplit.BackColor = Theme.Border;
        _mainSplit.SplitterWidth = 8;
        _mainSplit.Panel1.Controls.Add(BuildProcessPane());
        _mainSplit.Panel2.Controls.Add(BuildWorkPane());
        host.Controls.Add(_mainSplit);
    }

    /// <summary>
    /// Split constraints are applied once the form has a real width - setting a
    /// Panel2MinSize wider than the not-yet-laid-out control throws.
    /// </summary>
    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        try
        {
            _mainSplit.Panel1MinSize = 240;
            _mainSplit.Panel2MinSize = 520;
            _mainSplit.SplitterDistance =
                Math.Clamp(400, _mainSplit.Panel1MinSize, Math.Max(_mainSplit.Panel1MinSize,
                    _mainSplit.Width - _mainSplit.Panel2MinSize - _mainSplit.SplitterWidth));
        }
        catch (InvalidOperationException)
        {
            // Window opened smaller than the constraints allow; the default split is fine.
        }

        try { _rightSplit.SplitterDistance = (int)(_rightSplit.Height * 0.55); }
        catch (InvalidOperationException) { }

        _progress.Visible = false;
        FitProcessColumns();
    }

    private Control BuildProcessPane()
    {
        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Panel,
            Padding = new Padding(10),
            Margin = new Padding(0, 0, 10, 0),
        };
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, AutoSize = true,
            BackColor = Theme.Panel, Margin = new Padding(0),
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(SectionLabel("PROCESSES"), 0, 0);

        _procCount.ForeColor = Theme.Muted;
        _procCount.AutoSize = true;
        _procCount.Margin = new Padding(0, 0, 2, 2);
        header.Controls.Add(_procCount, 1, 0);
        pane.Controls.Add(header, 0, 0);

        _filter.Dock = DockStyle.Fill;
        _filter.BackColor = Theme.Field;
        _filter.ForeColor = Theme.Text;
        _filter.BorderStyle = BorderStyle.FixedSingle;
        _filter.PlaceholderText = "filter by name...";
        _filter.Margin = new Padding(0, 4, 0, 8);
        pane.Controls.Add(_filter, 0, 1);

        _procList.Dock = DockStyle.Fill;
        _procList.View = View.Details;
        _procList.FullRowSelect = true;
        _procList.MultiSelect = false;
        _procList.HideSelection = false;
        _procList.BackColor = Theme.Field;
        _procList.ForeColor = Theme.Text;
        _procList.BorderStyle = BorderStyle.FixedSingle;
        _procList.Font = Theme.Ui;
        _procList.Columns.Add("Process", 190);
        _procList.Columns.Add("PID", 64, HorizontalAlignment.Right);
        _procList.Columns.Add("RAM", 80, HorizontalAlignment.Right);
        pane.Controls.Add(_procList, 0, 2);

        var buttons = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, AutoSize = true,
            BackColor = Theme.Panel, Margin = new Padding(0, 8, 0, 0),
        };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));

        _attachBtn.Text = "Attach";
        _attachBtn.Dock = DockStyle.Fill;
        _attachBtn.Height = 32;
        StyleButton(_attachBtn, primary: true);
        buttons.Controls.Add(_attachBtn, 0, 0);

        _refreshBtn.Text = "Refresh";
        _refreshBtn.Dock = DockStyle.Fill;
        _refreshBtn.Height = 32;
        StyleButton(_refreshBtn, primary: false);
        _refreshBtn.Margin = new Padding(0);
        buttons.Controls.Add(_refreshBtn, 1, 0);

        pane.Controls.Add(buttons, 0, 3);
        return pane;
    }

    /// <summary>Gives the name column whatever width the other two do not need.</summary>
    private void FitProcessColumns()
    {
        if (_procList.ClientSize.Width <= 0) return;
        int rest = _procList.Columns[1].Width + _procList.Columns[2].Width;
        _procList.Columns[0].Width = Math.Max(120, _procList.ClientSize.Width - rest - 4);
    }

    private Control BuildWorkPane()
    {
        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Bg,
        };
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _attached.Text = "Not attached - double-click a process to begin";
        _attached.ForeColor = Theme.Muted;
        _attached.AutoSize = true;
        _attached.Margin = new Padding(2, 0, 0, 8);
        pane.Controls.Add(_attached, 0, 0);

        pane.Controls.Add(BuildScanBar(), 0, 1);
        pane.Controls.Add(BuildResultsSplit(), 0, 2);

        _status.Dock = DockStyle.Fill;
        _status.AutoSize = true;
        _status.ForeColor = Theme.Muted;
        _status.Margin = new Padding(2, 8, 0, 0);
        pane.Controls.Add(_status, 0, 3);

        return pane;
    }

    private Control BuildScanBar()
    {
        var box = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 7,
            RowCount = 3,
            AutoSize = true,
            BackColor = Theme.Panel,
            Padding = new Padding(10),
            Margin = new Padding(0, 0, 0, 10),
        };
        for (int i = 0; i < 6; i++) box.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        box.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        _type.DropDownStyle = ComboBoxStyle.DropDownList;
        _type.Items.AddRange(new object[]
        {
            "Int 32", "Int 64", "Float", "Double", "Text (UTF-8)", "Text (UTF-16)", "Bytes (hex)",
        });
        _type.SelectedIndex = 0;
        _type.Width = 120;
        _type.BackColor = Theme.Field;
        _type.ForeColor = Theme.Text;
        _type.FlatStyle = FlatStyle.Flat;
        _type.Margin = new Padding(0, 0, 8, 0);
        box.Controls.Add(_type, 0, 0);

        _value.Width = 220;
        _value.BackColor = Theme.Field;
        _value.ForeColor = Theme.Text;
        _value.BorderStyle = BorderStyle.FixedSingle;
        _value.Font = Theme.Mono;
        _value.PlaceholderText = "value to find";
        _value.Margin = new Padding(0, 0, 8, 0);
        box.Controls.Add(_value, 1, 0);

        _firstScan.Text = "First Scan";
        _firstScan.Width = 100;
        StyleButton(_firstScan, primary: true);
        box.Controls.Add(_firstScan, 2, 0);

        _nextScan.Text = "Next Scan";
        _nextScan.Width = 100;
        _nextScan.Enabled = false;
        StyleButton(_nextScan, primary: false);
        box.Controls.Add(_nextScan, 3, 0);

        _reset.Text = "Reset";
        _reset.Width = 76;
        StyleButton(_reset, primary: false);
        box.Controls.Add(_reset, 4, 0);

        _progress.Width = 180;
        _progress.Height = 28;
        _progress.Style = ProgressBarStyle.Continuous;
        _progress.Margin = new Padding(12, 1, 0, 0);
        box.Controls.Add(_progress, 5, 0);

        _consoleMode.Text = "Console mode";
        _consoleMode.Width = 120;
        _consoleMode.Anchor = AnchorStyles.Right;
        StyleButton(_consoleMode, primary: false);
        _consoleMode.Margin = new Padding(12, 0, 0, 0);
        box.Controls.Add(_consoleMode, 6, 0);

        // --- second row: finding a value you cannot name ---
        var unknownRow = new FlowLayoutPanel
        {
            AutoSize = true, BackColor = Theme.Panel, Margin = new Padding(0, 10, 0, 0),
            WrapContents = false,
        };

        unknownRow.Controls.Add(new Label
        {
            Text = "Don't know the number?",
            ForeColor = Theme.Muted, AutoSize = true, Margin = new Padding(0, 7, 8, 0),
        });

        _unknownScan.Text = "Snapshot";
        _unknownScan.Width = 96;
        StyleButton(_unknownScan, primary: false);
        unknownRow.Controls.Add(_unknownScan);

        _delta.DropDownStyle = ComboBoxStyle.DropDownList;
        _delta.Items.AddRange(new object[]
        {
            "changed", "did not change", "went up", "went down", "went up by", "went down by",
        });
        _delta.SelectedIndex = 3;
        _delta.Width = 130;
        _delta.BackColor = Theme.Field;
        _delta.ForeColor = Theme.Text;
        _delta.FlatStyle = FlatStyle.Flat;
        _delta.Enabled = false;
        _delta.Margin = new Padding(0, 1, 8, 0);
        unknownRow.Controls.Add(_delta);

        _deltaAmount.Width = 90;
        _deltaAmount.BackColor = Theme.Field;
        _deltaAmount.ForeColor = Theme.Text;
        _deltaAmount.BorderStyle = BorderStyle.FixedSingle;
        _deltaAmount.Font = Theme.Mono;
        _deltaAmount.PlaceholderText = "amount";
        _deltaAmount.Enabled = false;
        _deltaAmount.Margin = new Padding(0, 2, 8, 0);
        unknownRow.Controls.Add(_deltaAmount);

        _applyDelta.Text = "Filter";
        _applyDelta.Width = 90;
        _applyDelta.Enabled = false;
        StyleButton(_applyDelta, primary: true);
        unknownRow.Controls.Add(_applyDelta);

        _deltaInfo.Text = "";
        _deltaInfo.ForeColor = Theme.Muted;
        _deltaInfo.AutoSize = true;
        _deltaInfo.Margin = new Padding(4, 7, 0, 0);
        unknownRow.Controls.Add(_deltaInfo);

        box.SetColumnSpan(unknownRow, 7);
        box.Controls.Add(unknownRow, 0, 1);

        var hint = new Label
        {
            Text = "Know it: scan the value, change it in-app, Next Scan.        " +
                   "Don't know it: Snapshot, do the thing in-app, then Filter (e.g. spend 50 -> \"went down by\" 50).",
            ForeColor = Theme.Muted,
            AutoSize = true,
            Margin = new Padding(0, 10, 0, 0),
        };
        box.SetColumnSpan(hint, 7);
        box.Controls.Add(hint, 0, 2);

        return box;
    }

    private Control BuildResultsSplit()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterDistance = 430,
            BackColor = Theme.Bg,
        };

        _grid.Dock = DockStyle.Fill;
        _grid.VirtualMode = true;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.MultiSelect = true;   // ctrl+click or shift+click to watch several at once
        _grid.BackgroundColor = Theme.Field;
        _grid.BorderStyle = BorderStyle.FixedSingle;
        _grid.GridColor = Theme.Border;
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        _grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Panel;
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        _grid.DefaultCellStyle.BackColor = Theme.Field;
        _grid.DefaultCellStyle.ForeColor = Theme.Text;
        _grid.DefaultCellStyle.SelectionBackColor = Theme.Accent;
        _grid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _grid.DefaultCellStyle.Font = Theme.Mono;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", Width = 180 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = "Value (live)",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
        });

        var resultsPane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Bg,
        };
        resultsPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        resultsPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        resultsPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        resultsPane.Controls.Add(SectionLabel("SCAN RESULTS"), 0, 0);
        resultsPane.Controls.Add(_grid, 0, 1);

        var resultBtns = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Bg,
            Margin = new Padding(0, 6, 0, 0),
        };
        _addWatch.Text = "Add to watch";
        _addWatch.Width = 120;
        StyleButton(_addWatch, primary: true);
        resultBtns.Controls.Add(_addWatch);

        _writeAll.Text = "Write value to all results";
        _writeAll.Width = 190;
        StyleButton(_writeAll, primary: false);
        resultBtns.Controls.Add(_writeAll);
        resultsPane.Controls.Add(resultBtns, 0, 2);

        split.Panel1.Controls.Add(resultsPane);
        split.Panel2.Controls.Add(BuildWatchAndDump());
        return split;
    }

    private Control BuildWatchAndDump()
    {
        _rightSplit.Dock = DockStyle.Fill;
        _rightSplit.Orientation = Orientation.Horizontal;
        _rightSplit.BackColor = Theme.Border;
        _rightSplit.SplitterWidth = 8;

        // --- watch list ---
        var watchPane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Bg,
        };
        watchPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        watchPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        watchPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        watchPane.Controls.Add(SectionLabel("WATCH LIST  -  edit the Value cell, tick Freeze to hold it"), 0, 0);

        _watchGrid.Dock = DockStyle.Fill;
        _watchGrid.VirtualMode = true;
        _watchGrid.AllowUserToAddRows = false;
        _watchGrid.AllowUserToResizeRows = false;
        _watchGrid.RowHeadersVisible = false;
        _watchGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _watchGrid.BackgroundColor = Theme.Field;
        _watchGrid.BorderStyle = BorderStyle.FixedSingle;
        _watchGrid.GridColor = Theme.Border;
        _watchGrid.EnableHeadersVisualStyles = false;
        _watchGrid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _watchGrid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        _watchGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Panel;
        _watchGrid.DefaultCellStyle.BackColor = Theme.Field;
        _watchGrid.DefaultCellStyle.ForeColor = Theme.Text;
        _watchGrid.DefaultCellStyle.SelectionBackColor = Theme.Accent;
        _watchGrid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _watchGrid.DefaultCellStyle.Font = Theme.Mono;

        _watchGrid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Address", Width = 160, ReadOnly = true });
        _watchGrid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Type", Width = 70, ReadOnly = true });
        _watchGrid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Value", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _watchGrid.Columns.Add(new DataGridViewCheckBoxColumn
        { HeaderText = "Freeze", Width = 56 });
        _watchGrid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Writes", Width = 60, ReadOnly = true });
        watchPane.Controls.Add(_watchGrid, 0, 1);

        var watchBtns = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Bg,
            Margin = new Padding(0, 6, 0, 0), WrapContents = false,
        };

        _dropWatch.Text = "Remove selected";
        _dropWatch.Width = 140;
        StyleButton(_dropWatch, primary: false);
        watchBtns.Controls.Add(_dropWatch);

        _logging.Text = "Log changes";
        _logging.Checked = true;
        _logging.ForeColor = Theme.Text;
        _logging.AutoSize = true;
        _logging.Margin = new Padding(12, 6, 8, 0);
        watchBtns.Controls.Add(_logging);

        _clearLog.Text = "Clear log";
        _clearLog.Width = 90;
        StyleButton(_clearLog, primary: false);
        watchBtns.Controls.Add(_clearLog);

        watchBtns.Controls.Add(new Label
        {
            Text = "Check every", ForeColor = Theme.Muted,
            AutoSize = true, Margin = new Padding(12, 7, 6, 0),
        });

        _rate.DropDownStyle = ComboBoxStyle.DropDownList;
        _rate.Items.AddRange(new object[] { "100 ms", "250 ms", "500 ms", "1 second", "2 seconds" });
        _rate.SelectedIndex = 2;
        _rate.Width = 90;
        _rate.BackColor = Theme.Field;
        _rate.ForeColor = Theme.Text;
        _rate.FlatStyle = FlatStyle.Flat;
        _rate.Margin = new Padding(0, 2, 8, 0);
        watchBtns.Controls.Add(_rate);

        _monitorCost.ForeColor = Theme.Muted;
        _monitorCost.AutoSize = true;
        _monitorCost.Margin = new Padding(0, 7, 0, 0);
        watchBtns.Controls.Add(_monitorCost);

        watchPane.Controls.Add(watchBtns, 0, 2);
        _rightSplit.Panel1.Controls.Add(watchPane);

        // --- bottom: hex dump and change log share the space as tabs ---
        _tabs.Dock = DockStyle.Fill;
        _tabs.Appearance = TabAppearance.FlatButtons;
        _tabs.ItemSize = new Size(90, 24);
        _tabs.SizeMode = TabSizeMode.Fixed;

        _dump.Dock = DockStyle.Fill;
        _dump.ReadOnly = true;
        _dump.BackColor = Theme.Field;
        _dump.ForeColor = Theme.Text;
        _dump.BorderStyle = BorderStyle.None;
        _dump.Font = Theme.Mono;
        _dump.WordWrap = false;
        _dump.Text = "  Select a result to dump the bytes around it.";

        var dumpTab = new TabPage("Hex dump") { BackColor = Theme.Field, Padding = new Padding(2) };
        dumpTab.Controls.Add(_dump);

        _log.Dock = DockStyle.Fill;
        _log.BackColor = Theme.Field;
        _log.ForeColor = Theme.Text;
        _log.BorderStyle = BorderStyle.None;
        _log.Font = Theme.Mono;
        _log.IntegralHeight = false;
        _log.HorizontalScrollbar = true;
        _log.Items.Add("  Add an address to the watch list - every write to it lands here.");

        var logTab = new TabPage("Change log") { BackColor = Theme.Field, Padding = new Padding(2) };
        logTab.Controls.Add(_log);

        _tabs.TabPages.Add(dumpTab);
        _tabs.TabPages.Add(logTab);
        _tabs.TabPages.Add(BuildPointerTab());
        _tabs.TabPages.Add(BuildCorrelateTab());
        _tabs.TabPages.Add(BuildJournalTab());
        _tabs.TabPages.Add(BuildDisassemblyTab());
        _rightSplit.Panel2.Controls.Add(_tabs);

        return _rightSplit;
    }

    private TabPage BuildPointerTab()
    {
        var page = new TabPage("Pointers") { BackColor = Theme.Field, Padding = new Padding(2) };

        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Theme.Field,
        };
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _chainList.Dock = DockStyle.Fill;
        _chainList.BackColor = Theme.Field;
        _chainList.ForeColor = Theme.Text;
        _chainList.BorderStyle = BorderStyle.None;
        _chainList.Font = Theme.Mono;
        _chainList.HorizontalScrollbar = true;
        _chainList.IntegralHeight = false;
        _chainList.Items.Add("  Pick a watch row, then Find chains.");
        _chainList.Items.Add("  A chain starts at a module and still works after a restart.");
        pane.Controls.Add(_chainList, 0, 0);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Field,
            Margin = new Padding(0, 4, 0, 0), WrapContents = false,
        };

        _findPtr.Text = "Find chains";
        _findPtr.Width = 110;
        StyleButton(_findPtr, primary: true);
        buttons.Controls.Add(_findPtr);

        _resolvePtr.Text = "Resolve -> watch";
        _resolvePtr.Width = 140;
        StyleButton(_resolvePtr, primary: false);
        buttons.Controls.Add(_resolvePtr);

        _savePtr.Text = "Save";
        _savePtr.Width = 70;
        StyleButton(_savePtr, primary: false);
        buttons.Controls.Add(_savePtr);

        _loadPtr.Text = "Load";
        _loadPtr.Width = 70;
        StyleButton(_loadPtr, primary: false);
        buttons.Controls.Add(_loadPtr);

        pane.Controls.Add(buttons, 0, 1);
        page.Controls.Add(pane);
        return page;
    }

    private TabPage BuildCorrelateTab()
    {
        var page = new TabPage("Correlate") { BackColor = Theme.Field, Padding = new Padding(2) };

        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, BackColor = Theme.Field,
        };
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var intro = new Label
        {
            Text = "Don't know which candidate is right? Start a capture, alt-tab to the game, " +
                   "press F8 the instant something happens (took damage, bought an item) a few " +
                   "times, then Stop. The address that changed near every press - and nowhere " +
                   "else - is ranked first.",
            ForeColor = Theme.Muted,
            AutoSize = false,
            Dock = DockStyle.Fill,
            Height = 48,
        };
        pane.Controls.Add(intro, 0, 0);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Field,
            Margin = new Padding(0, 6, 0, 6), WrapContents = false,
        };

        _corrStart.Text = "Start capture";
        _corrStart.Width = 110;
        StyleButton(_corrStart, primary: true);
        buttons.Controls.Add(_corrStart);

        _corrMark.Text = "Mark  (F8)";
        _corrMark.Width = 100;
        _corrMark.Enabled = false;
        StyleButton(_corrMark, primary: false);
        buttons.Controls.Add(_corrMark);

        _corrStop.Text = "Stop && rank";
        _corrStop.Width = 100;
        _corrStop.Enabled = false;
        StyleButton(_corrStop, primary: false);
        buttons.Controls.Add(_corrStop);

        _corrStatus.Text = "Get some results (First Scan or Snapshot+Filter), then Start capture.";
        _corrStatus.ForeColor = Theme.Muted;
        _corrStatus.AutoSize = true;
        _corrStatus.Margin = new Padding(12, 7, 0, 0);
        buttons.Controls.Add(_corrStatus);

        pane.Controls.Add(buttons, 0, 1);

        _corrGrid.Dock = DockStyle.Fill;
        _corrGrid.VirtualMode = true;
        _corrGrid.ReadOnly = true;
        _corrGrid.AllowUserToAddRows = false;
        _corrGrid.RowHeadersVisible = false;
        _corrGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _corrGrid.MultiSelect = true;
        _corrGrid.BackgroundColor = Theme.Field;
        _corrGrid.BorderStyle = BorderStyle.FixedSingle;
        _corrGrid.GridColor = Theme.Border;
        _corrGrid.EnableHeadersVisualStyles = false;
        _corrGrid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _corrGrid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        _corrGrid.DefaultCellStyle.BackColor = Theme.Field;
        _corrGrid.DefaultCellStyle.ForeColor = Theme.Text;
        _corrGrid.DefaultCellStyle.SelectionBackColor = Theme.Accent;
        _corrGrid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _corrGrid.DefaultCellStyle.Font = Theme.Mono;
        _corrGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", Width = 160 });
        _corrGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Hits", Width = 70 });
        _corrGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Noise", Width = 70 });
        pane.Controls.Add(_corrGrid, 0, 2);

        _corrAddToWatch.Text = "Add selected to watch";
        _corrAddToWatch.Width = 160;
        _corrAddToWatch.Enabled = false;
        StyleButton(_corrAddToWatch, primary: false);
        _corrAddToWatch.Margin = new Padding(0, 6, 0, 0);
        pane.Controls.Add(_corrAddToWatch, 0, 3);

        page.Controls.Add(pane);
        return page;
    }

    private static Label SectionLabel(string text) => new()
    {
        Text = text,
        ForeColor = Theme.Muted,
        Font = new Font("Segoe UI", 8F, FontStyle.Bold),
        AutoSize = true,
        Margin = new Padding(2, 0, 0, 2),
    };

    private static void StyleButton(Button b, bool primary)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.Height = 28;
        b.BackColor = primary ? Theme.Accent : Theme.Field;
        b.ForeColor = primary ? Color.Black : Theme.Text;
        b.FlatAppearance.BorderColor = Theme.Border;
        b.Margin = new Padding(0, 0, 8, 0);
        b.Cursor = Cursors.Hand;
    }

    // ---------------------------------------------------------------- events

    private void WireEvents()
    {
        _refreshBtn.Click += (_, _) => RefreshProcesses();
        _attachBtn.Click += (_, _) => AttachSelected();
        _filter.TextChanged += (_, _) => RefreshProcesses();
        _procList.DoubleClick += (_, _) => AttachSelected();
        _procList.ColumnClick += (_, e) => SortByColumn(e.Column);
        _procList.Resize += (_, _) => FitProcessColumns();
        _filter.KeyDown += (_, e) =>
        {
            // Enter in the filter box attaches to the only remaining match.
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            if (_procList.Items.Count > 0)
            {
                _procList.Items[0].Selected = true;
                AttachSelected();
            }
        };
        _firstScan.Click += async (_, _) => await RunScan(first: true);
        _nextScan.Click += async (_, _) => await RunScan(first: false);
        _reset.Click += (_, _) => ResetResults();
        _value.KeyDown += async (_, e) =>
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            await RunScan(first: !_nextScan.Enabled);
        };

        _grid.CellValueNeeded += OnCellValueNeeded;
        _grid.SelectionChanged += (_, _) => ShowDump();

        _consoleMode.Click += (_, _) => SwitchToConsole();
        _disasmGo.Click += (_, _) => RunDisassembly();
        _disasmAddr.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; RunDisassembly(); } };

        _journalGrid.CellValueNeeded += OnJournalValueNeeded;
        _undoSelected.Click += (_, _) => UndoSelectedWrite();
        _undoAll.Click += (_, _) => UndoAllWrites();

        _corrStart.Click += (_, _) => StartCorrelation();
        _corrMark.Click += (_, _) => MarkCorrelationEvent();
        _corrStop.Click += (_, _) => StopCorrelation();
        _corrAddToWatch.Click += (_, _) => AddCorrelationSelectionToWatch();
        _corrGrid.CellValueNeeded += OnCorrGridValueNeeded;

        _findPtr.Click += async (_, _) => await FindPointerChains();
        _resolvePtr.Click += (_, _) => ResolveChainsToWatch();
        _savePtr.Click += (_, _) => SaveChains();
        _loadPtr.Click += (_, _) => LoadChains();
        _unknownScan.Click += async (_, _) => await TakeSnapshot();
        _applyDelta.Click += async (_, _) => await ApplyDeltaFilter();
        _delta.SelectedIndexChanged += (_, _) => SyncDeltaControls();

        _addWatch.Click += (_, _) => AddSelectedToWatch();
        _writeAll.Click += (_, _) => WriteValueToAllResults();
        _dropWatch.Click += (_, _) => RemoveSelectedWatch();
        _grid.CellDoubleClick += (_, _) => AddSelectedToWatch();

        _watchGrid.CellValueNeeded += OnWatchValueNeeded;
        _watchGrid.CellValuePushed += OnWatchValuePushed;
        // Checkbox edits only commit on focus loss otherwise, which feels broken.
        _watchGrid.CurrentCellDirtyStateChanged += (_, _) =>
        {
            if (_watchGrid.IsCurrentCellDirty && _watchGrid.CurrentCell?.ColumnIndex == 3)
                _watchGrid.CommitEdit(DataGridViewDataErrorContexts.Commit);
        };
        _watchGrid.DataError += (_, e) => e.ThrowException = false;
        // Rows that moved in the last second glow, so a change is visible at a glance.
        _watchGrid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || e.RowIndex >= _watch.Count || e.CellStyle is null) return;
            var w = _watch[e.RowIndex];
            bool fresh = w.ChangedAt != default && (DateTime.Now - w.ChangedAt).TotalSeconds < 1.0;
            e.CellStyle.ForeColor = fresh ? Theme.Good : Theme.Text;
        };
        _watchGrid.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Delete) { RemoveSelectedWatch(); e.Handled = true; }
        };
        _watchGrid.ColumnHeaderMouseClick += (_, e) => SortWatchList(e.ColumnIndex);

        _live.Interval = 800;
        _live.Tick += (_, _) =>
        {
            if (_results.Count > 0) _grid.Invalidate();
            // Don't repaint a cell mid-edit or the user's typing is wiped out.
            if (_watch.Count > 0 && !_watchGrid.IsCurrentCellInEditMode) _watchGrid.Invalidate();
        };
        _live.Start();

        _freeze.Interval = 100;
        _freeze.Tick += (_, _) => ApplyFrozen();
        _freeze.Start();

        _clearLog.Click += (_, _) => { _log.Items.Clear(); };
        _rate.SelectedIndexChanged += (_, _) => TuneMonitorRate();
        _monitor.Interval = 500;
        _monitor.Tick += (_, _) => MonitorWatched();
        _monitor.Start();

        FormClosed += (_, _) =>
        {
            _live.Stop(); _freeze.Stop(); _monitor.Stop();
            if (_hotkeyRegistered) Native.UnregisterHotKey(Handle, MarkHotkeyId);
            _correlation?.Dispose();
            _target?.Dispose();
        };
    }

    private void RefreshProcesses()
    {
        string filter = _filter.Text.Trim();
        int selectedPid = _procList.SelectedItems.Count > 0 ? (int)_procList.SelectedItems[0].Tag! : -1;

        _procList.BeginUpdate();
        _procList.Items.Clear();
        int total = 0;

        foreach (var p in Process.GetProcesses())
        {
            total++;
            if (filter.Length > 0 && !p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                p.Dispose();
                continue;
            }

            long bytes;
            try { bytes = p.WorkingSet64; } catch { bytes = 0; }
            string ram = bytes > 0 ? $"{bytes / 1024 / 1024:N0} MB" : "-";

            var item = new ListViewItem(new[] { p.ProcessName, p.Id.ToString(), ram }) { Tag = p.Id };
            item.SubItems[2].Tag = bytes; // keep the raw size so sorting is numeric, not textual
            _procList.Items.Add(item);
            if (p.Id == selectedPid) item.Selected = true;
            p.Dispose();
        }

        _procList.ListViewItemSorter = new ProcessSorter(_sortColumn, _sortOrder);
        _procList.Sort();
        _procList.EndUpdate();
        FitProcessColumns();

        _procCount.Text = filter.Length > 0
            ? $"{_procList.Items.Count} of {total}"
            : $"{total}";
    }

    private void SortByColumn(int column)
    {
        if (column == _sortColumn)
            _sortOrder = _sortOrder == SortOrder.Ascending ? SortOrder.Descending : SortOrder.Ascending;
        else
        {
            _sortColumn = column;
            _sortOrder = column == 0 ? SortOrder.Ascending : SortOrder.Descending;
        }

        _procList.ListViewItemSorter = new ProcessSorter(_sortColumn, _sortOrder);
        _procList.Sort();
    }

    /// <summary>Sorts names as text, PID and RAM as numbers.</summary>
    private sealed class ProcessSorter(int column, SortOrder order) : System.Collections.IComparer
    {
        public int Compare(object? x, object? y)
        {
            if (x is not ListViewItem a || y is not ListViewItem b) return 0;

            int cmp = column switch
            {
                1 => ((int)a.Tag!).CompareTo((int)b.Tag!),
                2 => ((long)(a.SubItems[2].Tag ?? 0L)).CompareTo((long)(b.SubItems[2].Tag ?? 0L)),
                _ => string.Compare(a.Text, b.Text, StringComparison.OrdinalIgnoreCase),
            };
            return order == SortOrder.Descending ? -cmp : cmp;
        }
    }

    private void AttachSelected()
    {
        if (_procList.SelectedItems.Count == 0) return;
        int pid = (int)_procList.SelectedItems[0].Tag!;

        try
        {
            // A capture polling the old handle must stop before that handle closes,
            // or its background loop reads through a disposed ProcessMemory.
            if (_correlation is not null) StopCorrelation();

            _target?.Dispose();
            _target = ProcessMemory.Open(pid);
            ResetResults();
            _watch.Clear();
            _ptrScan = null;
            _watchOrderStale = true;
            TuneMonitorRate();
            _watchGrid.RowCount = 0;
            _corrResults = new List<CorrelationResult>();
            _corrGrid.RowCount = 0;
            _corrAddToWatch.Enabled = false;
            _journal.Clear();
            _journalGrid.RowCount = 0;

            _attached.Text = $"Attached to {_target.Process.ProcessName}  (PID {_target.Process.Id}, " +
                             $"{(_target.Is32Bit ? "32-bit" : "64-bit")})  -  " +
                             (_target.CanWrite ? "read / write" : "READ-ONLY (no write access)");
            _attached.ForeColor = _target.CanWrite ? Theme.Good : Theme.Warn;
            SetStatus("Ready. Enter a value and hit First Scan.", Theme.Muted);
        }
        catch (Exception ex)
        {
            _target = null;
            _attached.Text = "Not attached";
            _attached.ForeColor = Theme.Muted;
            SetStatus(ex.Message, Theme.Warn);
        }
    }

    private async Task RunScan(bool first)
    {
        if (_target is null) { SetStatus("Attach to a process first.", Theme.Warn); return; }
        if (_value.Text.Length == 0) { SetStatus("Enter a value to search for.", Theme.Warn); return; }
        if (!first && _results.Count == 0) { SetStatus("Nothing to narrow - run First Scan.", Theme.Warn); return; }

        Needle needle;
        try
        {
            needle = Needle.Parse(first ? SelectedKind() : _lastKind, _value.Text.Trim());
        }
        catch (Exception ex)
        {
            SetStatus($"Cannot read that value: {ex.Message}", Theme.Warn);
            return;
        }

        var mem = _target;
        SetScanning(true);
        var sw = Stopwatch.StartNew();

        try
        {
            if (first)
            {
                // Total readable bytes gives the progress bar something honest to divide by.
                long total = await Task.Run(() => mem.Regions().Sum(r => r.RegionSize.ToInt64()));
                _progress.Maximum = 1000;

                var hits = await Task.Run(() => Scanner.FirstScan(mem, needle, done =>
                {
                    int pct = total > 0 ? (int)Math.Min(1000, done * 1000 / total) : 0;
                    _progress.BeginInvoke(() => _progress.Value = pct);
                }));

                _results = hits;
                _lastKind = needle.Kind;
                _lastSize = needle.Size;
            }
            else
            {
                var snapshot = _results;
                _results = await Task.Run(() => Scanner.Refine(mem, snapshot, needle));
                _lastSize = needle.Size;
            }

            sw.Stop();
            ShowResults();
            SetStatus($"{_results.Count:N0} match(es) for {needle.Display} in {sw.ElapsedMilliseconds:N0} ms" +
                      (_results.Count > 1
                          ? "  -  change the value in the target, then Next Scan to narrow it."
                          : ""),
                      Theme.Muted);
        }
        catch (Exception ex)
        {
            SetStatus($"Scan failed: {ex.Message}", Theme.Warn);
        }
        finally
        {
            SetScanning(false);
        }
    }

    private void SetScanning(bool on)
    {
        _firstScan.Enabled = !on;
        _reset.Enabled = !on;
        _nextScan.Enabled = !on && _results.Count > 0;
        _procList.Enabled = !on;
        _writeAll.Enabled = !on;
        _unknownScan.Enabled = !on;
        _findPtr.Enabled = !on;
        _applyDelta.Enabled = !on && _deltaScan is not null;
        _progress.Visible = on;
        _progress.Value = 0;
        if (on) SetStatus("Scanning...", Theme.Accent);
    }

    private void ResetResults()
    {
        _results = new List<IntPtr>();
        _deltaScan = null;
        _delta.Enabled = _applyDelta.Enabled = _deltaAmount.Enabled = false;
        _deltaInfo.Text = "";
        ShowResults();
        _dump.Text = "  Select a result to dump the bytes around it.";
        SetStatus("Results cleared.", Theme.Muted);
    }

    private void ShowResults()
    {
        // The grid is virtual, so it only ever asks for the rows actually on screen.
        _grid.RowCount = Math.Min(_results.Count, 50_000);
        _grid.Invalidate();
        _nextScan.Enabled = _results.Count > 0;
        if (_grid.RowCount > 0) ShowDump();
    }

    private void OnCellValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _results.Count) return;
        var addr = _results[e.RowIndex];
        e.Value = e.ColumnIndex == 0
            ? $"{addr.ToInt64():X16}"
            : ReadAsText(addr);
    }

    /// <summary>Re-reads an address live, so the grid reflects the target as it runs.</summary>
    private string ReadAsText(IntPtr addr)
    {
        if (_target is null) return "-";
        var data = _target.Read(addr, _lastSize);
        if (data is null) return "<unreadable>";

        return _lastKind switch
        {
            ValueKind.Int32 => BitConverter.ToInt32(data).ToString(),
            ValueKind.Int64 => BitConverter.ToInt64(data).ToString(),
            ValueKind.Float => BitConverter.ToSingle(data).ToString(CultureInfo.InvariantCulture),
            ValueKind.Double => BitConverter.ToDouble(data).ToString(CultureInfo.InvariantCulture),
            ValueKind.Utf8 => Encoding.UTF8.GetString(data),
            ValueKind.Utf16 => Encoding.Unicode.GetString(data),
            _ => BitConverter.ToString(data).Replace('-', ' '),
        };
    }

    // -------------------------------------------------------------- console mode

    /// <summary>
    /// Hands over to the console build and closes this window. The attached PID goes
    /// with it, so the session continues rather than starting from nothing.
    /// </summary>
    private void SwitchToConsole()
    {
        var exe = FindConsoleExe();
        if (exe is null)
        {
            SetStatus("Could not find MemReader.exe next to this app.", Theme.Warn);
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = _target is null ? "" : _target.Process.Id.ToString(),
                UseShellExecute = true, // gives it its own console window
            });
            Close();
        }
        catch (Exception ex)
        {
            SetStatus($"Could not start console mode: {ex.Message}", Theme.Warn);
        }
    }

    /// <summary>Looks beside the app first, then in the sibling project's output.</summary>
    private static string? FindConsoleExe()
    {
        string here = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(here, "MemReader.exe"),
            Path.GetFullPath(Path.Combine(here, "..", "..", "MemReader", "dist", "MemReader.exe")),
            Path.GetFullPath(Path.Combine(here, "..", "..", "..", "..", "MemReader", "dist", "MemReader.exe")),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private TabPage BuildDisassemblyTab()
    {
        var page = new TabPage("Disassembly") { BackColor = Theme.Field, Padding = new Padding(2) };

        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Field,
        };
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var row = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Field, WrapContents = false,
        };

        row.Controls.Add(new Label
        {
            Text = "Address", ForeColor = Theme.Muted, AutoSize = true, Margin = new Padding(0, 7, 6, 0),
        });

        _disasmAddr.Width = 160;
        _disasmAddr.BackColor = Theme.Field;
        _disasmAddr.ForeColor = Theme.Text;
        _disasmAddr.BorderStyle = BorderStyle.FixedSingle;
        _disasmAddr.Font = Theme.Mono;
        _disasmAddr.PlaceholderText = "0x7ff6...";
        _disasmAddr.Margin = new Padding(0, 2, 8, 0);
        row.Controls.Add(_disasmAddr);

        _disasmGo.Text = "Disassemble";
        _disasmGo.Width = 100;
        StyleButton(_disasmGo, primary: true);
        row.Controls.Add(_disasmGo);

        pane.Controls.Add(row, 0, 0);

        _disasmOutput.Dock = DockStyle.Fill;
        _disasmOutput.ReadOnly = true;
        _disasmOutput.BackColor = Theme.Field;
        _disasmOutput.ForeColor = Theme.Text;
        _disasmOutput.BorderStyle = BorderStyle.FixedSingle;
        _disasmOutput.Font = Theme.Mono;
        _disasmOutput.WordWrap = false;
        _disasmOutput.Text = "  Type a code address (from the hex dump, or a module base + offset) " +
                             "and click Disassemble to see the actual instructions there.";
        pane.Controls.Add(_disasmOutput, 0, 1);

        _disasmStatus.ForeColor = Theme.Muted;
        _disasmStatus.AutoSize = true;
        _disasmStatus.Margin = new Padding(0, 6, 0, 0);
        pane.Controls.Add(_disasmStatus, 0, 2);

        page.Controls.Add(pane);
        return page;
    }

    private TabPage BuildJournalTab()
    {
        var page = new TabPage("Write journal") { BackColor = Theme.Field, Padding = new Padding(2) };

        var pane = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Field,
        };
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        pane.Controls.Add(new Label
        {
            Text = "Every manual edit and \"write to all results\" lands here. Freeze corrects " +
                   "itself many times a second and isn't logged - untick it to stop that instead.",
            ForeColor = Theme.Muted, AutoSize = false, Dock = DockStyle.Fill, Height = 34,
        }, 0, 0);

        _journalGrid.Dock = DockStyle.Fill;
        _journalGrid.VirtualMode = true;
        _journalGrid.ReadOnly = true;
        _journalGrid.AllowUserToAddRows = false;
        _journalGrid.RowHeadersVisible = false;
        _journalGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _journalGrid.MultiSelect = false;
        _journalGrid.BackgroundColor = Theme.Field;
        _journalGrid.BorderStyle = BorderStyle.FixedSingle;
        _journalGrid.GridColor = Theme.Border;
        _journalGrid.EnableHeadersVisualStyles = false;
        _journalGrid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _journalGrid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        _journalGrid.DefaultCellStyle.BackColor = Theme.Field;
        _journalGrid.DefaultCellStyle.ForeColor = Theme.Text;
        _journalGrid.DefaultCellStyle.SelectionBackColor = Theme.Accent;
        _journalGrid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _journalGrid.DefaultCellStyle.Font = Theme.Mono;
        _journalGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "When", Width = 80 });
        _journalGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", Width = 150 });
        _journalGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Before", Width = 110 });
        _journalGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "After", Width = 110 });
        _journalGrid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Source", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        pane.Controls.Add(_journalGrid, 0, 1);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, BackColor = Theme.Field,
            Margin = new Padding(0, 6, 0, 0), WrapContents = false,
        };

        _undoSelected.Text = "Undo selected";
        _undoSelected.Width = 110;
        StyleButton(_undoSelected, primary: true);
        buttons.Controls.Add(_undoSelected);

        _undoAll.Text = "Undo all";
        _undoAll.Width = 90;
        StyleButton(_undoAll, primary: false);
        buttons.Controls.Add(_undoAll);

        _journalStatus.ForeColor = Theme.Muted;
        _journalStatus.AutoSize = true;
        _journalStatus.Margin = new Padding(12, 7, 0, 0);
        buttons.Controls.Add(_journalStatus);

        pane.Controls.Add(buttons, 0, 2);
        page.Controls.Add(pane);
        return page;
    }

    // ------------------------------------------------------------- disassembly

    private void RunDisassembly()
    {
        if (_target is null) { SetDisasmStatus("Attach to a process first.", Theme.Warn); return; }

        string text = _disasmAddr.Text.Trim();
        if (text.Length == 0) { SetDisasmStatus("Enter an address.", Theme.Warn); return; }

        ulong addr;
        try
        {
            text = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text;
            addr = ulong.Parse(text, System.Globalization.NumberStyles.HexNumber);
        }
        catch (Exception)
        {
            SetDisasmStatus("That doesn't look like a hex address.", Theme.Warn);
            return;
        }

        var lines = Disassembler.Decode(_target, (IntPtr)(long)addr, 40);
        if (lines.Count == 0)
        {
            _disasmOutput.Text = "  Could not read or decode at that address - it may not be committed, " +
                                 "or it may not be executable code.";
            SetDisasmStatus("No instructions decoded.", Theme.Warn);
            return;
        }

        var sb = new System.Text.StringBuilder();
        foreach (var l in lines)
            sb.AppendLine($"  {l.Address:X16}  {l.Bytes,-24}  {l.Text}");
        _disasmOutput.Text = sb.ToString();

        SetDisasmStatus($"{lines.Count} instruction(s) decoded.", Theme.Good);
    }

    private void SetDisasmStatus(string text, Color color)
    {
        _disasmStatus.Text = text;
        _disasmStatus.ForeColor = color;
    }

    // -------------------------------------------------------------- write journal

    private void OnJournalValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        // Newest first - the write you probably want to undo is the one you just made.
        int i = _journal.Entries.Count - 1 - e.RowIndex;
        if (i < 0 || i >= _journal.Entries.Count) return;
        var entry = _journal.Entries[i];

        e.Value = e.ColumnIndex switch
        {
            0 => entry.When.ToString("HH:mm:ss"),
            1 => $"{entry.Address.ToInt64():X16}",
            2 => BitConverter.ToString(entry.Before).Replace('-', ' '),
            3 => BitConverter.ToString(entry.After).Replace('-', ' '),
            _ => entry.Source,
        };
    }

    private void UndoSelectedWrite()
    {
        if (_target is null) { SetJournalStatus("Attach to a process first.", Theme.Warn); return; }
        if (_journalGrid.CurrentRow is not { Index: >= 0 } row) { SetJournalStatus("Select a row first.", Theme.Warn); return; }

        int i = _journal.Entries.Count - 1 - row.Index;
        if (i < 0 || i >= _journal.Entries.Count) return;
        var entry = _journal.Entries[i];

        SetJournalStatus(_journal.Undo(_target, entry)
            ? $"Reverted {entry.Address.ToInt64():X} to {BitConverter.ToString(entry.Before).Replace('-', ' ')}."
            : $"Undo failed for {entry.Address.ToInt64():X} - is the process still writable?",
            Theme.Good);
    }

    private void UndoAllWrites()
    {
        if (_target is null) { SetJournalStatus("Attach to a process first.", Theme.Warn); return; }
        if (_journal.Entries.Count == 0) { SetJournalStatus("Nothing to undo.", Theme.Muted); return; }

        int touched = _journal.Entries.Select(e => e.Address).Distinct().Count();
        int ok = _journal.UndoAll(_target);
        _journalGrid.RowCount = 0;
        _journalGrid.Invalidate();

        SetJournalStatus($"Reverted {ok} of {touched} address(es) to their pre-session state.",
            ok == touched ? Theme.Good : Theme.Warn);
    }

    private void SetJournalStatus(string text, Color color)
    {
        _journalStatus.Text = text;
        _journalStatus.ForeColor = color;
    }

    // ---------------------------------------------------------------- correlation

    /// <summary>Catches WM_HOTKEY so F8 marks an event even while another window has focus.</summary>
    protected override void WndProc(ref Message m)
    {
        if (m.Msg == Native.WM_HOTKEY && m.WParam.ToInt32() == MarkHotkeyId)
            MarkCorrelationEvent();
        base.WndProc(ref m);
    }

    private void StartCorrelation()
    {
        if (_target is null) { SetCorrStatus("Attach to a process first.", Theme.Warn); return; }
        if (_results.Count == 0) { SetCorrStatus("No candidates - run a scan first.", Theme.Warn); return; }
        if (_correlation is not null) { SetCorrStatus("Already capturing.", Theme.Warn); return; }
        if (!DeltaScan.Supports(_lastKind))
        {
            SetCorrStatus("Correlation needs a number type (Int 32/64, Float, Double).", Theme.Warn);
            return;
        }

        _hotkeyRegistered = Native.RegisterHotKey(Handle, MarkHotkeyId, Native.MOD_NOREPEAT, MarkHotkeyVk);

        _correlation = new CorrelationDetector(_target, _results, _lastSize);
        _correlation.StartCapture(SelectedPollInterval());

        _corrStart.Enabled = false;
        _corrMark.Enabled = true;
        _corrStop.Enabled = true;
        SetCorrStatus(_hotkeyRegistered
            ? $"Capturing {_results.Count:N0} candidate(s). Press F8 anywhere the instant the event happens."
            : $"Capturing {_results.Count:N0} candidate(s). F8 is taken by another app - use the Mark button instead.",
            Theme.Accent);
    }

    private void MarkCorrelationEvent()
    {
        if (_correlation is null) return;
        _correlation.Mark();
        SetCorrStatus($"Marked ({_correlation.MarkCount}) - {_correlation.TickCount:N0} samples so far.", Theme.Accent);
    }

    private void StopCorrelation()
    {
        if (_correlation is null) return;

        if (_hotkeyRegistered) { Native.UnregisterHotKey(Handle, MarkHotkeyId); _hotkeyRegistered = false; }

        var marks = _correlation.MarkCount;
        _corrResults = _correlation.StopAndScore();
        _correlation.Dispose();
        _correlation = null;

        _corrStart.Enabled = true;
        _corrMark.Enabled = false;
        _corrStop.Enabled = false;
        _corrAddToWatch.Enabled = _corrResults.Count > 0;

        _corrGrid.RowCount = Math.Min(_corrResults.Count, 500);
        _corrGrid.Invalidate();

        var best = _corrResults.FirstOrDefault();
        SetCorrStatus(best is null
            ? "No candidates scored."
            : $"{_corrResults.Count:N0} candidate(s) ranked against {marks} mark(s). " +
              $"Top: {best.Address.ToInt64():X} - hits {best.Hits}/{marks}, noise {best.NoiseChanges}.",
            Theme.Good);
    }

    private void OnCorrGridValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _corrResults.Count) return;
        var r = _corrResults[e.RowIndex];
        e.Value = e.ColumnIndex switch
        {
            0 => $"{r.Address.ToInt64():X16}",
            1 => $"{r.Hits}/{r.TotalMarks}",
            _ => r.NoiseChanges.ToString(),
        };
    }

    private void AddCorrelationSelectionToWatch()
    {
        var picked = _corrGrid.SelectedRows.Cast<DataGridViewRow>()
            .Select(r => r.Index)
            .Where(i => i >= 0 && i < _corrResults.Count)
            .ToList();
        if (picked.Count == 0) { SetCorrStatus("Select a row first.", Theme.Warn); return; }

        var known = _watch.Select(w => w.Address).ToHashSet();
        int added = 0;
        foreach (int i in picked)
        {
            var addr = _corrResults[i].Address;
            if (!known.Add(addr)) continue;
            _watch.Add(new WatchEntry { Address = addr, Kind = _lastKind, Size = _lastSize });
            added++;
        }

        _watchOrderStale = true;
        TuneMonitorRate();
        _watchGrid.RowCount = _watch.Count;
        _watchGrid.Invalidate();
        SetCorrStatus($"Added {added} address(es) to the watch list.", Theme.Muted);
    }

    private void SetCorrStatus(string text, Color color)
    {
        _corrStatus.Text = text;
        _corrStatus.ForeColor = color;
    }

    // ----------------------------------------------------------- pointer chains

    /// <summary>
    /// Finds durable routes to the selected watch address. The index is the costly part,
    /// so it is built once per attach and reused for every later search.
    /// </summary>
    private async Task FindPointerChains()
    {
        if (_target is null) { SetStatus("Attach to a process first.", Theme.Warn); return; }

        var row = _watchGrid.CurrentRow;
        if (row is null || row.Index < 0 || row.Index >= _watch.Count)
        {
            SetStatus("Select a row in the watch list first - chains are found for one address.", Theme.Warn);
            return;
        }

        var addr = _watch[row.Index].Address;
        var mem = _target;
        SetScanning(true);
        _progress.Style = ProgressBarStyle.Marquee;
        var sw = Stopwatch.StartNew();

        try
        {
            if (_ptrScan is null)
            {
                SetStatus("Indexing every pointer in the process (once per attach)...", Theme.Accent);
                var scanner = new PointerScanner(mem);
                await Task.Run(() => scanner.BuildIndex());
                _ptrScan = scanner;
            }

            SetStatus($"Searching for chains to {addr.ToInt64():X}...", Theme.Accent);
            var scan = _ptrScan;
            _chains = await Task.Run(() => scan.Find(addr));
            sw.Stop();

            ShowChains();
            _tabs.SelectedIndex = 2;
            SetStatus($"{_chains.Count:N0} chain(s) to {addr.ToInt64():X} in {sw.ElapsedMilliseconds:N0} ms " +
                      $"({_ptrScan.PointerCount:N0} pointers indexed). " +
                      "Save them, and after a restart use Load then Resolve.",
                      _chains.Count > 0 ? Theme.Good : Theme.Warn);
        }
        catch (Exception ex)
        {
            SetStatus($"Pointer scan failed: {ex.Message}", Theme.Warn);
        }
        finally
        {
            _progress.Style = ProgressBarStyle.Continuous;
            SetScanning(false);
        }
    }

    private void ShowChains()
    {
        _chainList.BeginUpdate();
        _chainList.Items.Clear();
        foreach (var c in _chains.Take(300)) _chainList.Items.Add("  " + c);
        if (_chains.Count > 300) _chainList.Items.Add($"  ... {_chains.Count - 300:N0} more");
        if (_chains.Count == 0) _chainList.Items.Add("  No chains found - try a different address.");
        _chainList.EndUpdate();
    }

    /// <summary>
    /// Resolves chains against the process as it is now and watches whatever they land
    /// on. After a restart this is what turns a saved chain back into a live address.
    /// </summary>
    private void ResolveChainsToWatch()
    {
        if (_target is null || _chains.Count == 0)
        {
            SetStatus("Nothing to resolve - find or load chains first.", Theme.Warn);
            return;
        }

        _ptrScan ??= new PointerScanner(_target);

        var known = _watch.Select(w => w.Address).ToHashSet();
        int added = 0, broken = 0;

        foreach (var chain in _chains.Take(50))
        {
            var addr = _ptrScan.Resolve(chain);
            if (addr is null) { broken++; continue; }
            if (!known.Add(addr.Value)) continue;

            _watch.Add(new WatchEntry { Address = addr.Value, Kind = _lastKind, Size = _lastSize });
            added++;
        }

        _watchOrderStale = true;
        TuneMonitorRate();
        _watchGrid.RowCount = _watch.Count;
        _watchGrid.Invalidate();

        SetStatus($"Resolved {added} chain(s) onto the watch list" +
                  (broken > 0 ? $", {broken} no longer valid." : "."),
                  added > 0 ? Theme.Good : Theme.Warn);
    }

    private void SaveChains()
    {
        if (_chains.Count == 0) { SetStatus("No chains to save.", Theme.Warn); return; }

        using var dialog = new SaveFileDialog
        {
            Filter = "Pointer chains (*.chains)|*.chains|All files (*.*)|*.*",
            FileName = $"{_target?.Process.ProcessName ?? "target"}.chains",
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        File.WriteAllText(dialog.FileName, PointerScanner.Save(_chains));
        SetStatus($"Saved {_chains.Count:N0} chain(s) to {Path.GetFileName(dialog.FileName)}.", Theme.Good);
    }

    private void LoadChains()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Pointer chains (*.chains)|*.chains|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            _chains = PointerScanner.Load(File.ReadAllText(dialog.FileName));
            ShowChains();
            _tabs.SelectedIndex = 2;
            SetStatus($"Loaded {_chains.Count:N0} chain(s). Hit \"Resolve -> watch\" to turn them into addresses.",
                Theme.Good);
        }
        catch (Exception ex)
        {
            SetStatus($"Could not load chains: {ex.Message}", Theme.Warn);
        }
    }

    // ------------------------------------------------- unknown-value ("detector")

    /// <summary>
    /// Copies the target's private writable pages so later filters have something to
    /// compare against. This is the "I have no idea what the number is" starting point.
    /// </summary>
    private async Task TakeSnapshot()
    {
        if (_target is null) { SetStatus("Attach to a process first.", Theme.Warn); return; }

        var kind = SelectedKind();
        if (!DeltaScan.Supports(kind))
        {
            SetStatus("Unknown-value scans need a number type (Int 32/64, Float, Double).", Theme.Warn);
            return;
        }

        var mem = _target;
        SetScanning(true);
        SetStatus("Taking snapshot...", Theme.Accent);
        _progress.Style = ProgressBarStyle.Marquee;

        try
        {
            _deltaScan = await Task.Run(() => DeltaScan.Start(mem, kind));
            _lastKind = kind;
            _lastSize = _deltaScan.Size;

            _delta.Enabled = _applyDelta.Enabled = true;
            SyncDeltaControls();

            string extra = _deltaScan.SnapshotIncomplete ? "  (hit the 1 GB cap - very large target)" : "";
            _deltaInfo.Text = $"{_deltaScan.SnapshotBytes / 1024 / 1024:N0} MB captured";
            SetStatus($"Snapshot taken: {_deltaScan.SnapshotBytes / 1024 / 1024:N0} MB of private memory, " +
                      $"~{_deltaScan.Count:N0} candidates.{extra}  " +
                      "Now make the number change in the app, then pick a filter.", Theme.Good);
        }
        catch (Exception ex)
        {
            SetStatus($"Snapshot failed: {ex.Message}", Theme.Warn);
        }
        finally
        {
            _progress.Style = ProgressBarStyle.Continuous;
            SetScanning(false);
        }
    }

    private async Task ApplyDeltaFilter()
    {
        if (_deltaScan is null || _target is null) { SetStatus("Take a snapshot first.", Theme.Warn); return; }

        var (delta, needsAmount) = SelectedDelta();
        double amount = 0;

        if (needsAmount && !double.TryParse(_deltaAmount.Text.Trim(),
                NumberStyles.Float, CultureInfo.InvariantCulture, out amount))
        {
            SetStatus("Enter how much it changed by (e.g. 50).", Theme.Warn);
            return;
        }

        var scan = _deltaScan;
        SetScanning(true);
        _progress.Style = ProgressBarStyle.Marquee;
        var sw = Stopwatch.StartNew();

        try
        {
            await Task.Run(() => scan.Filter(delta, amount));
            sw.Stop();

            _results = scan.Addresses.ToList();
            _lastKind = scan.Kind;
            _lastSize = scan.Size;
            ShowResults();

            string capped = scan.Truncated
                ? $"  Stopped at {DeltaScan.MaxCandidates:N0} - use a sharper filter (\"went down by\") first."
                : "";
            _deltaInfo.Text = $"{_results.Count:N0} left";
            SetStatus($"{_results.Count:N0} address(es) survived \"{_delta.Text}\" in {sw.ElapsedMilliseconds:N0} ms." +
                      capped +
                      (_results.Count > 1 && !scan.Truncated
                          ? "  Change it again and filter once more to narrow further."
                          : ""),
                      _results.Count > 0 ? Theme.Good : Theme.Warn);
        }
        catch (Exception ex)
        {
            SetStatus($"Filter failed: {ex.Message}", Theme.Warn);
        }
        finally
        {
            _progress.Style = ProgressBarStyle.Continuous;
            SetScanning(false);
        }
    }

    private (Delta Delta, bool NeedsAmount) SelectedDelta() => _delta.SelectedIndex switch
    {
        0 => (Delta.Changed, false),
        1 => (Delta.Unchanged, false),
        2 => (Delta.Increased, false),
        3 => (Delta.Decreased, false),
        4 => (Delta.IncreasedBy, true),
        _ => (Delta.DecreasedBy, true),
    };

    private void SyncDeltaControls() => _deltaAmount.Enabled = _delta.Enabled && SelectedDelta().NeedsAmount;

    // ----------------------------------------------------------- watch + write

    private void AddSelectedToWatch()
    {
        if (_target is null || _results.Count == 0) return;

        var picked = _grid.SelectedRows.Cast<DataGridViewRow>()
            .Select(r => r.Index)
            .Where(i => i >= 0 && i < _results.Count)
            .ToList();
        if (picked.Count == 0 && _grid.CurrentRow is { Index: >= 0 } cur) picked.Add(cur.Index);
        if (picked.Count == 0) return;

        // Ctrl+A makes thousand-row adds routine, so membership has to be a set lookup.
        var known = _watch.Select(w => w.Address).ToHashSet();
        var incoming = picked.Select(i => _results[i]).Where(a => known.Add(a)).ToList();

        int room = MaxWatched - _watch.Count;
        if (room <= 0)
        {
            SetStatus($"Watch list is full ({MaxWatched:N0}). Remove some first.", Theme.Warn);
            return;
        }

        if (incoming.Count > room &&
            MessageBox.Show(this,
                $"Watching {room:N0} of the {incoming.Count:N0} selected addresses.\n\n" +
                $"The list caps at {MaxWatched:N0} so polling stays responsive. " +
                "Narrow the scan further for a complete picture.",
                "Add to watch", MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK)
            return;

        foreach (var addr in incoming.Take(room))
            _watch.Add(new WatchEntry { Address = addr, Kind = _lastKind, Size = _lastSize });

        _watchOrderStale = true;
        TuneMonitorRate();
        _watchGrid.RowCount = _watch.Count;
        _watchGrid.Invalidate();

        SetStatus(incoming.Count > 0
            ? $"Watching {_watch.Count:N0} address(es) at {_monitor.Interval} ms. " +
              "Do the thing in-game, then sort by Writes."
            : "Those addresses are already on the watch list.", Theme.Muted);
    }

    /// <summary>
    /// Sorting by Writes is how you spot the address you want: after doing the thing
    /// once in-game, the few rows that moved rise to the top of thousands that did not.
    /// </summary>
    private void SortWatchList(int column)
    {
        if (_watch.Count == 0) return;

        _watch.Sort(column switch
        {
            4 => (a, b) => b.Changes.CompareTo(a.Changes),
            _ => (a, b) => a.Address.ToInt64().CompareTo(b.Address.ToInt64()),
        });

        _watchOrderStale = true;
        _watchGrid.ClearSelection();
        _watchGrid.Invalidate();
        SetStatus(column == 4
            ? "Sorted by writes - the busiest addresses are at the top."
            : "Sorted by address.", Theme.Muted);
    }

    private void RemoveSelectedWatch()
    {
        var gone = _watchGrid.SelectedRows.Cast<DataGridViewRow>()
            .Select(r => r.Index)
            .Where(i => i >= 0 && i < _watch.Count)
            .OrderByDescending(i => i)
            .ToList();
        if (gone.Count == 0) return;

        foreach (int i in gone) _watch.RemoveAt(i);
        _watchOrderStale = true;
        TuneMonitorRate();
        _watchGrid.RowCount = _watch.Count;
        _watchGrid.ClearSelection();
        _watchGrid.Invalidate();
    }

    /// <summary>
    /// Writes the scan-bar value to every hit at once. Handy when a scan leaves a
    /// handful of candidates and you want to see which one the app reacts to.
    /// </summary>
    private void WriteValueToAllResults()
    {
        if (_target is null) { SetStatus("Attach to a process first.", Theme.Warn); return; }
        if (!_target.CanWrite) { SetStatus("This process was opened read-only - restart as Administrator.", Theme.Warn); return; }
        if (_results.Count == 0) { SetStatus("No results to write to.", Theme.Warn); return; }
        if (_value.Text.Length == 0) { SetStatus("Type the new value in the scan box first.", Theme.Warn); return; }

        byte[] bytes;
        try { bytes = Needle.Parse(_lastKind, _value.Text.Trim()).Pattern; }
        catch (Exception ex) { SetStatus($"Cannot read that value: {ex.Message}", Theme.Warn); return; }

        if (_results.Count > 50 &&
            MessageBox.Show(this,
                $"Write {_value.Text.Trim()} to all {_results.Count:N0} addresses?\n\n" +
                "With this many candidates you are writing over unrelated data, which can " +
                "destabilise the target. Narrow the scan first if you can.",
                "Write to every result", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK)
            return;

        int ok = _results.Count(addr => _journal.RecordedWrite(_target, addr, bytes, "write all"));
        _journalGrid.RowCount = _journal.Entries.Count;
        _journalGrid.Invalidate();
        _grid.Invalidate();
        SetStatus($"Wrote {_value.Text.Trim()} to {ok:N0} of {_results.Count:N0} address(es).",
            ok > 0 ? Theme.Good : Theme.Warn);
    }

    private void OnWatchValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _watch.Count) return;
        var w = _watch[e.RowIndex];

        switch (e.ColumnIndex)
        {
            case 0: e.Value = $"{w.Address.ToInt64():X16}"; break;
            case 1: e.Value = w.TypeName; break;
            case 3: e.Value = w.Frozen; break;
            case 4: e.Value = w.Changes == 0 ? "" : w.Changes.ToString("N0"); break;
            default:
                var data = _target?.Read(w.Address, w.Size);
                e.Value = data is null ? "<unreadable>" : w.Format(data);
                break;
        }
    }

    private void OnWatchValuePushed(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _watch.Count || _target is null) return;
        var w = _watch[e.RowIndex];

        if (e.ColumnIndex == 3)
        {
            w.Frozen = e.Value is true;
            if (w.Frozen)
                // Freeze holds whatever is there right now unless a value was typed.
                w.Locked ??= _target.Read(w.Address, w.Size);
            SetStatus(w.Frozen
                ? $"Frozen {w.Address.ToInt64():X} - rewritten every 100 ms."
                : $"Unfroze {w.Address.ToInt64():X}.", Theme.Muted);
            return;
        }

        if (e.ColumnIndex != 2) return;

        if (!_target.CanWrite)
        {
            SetStatus("This process was opened read-only - restart as Administrator.", Theme.Warn);
            return;
        }

        try
        {
            var bytes = w.ParseToBytes(Convert.ToString(e.Value) ?? "");
            if (_journal.RecordedWrite(_target, w.Address, bytes, "edit"))
            {
                w.Locked = bytes; // a frozen row now holds the value just typed
                _journalGrid.RowCount = _journal.Entries.Count;
                _journalGrid.Invalidate();
                SetStatus($"Wrote {e.Value} to {w.Address.ToInt64():X}.", Theme.Good);
            }
            else
            {
                SetStatus($"Write to {w.Address.ToInt64():X} was refused by the target.", Theme.Warn);
            }
        }
        catch (Exception ex)
        {
            SetStatus($"Cannot read that value: {ex.Message}", Theme.Warn);
        }
    }

    /// <summary>
    /// Polls every watched address and records each change. A frozen row is skipped,
    /// since the only writer there is us and the log would fill with our own writes.
    /// </summary>
    private void MonitorWatched()
    {
        if (_target is null || _watch.Count == 0) return;
        var clock = Stopwatch.StartNew();

        if (_watchOrderStale)
        {
            _watchOrder = Enumerable.Range(0, _watch.Count)
                .OrderBy(i => _watch[i].Address.ToInt64())
                .ToArray();
            _watchOrderStale = false;
        }

        var addrs = _watchOrder.Select(i => _watch[i].Address).ToList();
        var current = _target.ReadMany(addrs, i => _watch[_watchOrder[i]].Size);
        int logged = 0;

        for (int i = 0; i < _watchOrder.Length; i++)
        {
            if (current[i] is not { } now) continue;
            var w = _watch[_watchOrder[i]];

            if (w.Seen is null) { w.Seen = now; continue; }
            if (now.AsSpan().SequenceEqual(w.Seen)) continue;

            if (!w.Frozen)
            {
                w.Changes++;
                w.ChangedAt = DateTime.Now;
                // A thousand rows changing at once would bury the log in one tick.
                if (_logging.Checked && logged < 20) { LogChange(w, w.Seen, now); logged++; }
            }
            w.Seen = now;
        }

        if (logged >= 20 && _logging.Checked)
            LogNote($"... and more in the same tick - {_watch.Count:N0} addresses watched");

        clock.Stop();
        _tickCost = (int)clock.ElapsedMilliseconds;
        UpdateMonitorCost();
    }

    /// <summary>
    /// Applies the poll rate the user picked. The cost of a tick is measured rather
    /// than guessed, so a slow one can back itself off instead of pinning a core.
    /// </summary>
    private void TuneMonitorRate()
    {
        _monitor.Interval = SelectedPollInterval();
        _tickCost = 0;
        UpdateMonitorCost();
    }

    private int SelectedPollInterval() => _rate.SelectedIndex switch
    {
        0 => 100,
        1 => 250,
        2 => 500,
        3 => 1000,
        _ => 2000,
    };

    /// <summary>
    /// Shows what the monitor actually costs, and steps the rate down if a tick eats
    /// more than a third of its own interval - that is the point it starts to be felt.
    /// </summary>
    private void UpdateMonitorCost()
    {
        if (_watch.Count == 0) { _monitorCost.Text = ""; return; }

        int wanted = SelectedPollInterval();
        if (_tickCost > wanted / 3 && _monitor.Interval < 2000)
        {
            _monitor.Interval = Math.Min(2000, Math.Max(wanted, (int)(_tickCost * 4)));
            _monitorCost.ForeColor = Theme.Warn;
            _monitorCost.Text = $"{_watch.Count:N0} watched - {_tickCost} ms/poll, eased to {_monitor.Interval} ms";
            return;
        }

        _monitorCost.ForeColor = Theme.Muted;
        _monitorCost.Text = $"{_watch.Count:N0} watched - {_tickCost} ms per poll";
    }

    private void LogNote(string text)
    {
        _log.Items.Insert(0, $"  {DateTime.Now:HH:mm:ss.fff}  {text}");
        while (_log.Items.Count > MaxLogEntries) _log.Items.RemoveAt(_log.Items.Count - 1);
    }

    private void LogChange(WatchEntry w, byte[] before, byte[] after)
    {
        _log.BeginUpdate();
        _log.Items.Insert(0,
            $"  {DateTime.Now:HH:mm:ss.fff}  {w.Address.ToInt64():X16}  " +
            $"{w.Format(before)}  ->  {w.Format(after)}");

        while (_log.Items.Count > MaxLogEntries) _log.Items.RemoveAt(_log.Items.Count - 1);
        _log.EndUpdate();
    }

    /// <summary>Rewrites every frozen address. This is what keeps a value pinned.</summary>
    private void ApplyFrozen()
    {
        if (_target is null || !_target.CanWrite) return;
        foreach (var w in _watch)
            if (w.Frozen && w.Locked is { } bytes)
                _target.Write(w.Address, bytes);
    }

    private void ShowDump()
    {
        if (_target is null || _grid.CurrentRow is null) return;
        int i = _grid.CurrentRow.Index;
        if (i < 0 || i >= _results.Count) return;

        var addr = _results[i];
        // Back up a little so the hit sits in context rather than at the very top.
        ulong start = (ulong)addr.ToInt64() >= 64 ? (ulong)addr.ToInt64() - 64 : 0;
        var data = _target.Read((IntPtr)(long)start, 256) ?? _target.Read(addr, 128);
        if (data is null) { _dump.Text = "  <unreadable>"; return; }

        ulong shown = data.Length == 256 ? start : (ulong)addr.ToInt64();
        var sb = new StringBuilder();
        sb.AppendLine($"  {addr.ToInt64():X16}   hit address");
        sb.AppendLine();
        sb.Append(Scanner.HexDump(data, shown));
        _dump.Text = sb.ToString();
    }

    private ValueKind SelectedKind() => _type.SelectedIndex switch
    {
        0 => ValueKind.Int32,
        1 => ValueKind.Int64,
        2 => ValueKind.Float,
        3 => ValueKind.Double,
        4 => ValueKind.Utf8,
        5 => ValueKind.Utf16,
        _ => ValueKind.Bytes,
    };

    private void SetStatus(string text, Color color)
    {
        _status.Text = text;
        _status.ForeColor = color;
    }
}
