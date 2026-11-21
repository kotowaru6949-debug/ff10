using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace FFXComfortTool
{
    internal static class NativeMethods
    {
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const int STILL_ACTIVE = 259;

        public const int WM_HOTKEY = 0x0312;
        public const uint MOD_NONE = 0x0000;
        public const uint VK_F5 = 0x74;
        public const uint VK_F6 = 0x75;
        public const uint VK_F7 = 0x76;
        public const uint VK_F8 = 0x77;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    }

    internal sealed class CodePatch
    {
        public string Name { get; private set; }
        public int Rva { get; private set; }
        public byte[] Original { get; private set; }
        public byte[] Patched { get; private set; }

        public CodePatch(string name, int rva, byte[] original, byte[] patched)
        {
            Name = name;
            Rva = rva;
            Original = original;
            Patched = patched;
        }
    }

    internal enum SlotMode
    {
        NormalRng = 0,
        AlwaysRare = 1,
        AlwaysCommon = 2
    }

    internal sealed class FFXMemoryClient : IDisposable
    {
        private IntPtr _handle = IntPtr.Zero;
        public int ProcessId { get; private set; }
        public IntPtr BaseAddress { get; private set; }
        public string LastError { get; private set; }

        public bool IsAttached
        {
            get
            {
                if (_handle == IntPtr.Zero)
                {
                    return false;
                }
                int exitCode;
                if (!NativeMethods.GetExitCodeProcess(_handle, out exitCode) || exitCode != NativeMethods.STILL_ACTIVE)
                {
                    Detach();
                    return false;
                }
                return true;
            }
        }

        public bool TryAttach(out bool newlyAttached)
        {
            newlyAttached = false;
            if (IsAttached)
            {
                return true;
            }

            Process[] processes = Process.GetProcessesByName("FFX");
            if (processes == null || processes.Length == 0)
            {
                LastError = "FFX.exe が起動していません";
                return false;
            }

            Process target = processes[0];
            try
            {
                for (int i = 1; i < processes.Length; i++)
                {
                    processes[i].Dispose();
                }

                uint access = NativeMethods.PROCESS_VM_OPERATION
                    | NativeMethods.PROCESS_VM_READ
                    | NativeMethods.PROCESS_VM_WRITE
                    | NativeMethods.PROCESS_QUERY_INFORMATION;

                IntPtr handle = NativeMethods.OpenProcess(access, false, target.Id);
                if (handle == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    LastError = (err == 5)
                        ? "OpenProcess 拒否 (管理者として実行してください)"
                        : string.Format("OpenProcess 失敗 (Error: {0})", err);
                    return false;
                }

                IntPtr baseAddr;
                try
                {
                    baseAddr = target.MainModule.BaseAddress;
                }
                catch (Exception ex)
                {
                    NativeMethods.CloseHandle(handle);
                    LastError = "MainModule 取得失敗: " + ex.Message;
                    return false;
                }

                _handle = handle;
                ProcessId = target.Id;
                BaseAddress = baseAddr;
                LastError = string.Empty;

                byte[] mz = ReadBytes(0, 2);
                if (mz == null || mz.Length < 2 || mz[0] != 0x4D || mz[1] != 0x5A)
                {
                    Detach();
                    LastError = "FFX.exe メモリ読み取り検証に失敗しました";
                    return false;
                }

                newlyAttached = true;
                return true;
            }
            finally
            {
                target.Dispose();
            }
        }

        public void Detach()
        {
            if (_handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(_handle);
                _handle = IntPtr.Zero;
            }
            ProcessId = 0;
            BaseAddress = IntPtr.Zero;
        }

        private IntPtr ResolveAddress(int rva)
        {
            return new IntPtr(unchecked((int)((uint)BaseAddress.ToInt32() + (uint)rva)));
        }

        public byte[] ReadBytes(int rva, int length)
        {
            if (_handle == IntPtr.Zero)
            {
                return null;
            }
            byte[] buffer = new byte[length];
            int bytesRead;
            if (!NativeMethods.ReadProcessMemory(_handle, ResolveAddress(rva), buffer, length, out bytesRead) || bytesRead != length)
            {
                LastError = string.Format("ReadProcessMemory 失敗 RVA=0x{0:X8} (Error: {1})", rva, Marshal.GetLastWin32Error());
                return null;
            }
            return buffer;
        }

        public bool WriteBytes(int rva, byte[] data, bool isCode)
        {
            if (_handle == IntPtr.Zero)
            {
                return false;
            }
            IntPtr addr = ResolveAddress(rva);
            uint oldProtect = 0;
            bool changedProtect = false;

            if (isCode)
            {
                if (!NativeMethods.VirtualProtectEx(_handle, addr, (UIntPtr)data.Length, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    LastError = string.Format("VirtualProtectEx 失敗 RVA=0x{0:X8} (Error: {1})", rva, Marshal.GetLastWin32Error());
                    return false;
                }
                changedProtect = true;
            }

            try
            {
                int written;
                if (!NativeMethods.WriteProcessMemory(_handle, addr, data, data.Length, out written) || written != data.Length)
                {
                    LastError = string.Format("WriteProcessMemory 失敗 RVA=0x{0:X8} (Error: {1})", rva, Marshal.GetLastWin32Error());
                    return false;
                }
                return true;
            }
            finally
            {
                if (changedProtect)
                {
                    uint ignored;
                    NativeMethods.VirtualProtectEx(_handle, addr, (UIntPtr)data.Length, oldProtect, out ignored);
                }
            }
        }

        public bool ReadByte(int rva, out byte value)
        {
            value = 0;
            byte[] buf = ReadBytes(rva, 1);
            if (buf == null) return false;
            value = buf[0];
            return true;
        }

        public bool WriteByte(int rva, byte value)
        {
            return WriteBytes(rva, new byte[] { value }, false);
        }

        public bool ReadUInt32(int rva, out uint value)
        {
            value = 0;
            byte[] buf = ReadBytes(rva, 4);
            if (buf == null) return false;
            value = BitConverter.ToUInt32(buf, 0);
            return true;
        }

        public bool WriteUInt32(int rva, uint value)
        {
            return WriteBytes(rva, BitConverter.GetBytes(value), false);
        }

        public bool ApplyPatch(CodePatch patch, bool enable)
        {
            byte[] current = ReadBytes(patch.Rva, patch.Original.Length);
            if (current == null)
            {
                return false;
            }
            if (!BytesEqual(current, patch.Original) && !BytesEqual(current, patch.Patched))
            {
                LastError = string.Format("{0}: 想定バイト列と一致しません (RVA=0x{1:X8})", patch.Name, patch.Rva);
                return false;
            }
            byte[] target = enable ? patch.Patched : patch.Original;
            if (BytesEqual(current, target))
            {
                return true;
            }
            return WriteBytes(patch.Rva, target, true);
        }

        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        public void Dispose()
        {
            Detach();
        }
    }

    internal sealed class MultiplierOption
    {
        public string Label { get; private set; }
        public byte Value { get; private set; }

        public MultiplierOption(string label, byte value)
        {
            Label = label;
            Value = value;
        }

        public override string ToString()
        {
            return Label;
        }
    }

    internal sealed class MainForm : Form
    {
        // --- Verified RVAs (BaseAddress + RVA) ---
        private static readonly CodePatch PatchItemDrop100 = new CodePatch(
            "アイテムドロップ率 100%", 0x003992A2,
            new byte[] { 0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00 },
            new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });

        private static readonly CodePatch PatchEquipDrop100 = new CodePatch(
            "装備ドロップ率 100%", 0x0039938D,
            new byte[] { 0x74, 0x13 },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch PatchEquip4Slots = new CodePatch(
            "ドロップ装備 4スロット固定", 0x00398D1B,
            new byte[] { 0x6A, 0x01 },
            new byte[] { 0x6A, 0x04 });

        private static readonly CodePatch PatchSteal100 = new CodePatch(
            "盗む／ぶんどる 100%", 0x0038B7F6,
            new byte[] { 0x3B, 0xD3, 0x7C, 0x0D },
            new byte[] { 0x85, 0xDB, 0x75, 0x0D });

        private static readonly CodePatch PatchStealNoDecay = new CodePatch(
            "何回でも100%盗める", 0x0038B829,
            new byte[] { 0x88, 0x46, 0x0A },
            new byte[] { 0x90, 0x90, 0x90 });

        private const int RvaRareFlag = 0x00D2A911;
        private const int RvaStealCommonRareJump = 0x0038B848;
        private const int RvaDropCommonRareJump = 0x003992C2;
        private static readonly byte[] StealJumpOrig = new byte[] { 0x7C, 0x08 };
        private static readonly byte[] DropJumpOrig = new byte[] { 0x7C, 0x0D };
        private static readonly byte[] Nop2 = new byte[] { 0x90, 0x90 };

        private const int RvaDropQtySpot1 = 0x00399213;
        private static readonly byte[] DropQtySpot1Orig = new byte[] { 0xE8, 0xD8, 0x30, 0x11, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x19 };
        private const int RvaDropQtySpot2 = 0x00399317;
        private static readonly byte[] DropQtySpot2Orig = new byte[] { 0xE8, 0xD4, 0x2F, 0x11, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x1C };

        private const int RvaStealQtySpot = 0x0038B884;
        private static readonly byte[] StealQtySpotOrig = new byte[] { 0xE8, 0x67, 0x0A, 0x12, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x2D };

        private static readonly CodePatch PatchAllPartyAp1 = new CodePatch(
            "全員AP獲得(1)", 0x00398A2F,
            new byte[] { 0x74, 0x2C },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch PatchAllPartyAp2 = new CodePatch(
            "全員AP獲得(2)", 0x00398B83,
            new byte[] { 0x74, 0x12 },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch PatchBribe1 = new CodePatch(
            "わいろ1ギル(1)", 0x0038B95C,
            new byte[] { 0x0F, 0xBF, 0x83, 0x12, 0x07, 0x00, 0x00 },
            new byte[] { 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x90, 0x90 });

        private static readonly CodePatch PatchBribe2 = new CodePatch(
            "わいろ1ギル(2)", 0x0038B9B9,
            new byte[] { 0x0F, 0xBF, 0x83, 0x12, 0x07, 0x00, 0x00 },
            new byte[] { 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x90, 0x90 });

        private static readonly CodePatch PatchCapture10 = new CodePatch(
            "捕獲1回で10体カウント", 0x00390BAE,
            new byte[] { 0x03, 0x45, 0x0C },
            new byte[] { 0x83, 0xC0, 0x0A });

        private const int RvaApMultFlag = 0x00D2A912;
        private const int RvaApMultImm = 0x00399115;
        private const int RvaGilMultFlag = 0x00D2A913;
        private const int RvaGilMultImm = 0x00399130;

        private const int RvaFlagSensor = 0x00D2A915;
        private const int RvaFlagOverkill = 0x00D2A914;
        private const int RvaFlagCritical = 0x00D2A90D;
        private const int RvaFlagInvincible = 0x00D2A90C;

        // SaveRAM RVAs
        private const int RvaSaveItemIds = 0x00D3095C;
        private const int RvaSaveItemCounts = 0x00D30B5C;
        private const int RvaSaveGil = 0x00D307D8;
        private const int RvaSavePlyBase = 0x00D3205C;
        private const int PlyStructSize = 0x94;
        private const int PlySlvOffset = 0x3B;
        private const int RvaSaveAlBhed = 0x00D307A4;
        private const int RvaSaveArenaCaptures = 0x00D30C9C;

        private const int HotkeyDropSteal = 1;
        private const int HotkeySlotMode = 2;
        private const int HotkeyAllPartyAp = 3;
        private const int HotkeyOverkill = 4;

        private readonly FFXMemoryClient _mem = new FFXMemoryClient();
        private readonly Timer _pollTimer = new Timer();
        private bool _suppressEvents;

        // Header controls
        private Label _lblConnection;
        private Button _btnPresetComfort;
        private Button _btnResetAll;

        // Phase 1 controls
        private CheckBox _chkItemDrop100;
        private CheckBox _chkEquipDrop100;
        private CheckBox _chkEquip4Slots;
        private CheckBox _chkSteal100;
        private CheckBox _chkStealNoDecay;
        private RadioButton _radSlotNormal;
        private RadioButton _radSlotRare;
        private RadioButton _radSlotCommon;
        private ComboBox _cmbDropQty;
        private ComboBox _cmbStealQty;

        // Phase 2 controls
        private CheckBox _chkAllPartyAp;
        private CheckBox _chkBribe1Gil;
        private CheckBox _chkCapture10;
        private CheckBox _chkSensor;
        private CheckBox _chkOverkill;
        private CheckBox _chkCritical;
        private CheckBox _chkInvincible;
        private ComboBox _cmbApMult;
        private ComboBox _cmbGilMult;

        // Footer
        private Label _lblStatus;

        public MainForm()
        {
            InitializeUi();
            _pollTimer.Interval = 1000;
            _pollTimer.Tick += PollTimer_Tick;
            _pollTimer.Start();
            PollProcessAndSync();
        }

        private void InitializeUi()
        {
            Text = "FF10 快適化ツール (FFX Comfort Tool)";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(650, 648);
            Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            BackColor = Color.FromArgb(245, 247, 250);

            // Top Banner Panel
            Panel headerPanel = new Panel();
            headerPanel.BackColor = Color.FromArgb(30, 41, 59);
            headerPanel.Location = new Point(0, 0);
            headerPanel.Size = new Size(650, 56);
            Controls.Add(headerPanel);

            _lblConnection = new Label();
            _lblConnection.ForeColor = Color.FromArgb(251, 191, 36);
            _lblConnection.Font = new Font("Meiryo UI", 9.5f, FontStyle.Bold);
            _lblConnection.Location = new Point(14, 17);
            _lblConnection.Size = new Size(390, 24);
            _lblConnection.Text = "● FFX.exe 待機中...";
            headerPanel.Controls.Add(_lblConnection);

            _btnPresetComfort = new Button();
            _btnPresetComfort.Text = "快適セット ON";
            _btnPresetComfort.FlatStyle = FlatStyle.Flat;
            _btnPresetComfort.BackColor = Color.FromArgb(37, 99, 235);
            _btnPresetComfort.ForeColor = Color.White;
            _btnPresetComfort.FlatAppearance.BorderSize = 0;
            _btnPresetComfort.Location = new Point(414, 13);
            _btnPresetComfort.Size = new Size(110, 30);
            _btnPresetComfort.Click += BtnPresetComfort_Click;
            headerPanel.Controls.Add(_btnPresetComfort);

            _btnResetAll = new Button();
            _btnResetAll.Text = "すべて OFF";
            _btnResetAll.FlatStyle = FlatStyle.Flat;
            _btnResetAll.BackColor = Color.FromArgb(71, 85, 105);
            _btnResetAll.ForeColor = Color.White;
            _btnResetAll.FlatAppearance.BorderSize = 0;
            _btnResetAll.Location = new Point(530, 13);
            _btnResetAll.Size = new Size(104, 30);
            _btnResetAll.Click += BtnResetAll_Click;
            headerPanel.Controls.Add(_btnResetAll);

            // --- Phase 1 Group ---
            GroupBox grpPhase1 = new GroupBox();
            grpPhase1.Text = "Phase 1：ドロップ ＆ 盗む 快適化  [F5: 100%一括 / F6: レア・通常枠切替]";
            grpPhase1.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            grpPhase1.ForeColor = Color.FromArgb(30, 58, 138);
            grpPhase1.Location = new Point(12, 66);
            grpPhase1.Size = new Size(626, 206);
            Controls.Add(grpPhase1);

            _chkItemDrop100 = CreateCheckBox(grpPhase1, "アイテムドロップ率 100%", 16, 28, 250, OnPatchControlChanged);
            _chkEquipDrop100 = CreateCheckBox(grpPhase1, "装備ドロップ率 100%", 16, 56, 250, OnPatchControlChanged);
            _chkEquip4Slots = CreateCheckBox(grpPhase1, "ドロップ装備 4スロット固定", 16, 84, 250, OnPatchControlChanged);
            _chkSteal100 = CreateCheckBox(grpPhase1, "「盗む／ぶんどる」成功率 100%", 310, 28, 290, OnPatchControlChanged);
            _chkStealNoDecay = CreateCheckBox(grpPhase1, "同じ敵から何回でも100%盗める", 310, 56, 290, OnPatchControlChanged);

            Panel pnlSlotMode = new Panel();
            pnlSlotMode.BackColor = Color.FromArgb(238, 242, 248);
            pnlSlotMode.Location = new Point(16, 114);
            pnlSlotMode.Size = new Size(594, 42);
            grpPhase1.Controls.Add(pnlSlotMode);

            Label lblSlotMode = new Label();
            lblSlotMode.Text = "枠選択 [F6]:";
            lblSlotMode.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            lblSlotMode.ForeColor = Color.Black;
            lblSlotMode.Location = new Point(8, 11);
            lblSlotMode.Size = new Size(92, 20);
            pnlSlotMode.Controls.Add(lblSlotMode);

            _radSlotNormal = CreateRadio(pnlSlotMode, "通常確率 (7/8・1/8)", 104, 10, 162, true, OnSlotModeChanged);
            _radSlotRare = CreateRadio(pnlSlotMode, "レア枠 100%", 274, 10, 140, false, OnSlotModeChanged);
            _radSlotCommon = CreateRadio(pnlSlotMode, "通常枠 100%", 422, 10, 150, false, OnSlotModeChanged);

            Label lblDropQty = CreateLabel(grpPhase1, "ドロップ個数倍率:", 16, 168, 126);
            _cmbDropQty = CreateMultiplierCombo(grpPhase1, 146, 164, 130, new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×4", 4),
                new MultiplierOption("×10", 10),
                new MultiplierOption("99個 (×99)", 99)
            }, OnDropQtyChanged);

            Label lblStealQty = CreateLabel(grpPhase1, "盗む個数倍率:", 310, 168, 106);
            _cmbStealQty = CreateMultiplierCombo(grpPhase1, 420, 164, 140, new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×4", 4),
                new MultiplierOption("×10", 10),
                new MultiplierOption("99個 (×99)", 99)
            }, OnStealQtyChanged);

            // --- Phase 2 Group ---
            GroupBox grpPhase2 = new GroupBox();
            grpPhase2.Text = "Phase 2：バトル・育成・収集 快適化  [F7: 全員AP / F8: 常時オーバーキル]";
            grpPhase2.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            grpPhase2.ForeColor = Color.FromArgb(30, 58, 138);
            grpPhase2.Location = new Point(12, 280);
            grpPhase2.Size = new Size(626, 178);
            Controls.Add(grpPhase2);

            _chkAllPartyAp = CreateCheckBox(grpPhase2, "控えメンバーにもAP 100%分配 (全員AP)", 16, 28, 290, OnPatchControlChanged);
            _chkBribe1Gil = CreateCheckBox(grpPhase2, "わいろ 1ギルで100%成功＆最大個数", 16, 56, 290, OnPatchControlChanged);
            _chkCapture10 = CreateCheckBox(grpPhase2, "モンスター捕獲 1回で10体カウント", 16, 84, 290, OnPatchControlChanged);

            _chkSensor = CreateCheckBox(grpPhase2, "常時「みやぶる（センサー）」表示", 320, 28, 290, OnFlagCheckChanged);
            _chkOverkill = CreateCheckBox(grpPhase2, "常時オーバーキル (Overkill)", 320, 56, 290, OnFlagCheckChanged);
            _chkCritical = CreateCheckBox(grpPhase2, "常時クリティカル", 320, 84, 290, OnFlagCheckChanged);
            _chkInvincible = CreateCheckBox(grpPhase2, "味方無敵 (Player Invincible)", 320, 112, 290, OnFlagCheckChanged);

            Label lblApMult = CreateLabel(grpPhase2, "獲得AP倍率:", 16, 140, 100);
            _cmbApMult = CreateMultiplierCombo(grpPhase2, 120, 136, 120, new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×5", 5),
                new MultiplierOption("×10", 10),
                new MultiplierOption("×50", 50),
                new MultiplierOption("×100", 100)
            }, OnApMultChanged);

            Label lblGilMult = CreateLabel(grpPhase2, "獲得ギル倍率:", 320, 140, 106);
            _cmbGilMult = CreateMultiplierCombo(grpPhase2, 430, 136, 120, new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×5", 5),
                new MultiplierOption("×10", 10),
                new MultiplierOption("×50", 50),
                new MultiplierOption("×100", 100)
            }, OnGilMultChanged);

            // --- Phase 3 Group ---
            GroupBox grpPhase3 = new GroupBox();
            grpPhase3.Text = "Phase 3：ワンクリック便利機能（セーブデータ即時編集）";
            grpPhase3.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            grpPhase3.ForeColor = Color.FromArgb(30, 58, 138);
            grpPhase3.Location = new Point(12, 466);
            grpPhase3.Size = new Size(626, 130);
            Controls.Add(grpPhase3);

            Label lblSaveNote = new Label();
            lblSaveNote.Text = "※セーブデータロード後に実行してください（表示はメニュー開閉またはバトル後に更新されます）";
            lblSaveNote.Font = new Font("Meiryo UI", 8.25f, FontStyle.Regular);
            lblSaveNote.ForeColor = Color.FromArgb(80, 90, 105);
            lblSaveNote.Location = new Point(14, 24);
            lblSaveNote.Size = new Size(598, 18);
            grpPhase3.Controls.Add(lblSaveNote);

            CreateActionButton(grpPhase3, "所持中アイテム全種 99個化", 16, 48, 190, 32, BtnMaxItems_Click);
            CreateActionButton(grpPhase3, "所持ギル +1,000,000", 218, 48, 190, 32, BtnAddGil_Click);
            CreateActionButton(grpPhase3, "所持ギル 999,999,999 (MAX)", 420, 48, 190, 32, BtnMaxGil_Click);

            CreateActionButton(grpPhase3, "味方全員 S.Lv 99", 16, 88, 190, 32, BtnMaxSlv_Click);
            CreateActionButton(grpPhase3, "アルベド語辞書 全26巻コンプ", 218, 88, 190, 32, BtnAlBhedAll_Click);
            CreateActionButton(grpPhase3, "訓練場 全104種×10体捕獲済", 420, 88, 190, 32, BtnArenaAll_Click);

            // --- Status Footer ---
            Panel footerPanel = new Panel();
            footerPanel.BackColor = Color.FromArgb(226, 232, 240);
            footerPanel.Location = new Point(0, 608);
            footerPanel.Size = new Size(650, 40);
            Controls.Add(footerPanel);

            _lblStatus = new Label();
            _lblStatus.Font = new Font("Meiryo UI", 8.5f, FontStyle.Regular);
            _lblStatus.ForeColor = Color.FromArgb(30, 41, 59);
            _lblStatus.Location = new Point(12, 10);
            _lblStatus.Size = new Size(626, 20);
            _lblStatus.Text = "準備完了: ゲームを起動すると選択中の設定を自動適用します。";
            footerPanel.Controls.Add(_lblStatus);
        }

        private static CheckBox CreateCheckBox(Control parent, string text, int x, int y, int w, EventHandler onChanged)
        {
            CheckBox chk = new CheckBox();
            chk.Text = text;
            chk.Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            chk.ForeColor = Color.Black;
            chk.Location = new Point(x, y);
            chk.Size = new Size(w, 22);
            chk.CheckedChanged += onChanged;
            parent.Controls.Add(chk);
            return chk;
        }

        private static RadioButton CreateRadio(Control parent, string text, int x, int y, int w, bool isChecked, EventHandler onChanged)
        {
            RadioButton rad = new RadioButton();
            rad.Text = text;
            rad.Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            rad.ForeColor = Color.Black;
            rad.Location = new Point(x, y);
            rad.Size = new Size(w, 22);
            rad.Checked = isChecked;
            rad.CheckedChanged += onChanged;
            parent.Controls.Add(rad);
            return rad;
        }

        private static Label CreateLabel(Control parent, string text, int x, int y, int w)
        {
            Label lbl = new Label();
            lbl.Text = text;
            lbl.Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            lbl.ForeColor = Color.Black;
            lbl.Location = new Point(x, y);
            lbl.Size = new Size(w, 20);
            parent.Controls.Add(lbl);
            return lbl;
        }

        private static ComboBox CreateMultiplierCombo(Control parent, int x, int y, int w, MultiplierOption[] options, EventHandler onChanged)
        {
            ComboBox cmb = new ComboBox();
            cmb.DropDownStyle = ComboBoxStyle.DropDownList;
            cmb.Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            cmb.Location = new Point(x, y);
            cmb.Size = new Size(w, 24);
            cmb.Items.AddRange(options);
            cmb.SelectedIndex = 0;
            cmb.SelectedIndexChanged += onChanged;
            parent.Controls.Add(cmb);
            return cmb;
        }

        private static Button CreateActionButton(Control parent, string text, int x, int y, int w, int h, EventHandler onClick)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Font = new Font("Meiryo UI", 8.75f, FontStyle.Regular);
            btn.ForeColor = Color.FromArgb(15, 23, 42);
            btn.BackColor = Color.White;
            btn.FlatStyle = FlatStyle.System;
            btn.Location = new Point(x, y);
            btn.Size = new Size(w, h);
            btn.Click += onClick;
            parent.Controls.Add(btn);
            return btn;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            List<string> failed = new List<string>();
            if (!NativeMethods.RegisterHotKey(Handle, HotkeyDropSteal, NativeMethods.MOD_NONE, NativeMethods.VK_F5)) failed.Add("F5");
            if (!NativeMethods.RegisterHotKey(Handle, HotkeySlotMode, NativeMethods.MOD_NONE, NativeMethods.VK_F6)) failed.Add("F6");
            if (!NativeMethods.RegisterHotKey(Handle, HotkeyAllPartyAp, NativeMethods.MOD_NONE, NativeMethods.VK_F7)) failed.Add("F7");
            if (!NativeMethods.RegisterHotKey(Handle, HotkeyOverkill, NativeMethods.MOD_NONE, NativeMethods.VK_F8)) failed.Add("F8");
            if (failed.Count > 0)
            {
                SetStatus("注意: ホットキー登録失敗 (" + string.Join(", ", failed.ToArray()) + ") - 他アプリで使用中");
            }
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            NativeMethods.UnregisterHotKey(Handle, HotkeyDropSteal);
            NativeMethods.UnregisterHotKey(Handle, HotkeySlotMode);
            NativeMethods.UnregisterHotKey(Handle, HotkeyAllPartyAp);
            NativeMethods.UnregisterHotKey(Handle, HotkeyOverkill);
            _pollTimer.Stop();
            _mem.Dispose();
            base.OnFormClosed(e);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == NativeMethods.WM_HOTKEY)
            {
                int id = m.WParam.ToInt32();
                HandleHotkey(id);
                return;
            }
            base.WndProc(ref m);
        }

        private void HandleHotkey(int id)
        {
            switch (id)
            {
                case HotkeyDropSteal:
                    bool allOn = _chkItemDrop100.Checked && _chkEquipDrop100.Checked && _chkSteal100.Checked && _chkStealNoDecay.Checked;
                    bool nextState = !allOn;
                    _suppressEvents = true;
                    _chkItemDrop100.Checked = nextState;
                    _chkEquipDrop100.Checked = nextState;
                    _chkSteal100.Checked = nextState;
                    _chkStealNoDecay.Checked = nextState;
                    _suppressEvents = false;
                    ApplyTogglePatches();
                    SetStatus("[F5] ドロップ＆盗む 100% 一括: " + (nextState ? "ON" : "OFF"));
                    break;

                case HotkeySlotMode:
                    if (_radSlotNormal.Checked) _radSlotRare.Checked = true;
                    else if (_radSlotRare.Checked) _radSlotCommon.Checked = true;
                    else _radSlotNormal.Checked = true;
                    SetStatus("[F6] 枠選択切替: " + GetSlotModeLabel(GetSelectedSlotMode()));
                    break;

                case HotkeyAllPartyAp:
                    _chkAllPartyAp.Checked = !_chkAllPartyAp.Checked;
                    SetStatus("[F7] 全員AP獲得: " + (_chkAllPartyAp.Checked ? "ON" : "OFF"));
                    break;

                case HotkeyOverkill:
                    _chkOverkill.Checked = !_chkOverkill.Checked;
                    SetStatus("[F8] 常時オーバーキル: " + (_chkOverkill.Checked ? "ON" : "OFF"));
                    break;
            }
        }

        private void PollTimer_Tick(object sender, EventArgs e)
        {
            PollProcessAndSync();
        }

        private void PollProcessAndSync()
        {
            bool newlyAttached;
            if (!_mem.TryAttach(out newlyAttached))
            {
                _lblConnection.ForeColor = Color.FromArgb(251, 191, 36);
                _lblConnection.Text = string.IsNullOrEmpty(_mem.LastError)
                    ? "● FFX.exe 待機中..."
                    : "● " + _mem.LastError;
                return;
            }

            if (newlyAttached)
            {
                ApplyAllSettings();
                SetStatus(string.Format("FFX.exe (PID: {0}) に接続し、現在の設定を適用しました。", _mem.ProcessId));
            }
            else
            {
                KeepDataFlagsSynced();
            }

            uint gil;
            string gilText = _mem.ReadUInt32(RvaSaveGil, out gil)
                ? string.Format("{0:N0} G", gil)
                : "--- G";

            _lblConnection.ForeColor = Color.FromArgb(74, 222, 128);
            _lblConnection.Text = string.Format("● 接続中 (PID: {0}, Base: 0x{1:X8}, 所持ギル: {2})",
                _mem.ProcessId, unchecked((uint)_mem.BaseAddress.ToInt32()), gilText);
        }

        private void SetStatus(string message)
        {
            _lblStatus.Text = string.Format("[{0:HH:mm:ss}] {1}", DateTime.Now, message);
        }

        private bool EnsureAttachedForAction()
        {
            bool newlyAttached;
            if (_mem.TryAttach(out newlyAttached))
            {
                if (newlyAttached)
                {
                    ApplyAllSettings();
                }
                return true;
            }
            SetStatus("未接続: " + _mem.LastError);
            return false;
        }

        private void BtnPresetComfort_Click(object sender, EventArgs e)
        {
            _suppressEvents = true;
            _chkItemDrop100.Checked = true;
            _chkEquipDrop100.Checked = true;
            _chkEquip4Slots.Checked = true;
            _chkSteal100.Checked = true;
            _chkStealNoDecay.Checked = true;
            _chkAllPartyAp.Checked = true;
            _chkBribe1Gil.Checked = true;
            _chkCapture10.Checked = true;
            _chkSensor.Checked = true;
            _suppressEvents = false;

            ApplyAllSettings();
            SetStatus("快適セット (ドロップ/盗む100%・4スロ・全員AP・わいろ1G・捕獲10・みやぶる) をONにしました。");
        }

        private void BtnResetAll_Click(object sender, EventArgs e)
        {
            _suppressEvents = true;
            _chkItemDrop100.Checked = false;
            _chkEquipDrop100.Checked = false;
            _chkEquip4Slots.Checked = false;
            _chkSteal100.Checked = false;
            _chkStealNoDecay.Checked = false;
            _radSlotNormal.Checked = true;
            _cmbDropQty.SelectedIndex = 0;
            _cmbStealQty.SelectedIndex = 0;

            _chkAllPartyAp.Checked = false;
            _chkBribe1Gil.Checked = false;
            _chkCapture10.Checked = false;
            _chkSensor.Checked = false;
            _chkOverkill.Checked = false;
            _chkCritical.Checked = false;
            _chkInvincible.Checked = false;
            _cmbApMult.SelectedIndex = 0;
            _cmbGilMult.SelectedIndex = 0;
            _suppressEvents = false;

            ApplyAllSettings();
            SetStatus("すべてのパッチ・倍率・補助フラグを通常状態 (OFF) に戻しました。");
        }

        private void OnPatchControlChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyTogglePatches();
        }

        private void OnSlotModeChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            RadioButton rad = sender as RadioButton;
            if (rad != null && !rad.Checked) return;
            ApplySlotMode();
        }

        private void OnDropQtyChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyDropQtyMultiplier();
        }

        private void OnStealQtyChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyStealQtyMultiplier();
        }

        private void OnApMultChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyApMultiplier();
        }

        private void OnGilMultChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyGilMultiplier();
        }

        private void OnFlagCheckChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            ApplyBattleFlags();
        }

        private void ApplyAllSettings()
        {
            if (!_mem.IsAttached) return;
            ApplyTogglePatches();
            ApplySlotMode();
            ApplyDropQtyMultiplier();
            ApplyStealQtyMultiplier();
            ApplyApMultiplier();
            ApplyGilMultiplier();
            ApplyBattleFlags();
        }

        private void ApplyTogglePatches()
        {
            if (!_mem.IsAttached) return;
            bool ok = true;
            ok &= _mem.ApplyPatch(PatchItemDrop100, _chkItemDrop100.Checked);
            ok &= _mem.ApplyPatch(PatchEquipDrop100, _chkEquipDrop100.Checked);
            ok &= _mem.ApplyPatch(PatchEquip4Slots, _chkEquip4Slots.Checked);
            ok &= _mem.ApplyPatch(PatchSteal100, _chkSteal100.Checked);
            ok &= _mem.ApplyPatch(PatchStealNoDecay, _chkStealNoDecay.Checked);
            ok &= _mem.ApplyPatch(PatchAllPartyAp1, _chkAllPartyAp.Checked);
            ok &= _mem.ApplyPatch(PatchAllPartyAp2, _chkAllPartyAp.Checked);
            ok &= _mem.ApplyPatch(PatchBribe1, _chkBribe1Gil.Checked);
            ok &= _mem.ApplyPatch(PatchBribe2, _chkBribe1Gil.Checked);
            ok &= _mem.ApplyPatch(PatchCapture10, _chkCapture10.Checked);
            if (!ok) SetStatus("パッチ適用エラー: " + _mem.LastError);
        }

        private SlotMode GetSelectedSlotMode()
        {
            if (_radSlotRare.Checked) return SlotMode.AlwaysRare;
            if (_radSlotCommon.Checked) return SlotMode.AlwaysCommon;
            return SlotMode.NormalRng;
        }

        private static string GetSlotModeLabel(SlotMode mode)
        {
            switch (mode)
            {
                case SlotMode.AlwaysRare: return "レア枠 100%";
                case SlotMode.AlwaysCommon: return "通常枠 100%";
                default: return "通常確率 (7/8・1/8)";
            }
        }

        private void ApplySlotMode()
        {
            if (!_mem.IsAttached) return;
            SlotMode mode = GetSelectedSlotMode();
            byte flag = (mode == SlotMode.AlwaysRare) ? (byte)0x01 : (byte)0x00;
            bool forceCommon = (mode == SlotMode.AlwaysCommon);

            CodePatch stealPatch = new CodePatch("盗む枠選択", RvaStealCommonRareJump, StealJumpOrig, Nop2);
            CodePatch dropPatch = new CodePatch("ドロップ枠選択", RvaDropCommonRareJump, DropJumpOrig, Nop2);

            bool ok = true;
            ok &= _mem.WriteByte(RvaRareFlag, flag);
            ok &= _mem.ApplyPatch(stealPatch, forceCommon);
            ok &= _mem.ApplyPatch(dropPatch, forceCommon);
            if (!ok) SetStatus("枠選択適用エラー: " + _mem.LastError);
        }

        private static byte GetSelectedMultiplier(ComboBox cmb)
        {
            MultiplierOption opt = cmb.SelectedItem as MultiplierOption;
            return (opt != null) ? opt.Value : (byte)1;
        }

        private bool ApplyQtyPatch(int rva, byte[] orig, byte[] patched, byte mult, string label)
        {
            byte[] current = _mem.ReadBytes(rva, orig.Length);
            if (current == null) return false;

            bool matchesOrig = FFXMemoryClient.BytesEqual(current, orig);
            bool matchesPatchedPattern = (current[0] == patched[0]
                && current[1] == patched[1]
                && current[8] == patched[8]
                && current[9] == patched[9]);
            if (!matchesOrig && !matchesPatchedPattern)
            {
                SetStatus(string.Format("{0}: 想定バイト列と一致しません (RVA=0x{1:X8})", label, rva));
                return false;
            }

            byte[] target = (mult > 1) ? patched : orig;
            if (FFXMemoryClient.BytesEqual(current, target)) return true;
            return _mem.WriteBytes(rva, target, true);
        }

        private void ApplyDropQtyMultiplier()
        {
            if (!_mem.IsAttached) return;
            byte mult = GetSelectedMultiplier(_cmbDropQty);
            byte[] p1 = new byte[] { 0x6B, 0xF6, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x19 };
            byte[] p2 = new byte[] { 0x6B, 0xDB, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x1C };

            bool ok = ApplyQtyPatch(RvaDropQtySpot1, DropQtySpot1Orig, p1, mult, "ドロップ倍率(1)");
            ok &= ApplyQtyPatch(RvaDropQtySpot2, DropQtySpot2Orig, p2, mult, "ドロップ倍率(2)");
            if (!ok && !string.IsNullOrEmpty(_mem.LastError)) SetStatus("ドロップ倍率エラー: " + _mem.LastError);
        }

        private void ApplyStealQtyMultiplier()
        {
            if (!_mem.IsAttached) return;
            byte mult = GetSelectedMultiplier(_cmbStealQty);
            byte[] p = new byte[] { 0x6B, 0x47, 0x08, mult, 0x66, 0x89, 0x47, 0x08, 0xEB, 0x2D };

            bool ok = ApplyQtyPatch(RvaStealQtySpot, StealQtySpotOrig, p, mult, "盗む倍率");
            if (!ok && !string.IsNullOrEmpty(_mem.LastError)) SetStatus("盗む倍率エラー: " + _mem.LastError);
        }

        private void ApplyBattleMultiplier(int flagRva, int immRva, byte mult, string label)
        {
            if (!_mem.IsAttached) return;
            byte[] imulBytes = _mem.ReadBytes(immRva - 2, 3);
            if (imulBytes == null || imulBytes[0] != 0x6B || imulBytes[1] != 0xC0)
            {
                SetStatus(string.Format("{0}: 想定バイト列と一致しません (RVA=0x{1:X8})", label, immRva - 2));
                return;
            }

            byte flag = (mult > 1) ? (byte)0x01 : (byte)0x00;
            byte imm = (mult > 1) ? mult : (byte)0x64;

            bool ok = _mem.WriteByte(flagRva, flag);
            if (imulBytes[2] != imm)
            {
                ok &= _mem.WriteBytes(immRva, new byte[] { imm }, true);
            }
            if (!ok) SetStatus(label + "エラー: " + _mem.LastError);
        }

        private void ApplyApMultiplier()
        {
            ApplyBattleMultiplier(RvaApMultFlag, RvaApMultImm, GetSelectedMultiplier(_cmbApMult), "AP倍率");
        }

        private void ApplyGilMultiplier()
        {
            ApplyBattleMultiplier(RvaGilMultFlag, RvaGilMultImm, GetSelectedMultiplier(_cmbGilMult), "ギル倍率");
        }

        private void ApplyBattleFlags()
        {
            if (!_mem.IsAttached) return;
            bool ok = true;
            ok &= _mem.WriteByte(RvaFlagSensor, _chkSensor.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(RvaFlagOverkill, _chkOverkill.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(RvaFlagCritical, _chkCritical.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(RvaFlagInvincible, _chkInvincible.Checked ? (byte)0x01 : (byte)0x00);
            if (!ok) SetStatus("バトルフラグエラー: " + _mem.LastError);
        }

        private void KeepDataFlagsSynced()
        {
            if (!_mem.IsAttached) return;
            SyncDataByte(RvaRareFlag, (GetSelectedSlotMode() == SlotMode.AlwaysRare) ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaApMultFlag, (GetSelectedMultiplier(_cmbApMult) > 1) ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaGilMultFlag, (GetSelectedMultiplier(_cmbGilMult) > 1) ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaFlagSensor, _chkSensor.Checked ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaFlagOverkill, _chkOverkill.Checked ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaFlagCritical, _chkCritical.Checked ? (byte)0x01 : (byte)0x00);
            SyncDataByte(RvaFlagInvincible, _chkInvincible.Checked ? (byte)0x01 : (byte)0x00);
        }

        private void SyncDataByte(int rva, byte expected)
        {
            byte cur;
            if (_mem.ReadByte(rva, out cur) && cur != expected)
            {
                _mem.WriteByte(rva, expected);
            }
        }

        // --- Phase 3: SaveRAM One-Click Actions ---

        private void BtnMaxItems_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            byte[] ids = _mem.ReadBytes(RvaSaveItemIds, 512);
            if (ids == null)
            {
                SetStatus("アイテム読み取り失敗: " + _mem.LastError);
                return;
            }

            int updated = 0;
            for (int i = 0; i < 256; i++)
            {
                ushort itemId = BitConverter.ToUInt16(ids, i * 2);
                if (itemId != 0x00FF && (itemId & 0xF000) == 0x2000)
                {
                    if (_mem.WriteByte(RvaSaveItemCounts + i, 99))
                    {
                        updated++;
                    }
                }
            }
            SetStatus(string.Format("所持中アイテム {0} 種類をすべて 99 個にしました。", updated));
        }

        private void BtnAddGil_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            uint cur;
            if (!_mem.ReadUInt32(RvaSaveGil, out cur))
            {
                SetStatus("ギル読み取り失敗: " + _mem.LastError);
                return;
            }

            ulong next = (ulong)cur + 1000000UL;
            if (next > 999999999UL) next = 999999999UL;

            if (_mem.WriteUInt32(RvaSaveGil, (uint)next))
            {
                SetStatus(string.Format("所持ギルを更新しました: {0:N0} G", next));
            }
            else
            {
                SetStatus("ギル更新失敗: " + _mem.LastError);
            }
        }

        private void BtnMaxGil_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            if (_mem.WriteUInt32(RvaSaveGil, 999999999U))
            {
                SetStatus("所持ギルを 999,999,999 G (MAX) にしました。");
            }
            else
            {
                SetStatus("ギル更新失敗: " + _mem.LastError);
            }
        }

        private void BtnMaxSlv_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            bool ok = true;
            for (int c = 0; c < 7; c++)
            {
                ok &= _mem.WriteByte(RvaSavePlyBase + c * PlyStructSize + PlySlvOffset, 99);
            }
            SetStatus(ok
                ? "味方全員 (7人) のスフィアレベル (S.Lv) を 99 にしました。"
                : "S.Lv 更新エラー: " + _mem.LastError);
        }

        private void BtnAlBhedAll_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            if (_mem.WriteUInt32(RvaSaveAlBhed, 0x03FFFFFFU))
            {
                SetStatus("アルベド語辞書 全26巻をコンプリートしました。");
            }
            else
            {
                SetStatus("アルベド語辞書更新失敗: " + _mem.LastError);
            }
        }

        private void BtnArenaAll_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForAction()) return;

            byte[] counts = new byte[104];
            for (int i = 0; i < counts.Length; i++)
            {
                counts[i] = 10;
            }
            if (_mem.WriteBytes(RvaSaveArenaCaptures, counts, false))
            {
                SetStatus("訓練場モンスター 全104種を捕獲数 10 にしました。");
            }
            else
            {
                SetStatus("訓練場捕獲更新失敗: " + _mem.LastError);
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
