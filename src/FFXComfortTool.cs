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

    internal enum GameKind
    {
        None = 0,
        FFX = 1,
        FFX2 = 2
    }

    internal enum SlotMode
    {
        NormalRng = 0,
        AlwaysRare = 1,
        AlwaysCommon = 2
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

    internal sealed class FFXMemoryClient : IDisposable
    {
        private IntPtr _handle = IntPtr.Zero;
        public GameKind AttachedGame { get; private set; }
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

            string ffxErr;
            if (TryAttachByName("FFX", GameKind.FFX, out ffxErr))
            {
                newlyAttached = true;
                return true;
            }

            string ffx2Err;
            if (TryAttachByName("FFX-2", GameKind.FFX2, out ffx2Err))
            {
                newlyAttached = true;
                return true;
            }

            LastError = !string.IsNullOrEmpty(ffxErr)
                ? ffxErr
                : (!string.IsNullOrEmpty(ffx2Err) ? ffx2Err : string.Empty);
            return false;
        }

        private bool TryAttachByName(string processName, GameKind kind, out string error)
        {
            error = string.Empty;
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes == null || processes.Length == 0)
            {
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
                    error = (err == 5)
                        ? "OpenProcess 拒否 (管理者として実行してください)"
                        : string.Format("{0}.exe OpenProcess 失敗 (Error: {1})", processName, err);
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
                    error = processName + ".exe MainModule 取得失敗: " + ex.Message;
                    return false;
                }

                _handle = handle;
                AttachedGame = kind;
                ProcessId = target.Id;
                BaseAddress = baseAddr;
                LastError = string.Empty;

                byte[] mz = ReadBytes(0, 2);
                if (mz == null || mz.Length < 2 || mz[0] != 0x4D || mz[1] != 0x5A)
                {
                    Detach();
                    error = processName + ".exe メモリ読み取り検証に失敗しました";
                    return false;
                }

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
            AttachedGame = GameKind.None;
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

        public bool ApplyVariablePatch(int rva, byte[] orig, byte[] patched, bool enable, int[] fixedIndices, string label)
        {
            byte[] current = ReadBytes(rva, orig.Length);
            if (current == null)
            {
                return false;
            }

            bool matchesOrig = BytesEqual(current, orig);
            bool matchesPatchedPattern = true;
            for (int i = 0; i < fixedIndices.Length; i++)
            {
                int idx = fixedIndices[i];
                if (current[idx] != patched[idx])
                {
                    matchesPatchedPattern = false;
                    break;
                }
            }

            if (!matchesOrig && !matchesPatchedPattern)
            {
                LastError = string.Format("{0}: 想定バイト列と一致しません (RVA=0x{1:X8})", label, rva);
                return false;
            }

            byte[] target = enable ? patched : orig;
            if (BytesEqual(current, target))
            {
                return true;
            }
            return WriteBytes(rva, target, true);
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

    internal sealed class MainForm : Form
    {
        // ============================================================
        // FF10 (FFX.exe) Verified RVAs
        // ============================================================
        private static readonly CodePatch FfxPatchItemDrop100 = new CodePatch(
            "FFX アイテムドロップ率 100%", 0x003992A2,
            new byte[] { 0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00 },
            new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });

        private static readonly CodePatch FfxPatchEquipDrop100 = new CodePatch(
            "FFX 装備ドロップ率 100%", 0x0039938D,
            new byte[] { 0x74, 0x13 },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch FfxPatchEquip4Slots = new CodePatch(
            "FFX ドロップ装備 4スロット固定", 0x00398D1B,
            new byte[] { 0x6A, 0x01 },
            new byte[] { 0x6A, 0x04 });

        private static readonly CodePatch FfxPatchSteal100 = new CodePatch(
            "FFX 盗む／ぶんどる 100%", 0x0038B7F6,
            new byte[] { 0x3B, 0xD3, 0x7C, 0x0D },
            new byte[] { 0x85, 0xDB, 0x75, 0x0D });

        private static readonly CodePatch FfxPatchStealNoDecay = new CodePatch(
            "FFX 何回でも100%盗める", 0x0038B829,
            new byte[] { 0x88, 0x46, 0x0A },
            new byte[] { 0x90, 0x90, 0x90 });

        private const int FfxRvaRareFlag = 0x00D2A911;
        private const int FfxRvaStealCommonRareJump = 0x0038B848;
        private const int FfxRvaDropCommonRareJump = 0x003992C2;
        private static readonly byte[] FfxStealJumpOrig = new byte[] { 0x7C, 0x08 };
        private static readonly byte[] FfxDropJumpOrig = new byte[] { 0x7C, 0x0D };

        private const int FfxRvaDropQtySpot1 = 0x00399213;
        private static readonly byte[] FfxDropQtySpot1Orig = new byte[] { 0xE8, 0xD8, 0x30, 0x11, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x19 };
        private static readonly int[] FfxDropQtyFixed = new int[] { 0, 1, 8, 9 };

        private const int FfxRvaDropQtySpot2 = 0x00399317;
        private static readonly byte[] FfxDropQtySpot2Orig = new byte[] { 0xE8, 0xD4, 0x2F, 0x11, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x1C };

        private const int FfxRvaStealQtySpot = 0x0038B884;
        private static readonly byte[] FfxStealQtySpotOrig = new byte[] { 0xE8, 0x67, 0x0A, 0x12, 0x00, 0x83, 0xF8, 0x0B, 0x75, 0x2D };
        private static readonly int[] FfxStealQtyFixed = new int[] { 0, 1, 2, 4, 5, 6, 7, 8, 9 };

        private static readonly CodePatch FfxPatchAllPartyAp1 = new CodePatch(
            "FFX 全員AP獲得(1)", 0x00398A2F,
            new byte[] { 0x74, 0x2C },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch FfxPatchAllPartyAp2 = new CodePatch(
            "FFX 全員AP獲得(2)", 0x00398B83,
            new byte[] { 0x74, 0x12 },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch FfxPatchBribe1 = new CodePatch(
            "FFX わいろ1ギル(1)", 0x0038B95C,
            new byte[] { 0x0F, 0xBF, 0x83, 0x12, 0x07, 0x00, 0x00 },
            new byte[] { 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x90, 0x90 });

        private static readonly CodePatch FfxPatchBribe2 = new CodePatch(
            "FFX わいろ1ギル(2)", 0x0038B9B9,
            new byte[] { 0x0F, 0xBF, 0x83, 0x12, 0x07, 0x00, 0x00 },
            new byte[] { 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x90, 0x90 });

        private static readonly CodePatch FfxPatchCapture10 = new CodePatch(
            "FFX 捕獲1回で10体カウント", 0x00390BAE,
            new byte[] { 0x03, 0x45, 0x0C },
            new byte[] { 0x83, 0xC0, 0x0A });

        private const int FfxRvaApMultFlag = 0x00D2A912;
        private const int FfxRvaApMultImm = 0x00399115;
        private const int FfxRvaGilMultFlag = 0x00D2A913;
        private const int FfxRvaGilMultImm = 0x00399130;

        private const int FfxRvaFlagSensor = 0x00D2A915;
        private const int FfxRvaFlagOverkill = 0x00D2A914;
        private const int FfxRvaFlagCritical = 0x00D2A90D;
        private const int FfxRvaFlagInvincible = 0x00D2A90C;

        private const int FfxRvaSaveItemIds = 0x00D3095C;
        private const int FfxRvaSaveItemCounts = 0x00D30B5C;
        private const int FfxRvaSaveGil = 0x00D307D8;
        private const int FfxRvaSavePlyBase = 0x00D3205C;
        private const int FfxPlyStructSize = 0x94;
        private const int FfxPlySlvOffset = 0x3B;
        private const int FfxRvaSaveAlBhed = 0x00D307A4;
        private const int FfxRvaSaveArenaCaptures = 0x00D30C9C;

        // ============================================================
        // FF10-2 (FFX-2.exe) Verified RVAs
        // ============================================================
        private static readonly CodePatch Ffx2PatchItemDrop100 = new CodePatch(
            "FFX-2 アイテムドロップ率 100%", 0x002247D6,
            new byte[] { 0x74, 0x4B },
            new byte[] { 0x90, 0x90 });

        private static readonly CodePatch Ffx2PatchSteal100 = new CodePatch(
            "FFX-2 盗む成功率 100%", 0x00219C8B,
            new byte[] { 0x3B, 0xCB, 0x7C, 0x09 },
            new byte[] { 0x85, 0xDB, 0x75, 0x09 });

        private static readonly CodePatch Ffx2PatchStealNoDecay = new CodePatch(
            "FFX-2 何回でも100%盗める", 0x0021AAE3,
            new byte[] { 0xC6, 0x80, 0xAD, 0x06, 0x00, 0x00, 0x00 },
            new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });

        private const int Ffx2RvaRareFlag = 0x009F68D5;
        private const int Ffx2RvaStealCommonRareJump = 0x00219CC1;
        private const int Ffx2RvaDropCommonRareJump = 0x002247F1;
        private static readonly byte[] Ffx2StealJumpOrig = new byte[] { 0x7C, 0x08 };
        private static readonly byte[] Ffx2DropJumpOrig = new byte[] { 0x7C, 0x0D };

        private const int Ffx2RvaDropQtySpot = 0x00224733;
        private static readonly byte[] Ffx2DropQtyOrig = new byte[] { 0xC7, 0x45, 0xF4, 0x01, 0x00, 0x00, 0x00 };
        private static readonly int[] Ffx2DropQtyFixed = new int[] { 0, 1, 2, 4, 5, 6 };

        private const int Ffx2RvaStealQtySpot = 0x00219CF5;
        private static readonly byte[] Ffx2StealQtyOrig = new byte[] {
            0x89, 0x47, 0x20, 0x5F, 0x5E, 0x8B, 0xC3, 0x5B, 0x5D, 0xC3, 0x5E, 0x8B,
            0xC3, 0x5B, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
        };
        private static readonly int[] Ffx2StealQtyFixed = new int[] { 0, 1, 16, 17, 19, 20, 21, 22, 23 };

        private static readonly CodePatch Ffx2PatchBribe1Gil = new CodePatch(
            "FFX-2 わいろ／オメデトウ！1ギル", 0x002417A9,
            new byte[] { 0xE8, 0x22, 0xC8, 0x23, 0x00, 0x8B, 0xC8 },
            new byte[] { 0xDD, 0xD8, 0xB8, 0x00, 0x01, 0x00, 0x00 });

        private const int Ffx2RvaExpMultSpot = 0x0022456D;
        private static readonly byte[] Ffx2ExpMultOrig = new byte[] { 0x8B, 0x45, 0x10, 0xF6, 0xC1, 0x40, 0x74, 0x02, 0x03, 0xC0 };
        private static readonly int[] Ffx2ExpMultFixed = new int[] { 0, 1, 2, 4, 5, 6, 7, 8, 9 };

        private const int Ffx2RvaApMultSpot = 0x002355F7;
        private static readonly byte[] Ffx2ApMultOrig = new byte[] {
            0xF7, 0xC2, 0x00, 0x10, 0x00, 0x00, 0x74, 0x08, 0x8B, 0x45,
            0x0C, 0x8D, 0x0C, 0x00, 0xEB, 0x03, 0x8B, 0x4D, 0x0C
        };
        private static readonly int[] Ffx2ApMultFixed = new int[] { 0, 1, 2, 4, 5, 6, 7, 8, 9, 10 };

        private const int Ffx2RvaGilMultFlag = 0x009F68D7;
        private const int Ffx2RvaGilMultImm = 0x002246F9;

        private const int Ffx2RvaFlagScan = 0x009F68D9;
        private const int Ffx2RvaFlagDmg99999 = 0x009F68D4;
        private const int Ffx2RvaFlagCritical = 0x009F68CC;
        private const int Ffx2RvaFlagInvincible = 0x009F68D1;

        private const int Ffx2RvaSaveItemIds = 0x009FFE50;
        private const int Ffx2RvaSaveItemCounts = 0x00A00050;
        private const int Ffx2RvaSaveAccIds = 0x00A00190;
        private const int Ffx2RvaSaveAccCounts = 0x00A00290;
        private const int Ffx2RvaSaveGil = 0x009FFCE8;
        private const int Ffx2RvaSaveAlBhed = 0x009FFCF4;
        private const int Ffx2RvaSaveGarmentGrids = 0x009FFD14;
        private const int Ffx2RvaSaveDresspheres = 0x009FFD1C;

        private static readonly byte[] Nop2 = new byte[] { 0x90, 0x90 };

        private const int HotkeyDropSteal = 1;
        private const int HotkeySlotMode = 2;
        private const int HotkeyPhase2A = 3;
        private const int HotkeyPhase2B = 4;

        private readonly FFXMemoryClient _mem = new FFXMemoryClient();
        private readonly Timer _pollTimer = new Timer();
        private bool _suppressEvents;

        // Header & Tabs
        private Label _lblConnection;
        private Button _btnPresetComfort;
        private Button _btnResetAll;
        private TabControl _tabGames;
        private TabPage _tabFfx;
        private TabPage _tabFfx2;

        // FF10 Controls
        private CheckBox _ffxChkItemDrop100;
        private CheckBox _ffxChkEquipDrop100;
        private CheckBox _ffxChkEquip4Slots;
        private CheckBox _ffxChkSteal100;
        private CheckBox _ffxChkStealNoDecay;
        private RadioButton _ffxRadSlotNormal;
        private RadioButton _ffxRadSlotRare;
        private RadioButton _ffxRadSlotCommon;
        private ComboBox _ffxCmbDropQty;
        private ComboBox _ffxCmbStealQty;
        private CheckBox _ffxChkAllPartyAp;
        private CheckBox _ffxChkBribe1Gil;
        private CheckBox _ffxChkCapture10;
        private CheckBox _ffxChkSensor;
        private CheckBox _ffxChkOverkill;
        private CheckBox _ffxChkCritical;
        private CheckBox _ffxChkInvincible;
        private ComboBox _ffxCmbApMult;
        private ComboBox _ffxCmbGilMult;

        // FF10-2 Controls
        private CheckBox _ffx2ChkItemDrop100;
        private CheckBox _ffx2ChkSteal100;
        private CheckBox _ffx2ChkStealNoDecay;
        private RadioButton _ffx2RadSlotNormal;
        private RadioButton _ffx2RadSlotRare;
        private RadioButton _ffx2RadSlotCommon;
        private ComboBox _ffx2CmbDropQty;
        private ComboBox _ffx2CmbStealQty;
        private CheckBox _ffx2ChkBribe1Gil;
        private CheckBox _ffx2ChkScan;
        private CheckBox _ffx2ChkDmg99999;
        private CheckBox _ffx2ChkCritical;
        private CheckBox _ffx2ChkInvincible;
        private ComboBox _ffx2CmbExpMult;
        private ComboBox _ffx2CmbApMult;
        private ComboBox _ffx2CmbGilMult;

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
            Text = "FF10 / FF10-2 快適化ツール (FFX & FFX-2 Comfort Tool)";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(654, 672);
            Font = new Font("Meiryo UI", 9f, FontStyle.Regular);
            BackColor = Color.FromArgb(245, 247, 250);

            // Top Banner Panel
            Panel headerPanel = new Panel();
            headerPanel.BackColor = Color.FromArgb(30, 41, 59);
            headerPanel.Location = new Point(0, 0);
            headerPanel.Size = new Size(654, 56);
            Controls.Add(headerPanel);

            _lblConnection = new Label();
            _lblConnection.ForeColor = Color.FromArgb(251, 191, 36);
            _lblConnection.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            _lblConnection.Location = new Point(14, 17);
            _lblConnection.Size = new Size(406, 24);
            _lblConnection.Text = "● FFX.exe / FFX-2.exe 待機中...";
            headerPanel.Controls.Add(_lblConnection);

            _btnPresetComfort = new Button();
            _btnPresetComfort.Text = "快適セット ON";
            _btnPresetComfort.FlatStyle = FlatStyle.Flat;
            _btnPresetComfort.BackColor = Color.FromArgb(37, 99, 235);
            _btnPresetComfort.ForeColor = Color.White;
            _btnPresetComfort.FlatAppearance.BorderSize = 0;
            _btnPresetComfort.Location = new Point(426, 13);
            _btnPresetComfort.Size = new Size(106, 30);
            _btnPresetComfort.Click += BtnPresetComfort_Click;
            headerPanel.Controls.Add(_btnPresetComfort);

            _btnResetAll = new Button();
            _btnResetAll.Text = "すべて OFF";
            _btnResetAll.FlatStyle = FlatStyle.Flat;
            _btnResetAll.BackColor = Color.FromArgb(71, 85, 105);
            _btnResetAll.ForeColor = Color.White;
            _btnResetAll.FlatAppearance.BorderSize = 0;
            _btnResetAll.Location = new Point(538, 13);
            _btnResetAll.Size = new Size(102, 30);
            _btnResetAll.Click += BtnResetAll_Click;
            headerPanel.Controls.Add(_btnResetAll);

            // TabControl for FF10 / FF10-2
            _tabGames = new TabControl();
            _tabGames.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            _tabGames.Location = new Point(8, 64);
            _tabGames.Size = new Size(638, 562);
            Controls.Add(_tabGames);

            _tabFfx = new TabPage("  FF10 (FFX.exe)  ");
            _tabFfx.BackColor = Color.FromArgb(245, 247, 250);
            _tabGames.TabPages.Add(_tabFfx);

            _tabFfx2 = new TabPage("  FF10-2 (FFX-2.exe)  ");
            _tabFfx2.BackColor = Color.FromArgb(245, 247, 250);
            _tabGames.TabPages.Add(_tabFfx2);

            BuildFfxTab(_tabFfx);
            BuildFfx2Tab(_tabFfx2);

            // Status Footer
            Panel footerPanel = new Panel();
            footerPanel.BackColor = Color.FromArgb(226, 232, 240);
            footerPanel.Location = new Point(0, 632);
            footerPanel.Size = new Size(654, 40);
            Controls.Add(footerPanel);

            _lblStatus = new Label();
            _lblStatus.Font = new Font("Meiryo UI", 8.5f, FontStyle.Regular);
            _lblStatus.ForeColor = Color.FromArgb(30, 41, 59);
            _lblStatus.Location = new Point(12, 10);
            _lblStatus.Size = new Size(630, 20);
            _lblStatus.Text = "準備完了: FF10 または FF10-2 を起動すると自動判別して設定を適用します。";
            footerPanel.Controls.Add(_lblStatus);
        }

        private void BuildFfxTab(TabPage page)
        {
            GroupBox grp1 = CreateGroupBox(page, "Phase 1：ドロップ ＆ 盗む 快適化  [F5: 100%一括 / F6: 枠切替]", 6, 6, 618, 204);
            _ffxChkItemDrop100 = CreateCheckBox(grp1, "アイテムドロップ率 100%", 14, 26, 250, OnFfxPatchControlChanged);
            _ffxChkEquipDrop100 = CreateCheckBox(grp1, "装備ドロップ率 100%", 14, 54, 250, OnFfxPatchControlChanged);
            _ffxChkEquip4Slots = CreateCheckBox(grp1, "ドロップ装備 4スロット固定", 14, 82, 250, OnFfxPatchControlChanged);
            _ffxChkSteal100 = CreateCheckBox(grp1, "「盗む／ぶんどる」成功率 100%", 306, 26, 290, OnFfxPatchControlChanged);
            _ffxChkStealNoDecay = CreateCheckBox(grp1, "同じ敵から何回でも100%盗める", 306, 54, 290, OnFfxPatchControlChanged);

            CreateSlotModePanel(grp1, 14, 112, out _ffxRadSlotNormal, out _ffxRadSlotRare, out _ffxRadSlotCommon, OnFfxSlotModeChanged);

            CreateLabel(grp1, "ドロップ個数倍率:", 14, 166, 126);
            _ffxCmbDropQty = CreateMultiplierCombo(grp1, 144, 162, 130, GetLootMultOptions(), OnFfxDropQtyChanged);

            CreateLabel(grp1, "盗む個数倍率:", 306, 166, 106);
            _ffxCmbStealQty = CreateMultiplierCombo(grp1, 416, 162, 140, GetLootMultOptions(), OnFfxStealQtyChanged);

            GroupBox grp2 = CreateGroupBox(page, "Phase 2：バトル・育成・収集 快適化  [F7: 全員AP / F8: 常時オーバーキル]", 6, 216, 618, 174);
            _ffxChkAllPartyAp = CreateCheckBox(grp2, "控えメンバーにもAP 100%分配 (全員AP)", 14, 26, 286, OnFfxPatchControlChanged);
            _ffxChkBribe1Gil = CreateCheckBox(grp2, "わいろ 1ギルで100%成功＆最大個数", 14, 54, 286, OnFfxPatchControlChanged);
            _ffxChkCapture10 = CreateCheckBox(grp2, "モンスター捕獲 1回で10体カウント", 14, 82, 286, OnFfxPatchControlChanged);

            _ffxChkSensor = CreateCheckBox(grp2, "常時「みやぶる（センサー）」表示", 316, 26, 286, OnFfxFlagCheckChanged);
            _ffxChkOverkill = CreateCheckBox(grp2, "常時オーバーキル (Overkill)", 316, 54, 286, OnFfxFlagCheckChanged);
            _ffxChkCritical = CreateCheckBox(grp2, "常時クリティカル", 316, 82, 286, OnFfxFlagCheckChanged);
            _ffxChkInvincible = CreateCheckBox(grp2, "味方無敵 (Player Invincible)", 316, 110, 286, OnFfxFlagCheckChanged);

            CreateLabel(grp2, "獲得AP倍率:", 14, 138, 96);
            _ffxCmbApMult = CreateMultiplierCombo(grp2, 114, 134, 120, GetRewardMultOptions(), OnFfxApMultChanged);

            CreateLabel(grp2, "獲得ギル倍率:", 316, 138, 102);
            _ffxCmbGilMult = CreateMultiplierCombo(grp2, 422, 134, 120, GetRewardMultOptions(), OnFfxGilMultChanged);

            GroupBox grp3 = CreateGroupBox(page, "Phase 3：ワンクリック便利機能（セーブデータ即時編集）", 6, 396, 618, 128);
            CreateSaveNoteLabel(grp3);

            CreateActionButton(grp3, "所持中アイテム全種 99個化", 14, 46, 188, 32, BtnFfxMaxItems_Click);
            CreateActionButton(grp3, "所持ギル +1,000,000", 214, 46, 188, 32, BtnFfxAddGil_Click);
            CreateActionButton(grp3, "所持ギル 999,999,999 (MAX)", 414, 46, 188, 32, BtnFfxMaxGil_Click);

            CreateActionButton(grp3, "味方全員 S.Lv 99", 14, 86, 188, 32, BtnFfxMaxSlv_Click);
            CreateActionButton(grp3, "アルベド語辞書 全26巻コンプ", 214, 86, 188, 32, BtnFfxAlBhedAll_Click);
            CreateActionButton(grp3, "訓練場 全104種×10体捕獲済", 414, 86, 188, 32, BtnFfxArenaAll_Click);
        }

        private void BuildFfx2Tab(TabPage page)
        {
            GroupBox grp1 = CreateGroupBox(page, "Phase 1：ドロップ ＆ 盗む 快適化  [F5: 100%一括 / F6: 枠切替]", 6, 6, 618, 204);
            _ffx2ChkItemDrop100 = CreateCheckBox(grp1, "アイテムドロップ率 100%", 14, 26, 250, OnFfx2PatchControlChanged);
            _ffx2ChkSteal100 = CreateCheckBox(grp1, "「盗む」成功率 100%", 306, 26, 290, OnFfx2PatchControlChanged);
            _ffx2ChkStealNoDecay = CreateCheckBox(grp1, "同じ敵から何回でも100%盗める", 306, 54, 290, OnFfx2PatchControlChanged);

            CreateLabel(grp1, "※FF10-2ではドレスやリザルトプレート等で補助効果が付きます", 14, 58, 286);
            CreateSlotModePanel(grp1, 14, 112, out _ffx2RadSlotNormal, out _ffx2RadSlotRare, out _ffx2RadSlotCommon, OnFfx2SlotModeChanged);

            CreateLabel(grp1, "ドロップ個数倍率:", 14, 166, 126);
            _ffx2CmbDropQty = CreateMultiplierCombo(grp1, 144, 162, 130, GetLootMultOptions(), OnFfx2DropQtyChanged);

            CreateLabel(grp1, "盗む個数倍率:", 306, 166, 106);
            _ffx2CmbStealQty = CreateMultiplierCombo(grp1, 416, 162, 140, GetLootMultOptions(), OnFfx2StealQtyChanged);

            GroupBox grp2 = CreateGroupBox(page, "Phase 2：バトル・育成・ドレスフィア快適化  [F7: みやぶる / F8: 99999ダメ]", 6, 216, 618, 174);
            _ffx2ChkBribe1Gil = CreateCheckBox(grp2, "わいろ／オメデトウ！1ギルで100%成功", 14, 26, 290, OnFfx2PatchControlChanged);
            _ffx2ChkScan = CreateCheckBox(grp2, "常時「みやぶる（ライブラ）」表示", 316, 26, 286, OnFfx2FlagCheckChanged);
            _ffx2ChkDmg99999 = CreateCheckBox(grp2, "常時 99999 ダメージ", 316, 54, 286, OnFfx2FlagCheckChanged);
            _ffx2ChkCritical = CreateCheckBox(grp2, "常時クリティカル", 316, 82, 286, OnFfx2FlagCheckChanged);
            _ffx2ChkInvincible = CreateCheckBox(grp2, "味方無敵 (Player Invincible)", 316, 110, 286, OnFfx2FlagCheckChanged);

            CreateLabel(grp2, "獲得EXP倍率:", 14, 62, 106);
            _ffx2CmbExpMult = CreateMultiplierCombo(grp2, 126, 58, 120, GetRewardMultOptions(), OnFfx2ExpMultChanged);

            CreateLabel(grp2, "獲得AP倍率 (ドレス):", 14, 98, 112);
            _ffx2CmbApMult = CreateMultiplierCombo(grp2, 126, 94, 120, GetRewardMultOptions(), OnFfx2ApMultChanged);

            CreateLabel(grp2, "獲得ギル倍率:", 14, 138, 106);
            _ffx2CmbGilMult = CreateMultiplierCombo(grp2, 126, 134, 120, GetRewardMultOptions(), OnFfx2GilMultChanged);

            GroupBox grp3 = CreateGroupBox(page, "Phase 3：ワンクリック便利機能（セーブデータ即時編集）", 6, 396, 618, 128);
            CreateSaveNoteLabel(grp3);

            CreateActionButton(grp3, "所持中アイテム全種 99個化", 14, 46, 188, 32, BtnFfx2MaxItems_Click);
            CreateActionButton(grp3, "所持中アクセサリ全種 99個化", 214, 46, 188, 32, BtnFfx2MaxAccs_Click);
            CreateActionButton(grp3, "所持ギル +1,000,000", 414, 46, 188, 32, BtnFfx2AddGil_Click);

            CreateActionButton(grp3, "所持ギル 999,999,999 (MAX)", 14, 86, 188, 32, BtnFfx2MaxGil_Click);
            CreateActionButton(grp3, "アルベド語辞書 全26巻コンプ", 214, 86, 188, 32, BtnFfx2AlBhedAll_Click);
            CreateActionButton(grp3, "全ドレス(3個)＆リザルト解放", 414, 86, 188, 32, BtnFfx2AllJobs_Click);
        }

        private static MultiplierOption[] GetLootMultOptions()
        {
            return new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×4", 4),
                new MultiplierOption("×10", 10),
                new MultiplierOption("99個 (×99)", 99)
            };
        }

        private static MultiplierOption[] GetRewardMultOptions()
        {
            return new MultiplierOption[] {
                new MultiplierOption("×1 (通常)", 1),
                new MultiplierOption("×2", 2),
                new MultiplierOption("×5", 5),
                new MultiplierOption("×10", 10),
                new MultiplierOption("×50", 50),
                new MultiplierOption("×100", 100)
            };
        }

        private static GroupBox CreateGroupBox(Control parent, string text, int x, int y, int w, int h)
        {
            GroupBox grp = new GroupBox();
            grp.Text = text;
            grp.Font = new Font("Meiryo UI", 8.75f, FontStyle.Bold);
            grp.ForeColor = Color.FromArgb(30, 58, 138);
            grp.Location = new Point(x, y);
            grp.Size = new Size(w, h);
            parent.Controls.Add(grp);
            return grp;
        }

        private static void CreateSlotModePanel(
            Control parent, int x, int y,
            out RadioButton radNormal, out RadioButton radRare, out RadioButton radCommon,
            EventHandler onChanged)
        {
            Panel pnl = new Panel();
            pnl.BackColor = Color.FromArgb(238, 242, 248);
            pnl.Location = new Point(x, y);
            pnl.Size = new Size(590, 40);
            parent.Controls.Add(pnl);

            Label lbl = new Label();
            lbl.Text = "枠選択 [F6]:";
            lbl.Font = new Font("Meiryo UI", 9f, FontStyle.Bold);
            lbl.ForeColor = Color.Black;
            lbl.Location = new Point(8, 10);
            lbl.Size = new Size(92, 20);
            pnl.Controls.Add(lbl);

            radNormal = CreateRadio(pnl, "通常確率 (7/8・1/8)", 102, 9, 160, true, onChanged);
            radRare = CreateRadio(pnl, "レア枠 100%", 272, 9, 138, false, onChanged);
            radCommon = CreateRadio(pnl, "通常枠 100%", 420, 9, 150, false, onChanged);
        }

        private static void CreateSaveNoteLabel(Control parent)
        {
            Label lbl = new Label();
            lbl.Text = "※セーブデータロード後に実行してください（表示はメニュー開閉またはバトル後に更新されます）";
            lbl.Font = new Font("Meiryo UI", 8f, FontStyle.Regular);
            lbl.ForeColor = Color.FromArgb(80, 90, 105);
            lbl.Location = new Point(14, 22);
            lbl.Size = new Size(590, 18);
            parent.Controls.Add(lbl);
        }

        private static CheckBox CreateCheckBox(Control parent, string text, int x, int y, int w, EventHandler onChanged)
        {
            CheckBox chk = new CheckBox();
            chk.Text = text;
            chk.Font = new Font("Meiryo UI", 8.75f, FontStyle.Regular);
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
            rad.Font = new Font("Meiryo UI", 8.75f, FontStyle.Regular);
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
            lbl.Font = new Font("Meiryo UI", 8.5f, FontStyle.Regular);
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
            cmb.Font = new Font("Meiryo UI", 8.75f, FontStyle.Regular);
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
            btn.Font = new Font("Meiryo UI", 8.5f, FontStyle.Regular);
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
            if (!NativeMethods.RegisterHotKey(Handle, HotkeyPhase2A, NativeMethods.MOD_NONE, NativeMethods.VK_F7)) failed.Add("F7");
            if (!NativeMethods.RegisterHotKey(Handle, HotkeyPhase2B, NativeMethods.MOD_NONE, NativeMethods.VK_F8)) failed.Add("F8");
            if (failed.Count > 0)
            {
                SetStatus("注意: ホットキー登録失敗 (" + string.Join(", ", failed.ToArray()) + ") - 他アプリで使用中");
            }
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            NativeMethods.UnregisterHotKey(Handle, HotkeyDropSteal);
            NativeMethods.UnregisterHotKey(Handle, HotkeySlotMode);
            NativeMethods.UnregisterHotKey(Handle, HotkeyPhase2A);
            NativeMethods.UnregisterHotKey(Handle, HotkeyPhase2B);
            _pollTimer.Stop();
            _mem.Dispose();
            base.OnFormClosed(e);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == NativeMethods.WM_HOTKEY)
            {
                HandleHotkey(m.WParam.ToInt32());
                return;
            }
            base.WndProc(ref m);
        }

        private GameKind GetActiveTargetGame()
        {
            if (_mem.IsAttached)
            {
                return _mem.AttachedGame;
            }
            return (_tabGames.SelectedIndex == 1) ? GameKind.FFX2 : GameKind.FFX;
        }

        private void HandleHotkey(int id)
        {
            GameKind game = GetActiveTargetGame();
            if (game == GameKind.FFX2)
            {
                HandleFfx2Hotkey(id);
            }
            else
            {
                HandleFfxHotkey(id);
            }
        }

        private void HandleFfxHotkey(int id)
        {
            switch (id)
            {
                case HotkeyDropSteal:
                    bool allOn = _ffxChkItemDrop100.Checked && _ffxChkEquipDrop100.Checked && _ffxChkSteal100.Checked && _ffxChkStealNoDecay.Checked;
                    bool nextState = !allOn;
                    _suppressEvents = true;
                    _ffxChkItemDrop100.Checked = nextState;
                    _ffxChkEquipDrop100.Checked = nextState;
                    _ffxChkSteal100.Checked = nextState;
                    _ffxChkStealNoDecay.Checked = nextState;
                    _suppressEvents = false;
                    ApplyFfxTogglePatches();
                    SetStatus("[F5][FF10] ドロップ＆盗む 100% 一括: " + (nextState ? "ON" : "OFF"));
                    break;

                case HotkeySlotMode:
                    CycleSlotRadios(_ffxRadSlotNormal, _ffxRadSlotRare, _ffxRadSlotCommon);
                    SetStatus("[F6][FF10] 枠選択切替: " + GetSlotModeLabel(GetSlotMode(_ffxRadSlotRare, _ffxRadSlotCommon)));
                    break;

                case HotkeyPhase2A:
                    _ffxChkAllPartyAp.Checked = !_ffxChkAllPartyAp.Checked;
                    SetStatus("[F7][FF10] 全員AP獲得: " + (_ffxChkAllPartyAp.Checked ? "ON" : "OFF"));
                    break;

                case HotkeyPhase2B:
                    _ffxChkOverkill.Checked = !_ffxChkOverkill.Checked;
                    SetStatus("[F8][FF10] 常時オーバーキル: " + (_ffxChkOverkill.Checked ? "ON" : "OFF"));
                    break;
            }
        }

        private void HandleFfx2Hotkey(int id)
        {
            switch (id)
            {
                case HotkeyDropSteal:
                    bool allOn = _ffx2ChkItemDrop100.Checked && _ffx2ChkSteal100.Checked && _ffx2ChkStealNoDecay.Checked;
                    bool nextState = !allOn;
                    _suppressEvents = true;
                    _ffx2ChkItemDrop100.Checked = nextState;
                    _ffx2ChkSteal100.Checked = nextState;
                    _ffx2ChkStealNoDecay.Checked = nextState;
                    _suppressEvents = false;
                    ApplyFfx2TogglePatches();
                    SetStatus("[F5][FF10-2] ドロップ＆盗む 100% 一括: " + (nextState ? "ON" : "OFF"));
                    break;

                case HotkeySlotMode:
                    CycleSlotRadios(_ffx2RadSlotNormal, _ffx2RadSlotRare, _ffx2RadSlotCommon);
                    SetStatus("[F6][FF10-2] 枠選択切替: " + GetSlotModeLabel(GetSlotMode(_ffx2RadSlotRare, _ffx2RadSlotCommon)));
                    break;

                case HotkeyPhase2A:
                    _ffx2ChkScan.Checked = !_ffx2ChkScan.Checked;
                    SetStatus("[F7][FF10-2] 常時みやぶる: " + (_ffx2ChkScan.Checked ? "ON" : "OFF"));
                    break;

                case HotkeyPhase2B:
                    _ffx2ChkDmg99999.Checked = !_ffx2ChkDmg99999.Checked;
                    SetStatus("[F8][FF10-2] 常時 99999 ダメージ: " + (_ffx2ChkDmg99999.Checked ? "ON" : "OFF"));
                    break;
            }
        }

        private static void CycleSlotRadios(RadioButton normal, RadioButton rare, RadioButton common)
        {
            if (normal.Checked) rare.Checked = true;
            else if (rare.Checked) common.Checked = true;
            else normal.Checked = true;
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
                    ? "● FFX.exe / FFX-2.exe 待機中..."
                    : "● " + _mem.LastError;
                return;
            }

            if (newlyAttached)
            {
                if (_mem.AttachedGame == GameKind.FFX)
                {
                    _tabGames.SelectedIndex = 0;
                    ApplyAllFfxSettings();
                    SetStatus(string.Format("FFX.exe (PID: {0}) に接続し、現在の設定を適用しました。", _mem.ProcessId));
                }
                else if (_mem.AttachedGame == GameKind.FFX2)
                {
                    _tabGames.SelectedIndex = 1;
                    ApplyAllFfx2Settings();
                    SetStatus(string.Format("FFX-2.exe (PID: {0}) に接続し、現在の設定を適用しました。", _mem.ProcessId));
                }
            }
            else
            {
                KeepDataFlagsSynced();
            }

            int gilRva = (_mem.AttachedGame == GameKind.FFX2) ? Ffx2RvaSaveGil : FfxRvaSaveGil;
            string gameTag = (_mem.AttachedGame == GameKind.FFX2) ? "FF10-2" : "FF10";
            uint gil;
            string gilText = _mem.ReadUInt32(gilRva, out gil)
                ? string.Format("{0:N0} G", gil)
                : "--- G";

            _lblConnection.ForeColor = Color.FromArgb(74, 222, 128);
            _lblConnection.Text = string.Format("● [{0}] 接続中 (PID: {1}, Base: 0x{2:X8}, ギル: {3})",
                gameTag, _mem.ProcessId, unchecked((uint)_mem.BaseAddress.ToInt32()), gilText);
        }

        private void SetStatus(string message)
        {
            _lblStatus.Text = string.Format("[{0:HH:mm:ss}] {1}", DateTime.Now, message);
        }

        private bool EnsureAttachedForGame(GameKind expectedGame)
        {
            bool newlyAttached;
            if (!_mem.TryAttach(out newlyAttached))
            {
                SetStatus("未接続: " + (string.IsNullOrEmpty(_mem.LastError) ? "対象ゲームが起動していません" : _mem.LastError));
                return false;
            }
            if (newlyAttached)
            {
                if (_mem.AttachedGame == GameKind.FFX) ApplyAllFfxSettings();
                else if (_mem.AttachedGame == GameKind.FFX2) ApplyAllFfx2Settings();
            }
            if (_mem.AttachedGame != expectedGame)
            {
                string expectedName = (expectedGame == GameKind.FFX2) ? "FFX-2.exe" : "FFX.exe";
                string actualName = (_mem.AttachedGame == GameKind.FFX2) ? "FFX-2.exe" : "FFX.exe";
                SetStatus(string.Format("現在 {0} に接続中のため、{1} の操作は実行できません。", actualName, expectedName));
                return false;
            }
            return true;
        }

        // --- Header Preset / Reset Buttons ---

        private void BtnPresetComfort_Click(object sender, EventArgs e)
        {
            GameKind game = GetActiveTargetGame();
            if (game == GameKind.FFX2)
            {
                _suppressEvents = true;
                _ffx2ChkItemDrop100.Checked = true;
                _ffx2ChkSteal100.Checked = true;
                _ffx2ChkStealNoDecay.Checked = true;
                _ffx2ChkBribe1Gil.Checked = true;
                _ffx2ChkScan.Checked = true;
                _suppressEvents = false;
                ApplyAllFfx2Settings();
                SetStatus("[FF10-2] 快適セット (ドロップ/盗む100%・わいろ1G・みやぶる) をONにしました。");
            }
            else
            {
                _suppressEvents = true;
                _ffxChkItemDrop100.Checked = true;
                _ffxChkEquipDrop100.Checked = true;
                _ffxChkEquip4Slots.Checked = true;
                _ffxChkSteal100.Checked = true;
                _ffxChkStealNoDecay.Checked = true;
                _ffxChkAllPartyAp.Checked = true;
                _ffxChkBribe1Gil.Checked = true;
                _ffxChkCapture10.Checked = true;
                _ffxChkSensor.Checked = true;
                _suppressEvents = false;
                ApplyAllFfxSettings();
                SetStatus("[FF10] 快適セット (ドロップ/盗む100%・4スロ・全員AP・わいろ1G・捕獲10・みやぶる) をONにしました。");
            }
        }

        private void BtnResetAll_Click(object sender, EventArgs e)
        {
            GameKind game = GetActiveTargetGame();
            if (game == GameKind.FFX2)
            {
                _suppressEvents = true;
                _ffx2ChkItemDrop100.Checked = false;
                _ffx2ChkSteal100.Checked = false;
                _ffx2ChkStealNoDecay.Checked = false;
                _ffx2RadSlotNormal.Checked = true;
                _ffx2CmbDropQty.SelectedIndex = 0;
                _ffx2CmbStealQty.SelectedIndex = 0;
                _ffx2ChkBribe1Gil.Checked = false;
                _ffx2ChkScan.Checked = false;
                _ffx2ChkDmg99999.Checked = false;
                _ffx2ChkCritical.Checked = false;
                _ffx2ChkInvincible.Checked = false;
                _ffx2CmbExpMult.SelectedIndex = 0;
                _ffx2CmbApMult.SelectedIndex = 0;
                _ffx2CmbGilMult.SelectedIndex = 0;
                _suppressEvents = false;
                ApplyAllFfx2Settings();
                SetStatus("[FF10-2] すべてのパッチ・倍率・補助フラグを通常状態 (OFF) に戻しました。");
            }
            else
            {
                _suppressEvents = true;
                _ffxChkItemDrop100.Checked = false;
                _ffxChkEquipDrop100.Checked = false;
                _ffxChkEquip4Slots.Checked = false;
                _ffxChkSteal100.Checked = false;
                _ffxChkStealNoDecay.Checked = false;
                _ffxRadSlotNormal.Checked = true;
                _ffxCmbDropQty.SelectedIndex = 0;
                _ffxCmbStealQty.SelectedIndex = 0;
                _ffxChkAllPartyAp.Checked = false;
                _ffxChkBribe1Gil.Checked = false;
                _ffxChkCapture10.Checked = false;
                _ffxChkSensor.Checked = false;
                _ffxChkOverkill.Checked = false;
                _ffxChkCritical.Checked = false;
                _ffxChkInvincible.Checked = false;
                _ffxCmbApMult.SelectedIndex = 0;
                _ffxCmbGilMult.SelectedIndex = 0;
                _suppressEvents = false;
                ApplyAllFfxSettings();
                SetStatus("[FF10] すべてのパッチ・倍率・補助フラグを通常状態 (OFF) に戻しました。");
            }
        }

        // --- Shared Helpers ---

        private static SlotMode GetSlotMode(RadioButton rare, RadioButton common)
        {
            if (rare.Checked) return SlotMode.AlwaysRare;
            if (common.Checked) return SlotMode.AlwaysCommon;
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

        private void ApplySlotModeCommon(
            int rareFlagRva, int stealJumpRva, byte[] stealOrig,
            int dropJumpRva, byte[] dropOrig, SlotMode mode, string tag)
        {
            byte flag = (mode == SlotMode.AlwaysRare) ? (byte)0x01 : (byte)0x00;
            bool forceCommon = (mode == SlotMode.AlwaysCommon);

            CodePatch stealPatch = new CodePatch(tag + " 盗む枠", stealJumpRva, stealOrig, Nop2);
            CodePatch dropPatch = new CodePatch(tag + " ドロップ枠", dropJumpRva, dropOrig, Nop2);

            bool ok = _mem.WriteByte(rareFlagRva, flag);
            ok &= _mem.ApplyPatch(stealPatch, forceCommon);
            ok &= _mem.ApplyPatch(dropPatch, forceCommon);
            if (!ok) SetStatus("枠選択エラー: " + _mem.LastError);
        }

        private static byte GetSelectedMultiplier(ComboBox cmb)
        {
            MultiplierOption opt = cmb.SelectedItem as MultiplierOption;
            return (opt != null) ? opt.Value : (byte)1;
        }

        private void ApplyImulMultiplier(int flagRva, int immRva, byte mult, string label)
        {
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

        private void SyncDataByte(int rva, byte expected)
        {
            byte cur;
            if (_mem.ReadByte(rva, out cur) && cur != expected)
            {
                _mem.WriteByte(rva, expected);
            }
        }

        private void KeepDataFlagsSynced()
        {
            if (!_mem.IsAttached) return;
            if (_mem.AttachedGame == GameKind.FFX)
            {
                SyncDataByte(FfxRvaRareFlag, (GetSlotMode(_ffxRadSlotRare, _ffxRadSlotCommon) == SlotMode.AlwaysRare) ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaApMultFlag, (GetSelectedMultiplier(_ffxCmbApMult) > 1) ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaGilMultFlag, (GetSelectedMultiplier(_ffxCmbGilMult) > 1) ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaFlagSensor, _ffxChkSensor.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaFlagOverkill, _ffxChkOverkill.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaFlagCritical, _ffxChkCritical.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(FfxRvaFlagInvincible, _ffxChkInvincible.Checked ? (byte)0x01 : (byte)0x00);
            }
            else if (_mem.AttachedGame == GameKind.FFX2)
            {
                SyncDataByte(Ffx2RvaRareFlag, (GetSlotMode(_ffx2RadSlotRare, _ffx2RadSlotCommon) == SlotMode.AlwaysRare) ? (byte)0x01 : (byte)0x00);
                SyncDataByte(Ffx2RvaGilMultFlag, (GetSelectedMultiplier(_ffx2CmbGilMult) > 1) ? (byte)0x01 : (byte)0x00);
                SyncDataByte(Ffx2RvaFlagScan, _ffx2ChkScan.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(Ffx2RvaFlagDmg99999, _ffx2ChkDmg99999.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(Ffx2RvaFlagCritical, _ffx2ChkCritical.Checked ? (byte)0x01 : (byte)0x00);
                SyncDataByte(Ffx2RvaFlagInvincible, _ffx2ChkInvincible.Checked ? (byte)0x01 : (byte)0x00);
            }
        }

        private void MaxSaveInventorySlots(GameKind game, int idsRva, int countsRva, int slotCount, ushort typeMask, string itemKindLabel)
        {
            if (!EnsureAttachedForGame(game)) return;

            byte[] ids = _mem.ReadBytes(idsRva, slotCount * 2);
            if (ids == null)
            {
                SetStatus(itemKindLabel + "読み取り失敗: " + _mem.LastError);
                return;
            }

            int updated = 0;
            for (int i = 0; i < slotCount; i++)
            {
                ushort id = BitConverter.ToUInt16(ids, i * 2);
                if (id != 0x00FF && (id & 0xF000) == typeMask)
                {
                    if (_mem.WriteByte(countsRva + i, 99))
                    {
                        updated++;
                    }
                }
            }
            SetStatus(string.Format("所持中{0} {1} 種類をすべて 99 個にしました。", itemKindLabel, updated));
        }

        private void AddSaveGil(GameKind game, int gilRva, uint delta)
        {
            if (!EnsureAttachedForGame(game)) return;

            uint cur;
            if (!_mem.ReadUInt32(gilRva, out cur))
            {
                SetStatus("ギル読み取り失敗: " + _mem.LastError);
                return;
            }

            ulong next = (ulong)cur + (ulong)delta;
            if (next > 999999999UL) next = 999999999UL;

            SetStatus(_mem.WriteUInt32(gilRva, (uint)next)
                ? string.Format("所持ギルを更新しました: {0:N0} G", next)
                : "ギル更新失敗: " + _mem.LastError);
        }

        private void SetSaveGilMax(GameKind game, int gilRva)
        {
            if (!EnsureAttachedForGame(game)) return;
            SetStatus(_mem.WriteUInt32(gilRva, 999999999U)
                ? "所持ギルを 999,999,999 G (MAX) にしました。"
                : "ギル更新失敗: " + _mem.LastError);
        }

        private void SetSaveAlBhedAll(GameKind game, int alBhedRva)
        {
            if (!EnsureAttachedForGame(game)) return;
            SetStatus(_mem.WriteUInt32(alBhedRva, 0x03FFFFFFU)
                ? "アルベド語辞書 全26巻をコンプリートしました。"
                : "アルベド語辞書更新失敗: " + _mem.LastError);
        }

        // ============================================================
        // FF10 Event Handlers & Patch Appliers
        // ============================================================

        private void OnFfxPatchControlChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxTogglePatches();
        }

        private void OnFfxSlotModeChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            RadioButton rad = sender as RadioButton;
            if (rad == null || rad.Checked) ApplyFfxSlotMode();
        }

        private void OnFfxDropQtyChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxDropQtyMultiplier();
        }

        private void OnFfxStealQtyChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxStealQtyMultiplier();
        }

        private void OnFfxApMultChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxApMultiplier();
        }

        private void OnFfxGilMultChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxGilMultiplier();
        }

        private void OnFfxFlagCheckChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfxBattleFlags();
        }

        private void ApplyAllFfxSettings()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            ApplyFfxTogglePatches();
            ApplyFfxSlotMode();
            ApplyFfxDropQtyMultiplier();
            ApplyFfxStealQtyMultiplier();
            ApplyFfxApMultiplier();
            ApplyFfxGilMultiplier();
            ApplyFfxBattleFlags();
        }

        private void ApplyFfxTogglePatches()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            bool ok = true;
            ok &= _mem.ApplyPatch(FfxPatchItemDrop100, _ffxChkItemDrop100.Checked);
            ok &= _mem.ApplyPatch(FfxPatchEquipDrop100, _ffxChkEquipDrop100.Checked);
            ok &= _mem.ApplyPatch(FfxPatchEquip4Slots, _ffxChkEquip4Slots.Checked);
            ok &= _mem.ApplyPatch(FfxPatchSteal100, _ffxChkSteal100.Checked);
            ok &= _mem.ApplyPatch(FfxPatchStealNoDecay, _ffxChkStealNoDecay.Checked);
            ok &= _mem.ApplyPatch(FfxPatchAllPartyAp1, _ffxChkAllPartyAp.Checked);
            ok &= _mem.ApplyPatch(FfxPatchAllPartyAp2, _ffxChkAllPartyAp.Checked);
            ok &= _mem.ApplyPatch(FfxPatchBribe1, _ffxChkBribe1Gil.Checked);
            ok &= _mem.ApplyPatch(FfxPatchBribe2, _ffxChkBribe1Gil.Checked);
            ok &= _mem.ApplyPatch(FfxPatchCapture10, _ffxChkCapture10.Checked);
            if (!ok) SetStatus("[FF10] パッチ適用エラー: " + _mem.LastError);
        }

        private void ApplyFfxSlotMode()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            ApplySlotModeCommon(
                FfxRvaRareFlag, FfxRvaStealCommonRareJump, FfxStealJumpOrig,
                FfxRvaDropCommonRareJump, FfxDropJumpOrig,
                GetSlotMode(_ffxRadSlotRare, _ffxRadSlotCommon), "FF10");
        }

        private void ApplyFfxDropQtyMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            byte mult = GetSelectedMultiplier(_ffxCmbDropQty);
            byte[] p1 = new byte[] { 0x6B, 0xF6, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x19 };
            byte[] p2 = new byte[] { 0x6B, 0xDB, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x1C };

            bool ok = _mem.ApplyVariablePatch(FfxRvaDropQtySpot1, FfxDropQtySpot1Orig, p1, mult > 1, FfxDropQtyFixed, "FFX ドロップ倍率(1)");
            ok &= _mem.ApplyVariablePatch(FfxRvaDropQtySpot2, FfxDropQtySpot2Orig, p2, mult > 1, FfxDropQtyFixed, "FFX ドロップ倍率(2)");
            if (!ok) SetStatus("[FF10] ドロップ倍率エラー: " + _mem.LastError);
        }

        private void ApplyFfxStealQtyMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            byte mult = GetSelectedMultiplier(_ffxCmbStealQty);
            byte[] p = new byte[] { 0x6B, 0x47, 0x08, mult, 0x66, 0x89, 0x47, 0x08, 0xEB, 0x2D };

            if (!_mem.ApplyVariablePatch(FfxRvaStealQtySpot, FfxStealQtySpotOrig, p, mult > 1, FfxStealQtyFixed, "FFX 盗む倍率"))
            {
                SetStatus("[FF10] 盗む倍率エラー: " + _mem.LastError);
            }
        }

        private void ApplyFfxApMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            ApplyImulMultiplier(FfxRvaApMultFlag, FfxRvaApMultImm, GetSelectedMultiplier(_ffxCmbApMult), "[FF10] AP倍率");
        }

        private void ApplyFfxGilMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            ApplyImulMultiplier(FfxRvaGilMultFlag, FfxRvaGilMultImm, GetSelectedMultiplier(_ffxCmbGilMult), "[FF10] ギル倍率");
        }

        private void ApplyFfxBattleFlags()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX) return;
            bool ok = true;
            ok &= _mem.WriteByte(FfxRvaFlagSensor, _ffxChkSensor.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(FfxRvaFlagOverkill, _ffxChkOverkill.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(FfxRvaFlagCritical, _ffxChkCritical.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(FfxRvaFlagInvincible, _ffxChkInvincible.Checked ? (byte)0x01 : (byte)0x00);
            if (!ok) SetStatus("[FF10] バトルフラグエラー: " + _mem.LastError);
        }

        private void BtnFfxMaxItems_Click(object sender, EventArgs e)
        {
            MaxSaveInventorySlots(GameKind.FFX, FfxRvaSaveItemIds, FfxRvaSaveItemCounts, 256, 0x2000, "アイテム");
        }

        private void BtnFfxAddGil_Click(object sender, EventArgs e)
        {
            AddSaveGil(GameKind.FFX, FfxRvaSaveGil, 1000000U);
        }

        private void BtnFfxMaxGil_Click(object sender, EventArgs e)
        {
            SetSaveGilMax(GameKind.FFX, FfxRvaSaveGil);
        }

        private void BtnFfxMaxSlv_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForGame(GameKind.FFX)) return;
            bool ok = true;
            for (int c = 0; c < 7; c++)
            {
                ok &= _mem.WriteByte(FfxRvaSavePlyBase + c * FfxPlyStructSize + FfxPlySlvOffset, 99);
            }
            SetStatus(ok
                ? "味方全員 (7人) のスフィアレベル (S.Lv) を 99 にしました。"
                : "S.Lv 更新エラー: " + _mem.LastError);
        }

        private void BtnFfxAlBhedAll_Click(object sender, EventArgs e)
        {
            SetSaveAlBhedAll(GameKind.FFX, FfxRvaSaveAlBhed);
        }

        private void BtnFfxArenaAll_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForGame(GameKind.FFX)) return;
            byte[] counts = new byte[104];
            for (int i = 0; i < counts.Length; i++) counts[i] = 10;
            SetStatus(_mem.WriteBytes(FfxRvaSaveArenaCaptures, counts, false)
                ? "訓練場モンスター 全104種を捕獲数 10 にしました。"
                : "訓練場捕獲更新失敗: " + _mem.LastError);
        }

        // ============================================================
        // FF10-2 Event Handlers & Patch Appliers
        // ============================================================

        private void OnFfx2PatchControlChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2TogglePatches();
        }

        private void OnFfx2SlotModeChanged(object sender, EventArgs e)
        {
            if (_suppressEvents) return;
            RadioButton rad = sender as RadioButton;
            if (rad == null || rad.Checked) ApplyFfx2SlotMode();
        }

        private void OnFfx2DropQtyChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2DropQtyMultiplier();
        }

        private void OnFfx2StealQtyChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2StealQtyMultiplier();
        }

        private void OnFfx2ExpMultChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2ExpMultiplier();
        }

        private void OnFfx2ApMultChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2ApMultiplier();
        }

        private void OnFfx2GilMultChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2GilMultiplier();
        }

        private void OnFfx2FlagCheckChanged(object sender, EventArgs e)
        {
            if (!_suppressEvents) ApplyFfx2BattleFlags();
        }

        private void ApplyAllFfx2Settings()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            ApplyFfx2TogglePatches();
            ApplyFfx2SlotMode();
            ApplyFfx2DropQtyMultiplier();
            ApplyFfx2StealQtyMultiplier();
            ApplyFfx2ExpMultiplier();
            ApplyFfx2ApMultiplier();
            ApplyFfx2GilMultiplier();
            ApplyFfx2BattleFlags();
        }

        private void ApplyFfx2TogglePatches()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            bool ok = true;
            ok &= _mem.ApplyPatch(Ffx2PatchItemDrop100, _ffx2ChkItemDrop100.Checked);
            ok &= _mem.ApplyPatch(Ffx2PatchSteal100, _ffx2ChkSteal100.Checked);
            ok &= _mem.ApplyPatch(Ffx2PatchStealNoDecay, _ffx2ChkStealNoDecay.Checked);
            ok &= _mem.ApplyPatch(Ffx2PatchBribe1Gil, _ffx2ChkBribe1Gil.Checked);
            if (!ok) SetStatus("[FF10-2] パッチ適用エラー: " + _mem.LastError);
        }

        private void ApplyFfx2SlotMode()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            ApplySlotModeCommon(
                Ffx2RvaRareFlag, Ffx2RvaStealCommonRareJump, Ffx2StealJumpOrig,
                Ffx2RvaDropCommonRareJump, Ffx2DropJumpOrig,
                GetSlotMode(_ffx2RadSlotRare, _ffx2RadSlotCommon), "FF10-2");
        }

        private void ApplyFfx2DropQtyMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            byte mult = GetSelectedMultiplier(_ffx2CmbDropQty);
            byte[] patched = new byte[] { 0xC7, 0x45, 0xF4, mult, 0x00, 0x00, 0x00 };

            if (!_mem.ApplyVariablePatch(Ffx2RvaDropQtySpot, Ffx2DropQtyOrig, patched, mult > 1, Ffx2DropQtyFixed, "FFX-2 ドロップ倍率"))
            {
                SetStatus("[FF10-2] ドロップ倍率エラー: " + _mem.LastError);
            }
        }

        private void ApplyFfx2StealQtyMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            byte mult = GetSelectedMultiplier(_ffx2CmbStealQty);
            byte[] patched = new byte[] {
                0xEB, 0x0E, 0x90, 0x5F, 0x5E, 0x8B, 0xC3, 0x5B, 0x5D, 0xC3, 0x5E, 0x8B,
                0xC3, 0x5B, 0x5D, 0xC3, 0x6B, 0xC0, mult, 0x89, 0x47, 0x20, 0xEB, 0xEB
            };

            if (!_mem.ApplyVariablePatch(Ffx2RvaStealQtySpot, Ffx2StealQtyOrig, patched, mult > 1, Ffx2StealQtyFixed, "FFX-2 盗む倍率"))
            {
                SetStatus("[FF10-2] 盗む倍率エラー: " + _mem.LastError);
            }
        }

        private void ApplyFfx2ExpMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            byte mult = GetSelectedMultiplier(_ffx2CmbExpMult);
            byte[] patched = new byte[] { 0x6B, 0x45, 0x10, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

            if (!_mem.ApplyVariablePatch(Ffx2RvaExpMultSpot, Ffx2ExpMultOrig, patched, mult > 1, Ffx2ExpMultFixed, "FFX-2 EXP倍率"))
            {
                SetStatus("[FF10-2] EXP倍率エラー: " + _mem.LastError);
            }
        }

        private void ApplyFfx2ApMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            byte mult = GetSelectedMultiplier(_ffx2CmbApMult);
            byte[] patched = new byte[] {
                0x6B, 0x4D, 0x0C, mult, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
            };

            if (!_mem.ApplyVariablePatch(Ffx2RvaApMultSpot, Ffx2ApMultOrig, patched, mult > 1, Ffx2ApMultFixed, "FFX-2 AP倍率"))
            {
                SetStatus("[FF10-2] AP倍率エラー: " + _mem.LastError);
            }
        }

        private void ApplyFfx2GilMultiplier()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            ApplyImulMultiplier(Ffx2RvaGilMultFlag, Ffx2RvaGilMultImm, GetSelectedMultiplier(_ffx2CmbGilMult), "[FF10-2] ギル倍率");
        }

        private void ApplyFfx2BattleFlags()
        {
            if (!_mem.IsAttached || _mem.AttachedGame != GameKind.FFX2) return;
            bool ok = true;
            ok &= _mem.WriteByte(Ffx2RvaFlagScan, _ffx2ChkScan.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(Ffx2RvaFlagDmg99999, _ffx2ChkDmg99999.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(Ffx2RvaFlagCritical, _ffx2ChkCritical.Checked ? (byte)0x01 : (byte)0x00);
            ok &= _mem.WriteByte(Ffx2RvaFlagInvincible, _ffx2ChkInvincible.Checked ? (byte)0x01 : (byte)0x00);
            if (!ok) SetStatus("[FF10-2] バトルフラグエラー: " + _mem.LastError);
        }

        private void BtnFfx2MaxItems_Click(object sender, EventArgs e)
        {
            MaxSaveInventorySlots(GameKind.FFX2, Ffx2RvaSaveItemIds, Ffx2RvaSaveItemCounts, 68, 0x2000, "アイテム");
        }

        private void BtnFfx2MaxAccs_Click(object sender, EventArgs e)
        {
            MaxSaveInventorySlots(GameKind.FFX2, Ffx2RvaSaveAccIds, Ffx2RvaSaveAccCounts, 128, 0x9000, "アクセサリ");
        }

        private void BtnFfx2AddGil_Click(object sender, EventArgs e)
        {
            AddSaveGil(GameKind.FFX2, Ffx2RvaSaveGil, 1000000U);
        }

        private void BtnFfx2MaxGil_Click(object sender, EventArgs e)
        {
            SetSaveGilMax(GameKind.FFX2, Ffx2RvaSaveGil);
        }

        private void BtnFfx2AlBhedAll_Click(object sender, EventArgs e)
        {
            SetSaveAlBhedAll(GameKind.FFX2, Ffx2RvaSaveAlBhed);
        }

        private void BtnFfx2AllJobs_Click(object sender, EventArgs e)
        {
            if (!EnsureAttachedForGame(GameKind.FFX2)) return;

            byte[] grids = new byte[8];
            for (int i = 0; i < grids.Length; i++) grids[i] = 0xFF;

            byte[] dresses = new byte[29];
            for (int i = 0; i < dresses.Length; i++) dresses[i] = 3;

            bool ok = _mem.WriteBytes(Ffx2RvaSaveGarmentGrids, grids, false);
            ok &= _mem.WriteBytes(Ffx2RvaSaveDresspheres + 1, dresses, false);
            SetStatus(ok
                ? "[FF10-2] 全ドレスフィア(各3個) ＆ 全リザルトプレート(64種) を解放しました。"
                : "[FF10-2] ドレスフィア解放失敗: " + _mem.LastError);
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
