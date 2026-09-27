#Requires -Version 5.1
<#
    Doomsday Client Scanner v3

    Local forensic scanner for traces of the Doomsday ghost client. It builds a list
    of files Java has touched (Prefetch, Recent shortcuts, NTFS USN journal), then
    inspects every archive among them by content, whatever its extension.

    Nothing leaves the machine. The only thing written is the JSON report.

    Examples:
        .\doomsday-scanner-v3.ps1
        .\doomsday-scanner-v3.ps1 -ScanPath "$env:APPDATA\.minecraft" -DebugLog
        .\doomsday-scanner-v3.ps1 -HashList .\hashes.txt -OutputPath C:\Reports
#>
param(
    # Extra folders swept recursively. Files are checked by content, not extension.
    [string[]]$ScanPath,
    # Folder (or .json file) for the report. Defaults to the Desktop.
    [string]$OutputPath,
    # Optional local list of SHA-256 hashes, one "<hash> [label]" per line.
    [string]$HashList,
    # USN activity newer than this is flagged as recent.
    [int]$RecentMinutes = 60,
    # Larger files are listed but not opened.
    [int]$MaxFileSizeMB = 256,
    [switch]$NoUsn,
    [switch]$NoJson,
    [switch]$DebugLog
)

$script:ScannerVersion = '3.0.0'
$script:Options = @{
    ScanPath      = $ScanPath
    OutputPath    = $OutputPath
    HashList      = $HashList
    RecentMinutes = [Math]::Max(1, $RecentMinutes)
    MaxFileBytes  = [long][Math]::Max(1, $MaxFileSizeMB) * 1MB
    NoUsn         = [bool]$NoUsn
    NoJson        = [bool]$NoJson
    DebugLog      = [bool]$DebugLog
}

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

# Bytecode fragments from known Doomsday builds (unchanged from v1.2).
# #2 is #1 shifted back by 8 bytes: they share 56 of their 64 bytes and normally
# match together, so they form one group and only count once at full weight.
$script:ByteSignatures = @(
    @{ Id = 'SIG1'; Name = 'Known byte signature #1'; Group = 'A'
       Hex = '6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800' }
    @{ Id = 'SIG2'; Name = 'Known byte signature #2'; Group = 'A'
       Hex = '0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16' }
    @{ Id = 'SIG3'; Name = 'Known byte signature #3'; Group = 'B'
       Hex = '5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3' }
)

# Class layout of the client: single-letter classes inside net/java.
# v1.2 searched these as raw substrings, so "net/java/f" also matched any
# net/java/f* class. v3 matches exact entry names, plus exact constant pool
# references for classes stored under other names.
$script:ExpectedClasses = @(
    'net/java/f', 'net/java/g', 'net/java/h', 'net/java/i', 'net/java/k', 'net/java/l',
    'net/java/m', 'net/java/r', 'net/java/s', 'net/java/t', 'net/java/y'
)

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

# Doomsday-specific evidence dominates on purpose:
#   - one signature group alone reaches MEDIUM (40); two groups, or a signature
#     plus 6+ expected classes, reach HIGH (70)
#   - the full class layout without any bytecode match stays MEDIUM
#   - generic traits (renamed archive, obfuscation, hidden attribute...) are capped
#     and can never create a detection on their own; they only add confidence
#   - context (Prefetch, USN, shortcuts) is capped too: it shows the file was used,
#     not what it is
$script:Weights = @{
    KnownHash        = 100 # exact SHA-256 from the local -HashList
    SignatureFirst   = 40  # first signature hit in a group
    SignatureExtra   = 5   # further signature of an already matched (overlapping) group
    ClassEntry       = 5   # each expected net/java/<x>.class present as an entry
    ClassReference   = 1   # expected class only seen as a constant pool reference
    ReferenceCap     = 5

    DisguisedExt     = 8   # JAR content behind an extension used to hide files
    RenamedExt       = 4   # JAR content with some other non-.jar extension
    Polyglot         = 6   # archive appended to non-executable data
    HiddenClassData  = 6   # bytecode stored under a non-.class entry name
    EncryptedClasses = 6   # 3+ .class entries that are not class files
    Obfuscated       = 3   # mostly 1-2 letter class names; Minecraft itself looks like this
    JavaAgent        = 5   # manifest declares an instrumentation agent
    HiddenAttribute  = 4
    AlternateStream  = 8   # archive stored in an NTFS alternate data stream
    UsnRenamedAway   = 6   # journal shows a rename from *.jar to something else
    SecondaryCap     = 15

    PrefetchLoaded   = 5   # listed by a Java Prefetch file
    RecentLink       = 2   # opened from Explorer (Recent\*.lnk)
    UsnRecent        = 3   # journal activity inside -RecentMinutes
    ContextCap       = 10
}

$script:Thresholds = @{
    High           = 70
    Medium         = 40
    MinClassLayout = 3   # fewer expected classes than this is not enough on its own
}

$script:DisguiseExtensions = @(
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.txt', '.log', '.dll', '.exe', '.sys',
    '.dat', '.bin', '.tmp', '.ini', '.cfg', '.json', '.xml', '.mp3', '.mp4', '.wav', '.ogg',
    '.pdf', '.doc', '.docx', '.lnk', '.ttf'
)
# Extensions under which JAR content is normal.
$script:ArchiveExtensions = @('.jar', '.zip', '.litemod', '.war', '.ear')

$script:ManifestKeys = @(
    'Main-Class', 'Premain-Class', 'Agent-Class', 'Launcher-Agent-Class', 'Can-Redefine-Classes',
    'Can-Retransform-Classes', 'Created-By', 'Implementation-Title', 'Implementation-Version', 'Multi-Release'
)

# ---------------------------------------------------------------------------
# Native helpers
# ---------------------------------------------------------------------------

# Binary parsing and I/O live in C#: PowerShell loops over byte arrays are orders
# of magnitude slower, and P/Invoke is needed for USN, file IDs and streams anyway.
$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DsScan
{
    internal static class Win32
    {
        internal const uint GENERIC_READ = 0x80000000;
        internal const uint FILE_READ_ATTRIBUTES = 0x80;
        internal const uint SHARE_ALL = 7;
        internal const uint OPEN_EXISTING = 3;
        internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        internal const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        internal const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;

        [StructLayout(LayoutKind.Sequential)]
        internal struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public uint CreationLow, CreationHigh;
            public uint AccessLow, AccessHigh;
            public uint WriteLow, WriteHigh;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh, FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh, FileIndexLow;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct FILE_ID_DESCRIPTOR
        {
            [FieldOffset(0)] public uint Size;
            [FieldOffset(4)] public int Type;
            [FieldOffset(8)] public long FileId;
            [FieldOffset(16)] public long Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string StreamName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileSizeEx(SafeFileHandle handle, out long size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeFileHandle OpenFileById(SafeFileHandle hint, ref FILE_ID_DESCRIPTOR id, uint access, uint share, IntPtr security, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr FindFirstStreamW(string name, int level, out WIN32_FIND_STREAM_DATA data, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool FindNextStreamW(IntPtr find, out WIN32_FIND_STREAM_DATA data);

        [DllImport("kernel32.dll")]
        internal static extern bool FindClose(IntPtr find);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] input, int inputSize, byte[] output, int outputSize, out int returned, IntPtr overlapped);

        [DllImport("kernel32.dll")]
        internal static extern uint GetLogicalDrives();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint GetDriveTypeW(string root);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool GetVolumeInformationW(string root, StringBuilder label, int labelSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder fileSystem, int fileSystemSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint QueryDosDeviceW(string device, StringBuilder target, int size);

        [DllImport("ntdll.dll")]
        internal static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkspace, out uint fragmentWorkspace);

        [DllImport("ntdll.dll")]
        internal static extern uint RtlDecompressBufferEx(ushort format, byte[] output, int outputSize, byte[] input, int inputSize, out int finalSize, IntPtr workspace);
    }

    internal static class Bin
    {
        public static bool InRange(byte[] d, long offset, long length)
        {
            return offset >= 0 && length >= 0 && offset <= d.Length && length <= d.Length - offset;
        }

        public static uint U32(byte[] d, long offset) { return BitConverter.ToUInt32(d, (int)offset); }
        public static long I64(byte[] d, long offset) { return BitConverter.ToInt64(d, (int)offset); }

        public static DateTime FileTime(long value)
        {
            if (value <= 0) return DateTime.MinValue;
            try { return DateTime.FromFileTimeUtc(value); }
            catch (ArgumentOutOfRangeException) { return DateTime.MinValue; }
        }

        public static int ReadFull(Stream s, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int n = s.Read(buffer, offset + total, count - total);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }
    }

    public sealed class FileStat
    {
        public string Path;
        public bool Exists;
        public int Error;
        public string FinalPath;
        public long Size;
        public uint Attributes;
        public DateTime CreationUtc;
        public DateTime LastWriteUtc;
        public DateTime LastAccessUtc;
        public uint VolumeSerial;
        public long FileId;
        public bool IsDirectory { get { return (Attributes & 0x10) != 0; } }
        public string ErrorText { get { return Error == 0 ? null : new Win32Exception(Error).Message; } }
    }

    public sealed class StreamEntry
    {
        public string Name;
        public long Size;
    }

    public static class FileSystem
    {
        // \\?\ lifts MAX_PATH and keeps names with trailing dots or spaces intact.
        public static string ToNative(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith(@"\\?\") || path.StartsWith(@"\\.\")) return path;
            if (path.StartsWith(@"\\")) return @"\\?\UNC\" + path.Substring(2);
            if (path.Length >= 3 && path[1] == ':' && path[2] == '\\') return @"\\?\" + path;
            return path;
        }

        public static string FromNative(string path)
        {
            if (path == null) return null;
            if (path.StartsWith(@"\\?\UNC\")) return @"\\" + path.Substring(8);
            if (path.StartsWith(@"\\?\")) return path.Substring(4);
            return path;
        }

        static SafeFileHandle Open(string path, uint access)
        {
            return Win32.CreateFileW(ToNative(path), access, Win32.SHARE_ALL, IntPtr.Zero, Win32.OPEN_EXISTING, Win32.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        }

        public static FileStat Stat(string path)
        {
            FileStat st = new FileStat();
            st.Path = path;
            using (SafeFileHandle h = Open(path, Win32.FILE_READ_ATTRIBUTES))
            {
                if (h.IsInvalid) { st.Error = Marshal.GetLastWin32Error(); return st; }
                Win32.BY_HANDLE_FILE_INFORMATION info;
                if (!Win32.GetFileInformationByHandle(h, out info)) { st.Error = Marshal.GetLastWin32Error(); return st; }
                st.Exists = true;
                st.Attributes = info.FileAttributes;
                st.CreationUtc = Bin.FileTime(((long)info.CreationHigh << 32) | info.CreationLow);
                st.LastAccessUtc = Bin.FileTime(((long)info.AccessHigh << 32) | info.AccessLow);
                st.LastWriteUtc = Bin.FileTime(((long)info.WriteHigh << 32) | info.WriteLow);
                st.VolumeSerial = info.VolumeSerialNumber;
                st.FileId = (long)(((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
                long size;
                st.Size = Win32.GetFileSizeEx(h, out size) ? size : (((long)info.FileSizeHigh << 32) | info.FileSizeLow);
                st.FinalPath = FinalPath(h);
            }
            return st;
        }

        internal static string FinalPath(SafeFileHandle h)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = Win32.GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n >= sb.Capacity)
            {
                sb = new StringBuilder((int)n + 1);
                n = Win32.GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            }
            if (n == 0 || n >= sb.Capacity) return null;
            return FromNative(sb.ToString());
        }

        // Opens with full sharing so files held open by Java or the launcher can still be read.
        public static FileStream OpenRead(string path)
        {
            SafeFileHandle h = Open(path, Win32.GENERIC_READ);
            if (h.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                h.Dispose();
                throw new Win32Exception(error);
            }
            return new FileStream(h, FileAccess.Read, 64 * 1024);
        }

        public static byte[] ReadAllBytes(string path, long maxBytes)
        {
            using (FileStream fs = OpenRead(path))
            {
                long length = fs.Length;
                if (length > maxBytes) throw new IOException("file is larger than " + maxBytes + " bytes");
                byte[] data = new byte[length];
                int read = Bin.ReadFull(fs, data, 0, (int)length);
                if (read < length) Array.Resize(ref data, read);
                return data;
            }
        }

        public static string ReadText(string path, int maxBytes)
        {
            using (FileStream fs = OpenRead(path))
            {
                byte[] data = new byte[(int)Math.Min(fs.Length, maxBytes)];
                int read = Bin.ReadFull(fs, data, 0, data.Length);
                return Encoding.UTF8.GetString(data, 0, read);
            }
        }

        public static List<StreamEntry> ListStreams(string path)
        {
            List<StreamEntry> list = new List<StreamEntry>();
            Win32.WIN32_FIND_STREAM_DATA data;
            IntPtr find = Win32.FindFirstStreamW(ToNative(path), 0, out data, 0);
            if (find == new IntPtr(-1)) return list;
            try
            {
                do
                {
                    StreamEntry e = new StreamEntry();
                    e.Name = data.StreamName;
                    e.Size = data.StreamSize;
                    list.Add(e);
                } while (Win32.FindNextStreamW(find, out data));
            }
            finally { Win32.FindClose(find); }
            return list;
        }
    }

    // Maps NTFS file references (MFT entry + sequence) back to current paths.
    // A reference whose MFT record was reused has a different sequence number and
    // fails to open, so a hit really is the same file.
    public sealed class FileIdResolver : IDisposable
    {
        readonly Dictionary<char, SafeFileHandle> hints = new Dictionary<char, SafeFileHandle>();
        readonly Dictionary<string, string> cache = new Dictionary<string, string>();

        public string Resolve(string drive, long fileId)
        {
            if (string.IsNullOrEmpty(drive) || fileId == 0) return null;
            char letter = char.ToUpperInvariant(drive[0]);
            string key = letter + ":" + fileId.ToString("X");
            string cached;
            if (cache.TryGetValue(key, out cached)) return cached;

            string result = null;
            SafeFileHandle hint = Hint(letter);
            if (hint != null)
            {
                Win32.FILE_ID_DESCRIPTOR id = new Win32.FILE_ID_DESCRIPTOR();
                id.Size = 24;
                id.FileId = fileId;
                using (SafeFileHandle h = Win32.OpenFileById(hint, ref id, Win32.FILE_READ_ATTRIBUTES, Win32.SHARE_ALL, IntPtr.Zero, Win32.FILE_FLAG_BACKUP_SEMANTICS))
                {
                    if (!h.IsInvalid) result = FileSystem.FinalPath(h);
                }
            }
            cache[key] = result;
            return result;
        }

        SafeFileHandle Hint(char letter)
        {
            SafeFileHandle h;
            if (hints.TryGetValue(letter, out h)) return h;
            h = Win32.CreateFileW(letter + @":\", Win32.FILE_READ_ATTRIBUTES, Win32.SHARE_ALL, IntPtr.Zero, Win32.OPEN_EXISTING, Win32.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h.IsInvalid) { h.Dispose(); h = null; }
            hints[letter] = h;
            return h;
        }

        public void Dispose()
        {
            foreach (SafeFileHandle h in hints.Values) if (h != null) h.Dispose();
            hints.Clear();
        }
    }

    public sealed class VolumeInfo
    {
        public string Letter;
        public uint DriveType;
        public uint Serial;
        public string FileSystem;
        public string Label;
        public string Device;
    }

    public static class Volumes
    {
        public static List<VolumeInfo> Enumerate()
        {
            List<VolumeInfo> list = new List<VolumeInfo>();
            uint mask = Win32.GetLogicalDrives();
            for (int i = 0; i < 26; i++)
            {
                if ((mask & (1u << i)) == 0) continue;
                VolumeInfo v = new VolumeInfo();
                v.Letter = ((char)('A' + i)).ToString();
                string root = v.Letter + @":\";
                v.DriveType = Win32.GetDriveTypeW(root);
                StringBuilder device = new StringBuilder(512);
                if (Win32.QueryDosDeviceW(v.Letter + ":", device, device.Capacity) != 0) v.Device = device.ToString();
                // Network drives are skipped: a dead share can block for a long time here.
                if (v.DriveType != 4)
                {
                    StringBuilder label = new StringBuilder(261), fs = new StringBuilder(261);
                    uint serial, maxComponent, flags;
                    if (Win32.GetVolumeInformationW(root, label, label.Capacity, out serial, out maxComponent, out flags, fs, fs.Capacity))
                    {
                        v.Serial = serial;
                        v.FileSystem = fs.ToString();
                        v.Label = label.ToString();
                    }
                }
                list.Add(v);
            }
            return list;
        }
    }

    public sealed class PrefetchVolume
    {
        public string DevicePath;
        public uint Serial;
        public DateTime CreatedUtc;
    }

    public sealed class PrefetchEntry
    {
        public string Path;
        public long FileId;
    }

    public sealed class PrefetchInfo
    {
        public string Path;
        public bool Compressed;
        public uint Version;
        public string Executable;
        public string Hash;
        public int RunCount;
        public List<DateTime> LastRunsUtc = new List<DateTime>();
        public List<PrefetchVolume> Volumes = new List<PrefetchVolume>();
        public List<PrefetchEntry> Files = new List<PrefetchEntry>();
        public List<string> Warnings = new List<string>();
    }

    public static class Prefetch
    {
        public static bool IsCompressed(byte[] d)
        {
            return d != null && d.Length >= 8 && d[0] == 0x4D && d[1] == 0x41 && d[2] == 0x4D;
        }

        // Windows 8+ wraps prefetch in "MAM" + format byte + uncompressed size (8 bytes).
        // When the high bit of the format byte is set a CRC32 follows and the header is 12.
        // The low nibble is the RtlDecompressBufferEx format (4 = Xpress Huffman).
        public static byte[] Decompress(byte[] d)
        {
            if (!IsCompressed(d)) throw new InvalidDataException("missing MAM header");
            byte flags = d[3];
            ushort format = (ushort)(flags & 0x0F);
            int header = (flags & 0x80) != 0 ? 12 : 8;
            int size = BitConverter.ToInt32(d, 4);
            if (size <= 0 || size > 64 * 1024 * 1024) throw new InvalidDataException("implausible uncompressed size " + size);
            if (d.Length <= header) throw new InvalidDataException("truncated compressed prefetch");

            uint bufferWorkspace, fragmentWorkspace;
            uint status = Win32.RtlGetCompressionWorkSpaceSize(format, out bufferWorkspace, out fragmentWorkspace);
            if (status != 0) throw new InvalidDataException("RtlGetCompressionWorkSpaceSize failed: 0x" + status.ToString("X8"));

            byte[] input = new byte[d.Length - header];
            Buffer.BlockCopy(d, header, input, 0, input.Length);
            byte[] output = new byte[size];
            IntPtr workspace = Marshal.AllocHGlobal((int)Math.Max(fragmentWorkspace, 1u));
            try
            {
                int finalSize;
                status = Win32.RtlDecompressBufferEx(format, output, size, input, input.Length, out finalSize, workspace);
                if (status != 0) throw new InvalidDataException("RtlDecompressBufferEx failed: 0x" + status.ToString("X8"));
                if (finalSize > 0 && finalSize < size) Array.Resize(ref output, finalSize);
                return output;
            }
            finally { Marshal.FreeHGlobal(workspace); }
        }

        // Header (all versions): 0 version, 4 "SCCA", 16 executable name (UTF-16, 60 bytes),
        // 76 path hash. The file information block starts at 84:
        //   84 metrics offset, 88 metrics count, 100 strings offset, 104 strings size,
        //   108 volumes offset, 112 volumes count.
        public static PrefetchInfo Parse(string path)
        {
            PrefetchInfo info = new PrefetchInfo();
            info.Path = path;
            byte[] d = FileSystem.ReadAllBytes(path, 32L << 20);
            if (IsCompressed(d)) { info.Compressed = true; d = Decompress(d); }
            if (d.Length < 120 || d[4] != 'S' || d[5] != 'C' || d[6] != 'C' || d[7] != 'A')
                throw new InvalidDataException("no SCCA signature");

            info.Version = Bin.U32(d, 0);
            info.Executable = Utf16Z(d, 16, 60);
            info.Hash = Bin.U32(d, 76).ToString("X8");

            long metricsOffset = Bin.U32(d, 84);
            long metricsCount = Bin.U32(d, 88);
            long stringsOffset = Bin.U32(d, 100);
            long stringsSize = Bin.U32(d, 104);
            long volumesOffset = Bin.U32(d, 108);
            long volumesCount = Bin.U32(d, 112);

            int metricSize, volumeSize, runTimes;
            long runTimesOffset, runCountOffset;
            switch (info.Version)
            {
                case 17: metricSize = 20; volumeSize = 40; runTimesOffset = 120; runTimes = 1; runCountOffset = 144; break;
                case 23: metricSize = 32; volumeSize = 104; runTimesOffset = 128; runTimes = 1; runCountOffset = 152; break;
                case 26: metricSize = 32; volumeSize = 104; runTimesOffset = 128; runTimes = 8; runCountOffset = 208; break;
                case 30:
                case 31:
                    // Version 30 has two layouts; in the shorter one (metrics at 0x128)
                    // the run count sits 8 bytes earlier.
                    metricSize = 32; volumeSize = 96; runTimesOffset = 128; runTimes = 8;
                    runCountOffset = metricsOffset == 0x128 ? 200 : 208;
                    break;
                default:
                    info.Warnings.Add("unknown version " + info.Version + ", assuming the Windows 10 layout");
                    metricSize = 32; volumeSize = 96; runTimesOffset = 128; runTimes = 8; runCountOffset = 208;
                    break;
            }

            DateTime latest = DateTime.UtcNow.AddDays(1);
            for (int i = 0; i < runTimes; i++)
            {
                long o = runTimesOffset + i * 8;
                if (!Bin.InRange(d, o, 8)) break;
                DateTime t = Bin.FileTime(Bin.I64(d, o));
                if (t.Year >= 2000 && t <= latest) info.LastRunsUtc.Add(t);
            }
            if (Bin.InRange(d, runCountOffset, 4))
            {
                uint count = Bin.U32(d, runCountOffset);
                if (count < 10000000) info.RunCount = (int)count;
            }

            if (stringsSize == 0 || !Bin.InRange(d, stringsOffset, stringsSize))
            {
                info.Warnings.Add("filename strings section is out of bounds");
            }
            else
            {
                ReadMetrics(d, info, metricsOffset, metricsCount, metricSize, stringsOffset, stringsSize);
                if (info.Files.Count == 0) SplitStrings(d, info, stringsOffset, stringsSize);
            }
            ReadVolumes(d, info, volumesOffset, volumesCount, volumeSize);
            return info;
        }

        // Metrics entries point into the strings section (offset @12, chars @16; @8/@12
        // in version 17). From version 23 on they also carry the NTFS file reference @24.
        static void ReadMetrics(byte[] d, PrefetchInfo info, long offset, long count, int size, long stringsOffset, long stringsSize)
        {
            if (count == 0 || count > 200000 || !Bin.InRange(d, offset, count * size))
            {
                info.Warnings.Add("metrics array unusable, falling back to the raw string list");
                return;
            }
            bool legacy = size == 20;
            for (long i = 0; i < count; i++)
            {
                long e = offset + i * size;
                long nameOffset = Bin.U32(d, e + (legacy ? 8 : 12));
                long nameChars = Bin.U32(d, e + (legacy ? 12 : 16));
                if (nameChars == 0 || nameChars > 32767 || nameOffset + nameChars * 2 > stringsSize) continue;
                PrefetchEntry f = new PrefetchEntry();
                f.Path = Encoding.Unicode.GetString(d, (int)(stringsOffset + nameOffset), (int)(nameChars * 2));
                f.FileId = legacy ? 0 : Bin.I64(d, e + 24);
                info.Files.Add(f);
            }
        }

        static void SplitStrings(byte[] d, PrefetchInfo info, long start, long size)
        {
            long end = start + size, from = start;
            for (long i = start; i + 1 < end; i += 2)
            {
                if (d[i] != 0 || d[i + 1] != 0) continue;
                if (i > from)
                {
                    PrefetchEntry f = new PrefetchEntry();
                    f.Path = Encoding.Unicode.GetString(d, (int)from, (int)(i - from));
                    info.Files.Add(f);
                }
                from = i + 2;
            }
        }

        // Volume entries: device path offset (relative to the volumes section) @0,
        // its length in characters @4, creation time @8, serial number @16.
        static void ReadVolumes(byte[] d, PrefetchInfo info, long offset, long count, int size)
        {
            if (count == 0 || count > 256) return;
            for (long i = 0; i < count; i++)
            {
                long e = offset + i * size;
                if (!Bin.InRange(d, e, 20)) break;
                long pathOffset = Bin.U32(d, e);
                long pathChars = Bin.U32(d, e + 4);
                PrefetchVolume v = new PrefetchVolume();
                v.CreatedUtc = Bin.FileTime(Bin.I64(d, e + 8));
                v.Serial = Bin.U32(d, e + 16);
                if (pathChars > 0 && pathChars < 1024 && Bin.InRange(d, offset + pathOffset, pathChars * 2))
                    v.DevicePath = Encoding.Unicode.GetString(d, (int)(offset + pathOffset), (int)(pathChars * 2));
                info.Volumes.Add(v);
            }
        }

        static string Utf16Z(byte[] d, int offset, int length)
        {
            string s = Encoding.Unicode.GetString(d, offset, length);
            int zero = s.IndexOf('\0');
            return zero >= 0 ? s.Substring(0, zero) : s;
        }
    }

    public sealed class UsnRecord
    {
        public string Drive;
        public long FileId;
        public long ParentId;
        public long Usn;
        public DateTime TimeUtc;
        public uint Reason;
        public uint Attributes;
        public string Name;
    }

    public sealed class UsnJournalInfo
    {
        public string Drive;
        public bool Available;
        public string Error;
        public ulong JournalId;
        public long FirstUsn;
        public long NextUsn;
        public ulong MaximumSize;
        public long RecordsRead;
        public long RecordsKept;
        public bool Truncated;
        public DateTime OldestUtc = DateTime.MaxValue;
        public DateTime NewestUtc = DateTime.MinValue;
        // The journal ID is derived from the creation time; only trusted when plausible.
        public DateTime CreatedUtc
        {
            get
            {
                DateTime t = Bin.FileTime((long)JournalId);
                return (t.Year >= 2000 && t <= DateTime.UtcNow.AddDays(1)) ? t : DateTime.MinValue;
            }
        }
    }

    // Reads the change journal directly (FSCTL_READ_USN_JOURNAL) instead of parsing
    // fsutil output, which is localized and far slower. Only records matching the
    // file IDs, names or extensions of interest are kept.
    public static class UsnJournal
    {
        const int ERROR_HANDLE_EOF = 38;
        const int ERROR_JOURNAL_NOT_ACTIVE = 1179;
        const int ERROR_JOURNAL_ENTRY_DELETED = 1181;

        public static UsnJournalInfo Read(string drive, HashSet<long> fileIds, HashSet<string> names, string[] extensions, int maxKept, List<UsnRecord> output)
        {
            UsnJournalInfo info = new UsnJournalInfo();
            info.Drive = drive.Substring(0, 1).ToUpperInvariant();
            using (SafeFileHandle volume = Win32.CreateFileW(@"\\.\" + info.Drive + ":", Win32.GENERIC_READ, 3, IntPtr.Zero, Win32.OPEN_EXISTING, 0, IntPtr.Zero))
            {
                if (volume.IsInvalid) { info.Error = new Win32Exception(Marshal.GetLastWin32Error()).Message; return info; }
                if (!Query(volume, info)) return info;

                byte[] request = new byte[40];
                byte[] buffer = new byte[1 << 20];
                long start = info.FirstUsn;
                bool requeried = false;

                while (start < info.NextUsn)
                {
                    // READ_USN_JOURNAL_DATA_V0: StartUsn, ReasonMask, ReturnOnlyOnClose,
                    // Timeout, BytesToWaitFor, UsnJournalID. V0 returns USN_RECORD_V2.
                    Array.Clear(request, 0, request.Length);
                    Buffer.BlockCopy(BitConverter.GetBytes(start), 0, request, 0, 8);
                    Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFFu), 0, request, 8, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(info.JournalId), 0, request, 32, 8);

                    int returned;
                    if (!Win32.DeviceIoControl(volume, Win32.FSCTL_READ_USN_JOURNAL, request, request.Length, buffer, buffer.Length, out returned, IntPtr.Zero))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_HANDLE_EOF) break;
                        if (error == ERROR_JOURNAL_ENTRY_DELETED && !requeried)
                        {
                            // The oldest records were purged while reading; restart from the new start.
                            requeried = true;
                            if (!Query(volume, info)) break;
                            start = info.FirstUsn;
                            continue;
                        }
                        info.Error = new Win32Exception(error).Message;
                        break;
                    }
                    if (returned <= 8) break;

                    long next = BitConverter.ToInt64(buffer, 0);
                    int offset = 8;
                    while (offset + 60 <= returned)
                    {
                        int length = BitConverter.ToInt32(buffer, offset);
                        if (length < 60 || offset + length > returned) break;
                        if (BitConverter.ToUInt16(buffer, offset + 4) == 2)
                            Consider(buffer, offset, length, info, fileIds, names, extensions, maxKept, output);
                        offset += length;
                    }
                    if (next <= start) break;
                    start = next;
                }
            }
            return info;
        }

        static bool Query(SafeFileHandle volume, UsnJournalInfo info)
        {
            byte[] data = new byte[80];
            int returned;
            if (!Win32.DeviceIoControl(volume, Win32.FSCTL_QUERY_USN_JOURNAL, null, 0, data, data.Length, out returned, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                info.Error = error == ERROR_JOURNAL_NOT_ACTIVE ? "USN journal is not active" : new Win32Exception(error).Message;
                return false;
            }
            info.Available = true;
            info.JournalId = BitConverter.ToUInt64(data, 0);
            info.FirstUsn = BitConverter.ToInt64(data, 8);
            info.NextUsn = BitConverter.ToInt64(data, 16);
            info.MaximumSize = BitConverter.ToUInt64(data, 40);
            return true;
        }

        // USN_RECORD_V2: length @0, major @4, file ref @8, parent ref @16, usn @24,
        // timestamp @32, reason @40, attributes @52, name length @56, name offset @58.
        static void Consider(byte[] b, int o, int length, UsnJournalInfo info, HashSet<long> fileIds, HashSet<string> names, string[] extensions, int maxKept, List<UsnRecord> output)
        {
            info.RecordsRead++;
            DateTime time = Bin.FileTime(BitConverter.ToInt64(b, o + 32));
            if (time != DateTime.MinValue)
            {
                if (time < info.OldestUtc) info.OldestUtc = time;
                if (time > info.NewestUtc) info.NewestUtc = time;
            }

            int nameLength = BitConverter.ToUInt16(b, o + 56);
            int nameOffset = BitConverter.ToUInt16(b, o + 58);
            if (nameOffset + nameLength > length) return;
            long fileId = BitConverter.ToInt64(b, o + 8);
            string name = Encoding.Unicode.GetString(b, o + nameOffset, nameLength);

            bool keep = (fileIds != null && fileIds.Contains(fileId)) || (names != null && names.Contains(name));
            if (!keep && extensions != null)
            {
                for (int i = 0; i < extensions.Length && !keep; i++)
                    keep = name.EndsWith(extensions[i], StringComparison.OrdinalIgnoreCase);
            }
            if (!keep) return;
            if (info.RecordsKept >= maxKept) { info.Truncated = true; return; }

            UsnRecord r = new UsnRecord();
            r.Drive = info.Drive;
            r.FileId = fileId;
            r.ParentId = BitConverter.ToInt64(b, o + 16);
            r.Usn = BitConverter.ToInt64(b, o + 24);
            r.TimeUtc = time;
            r.Reason = BitConverter.ToUInt32(b, o + 40);
            r.Attributes = BitConverter.ToUInt32(b, o + 52);
            r.Name = name;
            output.Add(r);
            info.RecordsKept++;
        }
    }

    // Aho-Corasick automaton over all patterns: one pass per buffer no matter how
    // many patterns there are. Searching them one by one was the main cost, since the
    // constant pool patterns all start with 0x01, one of the most common class file bytes.
    public sealed class PatternSet
    {
        internal readonly SearchPattern[] Patterns;
        internal readonly int[] Next;        // state * 256 + byte -> next state
        internal readonly int[][] Matches;   // patterns ending in each state

        public PatternSet(SearchPattern[] patterns)
        {
            Patterns = patterns;
            List<int[]> trie = new List<int[]>();
            List<List<int>> outputs = new List<List<int>>();
            trie.Add(NewRow());
            outputs.Add(new List<int>());
            for (int p = 0; p < patterns.Length; p++)
            {
                int state = 0;
                foreach (byte b in patterns[p].Bytes)
                {
                    if (trie[state][b] < 0)
                    {
                        trie[state][b] = trie.Count;
                        trie.Add(NewRow());
                        outputs.Add(new List<int>());
                    }
                    state = trie[state][b];
                }
                outputs[state].Add(p);
            }

            int count = trie.Count;
            int[] fail = new int[count];
            Next = new int[count * 256];
            Queue<int> queue = new Queue<int>();
            for (int b = 0; b < 256; b++)
            {
                int t = trie[0][b];
                if (t < 0) continue;
                Next[b] = t;
                queue.Enqueue(t);
            }
            // Breadth-first, so a state's failure target is always complete before it.
            while (queue.Count > 0)
            {
                int s = queue.Dequeue();
                if (fail[s] != 0) outputs[s].AddRange(outputs[fail[s]]);
                for (int b = 0; b < 256; b++)
                {
                    int t = trie[s][b];
                    int fallback = Next[fail[s] * 256 + b];
                    if (t < 0) { Next[s * 256 + b] = fallback; continue; }
                    fail[t] = fallback;
                    Next[s * 256 + b] = t;
                    queue.Enqueue(t);
                }
            }

            Matches = new int[count][];
            for (int i = 0; i < count; i++) Matches[i] = outputs[i].Count > 0 ? outputs[i].ToArray() : null;
        }

        static int[] NewRow()
        {
            int[] row = new int[256];
            for (int i = 0; i < row.Length; i++) row[i] = -1;
            return row;
        }
    }

    // Read-only view of a stream starting at an offset, for zips with data in front.
    internal sealed class OffsetStream : Stream
    {
        readonly Stream inner;
        readonly long start;

        public OffsetStream(Stream inner, long start)
        {
            this.inner = inner;
            this.start = start;
            inner.Position = start;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return true; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return inner.Length - start; } }
        public override long Position
        {
            get { return inner.Position - start; }
            set { inner.Position = value + start; }
        }
        public override int Read(byte[] buffer, int offset, int count) { return inner.Read(buffer, offset, count); }
        public override long Seek(long offset, SeekOrigin origin)
        {
            long target = origin == SeekOrigin.Begin ? offset : origin == SeekOrigin.Current ? Position + offset : Length + offset;
            Position = target;
            return target;
        }
        public override void Flush() { }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }

    public sealed class ArchiveProbe
    {
        public string Kind = "none";   // zip, prefixed, class or none
        public long ZipOffset;
        public string Magic;

        public static ArchiveProbe Probe(string path)
        {
            using (FileStream fs = FileSystem.OpenRead(path)) return Probe(fs);
        }

        public static ArchiveProbe Probe(Stream s)
        {
            ArchiveProbe p = new ArchiveProbe();
            long length = s.Length;
            byte[] head = new byte[8];
            int n = Bin.ReadFull(s, head, 0, 8);
            p.Magic = BitConverter.ToString(head, 0, Math.Min(n, 4)).Replace("-", "");
            if (n >= 4 && head[0] == 0x50 && head[1] == 0x4B && ((head[2] == 3 && head[3] == 4) || (head[2] == 5 && head[3] == 6)))
            {
                p.Kind = "zip";
                return p;
            }
            // CAFEBABE is shared with Mach-O fat binaries; a real class file has a
            // major version of 45 (Java 1.0) or later where Mach-O has a small arch count.
            if (n == 8 && head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE)
            {
                int major = (head[6] << 8) | head[7];
                if (major >= 45 && major < 100) p.Kind = "class";
                return p;
            }
            if (length < 22) return p;

            // A zip appended to other data (exe wrappers, polyglots) is found through an
            // end-of-central-directory record that is consistent with the file size and
            // points at a real central directory.
            int tailLength = (int)Math.Min(length, 22 + 65535);
            byte[] tail = new byte[tailLength];
            s.Position = length - tailLength;
            if (Bin.ReadFull(s, tail, 0, tailLength) != tailLength) return p;
            byte[] sig = new byte[4];
            for (int i = tailLength - 22; i >= 0; i--)
            {
                if (tail[i] != 0x50 || tail[i + 1] != 0x4B || tail[i + 2] != 5 || tail[i + 3] != 6) continue;
                long eocd = length - tailLength + i;
                int commentLength = BitConverter.ToUInt16(tail, i + 20);
                if (eocd + 22 + commentLength != length) continue;
                long cdSize = BitConverter.ToUInt32(tail, i + 12);
                long cdOffset = BitConverter.ToUInt32(tail, i + 16);
                if (cdOffset == 0xFFFFFFFF || cdSize == 0) continue;
                long cdStart = eocd - cdSize;
                long prefix = cdStart - cdOffset;
                if (cdStart < 0 || prefix < 0) continue;
                s.Position = cdStart;
                if (Bin.ReadFull(s, sig, 0, 4) != 4 || sig[0] != 0x50 || sig[1] != 0x4B || sig[2] != 1 || sig[3] != 2) continue;
                p.Kind = "prefixed";
                p.ZipOffset = prefix;
                return p;
            }
            return p;
        }
    }

    public sealed class SearchPattern
    {
        public string Id;
        public byte[] Bytes;
        public SearchPattern(string id, byte[] bytes) { Id = id; Bytes = bytes; }
    }

    public sealed class PatternHit
    {
        public string Id;
        public string Entry;
        public int Offset;
    }

    public sealed class JarLimits
    {
        public int MaxEntries = 100000;
        public int MaxClassBytes = 16 * 1024 * 1024;
        public int MaxNestedBytes = 64 * 1024 * 1024;
        public long MaxTotalBytes = 1024L * 1024 * 1024;
        public int MaxDepth = 2;
    }

    public sealed class JarReport
    {
        public int Entries;
        public int ClassEntries;
        public int ClassData;
        public int HiddenClassData;
        public int InvalidClassEntries;
        public int ShortNameClasses;
        public int NestedArchives;
        public int EntryErrors;
        public long BytesRead;
        public bool Truncated;
        public string Error;
        public string Manifest;
        public DateTime? OldestEntryUtc;
        public DateTime? NewestEntryUtc;
        public List<PatternHit> Hits = new List<PatternHit>();
        public List<string> WatchedEntries = new List<string>();
        public List<string> SignatureFiles = new List<string>();
        public List<string> ShortNameSamples = new List<string>();
        public List<string> HiddenClassSamples = new List<string>();
        public List<string> Notes = new List<string>();
    }

    // Walks a zip without extracting it. Every entry is identified by its first bytes,
    // so bytecode under a fake name and jars nested inside jars are still inspected.
    // Only class data is pattern-matched, entry by entry, which avoids both loading the
    // whole archive and false matches across entry boundaries.
    public static class JarInspector
    {
        public static JarReport Inspect(string path, long zipOffset, PatternSet patterns, HashSet<string> watched, JarLimits limits)
        {
            JarReport report = new JarReport();
            Walker walker = new Walker(report, patterns ?? new PatternSet(new SearchPattern[0]), watched, limits ?? new JarLimits());
            try
            {
                using (FileStream fs = FileSystem.OpenRead(path))
                {
                    Stream source = fs;
                    if (zipOffset > 0) source = new OffsetStream(fs, zipOffset);
                    walker.Walk(source, "", 0);
                }
            }
            catch (Exception ex)
            {
                report.Error = ex.GetType().Name + ": " + ex.Message;
            }
            return report;
        }

        // A loose class file, as loaded from a directory on the classpath.
        public static JarReport InspectClass(string path, PatternSet patterns, JarLimits limits)
        {
            JarReport report = new JarReport();
            Walker walker = new Walker(report, patterns ?? new PatternSet(new SearchPattern[0]), null, limits ?? new JarLimits());
            try { walker.ScanClassFile(path); }
            catch (Exception ex) { report.Error = ex.GetType().Name + ": " + ex.Message; }
            return report;
        }

        internal static bool IsShortName(string entryName)
        {
            int slash = entryName.LastIndexOf('/');
            string simple = entryName.Substring(slash + 1, entryName.Length - slash - 1 - 6);
            int dollar = simple.IndexOf('$');
            if (dollar >= 0) simple = simple.Substring(0, dollar);
            if (simple.Length == 0 || simple.Length > 2) return false;
            for (int i = 0; i < simple.Length; i++) if (!char.IsLetter(simple[i])) return false;
            return true;
        }

        sealed class Walker
        {
            readonly JarReport report;
            readonly PatternSet patterns;
            readonly HashSet<string> watched;
            readonly JarLimits limits;
            readonly Dictionary<string, int> hitCounts = new Dictionary<string, int>();
            readonly byte[] head = new byte[4];
            byte[] buffer = new byte[256 * 1024];
            bool budgetSpent;

            public Walker(JarReport report, PatternSet patterns, HashSet<string> watched, JarLimits limits)
            {
                this.report = report;
                this.patterns = patterns;
                this.watched = watched;
                this.limits = limits;
            }

            public void Walk(Stream source, string prefix, int depth)
            {
                using (ZipArchive zip = new ZipArchive(source, ZipArchiveMode.Read, true))
                {
                    foreach (ZipArchiveEntry entry in zip.Entries)
                    {
                        string name = entry.FullName.Replace('\\', '/');
                        if (name.Length == 0 || name[name.Length - 1] == '/') continue;
                        if (report.Entries >= limits.MaxEntries)
                        {
                            report.Truncated = true;
                            Note("stopped after " + limits.MaxEntries + " entries");
                            return;
                        }
                        report.Entries++;
                        Visit(entry, name, prefix, depth);
                    }
                }
            }

            public void ScanClassFile(string path)
            {
                string name = System.IO.Path.GetFileName(path);
                using (FileStream fs = FileSystem.OpenRead(path))
                {
                    report.Entries = 1;
                    report.ClassData = 1;
                    if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                    {
                        report.ClassEntries = 1;
                        if (IsShortName(name)) report.ShortNameClasses = 1;
                    }
                    else
                    {
                        report.HiddenClassData = 1;
                        report.HiddenClassSamples.Add(name);
                    }
                    if (fs.Length > limits.MaxClassBytes)
                    {
                        report.Truncated = true;
                        Note("class too large to scan (" + fs.Length + " bytes)");
                        return;
                    }
                    int size = (int)fs.Length;
                    if (buffer.Length < size) buffer = new byte[size];
                    int length = Bin.ReadFull(fs, buffer, 0, size);
                    report.BytesRead = length;
                    Match(length, name);
                }
            }

            void Visit(ZipArchiveEntry entry, string name, string prefix, int depth)
            {
                string full = prefix + name;
                TrackTime(entry);

                bool classNamed = name.EndsWith(".class", StringComparison.OrdinalIgnoreCase);
                if (classNamed)
                {
                    report.ClassEntries++;
                    if (IsShortName(name))
                    {
                        report.ShortNameClasses++;
                        if (report.ShortNameSamples.Count < 12) report.ShortNameSamples.Add(full);
                    }
                    if (watched != null && watched.Contains(name)) report.WatchedEntries.Add(full);
                }
                if (depth == 0) CheckMetaInf(entry, name);

                long declared = entry.Length;
                if (declared == 0 || budgetSpent) return;
                if (report.BytesRead >= limits.MaxTotalBytes)
                {
                    budgetSpent = true;
                    report.Truncated = true;
                    Note("read budget of " + (limits.MaxTotalBytes >> 20) + " MB used up, remaining entries were not opened");
                    return;
                }

                try
                {
                    using (Stream es = entry.Open())
                    {
                        int n = Bin.ReadFull(es, head, 0, 4);
                        if (n < 4)
                        {
                            if (classNamed) report.InvalidClassEntries++;
                            return;
                        }

                        if (head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE)
                        {
                            report.ClassData++;
                            if (!classNamed)
                            {
                                report.HiddenClassData++;
                                if (report.HiddenClassSamples.Count < 12) report.HiddenClassSamples.Add(full);
                            }
                            if (declared > limits.MaxClassBytes)
                            {
                                report.Truncated = true;
                                Note("class too large to scan: " + full + " (" + declared + " bytes)");
                                return;
                            }
                            int size = (int)declared;
                            if (buffer.Length < size) buffer = new byte[Math.Max(size, buffer.Length * 2)];
                            Buffer.BlockCopy(head, 0, buffer, 0, 4);
                            int length = 4 + Bin.ReadFull(es, buffer, 4, Math.Max(0, size - 4));
                            report.BytesRead += length;
                            Match(length, full);
                        }
                        else if (head[0] == 0x50 && head[1] == 0x4B && head[2] == 3 && head[3] == 4)
                        {
                            if (depth + 1 > limits.MaxDepth) { Note("nested archive not opened (depth limit): " + full); return; }
                            if (declared > limits.MaxNestedBytes)
                            {
                                report.Truncated = true;
                                Note("nested archive too large: " + full + " (" + declared + " bytes)");
                                return;
                            }
                            byte[] nested = new byte[declared];
                            Buffer.BlockCopy(head, 0, nested, 0, 4);
                            int length = 4 + Bin.ReadFull(es, nested, 4, nested.Length - 4);
                            report.BytesRead += length;
                            report.NestedArchives++;
                            using (MemoryStream ms = new MemoryStream(nested, 0, length, false))
                                Walk(ms, full + "!/", depth + 1);
                        }
                        else if (classNamed)
                        {
                            report.InvalidClassEntries++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    report.EntryErrors++;
                    if (report.EntryErrors <= 3) Note("cannot read " + full + ": " + ex.Message);
                }
            }

            // Records the first offset of each pattern in this entry, and at most
            // 20 entries per pattern for the whole archive.
            void Match(int length, string entry)
            {
                int[] next = patterns.Next;
                int[][] matches = patterns.Matches;
                bool[] seenHere = null;
                int state = 0;
                for (int i = 0; i < length; i++)
                {
                    state = next[(state << 8) | buffer[i]];
                    int[] found = matches[state];
                    if (found == null) continue;
                    foreach (int index in found)
                    {
                        if (seenHere == null) seenHere = new bool[patterns.Patterns.Length];
                        if (seenHere[index]) continue;
                        seenHere[index] = true;
                        SearchPattern p = patterns.Patterns[index];
                        int seen;
                        hitCounts.TryGetValue(p.Id, out seen);
                        if (seen >= 20) continue;
                        hitCounts[p.Id] = seen + 1;
                        PatternHit hit = new PatternHit();
                        hit.Id = p.Id;
                        hit.Entry = entry;
                        hit.Offset = i - p.Bytes.Length + 1;
                        report.Hits.Add(hit);
                    }
                }
            }

            void CheckMetaInf(ZipArchiveEntry entry, string name)
            {
                string upper = name.ToUpperInvariant();
                if (!upper.StartsWith("META-INF/")) return;
                if (upper == "META-INF/MANIFEST.MF" && report.Manifest == null)
                {
                    try
                    {
                        using (Stream s = entry.Open())
                        {
                            byte[] text = new byte[16384];
                            int n = Bin.ReadFull(s, text, 0, text.Length);
                            report.Manifest = Encoding.UTF8.GetString(text, 0, n);
                        }
                    }
                    catch (Exception ex) { Note("cannot read manifest: " + ex.Message); }
                }
                else if (upper.EndsWith(".RSA") || upper.EndsWith(".DSA") || upper.EndsWith(".EC"))
                {
                    report.SignatureFiles.Add(name);
                }
            }

            void TrackTime(ZipArchiveEntry entry)
            {
                try
                {
                    DateTime t = entry.LastWriteTime.UtcDateTime;
                    if (t.Year < 1981 || t.Year > 2107) return;
                    if (!report.OldestEntryUtc.HasValue || t < report.OldestEntryUtc.Value) report.OldestEntryUtc = t;
                    if (!report.NewestEntryUtc.HasValue || t > report.NewestEntryUtc.Value) report.NewestEntryUtc = t;
                }
                catch (ArgumentException) { }
            }

            void Note(string message)
            {
                if (report.Notes.Count < 25 && !report.Notes.Contains(message)) report.Notes.Add(message);
            }
        }
    }

    public static class Hashing
    {
        public static string Sha256(string path)
        {
            using (FileStream fs = FileSystem.OpenRead(path))
            using (SHA256 sha = new SHA256Cng())
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(64);
                foreach (byte b in hash) sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }
    }
}
'@

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

function Show-Banner {
    $duck1 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡏⠉⢻⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣾⣿⣿⣶⣶⣶⣦⣤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⠏⠉⠉⠉⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀
"@

    $duck2 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⣤⣶⣾⣷⣄⠀⠀⠀⠀⠀
⠀⠀⣶⣤⣤⣤⣤⣤⣤⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⠛⢻⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⢀⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠈⢿⣿⣿⣏⡈⠛⠿⠿⣿⣿⣿⠿⠿⠟⠋⣁⣴⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⣿⣿⣶⣦⣤⣤⣤⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠻⠿⠿⠿⢿⡿⠿⠿⠿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀
"@

    $duck3 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡄⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣧⣾⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"@

    Write-Host $duck1 -ForegroundColor Yellow
    Write-Host $duck2 -ForegroundColor White
    Write-Host $duck3 -ForegroundColor Yellow

    Write-Host ""
    Write-Host "                    Made by " -NoNewline
    Write-Host "iTake (@cheatinformer) " -NoNewline -ForegroundColor White
    Write-Host "@" -NoNewline -ForegroundColor Blue
    Write-Host " FM Forensics" -ForegroundColor Red
    Write-Host ""
    Write-Host "                    Doomsday Client Scanner v$script:ScannerVersion" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step([string]$Text) { Write-Host "[*] $Text" -ForegroundColor Cyan }
function Write-Good([string]$Text) { Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Yellow }
function Write-DebugLog([string]$Text) {
    if ($script:Options.DebugLog) { Write-Host "    [debug] $Text" -ForegroundColor DarkGray }
}

function Write-Field {
    param([string]$Label, [string]$Value, [ConsoleColor]$Color = 'Gray')
    Write-Host ('      {0,-11} ' -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

$script:ProgressShown = [DateTime]::MinValue
function Update-Progress {
    param([string]$Activity, [int]$Current, [int]$Total)
    # Write-Progress is expensive on 5.1; redraw at most every 200 ms.
    $now = [DateTime]::UtcNow
    if ($Current -lt $Total -and ($now - $script:ProgressShown).TotalMilliseconds -lt 200) { return }
    $script:ProgressShown = $now
    $percent = [int][Math]::Min(100, 100 * $Current / [Math]::Max(1, $Total))
    Write-Progress -Activity $Activity -Status "$Current / $Total" -PercentComplete $percent
}

function Get-ErrorText($ErrorRecord) {
    $e = $ErrorRecord.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    return $e.Message
}

function Add-ScanError {
    param([string]$Stage, [string]$Target, [string]$Message)
    $script:ScanErrors.Add([pscustomobject]@{ Stage = $Stage; Target = $Target; Message = $Message })
    Write-DebugLog "$Stage | $Target | $Message"
}

function Format-LocalTime($Utc) {
    if ($null -eq $Utc) { return '-' }
    $t = [datetime]$Utc
    if ($t -eq [datetime]::MinValue -or $t -eq [datetime]::MaxValue) { return '-' }
    return $t.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

function Format-IsoTime($Utc) {
    if ($null -eq $Utc) { return $null }
    $t = [datetime]$Utc
    if ($t -eq [datetime]::MinValue -or $t -eq [datetime]::MaxValue) { return $null }
    return $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Format-Size([long]$Bytes) {
    $text = if ($Bytes -ge 1MB) { '{0:N2} MB' -f ($Bytes / 1MB) } elseif ($Bytes -ge 1KB) { '{0:N1} KB' -f ($Bytes / 1KB) } else { "$Bytes B" }
    return '{0} ({1:N0} bytes)' -f $text, $Bytes
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Native {
    if ('DsScan.JarInspector' -as [type]) { return }
    Add-Type -AssemblyName System.IO.Compression
    $references = @(
        [System.IO.Compression.ZipArchive].Assembly.Location
        [System.Collections.Generic.HashSet[int]].Assembly.Location
    )
    Add-Type -TypeDefinition $script:NativeSource -ReferencedAssemblies $references -ErrorAction Stop
}

function ConvertFrom-Hex([string]$Hex) {
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return , $bytes
}

function Initialize-Patterns {
    $patterns = [System.Collections.Generic.List[DsScan.SearchPattern]]::new()
    foreach ($sig in $script:ByteSignatures) {
        $patterns.Add([DsScan.SearchPattern]::new($sig.Id, (ConvertFrom-Hex $sig.Hex)))
    }

    # Exact constant pool entries (tag 1, u2 length, bytes) for the class name and its
    # field descriptor form. A bare substring would also hit net/java/foo.
    $script:WatchedEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($class in $script:ExpectedClasses) {
        [void]$script:WatchedEntries.Add("$class.class")
        foreach ($form in @($class, "L$class;")) {
            $text = [Text.Encoding]::ASCII.GetBytes($form)
            $bytes = New-Object byte[] ($text.Length + 3)
            $bytes[0] = 1
            $bytes[1] = [byte](($text.Length -shr 8) -band 0xFF)
            $bytes[2] = [byte]($text.Length -band 0xFF)
            [Array]::Copy($text, 0, $bytes, 3, $text.Length)
            $patterns.Add([DsScan.SearchPattern]::new("REF:$class", $bytes))
        }
    }
    $script:SearchPatterns = [DsScan.PatternSet]::new($patterns.ToArray())
    $script:JarLimits = New-Object DsScan.JarLimits
}

function Import-HashList([string]$Path) {
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warn "Hash list not found: $Path"
        return
    }
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).ProviderPath)) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -match '^([0-9A-Fa-f]{64})\s*(.*)$') {
            $label = if ($Matches[2]) { $Matches[2].Trim() } else { 'hash list' }
            $script:KnownHashes[$Matches[1].ToUpperInvariant()] = $label
        }
    }
    Write-Good "Loaded $($script:KnownHashes.Count) known hash(es)"
}

function Get-VolumeTable {
    $table = @{
        All      = [DsScan.Volumes]::Enumerate()
        BySerial = @{}
        ByDevice = @{}
        Ntfs     = [System.Collections.Generic.List[string]]::new()
    }
    foreach ($v in $table.All) {
        if ($v.Serial -ne 0) {
            $key = $v.Serial.ToString('X8')
            if (-not $table.BySerial.ContainsKey($key)) { $table.BySerial[$key] = $v.Letter }
        }
        if ($v.Device) { $table.ByDevice[$v.Device.ToUpperInvariant()] = $v.Letter }
        # 2 = removable, 3 = fixed
        if ($v.FileSystem -eq 'NTFS' -and ($v.DriveType -eq 2 -or $v.DriveType -eq 3)) { $table.Ntfs.Add($v.Letter) }
    }
    return $table
}

function Get-PrefetchSettings {
    $settings = [ordered]@{ EnablePrefetcher = $null; SysMain = $null }
    try {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        $settings.EnablePrefetcher = (Get-ItemProperty -LiteralPath $key -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher
    } catch { }
    try { $settings.SysMain = (Get-Service -Name SysMain -ErrorAction Stop).Status.ToString() } catch { }
    return $settings
}

# ---------------------------------------------------------------------------
# Paths and references
# ---------------------------------------------------------------------------

function Get-DriveLetter([string]$Path) {
    if ($Path -match '^([A-Za-z]):') { return $Matches[1].ToUpperInvariant() }
    return $null
}

# Java never loads a client from the Windows directory, and skipping it removes most
# Prefetch noise. Windows\Temp stays in because it is a plausible drop location.
$script:WindowsDir = $(if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }).TrimEnd('\') + '\'

function Test-SystemPath([string]$Path) {
    if ($Path.StartsWith($script:WindowsDir, [StringComparison]::OrdinalIgnoreCase)) {
        return -not $Path.StartsWith($script:WindowsDir + 'TEMP\', [StringComparison]::OrdinalIgnoreCase)
    }
    return $Path -match '^\\(VOLUME\{[^}]+\}|DEVICE\\[^\\]+)\\WINDOWS\\(?!TEMP\\)'
}

# Prefetch stores paths as \VOLUME{<creation time>-<serial>}\... (Win8+) or
# \DEVICE\HARDDISKVOLUMEn\... (older). The volume serial from the Prefetch volume
# table is matched against mounted volumes; the drive letter is never assumed.
function Resolve-DevicePath {
    param([string]$RawPath, $PrefetchVolumes)

    foreach ($vol in $PrefetchVolumes) {
        $device = $vol.DevicePath
        if (-not $device -or -not $RawPath.StartsWith($device + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $letter = $script:VolumeTable.BySerial[$vol.Serial.ToString('X8')]
        if ($letter) {
            return @{ Path = "${letter}:" + $RawPath.Substring($device.Length); Drive = $letter; Resolved = $true; Method = 'serial' }
        }
    }
    if ($RawPath -match '^\\VOLUME\{[0-9A-F]+-([0-9A-F]{8})\}(\\.*)$') {
        $letter = $script:VolumeTable.BySerial[$Matches[1]]
        if ($letter) { return @{ Path = "${letter}:" + $Matches[2]; Drive = $letter; Resolved = $true; Method = 'serial' } }
    }
    if ($RawPath -match '^\\DEVICE\\MUP\\(.+)$') {
        return @{ Path = '\\' + $Matches[1]; Drive = $null; Resolved = $true; Method = 'network' }
    }
    if ($RawPath -match '^(\\DEVICE\\[^\\]+)(\\.*)$') {
        # Device numbering can change between boots, so this is the weaker mapping.
        $letter = $script:VolumeTable.ByDevice[$Matches[1]]
        if ($letter) { return @{ Path = "${letter}:" + $Matches[2]; Drive = $letter; Resolved = $true; Method = 'device' } }
    }
    if ($RawPath -match '^([A-Za-z]):\\') {
        return @{ Path = $RawPath; Drive = $Matches[1].ToUpperInvariant(); Resolved = $true; Method = 'letter' }
    }
    return @{ Path = $RawPath; Drive = $null; Resolved = $false; Method = 'none' }
}

function Get-Reference {
    param($Resolution, [string]$RawPath)
    $ref = $null
    if (-not $script:Refs.TryGetValue($Resolution.Path, [ref]$ref)) {
        $ref = @{
            Path           = $Resolution.Path
            RawPath        = $RawPath
            Drive          = $Resolution.Drive
            VolumeResolved = $Resolution.Resolved
            ResolveMethod  = $Resolution.Method
            FileIds        = [System.Collections.Generic.HashSet[long]]::new()
            Prefetch       = [System.Collections.Generic.List[object]]::new()
            Links          = [System.Collections.Generic.List[object]]::new()
            State          = 'Unknown'
            StateDetail    = $null
            CurrentPath    = $null
            CurrentFileId  = 0
            SameFile       = $false
            Usn            = $null
            DeletedUtc     = $null
        }
        $script:Refs[$Resolution.Path] = $ref
    }
    return $ref
}

function Read-JavaPrefetch {
    $dir = Join-Path $env:SystemRoot 'Prefetch'
    $result = @{
        Directory       = $dir
        Files           = [System.Collections.Generic.List[object]]::new()
        Parsed          = 0
        TotalPrefetch   = 0
        OldestPrefetch  = $null
        Settings        = Get-PrefetchSettings
    }

    if ($result.Settings.EnablePrefetcher -eq 0) { Write-Warn 'Prefetch is disabled (EnablePrefetcher = 0)' }
    if ($result.Settings.SysMain -and $result.Settings.SysMain -ne 'Running') { Write-Warn "SysMain service is $($result.Settings.SysMain)" }

    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        Write-Warn "Prefetch folder not found: $dir"
        return $result
    }

    $all = @(Get-ChildItem -LiteralPath $dir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue)
    $result.TotalPrefetch = $all.Count
    if ($all.Count -gt 0) {
        $result.OldestPrefetch = ($all | Sort-Object CreationTimeUtc | Select-Object -First 1).CreationTimeUtc
    }
    if ($all.Count -gt 0 -and $all.Count -lt 30) {
        Write-Warn "Only $($all.Count) Prefetch files in total (oldest $(Format-LocalTime $result.OldestPrefetch)); the folder may have been cleared"
    }

    $java = @($all | Where-Object { $_.Name -like 'JAVA*.EXE-*.pf' })
    if ($java.Count -eq 0) {
        Write-Warn 'No Java Prefetch files (Java never ran, Prefetch was cleared or is disabled)'
        return $result
    }

    foreach ($file in $java) {
        $entry = [pscustomobject]@{ Name = $file.Name; Info = $null; Error = $null }
        $result.Files.Add($entry)
        try {
            $info = [DsScan.Prefetch]::Parse($file.FullName)
        }
        catch {
            $entry.Error = Get-ErrorText $_
            Add-ScanError 'Prefetch' $file.Name $entry.Error
            continue
        }
        $entry.Info = $info
        $result.Parsed++
        foreach ($warning in $info.Warnings) { Write-DebugLog "$($file.Name): $warning" }

        $lastRun = if ($info.LastRunsUtc.Count -gt 0) { $info.LastRunsUtc[0] } else { $null }
        foreach ($f in $info.Files) {
            $resolution = Resolve-DevicePath $f.Path $info.Volumes
            if (Test-SystemPath $resolution.Path) { continue }
            $ref = Get-Reference $resolution $f.Path
            if ($f.FileId -ne 0) { [void]$ref.FileIds.Add($f.FileId) }
            $ref.Prefetch.Add([pscustomobject]@{
                Name       = $file.Name
                LastRunUtc = $lastRun
                RunCount   = $info.RunCount
                FileId     = $f.FileId
            })
        }

        $runText = if ($lastRun) { "last run $(Format-LocalTime $lastRun)" } else { 'no run time' }
        Write-Host ('    {0,-28} v{1,-3} {2,-4} runs  {3}  ({4} files{5})' -f $file.Name, $info.Version, $info.RunCount, $runText, $info.Files.Count, $(if ($info.Compressed) { ', compressed' } else { '' })) -ForegroundColor Gray
    }
    return $result
}

function Get-ProfileFolders {
    $folders = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($key in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop) {
            if ($key.PSChildName -notlike 'S-1-5-21-*') { continue }
            $path = $key.GetValue('ProfileImagePath')
            if ($path) { $folders.Add([Environment]::ExpandEnvironmentVariables($path)) }
        }
    } catch { }
    if ($folders.Count -eq 0 -and $env:USERPROFILE) { $folders.Add($env:USERPROFILE) }
    return , $folders
}

# JARs opened from Explorer leave <name>.jar.lnk in each user's Recent folder.
function Read-RecentLinks {
    $count = 0
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell }
    catch {
        Add-ScanError 'Recent' 'WScript.Shell' (Get-ErrorText $_)
        return 0
    }
    try {
        foreach ($profile in Get-ProfileFolders) {
            $recent = Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Recent'
            if (-not (Test-Path -LiteralPath $recent -PathType Container)) { continue }
            foreach ($lnk in Get-ChildItem -LiteralPath $recent -Filter '*.jar.lnk' -File -Force -ErrorAction SilentlyContinue) {
                try { $target = $shell.CreateShortcut($lnk.FullName).TargetPath }
                catch {
                    Add-ScanError 'Recent' $lnk.FullName (Get-ErrorText $_)
                    continue
                }
                if (-not $target) { continue }
                $ref = Get-Reference @{ Path = $target; Drive = (Get-DriveLetter $target); Resolved = $true; Method = 'link' } $target
                $ref.Links.Add([pscustomobject]@{ Link = $lnk.FullName; LinkTimeUtc = $lnk.LastWriteTimeUtc })
                $count++
            }
        }
    }
    finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
    return $count
}

function Resolve-ReferenceState($Ref) {
    if (-not $Ref.VolumeResolved) {
        $Ref.State = 'NoVolume'
        $Ref.StateDetail = 'volume is not mounted or could not be identified'
        return
    }

    $st = [DsScan.FileSystem]::Stat($Ref.Path)
    if ($st.Exists) {
        if ($st.IsDirectory) { $Ref.State = 'Directory'; return }
        $Ref.CurrentPath = if ($st.FinalPath) { $st.FinalPath } else { $Ref.Path }
        $Ref.CurrentFileId = $st.FileId
        if ($Ref.FileIds.Count -gt 0 -and -not $Ref.FileIds.Contains($st.FileId)) {
            $Ref.State = 'Replaced'
            $Ref.StateDetail = 'a different file (other MFT reference) now sits at this path'
        }
        else {
            $Ref.State = 'Present'
            $Ref.SameFile = $Ref.FileIds.Count -gt 0
        }
        return
    }

    # 2 file not found, 3 path not found, 21 device not ready, 123 invalid name
    if ($st.Error -notin 2, 3, 21, 123) {
        $Ref.State = 'Inaccessible'
        $Ref.StateDetail = $st.ErrorText
        return
    }

    foreach ($fileId in $Ref.FileIds) {
        $moved = $script:Resolver.Resolve($Ref.Drive, $fileId)
        if ($moved) {
            $Ref.State = 'Moved'
            $Ref.CurrentPath = $moved
            $Ref.CurrentFileId = $fileId
            $Ref.SameFile = $true
            $Ref.StateDetail = "same file reference now at $moved"
            return
        }
    }
    $Ref.State = 'Missing'
}

function Add-Candidate {
    param([string]$Path, [string]$Source, [string]$Note)
    $c = $null
    if (-not $script:Candidates.TryGetValue($Path, [ref]$c)) {
        $c = @{
            Path       = $Path
            Sources    = [System.Collections.Generic.List[string]]::new()
            Notes      = [System.Collections.Generic.List[string]]::new()
            Refs       = [System.Collections.Generic.List[object]]::new()
            IsStream   = $Path.IndexOf(':', 2) -gt 0
            Stat       = $null
            Probe      = $null
            Status     = 'pending'
            Jar        = $null
            IsJava     = $false
            Sha256     = $null
            Zone       = $null
            Usn        = $null
            Assessment = $null
        }
        $script:Candidates[$Path] = $c
    }
    if (-not $c.Sources.Contains($Source)) { $c.Sources.Add($Source) }
    if ($Note -and -not $c.Notes.Contains($Note)) { $c.Notes.Add($Note) }
    return $c
}

function Update-CandidateInfo($Candidate) {
    if ($Candidate.Status -ne 'pending') { return }
    $st = [DsScan.FileSystem]::Stat($Candidate.Path)
    $Candidate.Stat = $st
    if (-not $st.Exists) {
        $Candidate.Status = 'gone'
        if ($st.Error -notin 2, 3) { Add-ScanError 'Stat' $Candidate.Path $st.ErrorText }
        return
    }
    if ($st.IsDirectory) { $Candidate.Status = 'directory'; return }
    if ($st.Size -lt 22) { $Candidate.Status = 'not-archive'; return }
    if ($st.Size -gt $script:Options.MaxFileBytes) {
        $Candidate.Status = 'too-large'
        Write-DebugLog "Skipped (size $($st.Size)): $($Candidate.Path)"
        return
    }
    try { $Candidate.Probe = [DsScan.ArchiveProbe]::Probe($Candidate.Path) }
    catch {
        $Candidate.Status = 'error'
        Add-ScanError 'Probe' $Candidate.Path (Get-ErrorText $_)
        return
    }
    $Candidate.Status = if ($Candidate.Probe.Kind -eq 'none') { 'not-archive' } else { 'archive' }
}

# ---------------------------------------------------------------------------
# USN journal
# ---------------------------------------------------------------------------

$script:UsnFlags = @{
    DataChange   = 0x7            # overwrite, extend, truncation
    StreamChange = 0x200070       # named data overwrite/extend/truncation, stream change
    Create       = 0x100
    Delete       = 0x200
    RenameOld    = 0x1000
    RenameNew    = 0x2000
    BasicInfo    = 0x8000         # attributes or timestamps
    HardLink     = 0x10000
    Close        = 2147483648     # 0x80000000, written as decimal to stay unsigned in PS 5.1
}

function Read-UsnJournals {
    param([string[]]$Drives, $FileIds, $Names)
    $records = [System.Collections.Generic.List[DsScan.UsnRecord]]::new()
    $journals = [System.Collections.Generic.List[object]]::new()
    foreach ($drive in $Drives) {
        Write-Step "Reading USN journal on ${drive}:"
        try {
            $info = [DsScan.UsnJournal]::Read($drive, $FileIds, $Names, [string[]]@('.jar'), 250000, $records)
        }
        catch {
            Add-ScanError 'USN' "${drive}:" (Get-ErrorText $_)
            continue
        }
        $journals.Add($info)
        if (-not $info.Available -or $info.Error) {
            if ($info.Error) { Write-Warn "USN ${drive}: $($info.Error)" }
            if (-not $info.Available) { continue }
        }
        $since = Format-LocalTime $info.OldestUtc
        Write-Host ('    {0}: {1:N0} records since {2}, {3:N0} relevant{4}' -f $drive, $info.RecordsRead, $since, $info.RecordsKept, $(if ($info.Truncated) { ' (limit reached)' } else { '' })) -ForegroundColor Gray
        $created = $info.CreatedUtc
        if ($created -ne [datetime]::MinValue -and ([DateTime]::UtcNow - $created).TotalHours -lt 24) {
            Write-Warn "USN journal on ${drive}: was created $(Format-LocalTime $created) (recently deleted or recreated?)"
        }
    }
    return @{ Records = $records; Journals = $journals }
}

function Add-ToIndex($Index, [string]$Key, $Record) {
    $list = $null
    if (-not $Index.TryGetValue($Key, [ref]$list)) {
        $list = [System.Collections.Generic.List[object]]::new()
        $Index[$Key] = $list
    }
    $list.Add($Record)
}

function Build-UsnIndex($Records) {
    $index = @{
        ByFile = [System.Collections.Generic.Dictionary[string, object]]::new()
        ByName = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    foreach ($r in $Records) {
        Add-ToIndex $index.ByFile ($r.Drive + '|' + $r.FileId) $r
        Add-ToIndex $index.ByName ($r.Drive + '|' + $r.Name) $r
    }
    return $index
}

function Get-UsnRecordsFor([string]$Drive, [long]$FileId) {
    if (-not $script:UsnIndex -or -not $Drive -or $FileId -eq 0) { return $null }
    $list = $null
    if ($script:UsnIndex.ByFile.TryGetValue($Drive + '|' + $FileId, [ref]$list)) { return , $list }
    return $null
}

# Turns raw records into readable events. A file operation produces several records;
# the one with the CLOSE flag carries the combined reasons, and RENAME_OLD_NAME
# records carry the previous name.
function Get-UsnTimeline($Records) {
    $events = [System.Collections.Generic.List[object]]::new()
    if (-not $Records) { return , $events }
    $f = $script:UsnFlags
    $recentLimit = [DateTime]::UtcNow.AddMinutes(-$script:Options.RecentMinutes)
    $oldName = $null
    foreach ($r in $Records) {
        $reason = [long]$r.Reason
        if ($reason -band $f.RenameOld) { $oldName = $r.Name }
        if (-not ($reason -band $f.Close)) { continue }

        $actions = [System.Collections.Generic.List[string]]::new()
        $renamedFrom = $null
        if ($reason -band $f.Create) { $actions.Add('created') }
        if ($reason -band $f.RenameNew) {
            if ($oldName -and $oldName -ne $r.Name) {
                $renamedFrom = $oldName
                $actions.Add("renamed from $oldName")
            }
            else { $actions.Add('moved') }
            $oldName = $null
        }
        if ($reason -band $f.DataChange) { $actions.Add('data written') }
        if ($reason -band $f.StreamChange) { $actions.Add('alternate stream changed') }
        if ($reason -band $f.BasicInfo) { $actions.Add('attributes/timestamps changed') }
        if ($reason -band $f.HardLink) { $actions.Add('hard link changed') }
        if ($reason -band $f.Delete) { $actions.Add('deleted') }
        if ($actions.Count -eq 0) { continue }

        $events.Add([pscustomobject]@{
            TimeUtc     = $r.TimeUtc
            Name        = $r.Name
            Actions     = $actions -join ', '
            Deleted     = [bool]($reason -band $f.Delete)
            Created     = [bool]($reason -band $f.Create)
            RenamedFrom = $renamedFrom
            Recent      = $r.TimeUtc -ge $recentLimit
            Usn         = $r.Usn
            Reason      = ('0x{0:X8}' -f $reason)
        })
    }
    return , $events
}

function Get-JournalFor([string]$Drive) {
    foreach ($j in $script:UsnJournals) { if ($j.Drive -eq $Drive -and $j.Available) { return $j } }
    return $null
}

# Upgrades 'Missing' to 'Deleted' only when the journal actually recorded a delete,
# by file reference or by name inside the same folder.
function Update-MissingReference($Ref) {
    $f = $script:UsnFlags
    foreach ($fileId in $Ref.FileIds) {
        $timeline = Get-UsnTimeline (Get-UsnRecordsFor $Ref.Drive $fileId)
        if ($timeline.Count -eq 0) { continue }
        $Ref.Usn = $timeline
        $deleted = $timeline | Where-Object { $_.Deleted } | Select-Object -Last 1
        if ($deleted) {
            $Ref.State = 'Deleted'
            $Ref.DeletedUtc = $deleted.TimeUtc
            $Ref.StateDetail = "delete recorded in USN (file reference match) as $($deleted.Name)"
            return
        }
    }

    $leaf = [IO.Path]::GetFileName($Ref.Path)
    $folder = [IO.Path]::GetDirectoryName($Ref.Path)
    $list = $null
    if ($Ref.Drive -and $script:UsnIndex.ByName.TryGetValue($Ref.Drive + '|' + $leaf, [ref]$list)) {
        foreach ($r in $list) {
            if (-not ([long]$r.Reason -band $f.Delete)) { continue }
            $parent = $script:Resolver.Resolve($Ref.Drive, $r.ParentId)
            if ($parent -and $parent.TrimEnd('\') -ieq $folder.TrimEnd('\')) {
                $Ref.State = 'Deleted'
                $Ref.DeletedUtc = $r.TimeUtc
                $Ref.StateDetail = 'delete recorded in USN (same name in the same folder)'
                return
            }
        }
    }

    $journal = Get-JournalFor $Ref.Drive
    if (-not $journal) {
        $Ref.StateDetail = 'not found; no USN data for this volume, deletion cannot be confirmed'
        return
    }
    $lastRun = $Ref.Prefetch | Where-Object { $_.LastRunUtc } | Sort-Object LastRunUtc -Descending | Select-Object -First 1
    if ($lastRun -and $journal.OldestUtc -gt $lastRun.LastRunUtc) {
        $Ref.StateDetail = "not found; the journal starts $(Format-LocalTime $journal.OldestUtc), after the last Java run, so deletion can neither be confirmed nor ruled out"
    }
    else {
        $Ref.StateDetail = "not found and no delete record since $(Format-LocalTime $journal.OldestUtc) (moved to another volume, renamed before the journal window, or removed without a record)"
    }
}

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

function Get-ZoneInfo([string]$Path) {
    try { $text = [DsScan.FileSystem]::ReadText("${Path}:Zone.Identifier", 8192) }
    catch { return $null }
    $zone = [ordered]@{}
    foreach ($line in $text -split "`r?`n") {
        if ($line -match '^(ZoneId|HostUrl|ReferrerUrl)=(.*)$') { $zone[$Matches[1]] = $Matches[2].Trim() }
    }
    if ($zone.Count -eq 0) { return $null }
    return $zone
}

function Get-ManifestAttributes([string]$Manifest) {
    $attributes = [ordered]@{}
    if (-not $Manifest) { return $attributes }
    # Only the main section; per-entry sections start after the first blank line.
    $main = ($Manifest -split "`r?`n`r?`n", 2)[0] -replace "`r?`n ", ''
    foreach ($line in $main -split "`r?`n") {
        if ($line -match '^([A-Za-z0-9_-]+):\s*(.*)$' -and $script:ManifestKeys -contains $Matches[1]) {
            $attributes[$Matches[1]] = $Matches[2].Trim()
        }
    }
    return $attributes
}

function Invoke-ArchiveAnalysis($Candidate) {
    if ($Candidate.Probe.Kind -eq 'class') {
        $jar = [DsScan.JarInspector]::InspectClass($Candidate.Path, $script:SearchPatterns, $script:JarLimits)
        # For a loose class the layout is the folder it sits in: look for the other
        # expected classes next to it under the same net\java root.
        if ($Candidate.Path -match '^(.*)\\net\\java\\[^\\]+$') {
            $root = $Matches[1]
            foreach ($class in $script:ExpectedClasses) {
                $file = Join-Path $root ($class.Replace('/', '\') + '.class')
                if ([DsScan.FileSystem]::Stat($file).Exists) { $jar.WatchedEntries.Add("$class.class") }
            }
        }
    }
    else {
        $jar = [DsScan.JarInspector]::Inspect($Candidate.Path, $Candidate.Probe.ZipOffset, $script:SearchPatterns, $script:WatchedEntries, $script:JarLimits)
    }
    $Candidate.Jar = $jar
    if ($jar.Error) { Add-ScanError 'Archive' $Candidate.Path $jar.Error }
    $Candidate.IsJava = $jar.ClassEntries -gt 0 -or $jar.ClassData -gt 0
    $Candidate.Manifest = Get-ManifestAttributes $jar.Manifest

    try { $Candidate.Sha256 = [DsScan.Hashing]::Sha256($Candidate.Path) }
    catch { Add-ScanError 'Hash' $Candidate.Path (Get-ErrorText $_) }
    if (-not $Candidate.IsStream) { $Candidate.Zone = Get-ZoneInfo $Candidate.Path }

    $Candidate.Assessment = Get-Assessment $Candidate
    $Candidate.Status = 'analyzed'
}

function Add-Evidence {
    param($List, [string]$Kind, [int]$Weight, [string]$Text)
    $List.Add([pscustomobject]@{ Kind = $Kind; Weight = $Weight; Text = $Text })
}

function Get-Assessment($Candidate) {
    $w = $script:Weights
    $jar = $Candidate.Jar
    $evidence = [System.Collections.Generic.List[object]]::new()
    $reasons = [System.Collections.Generic.List[string]]::new()
    $specific = 0
    $secondary = 0
    $context = 0
    $qualifies = $false

    # Doomsday-specific ------------------------------------------------------

    if ($Candidate.Sha256 -and $script:KnownHashes.ContainsKey($Candidate.Sha256)) {
        Add-Evidence $evidence 'specific' $w.KnownHash "SHA-256 matches a known sample ($($script:KnownHashes[$Candidate.Sha256]))"
        $specific += $w.KnownHash
        $qualifies = $true
        $reasons.Add('known sample hash')
    }

    $firstHit = @{}
    $referenceHits = [System.Collections.Generic.SortedSet[string]]::new()
    foreach ($hit in $jar.Hits) {
        if ($hit.Id.StartsWith('REF:')) { [void]$referenceHits.Add($hit.Id.Substring(4)) }
        elseif (-not $firstHit.ContainsKey($hit.Id)) { $firstHit[$hit.Id] = $hit }
    }

    $signatures = [System.Collections.Generic.List[object]]::new()
    $groups = @{}
    foreach ($sig in $script:ByteSignatures) {
        if (-not $firstHit.ContainsKey($sig.Id)) { continue }
        $hit = $firstHit[$sig.Id]
        $weight = if ($groups.ContainsKey($sig.Group)) { $w.SignatureExtra } else { $w.SignatureFirst }
        $groups[$sig.Group] = $true
        $signatures.Add([pscustomobject]@{ Id = $sig.Id; Name = $sig.Name; Entry = $hit.Entry; Offset = $hit.Offset })
        $note = if ($weight -eq $w.SignatureExtra) { ' (overlaps an already matched signature)' } else { '' }
        Add-Evidence $evidence 'specific' $weight ('{0} in {1} @0x{2:X}{3}' -f $sig.Name, $hit.Entry, $hit.Offset, $note)
        $specific += $weight
    }
    if ($groups.Count -gt 0) {
        $qualifies = $true
        $reasons.Add(('{0} known byte signature(s) in {1} independent group(s)' -f $signatures.Count, $groups.Count))
    }

    $layout = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $jar.WatchedEntries) {
        $name = ($entry -split '!/')[-1]
        [void]$layout.Add($name.Substring(0, $name.Length - 6))
    }
    $total = $script:ExpectedClasses.Count
    if ($layout.Count -gt 0) {
        $weight = $layout.Count * $w.ClassEntry
        $short = ($layout | ForEach-Object { $_.Substring($_.LastIndexOf('/') + 1) }) -join ', '
        if ($layout.Count -ge $script:Thresholds.MinClassLayout) {
            Add-Evidence $evidence 'specific' $weight "Matching class structure: $($layout.Count)/$total expected net/java classes ($short)"
            $qualifies = $true
            $reasons.Add("$($layout.Count)/$total expected classes")
        }
        else {
            Add-Evidence $evidence 'specific' $weight "Partial class structure: $($layout.Count)/$total expected net/java classes ($short), below the $($script:Thresholds.MinClassLayout) needed on its own"
        }
        $specific += $weight
    }

    $onlyReferenced = @($referenceHits | Where-Object { -not $layout.Contains($_) })
    if ($onlyReferenced.Count -gt 0) {
        $weight = [Math]::Min($w.ReferenceCap, $onlyReferenced.Count * $w.ClassReference)
        $short = ($onlyReferenced | ForEach-Object { $_.Substring($_.LastIndexOf('/') + 1) }) -join ', '
        Add-Evidence $evidence 'specific' $weight "Constant pool references to expected classes not stored as entries ($short)"
        $specific += $weight
    }

    # Secondary ----------------------------------------------------------------

    $isZip = $Candidate.Probe.Kind -ne 'class'
    $extension = if ($Candidate.IsStream) { '' } else { [IO.Path]::GetExtension($Candidate.Path).ToLowerInvariant() }
    if ($Candidate.IsStream) {
        Add-Evidence $evidence 'secondary' $w.AlternateStream 'Java content stored in an NTFS alternate data stream'
        $secondary += $w.AlternateStream
    }
    elseif ($isZip -and $Candidate.IsJava -and $script:ArchiveExtensions -notcontains $extension) {
        $label = if ($extension) { $extension } else { 'no' }
        if ($script:DisguiseExtensions -contains $extension) {
            Add-Evidence $evidence 'secondary' $w.DisguisedExt "JAR content with $label extension"
            $secondary += $w.DisguisedExt
        }
        else {
            Add-Evidence $evidence 'secondary' $w.RenamedExt "JAR content with $label extension"
            $secondary += $w.RenamedExt
        }
    }

    if ($Candidate.Probe.Kind -eq 'prefixed') {
        if ($Candidate.Probe.Magic.StartsWith('4D5A')) {
            Add-Evidence $evidence 'info' 0 ('Archive appended to an executable at offset {0:N0} (launcher wrapper)' -f $Candidate.Probe.ZipOffset)
        }
        else {
            Add-Evidence $evidence 'secondary' $w.Polyglot ('Archive hidden after {0:N0} bytes of other data (header {1})' -f $Candidate.Probe.ZipOffset, $Candidate.Probe.Magic)
            $secondary += $w.Polyglot
        }
    }
    if ($jar.HiddenClassData -gt 0) {
        Add-Evidence $evidence 'secondary' $w.HiddenClassData "$($jar.HiddenClassData) class file(s) stored under non-.class names (e.g. $($jar.HiddenClassSamples[0]))"
        $secondary += $w.HiddenClassData
    }
    if ($jar.InvalidClassEntries -ge 3) {
        Add-Evidence $evidence 'secondary' $w.EncryptedClasses "$($jar.InvalidClassEntries) .class entries are not valid class files (encrypted or packed)"
        $secondary += $w.EncryptedClasses
    }
    if ($jar.ClassEntries -ge 10 -and $jar.ShortNameClasses / $jar.ClassEntries -ge 0.5) {
        Add-Evidence $evidence 'secondary' $w.Obfuscated ('Obfuscated naming: {0} of {1} classes have 1-2 letter names' -f $jar.ShortNameClasses, $jar.ClassEntries)
        $secondary += $w.Obfuscated
    }
    $agentKeys = @('Premain-Class', 'Agent-Class', 'Launcher-Agent-Class') | Where-Object { $Candidate.Manifest.Contains($_) }
    if ($agentKeys) {
        Add-Evidence $evidence 'secondary' $w.JavaAgent "Manifest declares a Java agent ($(($agentKeys | ForEach-Object { "$_ = $($Candidate.Manifest[$_])" }) -join ', '))"
        $secondary += $w.JavaAgent
    }
    if ($Candidate.Stat -and ($Candidate.Stat.Attributes -band 0x6)) {
        Add-Evidence $evidence 'secondary' $w.HiddenAttribute 'File has the hidden or system attribute'
        $secondary += $w.HiddenAttribute
    }
    $renamedAway = @($Candidate.Usn | Where-Object { $_.RenamedFrom -and $_.RenamedFrom -match '\.jar$' -and $_.Name -notmatch '\.jar$' })
    if ($renamedAway.Count -gt 0) {
        $r = $renamedAway[-1]
        Add-Evidence $evidence 'secondary' $w.UsnRenamedAway "USN: renamed $($r.RenamedFrom) -> $($r.Name) at $(Format-LocalTime $r.TimeUtc)"
        $secondary += $w.UsnRenamedAway
    }

    # Context --------------------------------------------------------------------

    $prefetchRefs = @($Candidate.Refs | Where-Object { $_.Prefetch.Count -gt 0 })
    foreach ($ref in $prefetchRefs) {
        $pf = $ref.Prefetch | Sort-Object LastRunUtc -Descending | Select-Object -First 1
        $names = ($ref.Prefetch | ForEach-Object { $_.Name } | Select-Object -Unique) -join ', '
        $when = if ($pf.LastRunUtc) { ", last run $(Format-LocalTime $pf.LastRunUtc)" } else { '' }
        switch ($ref.State) {
            'Present' {
                $how = if ($ref.SameFile) { 'same file reference' } else { 'path match, no file reference recorded' }
                Add-Evidence $evidence 'context' $w.PrefetchLoaded "Referenced by Java Prefetch: $names$when ($how)"
                $context += $w.PrefetchLoaded
            }
            'Moved' {
                Add-Evidence $evidence 'context' $w.PrefetchLoaded "Referenced by Java Prefetch as $($ref.Path)$when; same file was later moved/renamed here"
                $context += $w.PrefetchLoaded
            }
            'Replaced' {
                Add-Evidence $evidence 'info' 0 "Path listed in Java Prefetch ($names$when), but the file there now has a different file reference"
            }
        }
    }
    $links = @($Candidate.Refs | ForEach-Object { $_.Links } | Where-Object { $_ })
    if ($links.Count -gt 0) {
        Add-Evidence $evidence 'context' $w.RecentLink "Opened from Explorer (Recent shortcut, $(Format-LocalTime $links[0].LinkTimeUtc))"
        $context += $w.RecentLink
    }
    $recent = @($Candidate.Usn | Where-Object { $_.Recent })
    if ($recent.Count -gt 0) {
        Add-Evidence $evidence 'context' $w.UsnRecent "Recent USN activity: $($recent[-1].Actions) at $(Format-LocalTime $recent[-1].TimeUtc)"
        $context += $w.UsnRecent
    }

    # Info ------------------------------------------------------------------------

    if ($Candidate.Zone) {
        $zoneText = ($Candidate.Zone.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '  '
        Add-Evidence $evidence 'info' 0 "Downloaded file (Zone.Identifier): $zoneText"
    }
    if ($jar.SignatureFiles.Count -gt 0) { Add-Evidence $evidence 'info' 0 "Signed JAR ($($jar.SignatureFiles -join ', '))" }
    if ($Candidate.Manifest.Contains('Main-Class')) { Add-Evidence $evidence 'info' 0 "Main-Class: $($Candidate.Manifest['Main-Class'])" }
    if ($jar.NestedArchives -gt 0) { Add-Evidence $evidence 'info' 0 "$($jar.NestedArchives) nested archive(s) inspected" }
    if ($jar.Truncated) { Add-Evidence $evidence 'info' 0 "Analysis limited: $($jar.Notes -join '; ')" }

    $secondaryUsed = [Math]::Min($secondary, $w.SecondaryCap)
    $contextUsed = [Math]::Min($context, $w.ContextCap)
    if ($secondary -gt $secondaryUsed) { Add-Evidence $evidence 'info' 0 "Secondary evidence capped at $($w.SecondaryCap) (raw $secondary)" }
    if ($context -gt $contextUsed) { Add-Evidence $evidence 'info' 0 "Context evidence capped at $($w.ContextCap) (raw $context)" }
    $score = [int][Math]::Min(100, $specific + $secondaryUsed + $contextUsed)

    $confidence = 'NONE'
    if ($qualifies) {
        $confidence = if ($score -ge $script:Thresholds.High) { 'HIGH' } elseif ($score -ge $script:Thresholds.Medium) { 'MEDIUM' } else { 'LOW' }
    }
    $suspicious = -not $qualifies -and ($secondary -ge 8 -or $layout.Count -gt 0 -or $onlyReferenced.Count -gt 0)

    $reason = if ($qualifies) {
        'Detected: ' + ($reasons -join '; ')
    }
    elseif ($suspicious) {
        'Not a detection: no Doomsday-specific evidence strong enough on its own; review manually'
    }
    else { 'No Doomsday evidence' }
    if ($qualifies -and $groups.Count -eq 0 -and -not $script:KnownHashes.ContainsKey([string]$Candidate.Sha256)) {
        $reason += ' (class structure only, no bytecode signature matched)'
    }

    return [pscustomobject]@{
        Score           = $score
        Confidence      = $confidence
        Detected        = $qualifies
        Suspicious      = $suspicious
        Reason          = $reason
        Evidence        = $evidence
        Signatures      = $signatures
        ClassLayout     = @($layout)
        ClassReferences = $onlyReferenced
        Specific        = $specific
        Secondary       = $secondaryUsed
        Context         = $contextUsed
    }
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

function Get-ConfidenceColor([string]$Confidence) {
    switch ($Confidence) {
        'HIGH' { return 'Red' }
        'MEDIUM' { return 'Yellow' }
        'LOW' { return 'DarkYellow' }
        default { return 'Gray' }
    }
}

function Write-Candidate($Candidate, [int]$Number) {
    $a = $Candidate.Assessment
    $st = $Candidate.Stat
    $jar = $Candidate.Jar
    $color = Get-ConfidenceColor $a.Confidence

    Write-Host ("  [$Number] ") -NoNewline -ForegroundColor $color
    Write-Host $Candidate.Path -ForegroundColor White
    Write-Host ('      {0,-11} ' -f 'Score') -NoNewline -ForegroundColor DarkGray
    Write-Host ('{0}/100' -f $a.Score) -NoNewline -ForegroundColor $color
    Write-Host '   Confidence ' -NoNewline -ForegroundColor DarkGray
    Write-Host $a.Confidence -ForegroundColor $color
    Write-Field 'SHA-256' $(if ($Candidate.Sha256) { $Candidate.Sha256 } else { 'unavailable' })
    Write-Field 'Size' (Format-Size $st.Size)
    Write-Field 'Created' (Format-LocalTime $st.CreationUtc)
    Write-Field 'Modified' (Format-LocalTime $st.LastWriteUtc)
    Write-Field 'Accessed' (Format-LocalTime $st.LastAccessUtc)
    if ($Candidate.Probe.Kind -eq 'class') {
        Write-Field 'Content' 'loose Java class file'
    }
    else {
        $built = if ($jar.NewestEntryUtc) { ", entries dated $(Format-LocalTime $jar.OldestEntryUtc) .. $(Format-LocalTime $jar.NewestEntryUtc)" } else { '' }
        Write-Field 'Content' ('{0} entries, {1} classes{2}' -f $jar.Entries, $jar.ClassEntries, $built)
    }
    Write-Field 'Found via' ($Candidate.Sources -join ', ')

    if ($a.Signatures.Count -gt 0) {
        $text = ($a.Signatures | ForEach-Object { '{0} ({1} @0x{2:X})' -f ($_.Name -replace 'Known byte signature ', ''), $_.Entry, $_.Offset }) -join ', '
        Write-Field 'Signatures' $text Red
    }
    else { Write-Field 'Signatures' 'none' }
    $classText = if ($a.ClassLayout.Count -gt 0) { "$($a.ClassLayout.Count)/$($script:ExpectedClasses.Count): $($a.ClassLayout -join ', ')" } else { 'none' }
    if ($a.ClassReferences.Count -gt 0) { $classText += "  | referenced only: $($a.ClassReferences -join ', ')" }
    Write-Field 'Classes' $classText
    if ($jar.ShortNameClasses -gt 0) { Write-Field 'Short names' ('{0} of {1} classes' -f $jar.ShortNameClasses, $jar.ClassEntries) }

    $prefetchLines = @($Candidate.Refs | Where-Object { $_.Prefetch.Count -gt 0 } | ForEach-Object {
            $ref = $_
            $ref.Prefetch | ForEach-Object { '{0} (last run {1}) [{2}]' -f $_.Name, (Format-LocalTime $_.LastRunUtc), $ref.State }
        } | Select-Object -Unique)
    if ($prefetchLines.Count -eq 0) { Write-Field 'Prefetch' 'not referenced' }
    for ($i = 0; $i -lt $prefetchLines.Count; $i++) { Write-Field $(if ($i -eq 0) { 'Prefetch' } else { '' }) $prefetchLines[$i] }

    $usnEvents = @($Candidate.Usn | Where-Object { $_ })
    if (-not $script:UsnIndex) { Write-Field 'USN' 'not checked' }
    elseif ($usnEvents.Count -eq 0) { Write-Field 'USN' 'no records for this file in the journal' }
    $shown = @($usnEvents | Select-Object -Last 8)
    for ($i = 0; $i -lt $shown.Count; $i++) {
        $e = $shown[$i]
        $mark = if ($e.Recent) { ' (recent)' } else { '' }
        Write-Field $(if ($i -eq 0) { 'USN' } else { '' }) ('{0}  {1}: {2}{3}' -f (Format-LocalTime $e.TimeUtc), $e.Name, $e.Actions, $mark)
    }
    if ($usnEvents.Count -gt $shown.Count) { Write-Field '' "... $($usnEvents.Count - $shown.Count) earlier event(s) in the JSON report" }

    Write-Host '      Evidence' -ForegroundColor DarkGray
    foreach ($e in $a.Evidence) {
        switch ($e.Kind) {
            'specific' { $mark = '[+]'; $c = 'Red' }
            'secondary' { $mark = '[~]'; $c = 'Yellow' }
            'context' { $mark = '[>]'; $c = 'Cyan' }
            default { $mark = '[i]'; $c = 'Gray' }
        }
        $weight = if ($e.Weight -gt 0) { '+{0,-3}' -f $e.Weight } else { '    ' }
        Write-Host "        $mark $weight " -NoNewline -ForegroundColor $c
        Write-Host $e.Text -ForegroundColor Gray
    }
    Write-Field 'Reason' $a.Reason White
    Write-Host ''
}

function Write-History {
    $interesting = @($script:Refs.Values | Where-Object {
            ($_.State -in 'Deleted', 'Missing', 'Moved', 'NoVolume', 'Replaced', 'Inaccessible') -and
            ($_.Path -match '\.jar$' -or $_.State -eq 'Moved' -or $_.Links.Count -gt 0)
        } | Sort-Object { $_.State }, { $_.Path })
    $usnDeleted = @($script:UsnOnlyHistory | Sort-Object TimeUtc -Descending)

    if ($interesting.Count -eq 0 -and $usnDeleted.Count -eq 0) { return }

    Write-Host ''
    Write-Host 'Historical JAR references' -ForegroundColor Cyan
    Write-Host '  Paths Java or Explorer used that no longer hold the same file. Not detections by themselves.' -ForegroundColor DarkGray
    Write-Host ''
    foreach ($ref in $interesting) {
        $color = switch ($ref.State) { 'Deleted' { 'Yellow' } 'Moved' { 'Cyan' } default { 'Gray' } }
        Write-Host ('  [{0,-12}] ' -f $ref.State.ToUpperInvariant()) -NoNewline -ForegroundColor $color
        Write-Host $ref.Path -ForegroundColor White
        $sources = @()
        if ($ref.Prefetch.Count -gt 0) {
            $pf = $ref.Prefetch | Sort-Object LastRunUtc -Descending | Select-Object -First 1
            $sources += "Prefetch $($pf.Name) (last run $(Format-LocalTime $pf.LastRunUtc))"
        }
        if ($ref.Links.Count -gt 0) { $sources += "Recent shortcut ($(Format-LocalTime $ref.Links[0].LinkTimeUtc))" }
        if ($sources) { Write-Host "                   $($sources -join ' | ')" -ForegroundColor DarkGray }
        if ($ref.StateDetail) { Write-Host "                   $($ref.StateDetail)" -ForegroundColor DarkGray }
    }

    if ($usnDeleted.Count -gt 0) {
        Write-Host ''
        Write-Host '  JARs deleted according to the USN journal (not referenced by Prefetch):' -ForegroundColor Gray
        foreach ($h in $usnDeleted | Select-Object -First 25) {
            $mark = if ($h.Recent) { ' (recent)' } else { '' }
            Write-Host ('    {0}  {1}{2}' -f (Format-LocalTime $h.TimeUtc), $h.Path, $mark) -ForegroundColor $(if ($h.Recent) { 'Yellow' } else { 'Gray' })
        }
        if ($usnDeleted.Count -gt 25) { Write-Host "    ... $($usnDeleted.Count - 25) more in the JSON report" -ForegroundColor DarkGray }
    }
}

function ConvertTo-ReportCandidate($c) {
    $st = $c.Stat
    $jar = $c.Jar
    $a = $c.Assessment
    return [ordered]@{
        Path       = $c.Path
        Sources    = @($c.Sources)
        Notes      = @($c.Notes)
        Status     = $c.Status
        IsStream   = $c.IsStream
        Size       = if ($st) { $st.Size } else { $null }
        Sha256     = $c.Sha256
        FileId     = if ($st -and $st.FileId) { '0x{0:X16}' -f $st.FileId } else { $null }
        Attributes = if ($st) { '0x{0:X}' -f $st.Attributes } else { $null }
        CreatedUtc  = if ($st) { Format-IsoTime $st.CreationUtc } else { $null }
        ModifiedUtc = if ($st) { Format-IsoTime $st.LastWriteUtc } else { $null }
        AccessedUtc = if ($st) { Format-IsoTime $st.LastAccessUtc } else { $null }
        Score      = if ($a) { $a.Score } else { 0 }
        Confidence = if ($a) { $a.Confidence } else { 'NONE' }
        Detected   = if ($a) { $a.Detected } else { $false }
        Suspicious = if ($a) { $a.Suspicious } else { $false }
        Reason     = if ($a) { $a.Reason } else { $null }
        ScoreParts = if ($a) { [ordered]@{ Specific = $a.Specific; Secondary = $a.Secondary; Context = $a.Context } } else { $null }
        Evidence   = if ($a) { @($a.Evidence | ForEach-Object { [ordered]@{ Kind = $_.Kind; Weight = $_.Weight; Text = $_.Text } }) } else { @() }
        Signatures = if ($a) { @($a.Signatures | ForEach-Object { [ordered]@{ Id = $_.Id; Name = $_.Name; Entry = $_.Entry; Offset = $_.Offset } }) } else { @() }
        ClassLayout     = if ($a) { @($a.ClassLayout) } else { @() }
        ClassReferences = if ($a) { @($a.ClassReferences) } else { @() }
        Archive    = if ($jar) {
            [ordered]@{
                Kind                = $c.Probe.Kind
                ZipOffset           = $c.Probe.ZipOffset
                Entries             = $jar.Entries
                ClassEntries        = $jar.ClassEntries
                ClassData           = $jar.ClassData
                HiddenClassData     = $jar.HiddenClassData
                InvalidClassEntries = $jar.InvalidClassEntries
                ShortNameClasses    = $jar.ShortNameClasses
                ShortNameSamples    = @($jar.ShortNameSamples)
                NestedArchives      = $jar.NestedArchives
                EntryErrors         = $jar.EntryErrors
                BytesRead           = $jar.BytesRead
                Truncated           = $jar.Truncated
                OldestEntryUtc      = Format-IsoTime $jar.OldestEntryUtc
                NewestEntryUtc      = Format-IsoTime $jar.NewestEntryUtc
                SignatureFiles      = @($jar.SignatureFiles)
                Manifest            = $c.Manifest
                Notes               = @($jar.Notes)
                Error               = $jar.Error
            }
        } else { $null }
        Prefetch   = @($c.Refs | ForEach-Object {
                $ref = $_
                $ref.Prefetch | ForEach-Object {
                    [ordered]@{ Prefetch = $_.Name; RecordedPath = $ref.Path; State = $ref.State; LastRunUtc = Format-IsoTime $_.LastRunUtc; RunCount = $_.RunCount; SameFileReference = $ref.SameFile }
                }
            })
        RecentLinks = @($c.Refs | ForEach-Object { $_.Links } | Where-Object { $_ } | ForEach-Object { [ordered]@{ Link = $_.Link; LinkTimeUtc = Format-IsoTime $_.LinkTimeUtc } })
        Usn        = @(ConvertTo-ReportEvents $c.Usn)
        Zone       = $c.Zone
    }
}

function ConvertTo-ReportEvents($Events) {
    foreach ($e in @($Events | Where-Object { $_ } | Select-Object -Last 200)) {
        [ordered]@{ TimeUtc = Format-IsoTime $e.TimeUtc; Name = $e.Name; Actions = $e.Actions; Reason = $e.Reason; Usn = $e.Usn; Recent = $e.Recent }
    }
}

function Get-ReportPath {
    $name = 'doomsday-scan-{0:yyyyMMdd-HHmmss}.json' -f (Get-Date)
    $target = $script:Options.OutputPath
    if ($target) {
        if ($target -like '*.json') { return $target }
        return Join-Path $target $name
    }
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop -or -not (Test-Path -LiteralPath $desktop)) { $desktop = $env:TEMP }
    return Join-Path $desktop $name
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Start-DoomsdayScan {
    $startedUtc = [DateTime]::UtcNow
    $script:ScanErrors = [System.Collections.Generic.List[object]]::new()
    $script:Refs = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $script:Candidates = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $script:KnownHashes = @{}
    $script:UsnJournals = [System.Collections.Generic.List[object]]::new()
    $script:UsnIndex = $null
    $script:UsnOnlyHistory = [System.Collections.Generic.List[object]]::new()

    Show-Banner

    if (-not (Test-Administrator)) {
        Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline
        Write-Host 'Administrator privileges required (Prefetch and the USN journal are protected).'
        Write-Host 'Run PowerShell or CMD as administrator and try again.' -ForegroundColor Yellow
        Write-Host ''
        return
    }

    try { Initialize-Native }
    catch {
        Write-Host "Could not load the native helpers: $(Get-ErrorText $_)" -ForegroundColor Red
        return
    }
    Initialize-Patterns

    $os = [Environment]::OSVersion.Version
    $osName = if ($os.Major -eq 10 -and $os.Build -ge 22000) { 'Windows 11' } elseif ($os.Major -eq 10) { 'Windows 10' } else { "Windows $($os.Major).$($os.Minor)" }
    Write-Step "$osName (build $($os.Build)), PowerShell $($PSVersionTable.PSVersion)"

    $script:Resolver = New-Object DsScan.FileIdResolver
    try {
        $script:VolumeTable = Get-VolumeTable
        Write-Step ('Volumes: {0}' -f (($script:VolumeTable.All | ForEach-Object {
                        $fs = if ($_.FileSystem) { $_.FileSystem } else { '?' }
                        "$($_.Letter): $fs"
                    }) -join ', '))
        Import-HashList $script:Options.HashList
        Write-Host ''

        # 1. Where Java has been --------------------------------------------------

        Write-Step 'Reading Java Prefetch'
        $prefetch = Read-JavaPrefetch
        Write-Good "Prefetch parsed: $($prefetch.Parsed)/$($prefetch.Files.Count), $($script:Refs.Count) paths outside the Windows folder"

        $linkCount = Read-RecentLinks
        if ($linkCount -gt 0) { Write-Good "Recent shortcuts to JAR files: $linkCount" }

        foreach ($ref in $script:Refs.Values) {
            try { Resolve-ReferenceState $ref }
            catch {
                $ref.State = 'Error'
                Add-ScanError 'Reference' $ref.Path (Get-ErrorText $_)
                continue
            }
            if ($ref.State -in 'Present', 'Replaced', 'Moved') {
                $c = Add-Candidate $ref.CurrentPath $(if ($ref.Prefetch.Count -gt 0) { 'Prefetch' } else { 'RecentLink' })
                if ($ref.Links.Count -gt 0 -and -not $c.Sources.Contains('RecentLink')) { $c.Sources.Add('RecentLink') }
                $c.Refs.Add($ref)
                if ($ref.State -eq 'Moved') { $c.Notes.Add("moved or renamed from $($ref.Path)") }
            }
        }
        $states = $script:Refs.Values | Group-Object { $_.State } | ForEach-Object { "$($_.Name) $($_.Count)" }
        if ($states) { Write-Host "    Reference states: $($states -join ', ')" -ForegroundColor Gray }

        foreach ($root in @($script:Options.ScanPath | Where-Object { $_ })) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                Write-Warn "Scan path not found: $root"
                continue
            }
            Write-Step "Sweeping $root"
            $walkErrors = $null
            foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable walkErrors) {
                $null = Add-Candidate $file.FullName 'ScanPath'
            }
            foreach ($e in @($walkErrors)) { if ($e) { Add-ScanError 'ScanPath' $root $e.Exception.Message } }
        }

        # 2. Identify archives by content ------------------------------------------

        Write-Step "Checking $($script:Candidates.Count) file(s) by content"
        $all = @($script:Candidates.Values)
        for ($i = 0; $i -lt $all.Count; $i++) {
            Update-Progress 'Identifying archives' ($i + 1) $all.Count
            try { Update-CandidateInfo $all[$i] }
            catch {
                $all[$i].Status = 'error'
                Add-ScanError 'Probe' $all[$i].Path (Get-ErrorText $_)
            }
        }
        Write-Progress -Activity 'Identifying archives' -Completed

        # 3. USN journal ---------------------------------------------------------

        if ($script:Options.NoUsn -or $script:VolumeTable.Ntfs.Count -eq 0) {
            foreach ($ref in $script:Refs.Values) {
                if ($ref.State -eq 'Missing') { $ref.StateDetail = 'not found at this path; USN not checked, so deletion is not confirmed' }
            }
        }
        if ($script:Options.NoUsn) {
            Write-Warn 'USN journal skipped (-NoUsn)'
        }
        elseif ($script:VolumeTable.Ntfs.Count -eq 0) {
            Write-Warn 'No NTFS volumes found, USN journal skipped'
        }
        else {
            # Keep the journal read focused: archives, anything .jar, and everything that
            # is missing (so a delete record can confirm what happened to it).
            $fileIds = [System.Collections.Generic.HashSet[long]]::new()
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($ref in $script:Refs.Values) {
                if ($ref.Path -match '\.jar$' -or $ref.State -in 'Missing', 'Moved', 'NoVolume', 'Replaced') {
                    foreach ($id in $ref.FileIds) { [void]$fileIds.Add($id) }
                    [void]$names.Add([IO.Path]::GetFileName($ref.Path))
                }
            }
            foreach ($c in $script:Candidates.Values) {
                if ($c.Status -eq 'archive' -and $c.Stat.FileId) {
                    [void]$fileIds.Add($c.Stat.FileId)
                    [void]$names.Add([IO.Path]::GetFileName($c.Path))
                }
            }

            $usn = Read-UsnJournals -Drives $script:VolumeTable.Ntfs -FileIds $fileIds -Names $names
            $script:UsnJournals = $usn.Journals
            $script:UsnIndex = Build-UsnIndex $usn.Records

            # Files that were .jar at some point: find where they are now.
            $recentLimit = [DateTime]::UtcNow.AddMinutes(-$script:Options.RecentMinutes)
            foreach ($key in @($script:UsnIndex.ByFile.Keys)) {
                $records = $script:UsnIndex.ByFile[$key]
                $jarRecord = $null
                foreach ($r in $records) { if ($r.Name -match '\.jar$') { $jarRecord = $r } }
                if (-not $jarRecord) { continue }
                $current = $script:Resolver.Resolve($jarRecord.Drive, $jarRecord.FileId)
                if ($current) {
                    if ((Test-SystemPath $current) -or $script:Candidates.ContainsKey($current)) { continue }
                    $c = Add-Candidate $current 'USN' "JAR activity in the USN journal (as $($jarRecord.Name))"
                    try { Update-CandidateInfo $c }
                    catch { Add-ScanError 'Probe' $current (Get-ErrorText $_) }
                    continue
                }
                $timeline = Get-UsnTimeline $records
                $deleted = $timeline | Where-Object { $_.Deleted } | Select-Object -Last 1
                if (-not $deleted) { continue }
                $folder = $script:Resolver.Resolve($jarRecord.Drive, $jarRecord.ParentId)
                $path = if ($folder) { Join-Path $folder $deleted.Name } else { "$($jarRecord.Drive):\<unknown folder>\$($deleted.Name)" }
                if (Test-SystemPath $path) { continue }
                if ($script:Refs.ContainsKey($path)) { continue }
                $script:UsnOnlyHistory.Add([pscustomobject]@{
                        Path     = $path
                        TimeUtc  = $deleted.TimeUtc
                        Recent   = $deleted.TimeUtc -ge $recentLimit
                        FileId   = '0x{0:X16}' -f $jarRecord.FileId
                        Timeline = $timeline
                    })
            }

            foreach ($ref in $script:Refs.Values) {
                if ($ref.State -eq 'Missing') {
                    try { Update-MissingReference $ref }
                    catch { Add-ScanError 'USN' $ref.Path (Get-ErrorText $_) }
                }
                elseif ($ref.State -in 'Replaced', 'Moved') {
                    foreach ($id in $ref.FileIds) {
                        $t = Get-UsnTimeline (Get-UsnRecordsFor $ref.Drive $id)
                        if ($t.Count -gt 0) { $ref.Usn = $t }
                    }
                }
            }
        }

        # 4. Archives hidden in alternate data streams --------------------------------

        foreach ($c in @($script:Candidates.Values)) {
            if ($c.IsStream -or -not $c.Stat -or -not $c.Stat.Exists -or $c.Stat.IsDirectory) { continue }
            try { $streams = [DsScan.FileSystem]::ListStreams($c.Path) }
            catch { continue }
            foreach ($s in $streams) {
                $name = $s.Name -replace ':\$DATA$', ''
                if (-not $name -or $name -eq ':' -or $s.Size -lt 22) { continue }
                $streamPath = $c.Path + $name
                try { $probe = [DsScan.ArchiveProbe]::Probe($streamPath) }
                catch {
                    Add-ScanError 'Stream' $streamPath (Get-ErrorText $_)
                    continue
                }
                if ($probe.Kind -eq 'none') { continue }
                $sc = Add-Candidate $streamPath 'ADS' "alternate data stream of $($c.Path)"
                Update-CandidateInfo $sc
            }
        }

        # 5. Analyze -----------------------------------------------------------------

        $archives = @($script:Candidates.Values | Where-Object { $_.Status -eq 'archive' })
        Write-Step "Analyzing $($archives.Count) archive(s)"
        for ($i = 0; $i -lt $archives.Count; $i++) {
            $c = $archives[$i]
            Update-Progress 'Analyzing archives' ($i + 1) $archives.Count
            if ($script:UsnIndex -and $c.Stat.FileId) {
                $c.Usn = Get-UsnTimeline (Get-UsnRecordsFor (Get-DriveLetter $c.Path) $c.Stat.FileId)
            }
            try { Invoke-ArchiveAnalysis $c }
            catch {
                $c.Status = 'error'
                Add-ScanError 'Analysis' $c.Path (Get-ErrorText $_)
            }
            if ($c.Assessment -and $c.Assessment.Detected) {
                Write-Host '[!] ' -NoNewline -ForegroundColor Red
                Write-Host "$($c.Assessment.Confidence) " -NoNewline -ForegroundColor (Get-ConfidenceColor $c.Assessment.Confidence)
                Write-Host $c.Path
            }
        }
        Write-Progress -Activity 'Analyzing archives' -Completed
    }
    finally {
        $script:Resolver.Dispose()
    }

    # 6. Report -------------------------------------------------------------------

    $analyzed = @($script:Candidates.Values | Where-Object { $_.Status -eq 'analyzed' })
    $jars = @($analyzed | Where-Object { $_.IsJava })
    $detections = @($analyzed | Where-Object { $_.Assessment.Detected } | Sort-Object { $_.Assessment.Score } -Descending)
    $suspicious = @($analyzed | Where-Object { $_.Assessment.Suspicious } | Sort-Object { $_.Assessment.Score } -Descending)
    $high = @($detections | Where-Object { $_.Assessment.Confidence -eq 'HIGH' }).Count
    $medium = @($detections | Where-Object { $_.Assessment.Confidence -eq 'MEDIUM' }).Count
    $low = @($detections | Where-Object { $_.Assessment.Confidence -eq 'LOW' }).Count
    $checked = @($script:Candidates.Values | Where-Object { $_.Status -notin 'pending', 'gone', 'directory' }).Count
    $tooLarge = @($script:Candidates.Values | Where-Object { $_.Status -eq 'too-large' })

    if ($detections.Count -gt 0) {
        Write-Host ''
        Write-Host '========================================' -ForegroundColor Red
        Write-Host 'DETECTIONS' -ForegroundColor Red
        Write-Host '========================================' -ForegroundColor Red
        Write-Host '  [+] Doomsday-specific  [~] secondary  [>] context  [i] info' -ForegroundColor DarkGray
        Write-Host ''
        $n = 1
        foreach ($c in $detections) { Write-Candidate $c $n; $n++ }
    }

    if ($suspicious.Count -gt 0) {
        Write-Host ''
        Write-Host 'Worth a manual look (generic indicators only, not detections)' -ForegroundColor Yellow
        Write-Host ''
        $n = 1
        foreach ($c in $suspicious | Select-Object -First 15) { Write-Candidate $c $n; $n++ }
        if ($suspicious.Count -gt 15) { Write-Host "  ... $($suspicious.Count - 15) more in the JSON report" -ForegroundColor DarkGray }
    }

    Write-History

    $finishedUtc = [DateTime]::UtcNow
    $refStates = @{}
    foreach ($ref in $script:Refs.Values) { $refStates[$ref.State] = 1 + [int]$refStates[$ref.State] }

    Write-Host ''
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host 'SUMMARY' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    $rows = [ordered]@{
        'Java Prefetch parsed'  = "$($prefetch.Parsed)/$($prefetch.Files.Count)"
        'Historical paths'      = "$($script:Refs.Count) (deleted $([int]$refStates['Deleted']), missing $([int]$refStates['Missing']), moved $([int]$refStates['Moved']))"
        'Files analyzed'        = $checked
        'Candidates'            = "$($jars.Count) with Java code ($($analyzed.Count) archives/class files opened)"
        'Detections'            = $detections.Count
        '  HIGH'                = $high
        '  MEDIUM'              = $medium
        '  LOW'                 = $low
        'Manual review'         = $suspicious.Count
        'Too large to open'     = $tooLarge.Count
        'Errors'                = $script:ScanErrors.Count
        'Duration'              = '{0:N1} s' -f ($finishedUtc - $startedUtc).TotalSeconds
    }
    foreach ($row in $rows.GetEnumerator()) {
        $color = 'Gray'
        if ($row.Key -eq 'Detections' -and $detections.Count -gt 0) { $color = 'Red' }
        if ($row.Key -eq '  HIGH' -and $high -gt 0) { $color = 'Red' }
        if ($row.Key -eq '  MEDIUM' -and $medium -gt 0) { $color = 'Yellow' }
        if ($row.Key -eq 'Errors' -and $script:ScanErrors.Count -gt 0) { $color = 'Yellow' }
        Write-Host ('  {0,-22} {1}' -f $row.Key, $row.Value) -ForegroundColor $color
    }
    Write-Host ''
    if ($high -gt 0) { Write-Host 'Doomsday client found on this system.' -ForegroundColor Red }
    elseif ($detections.Count -gt 0) { Write-Host 'Possible Doomsday traces found. Review the evidence above.' -ForegroundColor Yellow }
    else { Write-Host 'No Doomsday client detected.' -ForegroundColor Green }

    if ($script:ScanErrors.Count -gt 0 -and $script:Options.DebugLog) {
        Write-Host ''
        Write-Host 'Errors' -ForegroundColor Yellow
        foreach ($e in $script:ScanErrors) { Write-Host "  [$($e.Stage)] $($e.Target): $($e.Message)" -ForegroundColor DarkGray }
    }

    if ($script:Options.NoJson) { Write-Host ''; return }

    $report = [ordered]@{
        Scanner    = [ordered]@{
            Name           = 'Doomsday Client Scanner'
            Version        = $script:ScannerVersion
            ScanStartedUtc = Format-IsoTime $startedUtc
            ScanFinishedUtc = Format-IsoTime $finishedUtc
            DurationSeconds = [Math]::Round(($finishedUtc - $startedUtc).TotalSeconds, 1)
            Computer       = $env:COMPUTERNAME
            User           = "$env:USERDOMAIN\$env:USERNAME"
            OS             = "$osName build $($os.Build)"
            PowerShell     = $PSVersionTable.PSVersion.ToString()
        }
        Settings   = [ordered]@{
            RecentMinutes    = $script:Options.RecentMinutes
            MaxFileSizeMB    = [int]($script:Options.MaxFileBytes / 1MB)
            ScanPath         = @($script:Options.ScanPath)
            UsnEnabled       = -not $script:Options.NoUsn
            KnownHashes      = $script:KnownHashes.Count
            Weights          = $script:Weights
            Thresholds       = $script:Thresholds
        }
        Summary    = [ordered]@{
            PrefetchParsed   = $prefetch.Parsed
            PrefetchFiles    = $prefetch.Files.Count
            HistoricalPaths  = $script:Refs.Count
            ReferenceStates  = $refStates
            FilesAnalyzed    = $checked
            Archives         = $analyzed.Count
            Candidates       = $jars.Count
            Detections       = $detections.Count
            High             = $high
            Medium           = $medium
            Low              = $low
            ManualReview     = $suspicious.Count
            TooLarge         = @($tooLarge | ForEach-Object { [ordered]@{ Path = $_.Path; Size = $_.Stat.Size } })
            Errors           = $script:ScanErrors.Count
        }
        Detections = @($detections | ForEach-Object { ConvertTo-ReportCandidate $_ })
        ManualReview = @($suspicious | ForEach-Object { ConvertTo-ReportCandidate $_ })
        Archives   = @($analyzed | Where-Object { -not $_.Assessment.Detected -and -not $_.Assessment.Suspicious } | ForEach-Object {
                [ordered]@{ Path = $_.Path; Sources = @($_.Sources); Size = $_.Stat.Size; Sha256 = $_.Sha256; ClassEntries = $_.Jar.ClassEntries; Score = $_.Assessment.Score }
            })
        History    = @($script:Refs.Values | Where-Object { $_.State -ne 'Present' } | ForEach-Object {
                [ordered]@{
                    Path          = $_.Path
                    RawPath       = $_.RawPath
                    State         = $_.State
                    Detail        = $_.StateDetail
                    CurrentPath   = $_.CurrentPath
                    VolumeMapping = $_.ResolveMethod
                    DeletedUtc    = Format-IsoTime $_.DeletedUtc
                    FileIds       = @($_.FileIds | ForEach-Object { '0x{0:X16}' -f $_ })
                    Prefetch      = @($_.Prefetch | ForEach-Object { [ordered]@{ Prefetch = $_.Name; LastRunUtc = Format-IsoTime $_.LastRunUtc } })
                    RecentLinks   = @($_.Links | ForEach-Object { $_.Link })
                    Usn           = @(ConvertTo-ReportEvents $_.Usn)
                }
            })
        UsnDeletedJars = @($script:UsnOnlyHistory | Select-Object -First 500 | ForEach-Object {
                [ordered]@{ Path = $_.Path; DeletedUtc = Format-IsoTime $_.TimeUtc; FileId = $_.FileId; Usn = @(ConvertTo-ReportEvents $_.Timeline) }
            })
        Prefetch   = [ordered]@{
            Directory        = $prefetch.Directory
            TotalFiles       = $prefetch.TotalPrefetch
            OldestCreatedUtc = Format-IsoTime $prefetch.OldestPrefetch
            EnablePrefetcher = $prefetch.Settings.EnablePrefetcher
            SysMain          = $prefetch.Settings.SysMain
            Java             = @($prefetch.Files | ForEach-Object {
                    $info = $_.Info
                    [ordered]@{
                        Name       = $_.Name
                        Error      = $_.Error
                        Version    = if ($info) { $info.Version } else { $null }
                        Compressed = if ($info) { $info.Compressed } else { $null }
                        Executable = if ($info) { $info.Executable } else { $null }
                        RunCount   = if ($info) { $info.RunCount } else { $null }
                        LastRunsUtc = if ($info) { @($info.LastRunsUtc | ForEach-Object { Format-IsoTime $_ }) } else { @() }
                        Files      = if ($info) { $info.Files.Count } else { 0 }
                        Volumes    = if ($info) { @($info.Volumes | ForEach-Object { [ordered]@{ Device = $_.DevicePath; Serial = $_.Serial.ToString('X8') } }) } else { @() }
                        Warnings   = if ($info) { @($info.Warnings) } else { @() }
                    }
                })
        }
        UsnJournals = @($script:UsnJournals | ForEach-Object {
                [ordered]@{
                    Drive       = $_.Drive
                    Available   = $_.Available
                    Error       = $_.Error
                    CreatedUtc  = Format-IsoTime $_.CreatedUtc
                    OldestUtc   = Format-IsoTime $_.OldestUtc
                    NewestUtc   = Format-IsoTime $_.NewestUtc
                    RecordsRead = $_.RecordsRead
                    RecordsKept = $_.RecordsKept
                    Truncated   = $_.Truncated
                    MaximumSize = $_.MaximumSize
                }
            })
        Errors     = @($script:ScanErrors)
    }

    $path = Get-ReportPath
    try {
        $folder = Split-Path -Parent $path
        if ($folder -and -not (Test-Path -LiteralPath $folder)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
        $json = $report | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
        Write-Host ''
        Write-Good "Report saved: $path"
    }
    catch {
        Write-Warn "Could not write the report to ${path}: $(Get-ErrorText $_)"
    }
    Write-Host ''
}

Start-DoomsdayScan
