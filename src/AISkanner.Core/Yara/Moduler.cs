using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AISkanner.YaraMotor;

/// <summary>
/// YARA-modulene pe, math, hash, time, string og console. Tekst i YARA er bytes; her lagres de som tekst der hvert tegn er én byte.
/// </summary>
internal static class Moduler
{
    public static string Latin1(byte[] b, int fra = 0, int lengde = -1)
    {
        if (lengde < 0) lengde = b.Length - fra;
        var c = new char[lengde];
        for (int i = 0; i < lengde; i++) c[i] = (char)b[fra + i];
        return new string(c);
    }

    public static byte[] Bytes(string s)
    {
        var b = new byte[s.Length];
        for (int i = 0; i < s.Length; i++) b[i] = (byte)s[i];
        return b;
    }

    private static long? L(object? o) => o switch { long l => l, double d => (long)d, bool b => b ? 1 : 0, _ => null };
    private static double? D(object? o) => o switch { long l => l, double d => d, bool b => b ? 1 : 0, _ => null };

    /// <summary>Bytes fra (forskyvning, størrelse) eller fra en tekst, avhengig av argumentene. Uten kopi når det går.</summary>
    private static ArraySegment<byte>? Data(Kontekst k, object?[] a, int forste = 0)
    {
        if (a.Length > forste && a[forste] is string s) return new ArraySegment<byte>(Bytes(s));
        if (a.Length >= forste + 2 && L(a[forste]) is { } fra && L(a[forste + 1]) is { } st)
        {
            if (fra < 0 || st < 0 || fra >= k.Filstorrelse) return null;
            return k.Omrade(fra, System.Math.Min(st, k.Filstorrelse - fra));
        }
        if (a.Length == forste) return k.Omrade(0, k.Filstorrelse);
        return null;
    }

    /// <summary>Histogram for området, regnet ut én gang per fil og område.</summary>
    private static long[]? Histogram(Kontekst k, object?[] a, int forste = 0)
    {
        if (a.Length > forste && a[forste] is string)
            return Data(k, a, forste) is { } t ? Tell(t) : null;
        long fra = 0, st = k.Filstorrelse;
        if (a.Length >= forste + 2) { if (L(a[forste]) is not { } f || L(a[forste + 1]) is not { } l) return null; fra = f; st = l; }
        if (fra < 0 || st < 0 || fra >= k.Filstorrelse) return null;
        st = System.Math.Min(st, k.Filstorrelse - fra);
        if (k.Histogrammer.TryGetValue((fra, st), out var h)) return h;
        return k.Omrade(fra, st) is { } d ? k.Histogrammer[(fra, st)] = Tell(d) : null;
    }

    private static long[] Tell(ArraySegment<byte> d)
    {
        var n = new long[256];
        var arr = d.Array!;
        for (int i = d.Offset, slutt = d.Offset + d.Count; i < slutt; i++) n[arr[i]]++;
        return n;
    }

    // ---------- math ----------

    public static Struktur Math()
    {
        var m = new Struktur();
        m["MEAN_BYTES"] = 127.5;
        m["entropy"] = (Funksjon)((k, a) =>
        {
            var n = Histogram(k, a); if (n == null) return null;
            long tot = n.Sum(); if (tot == 0) return 0.0;
            double e = 0;
            foreach (var c in n) if (c > 0) { double p = (double)c / tot; e -= p * System.Math.Log(p, 2); }
            return e;
        });
        m["mean"] = (Funksjon)((k, a) =>
        {
            var n = Histogram(k, a); if (n == null) return null;
            long tot = n.Sum(); if (tot == 0) return null;
            double sum = 0; for (int i = 0; i < 256; i++) sum += (double)i * n[i];
            return sum / tot;
        });
        m["deviation"] = (Funksjon)((k, a) =>
        {
            var snitt = D(a[a.Length - 1]) ?? 0;
            var n = Histogram(k, a.Take(a.Length - 1).ToArray()); if (n == null) return null;
            long tot = n.Sum(); if (tot == 0) return null;
            double sum = 0; for (int i = 0; i < 256; i++) sum += System.Math.Abs(i - snitt) * n[i];
            return sum / tot;
        });
        m["serial_correlation"] = (Funksjon)((k, a) =>
        {
            if (Data(k, a) is not { } seg || seg.Count < 2) return null;
            var d = seg.Array!; int o = seg.Offset, c = seg.Count;
            double t1 = 0, t2 = 0, t3 = 0; double forrige = d[o + c - 1];
            for (int i = o; i < o + c; i++) { double x = d[i]; t1 += forrige * x; t2 += x; t3 += x * x; forrige = x; }
            double n = c, nevner = n * t3 - t2 * t2;
            return nevner == 0 ? -100000.0 : (n * t1 - t2 * t2) / nevner;
        });
        m["monte_carlo_pi"] = (Funksjon)((k, a) =>
        {
            if (Data(k, a) is not { } seg || seg.Count < 6) return null;
            var d = seg.Array!; int o = seg.Offset, c = seg.Count;
            long inni = 0, totalt = 0; double r = System.Math.Pow(256, 3) - 1;
            for (int i = o; i + 6 <= o + c; i += 6)
            {
                double x = d[i] * 65536.0 + d[i + 1] * 256.0 + d[i + 2], y = d[i + 3] * 65536.0 + d[i + 4] * 256.0 + d[i + 5];
                totalt++; if (x * x + y * y <= r * r) inni++;
            }
            return System.Math.Abs(4.0 * inni / totalt - System.Math.PI) / System.Math.PI;
        });
        m["in_range"] = (Funksjon)((k, a) => D(a[0]) is { } t && D(a[1]) is { } lo && D(a[2]) is { } hi ? (t >= lo && t <= hi) : null);
        m["max"] = (Funksjon)((k, a) => L(a[0]) is { } x && L(a[1]) is { } y ? System.Math.Max(x, y) : null);
        m["min"] = (Funksjon)((k, a) => L(a[0]) is { } x && L(a[1]) is { } y ? System.Math.Min(x, y) : null);
        m["abs"] = (Funksjon)((k, a) => L(a[0]) is { } x ? System.Math.Abs(x) : null);
        m["to_number"] = (Funksjon)((k, a) => L(a[0]));
        m["count"] = (Funksjon)((k, a) => L(a[0]) is { } b && b is >= 0 and <= 255 && Histogram(k, a, 1) is { } n ? n[b] : null);
        m["percentage"] = (Funksjon)((k, a) =>
            L(a[0]) is { } b && b is >= 0 and <= 255 && Histogram(k, a, 1) is { } n && n.Sum() is var tot and > 0 ? (double)n[b] / tot : null);
        m["mode"] = (Funksjon)((k, a) =>
        {
            var n = Histogram(k, a); if (n == null || n.Sum() == 0) return null;
            return (long)Array.IndexOf(n, n.Max());
        });
        return m;
    }

    // ---------- hash ----------

    public static Struktur Hash()
    {
        var m = new Struktur();
        static string Hex(byte[] h) => string.Concat(h.Select(b => b.ToString("x2")));
        m["md5"] = (Funksjon)((k, a) => Data(k, a) is { } d ? Hex(MD5.Create().ComputeHash(d.Array!, d.Offset, d.Count)) : null);
        m["sha1"] = (Funksjon)((k, a) => Data(k, a) is { } d ? Hex(SHA1.Create().ComputeHash(d.Array!, d.Offset, d.Count)) : null);
        m["sha256"] = (Funksjon)((k, a) => Data(k, a) is { } d ? Hex(SHA256.Create().ComputeHash(d.Array!, d.Offset, d.Count)) : null);
        m["crc32"] = (Funksjon)((k, a) => Data(k, a) is { } d ? (long)Crc32(d) : null);
        m["checksum32"] = (Funksjon)((k, a) =>
        {
            if (Data(k, a) is not { } d) return null;
            uint sum = 0; var arr = d.Array!; for (int i = d.Offset; i < d.Offset + d.Count; i++) sum += arr[i];
            return (long)sum;
        });
        return m;
    }

    private static readonly uint[] CrcTabell = Enumerable.Range(0, 256).Select(n =>
    {
        uint c = (uint)n;
        for (int i = 0; i < 8; i++) c = (c & 1) != 0 ? (c >> 1) ^ 0xEDB88320 : c >> 1;
        return c;
    }).ToArray();

    private static uint Crc32(ArraySegment<byte> d)
    {
        uint c = 0xFFFFFFFF;
        var arr = d.Array!;
        for (int i = d.Offset; i < d.Offset + d.Count; i++) c = CrcTabell[(c ^ arr[i]) & 0xFF] ^ (c >> 8);
        return ~c;
    }

    public static Struktur Tid()
    {
        var m = new Struktur();
        m["now"] = (Funksjon)((k, a) => (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);
        return m;
    }

    public static Struktur Tekst()
    {
        var m = new Struktur();
        m["to_int"] = (Funksjon)((k, a) =>
        {
            if (a[0] is not string s) return null;
            try
            {
                int grunntall = a.Length > 1 && L(a[1]) is { } g ? (int)g : 10;
                s = s.Trim();
                if (grunntall == 10 && s.StartsWith("0x")) return Convert.ToInt64(s.Substring(2), 16);
                return Convert.ToInt64(s, grunntall);
            }
            catch { return null; }
        });
        m["length"] = (Funksjon)((k, a) => a[0] is string s ? (long)s.Length : null);
        return m;
    }

    public static Struktur Konsoll()
    {
        var m = new Struktur();
        m["log"] = (Funksjon)((k, a) => true);
        m["hex"] = (Funksjon)((k, a) => true);
        return m;
    }

    // ---------- pe ----------

    public static Struktur Pe(Kontekst k)
    {
        var pe = new Struktur();
        // Konstanter
        foreach (var (n, v) in new (string, long)[]
        {
            ("MACHINE_UNKNOWN", 0), ("MACHINE_I386", 0x14c), ("MACHINE_AMD64", 0x8664), ("MACHINE_ARM", 0x1c0), ("MACHINE_ARMNT", 0x1c4), ("MACHINE_ARM64", 0xaa64), ("MACHINE_IA64", 0x200),
            ("RELOCS_STRIPPED", 0x1), ("EXECUTABLE_IMAGE", 0x2), ("LINE_NUMS_STRIPPED", 0x4), ("LOCAL_SYMS_STRIPPED", 0x8), ("LARGE_ADDRESS_AWARE", 0x20),
            ("MACHINE_32BIT", 0x100), ("DEBUG_STRIPPED", 0x200), ("SYSTEM", 0x1000), ("DLL", 0x2000),
            ("SUBSYSTEM_UNKNOWN", 0), ("SUBSYSTEM_NATIVE", 1), ("SUBSYSTEM_WINDOWS_GUI", 2), ("SUBSYSTEM_WINDOWS_CUI", 3), ("SUBSYSTEM_EFI_APPLICATION", 10),
            ("DYNAMIC_BASE", 0x40), ("FORCE_INTEGRITY", 0x80), ("NX_COMPAT", 0x100), ("NO_SEH", 0x400), ("GUARD_CF", 0x4000),
            ("SECTION_CNT_CODE", 0x20), ("SECTION_CNT_INITIALIZED_DATA", 0x40), ("SECTION_CNT_UNINITIALIZED_DATA", 0x80),
            ("SECTION_MEM_SHARED", 0x10000000), ("SECTION_MEM_EXECUTE", 0x20000000), ("SECTION_MEM_READ", 0x40000000), ("SECTION_MEM_WRITE", unchecked((long)0x80000000)),
            ("IMAGE_DIRECTORY_ENTRY_EXPORT", 0), ("IMAGE_DIRECTORY_ENTRY_IMPORT", 1), ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 2), ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4),
            ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 5), ("IMAGE_DIRECTORY_ENTRY_DEBUG", 6), ("IMAGE_DIRECTORY_ENTRY_TLS", 9), ("IMAGE_DIRECTORY_ENTRY_IAT", 12),
            ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 14),
        }) pe[n] = v;
        pe["is_pe"] = 0L;
        // Funksjonene finnes alltid, men gir "udefinert" for filer som ikke er PE
        Funksjon udef = (_, _) => null;
        foreach (var f in new[] { "imports", "exports", "is_dll", "is_32bit", "is_64bit", "imphash", "rva_to_offset", "section_index", "exports_index", "imports_index" }) pe[f] = udef;

        uint U32(long p) { var b = k.Les(p, 4); return b == null ? 0 : BitConverter.ToUInt32(b, 0); }
        ushort U16(long p) { var b = k.Les(p, 2); return b == null ? (ushort)0 : BitConverter.ToUInt16(b, 0); }
        ulong U64(long p) { var b = k.Les(p, 8); return b == null ? 0 : BitConverter.ToUInt64(b, 0); }

        if (k.Filstorrelse < 64 || U16(0) != 0x5A4D) return pe;
        long nt = U32(0x3C);
        if (nt <= 0 || nt > k.Filstorrelse - 24 || U32(nt) != 0x00004550) return pe;
        pe["is_pe"] = 1L;
        long coff = nt + 4;
        ushort maskin = U16(coff), antSeksjoner = U16(coff + 2), optStr = U16(coff + 16), kjennetegn = U16(coff + 18);
        long opt = coff + 20;
        ushort magic = U16(opt);
        bool er64 = magic == 0x20b;
        pe["machine"] = (long)maskin;
        pe["number_of_sections"] = (long)antSeksjoner;
        pe["timestamp"] = (long)U32(coff + 4);
        pe["pointer_to_symbol_table"] = (long)U32(coff + 8);
        pe["number_of_symbols"] = (long)U32(coff + 12);
        pe["size_of_optional_header"] = (long)optStr;
        pe["characteristics"] = (long)kjennetegn;
        pe["opthdr_magic"] = (long)magic;
        long entryRva = U32(opt + 16);
        pe["entry_point_raw"] = entryRva;
        pe["base_of_code"] = (long)U32(opt + 20);
        pe["image_base"] = er64 ? (long)U64(opt + 24) : U32(opt + 28);
        pe["section_alignment"] = (long)U32(opt + 32);
        pe["file_alignment"] = (long)U32(opt + 36);
        pe["major_operating_system_version"] = (long)U16(opt + 40);
        pe["minor_operating_system_version"] = (long)U16(opt + 42);
        pe["major_subsystem_version"] = (long)U16(opt + 48);
        pe["minor_subsystem_version"] = (long)U16(opt + 50);
        pe["size_of_image"] = (long)U32(opt + 56);
        pe["size_of_headers"] = (long)U32(opt + 60);
        pe["checksum"] = (long)U32(opt + 64);
        pe["subsystem"] = (long)U16(opt + 68);
        pe["dll_characteristics"] = (long)U16(opt + 70);
        long antRva = U32(opt + (er64 ? 108 : 92));
        pe["number_of_rva_and_sizes"] = antRva;
        long kataloger = opt + (er64 ? 112 : 96);
        var dirs = new List<object?>();
        for (int i = 0; i < System.Math.Min(antRva, 16); i++)
        {
            var d = new Struktur { ["virtual_address"] = (long)U32(kataloger + i * 8), ["size"] = (long)U32(kataloger + i * 8 + 4) };
            dirs.Add(d);
        }
        pe["data_directories"] = dirs;

        // Seksjoner
        long seksjonTabell = opt + optStr;
        var seksjoner = new List<object?>();
        var sek = new List<(string Navn, long Va, long Vs, long Ptr, long Str)>();
        for (int i = 0; i < System.Math.Min((int)antSeksjoner, 96); i++)
        {
            long p = seksjonTabell + i * 40;
            var navnB = k.Les(p, 8); if (navnB == null) break;
            int nl = Array.IndexOf(navnB, (byte)0); if (nl < 0) nl = 8;
            var navn = Latin1(navnB, 0, nl);
            long vs = U32(p + 8), va = U32(p + 12), str = U32(p + 16), ptr = U32(p + 20);
            sek.Add((navn, va, vs, ptr, str));
            seksjoner.Add(new Struktur
            {
                ["name"] = navn, ["full_name"] = navn, ["virtual_address"] = va, ["virtual_size"] = vs,
                ["raw_data_offset"] = ptr, ["raw_data_size"] = str, ["characteristics"] = (long)U32(p + 36),
                ["pointer_to_relocations"] = (long)U32(p + 24), ["pointer_to_line_numbers"] = (long)U32(p + 28),
                ["number_of_relocations"] = (long)U16(p + 32), ["number_of_line_numbers"] = (long)U16(p + 34),
            });
        }
        pe["sections"] = seksjoner;

        long? TilFil(long rva)
        {
            foreach (var s in sek)
                if (rva >= s.Va && rva < s.Va + System.Math.Max(s.Vs, s.Str)) return s.Ptr + (rva - s.Va);
            return rva < (long)U32(opt + 60) ? rva : null;
        }
        string? Ztekst(long? fil, int maks = 512)
        {
            if (fil is not { } f) return null;
            var sb = new StringBuilder();
            for (int i = 0; i < maks; i++) { int c = k.Byte(f + i); if (c <= 0) break; sb.Append((char)c); }
            return sb.ToString();
        }
        pe["entry_point"] = TilFil(entryRva) ?? -1L;
        pe["rva_to_offset"] = (Funksjon)((_, a) => L(a[0]) is { } r ? TilFil(r) : null);
        pe["section_index"] = (Funksjon)((_, a) =>
        {
            if (a[0] is string n) { int i = sek.FindIndex(s => s.Navn == n); return i < 0 ? null : (long)i; }
            if (L(a[0]) is { } adr) { int i = sek.FindIndex(s => adr >= s.Va && adr < s.Va + System.Math.Max(s.Vs, s.Str)); return i < 0 ? null : (long)i; }
            return null;
        });

        // Importer
        var importer = new List<(string Dll, List<(string? Navn, long? Ordinal)> Funk)>();
        if (antRva > 1 && U32(kataloger + 8) is var impRva && impRva != 0 && TilFil(impRva) is { } imp)
        {
            for (int i = 0; i < 512; i++)
            {
                long d = imp + i * 20;
                uint oft = U32(d), navnRva = U32(d + 12), ft = U32(d + 16);
                if (oft == 0 && navnRva == 0 && ft == 0) break;
                var dll = Ztekst(TilFil(navnRva), 256);
                if (string.IsNullOrEmpty(dll)) break;
                var funk = new List<(string?, long?)>();
                if (TilFil(oft != 0 ? oft : ft) is { } th)
                {
                    for (int j = 0; j < 8192; j++)
                    {
                        long verdi = er64 ? (long)U64(th + j * 8) : U32(th + j * 4);
                        if (verdi == 0) break;
                        bool ordinal = er64 ? (verdi & long.MinValue) != 0 : (verdi & 0x80000000) != 0;
                        if (ordinal) funk.Add((null, verdi & 0xFFFF));
                        else funk.Add((Ztekst(TilFil((verdi & 0x7FFFFFFF) + 2), 256), null));
                    }
                }
                importer.Add((dll!, funk));
            }
        }
        pe["number_of_imports"] = (long)importer.Count;
        pe["number_of_imported_functions"] = (long)importer.Sum(x => x.Funk.Count);
        pe["import_details"] = importer.Select(x => (object?)new Struktur
        {
            ["library_name"] = x.Dll, ["number_of_functions"] = (long)x.Funk.Count,
            ["functions"] = x.Funk.Select(f => (object?)new Struktur { ["name"] = f.Navn, ["ordinal"] = f.Ordinal }).ToList(),
        }).ToList();
        pe["imports"] = (Funksjon)((_, a) =>
        {
            // imports("dll"), imports("dll", "funksjon"), imports("dll", ordinal), imports(/re/, /re/) tar ikke med regex her
            if (a.Length == 0 || a[0] is not string dll) return null;
            var treff = importer.Where(x => string.Equals(x.Dll, dll, StringComparison.OrdinalIgnoreCase)).ToList();
            if (a.Length == 1) return (long)treff.Sum(x => x.Funk.Count);
            if (a[1] is string fn) return treff.Any(x => x.Funk.Any(f => f.Navn == fn)) ? 1L : 0L;
            if (L(a[1]) is { } o) return treff.Any(x => x.Funk.Any(f => f.Ordinal == o)) ? 1L : 0L;
            return null;
        });
        pe["imphash"] = (Funksjon)((_, _) =>
        {
            var deler = new List<string>();
            foreach (var (dll, funk) in importer)
            {
                var d = dll.ToLowerInvariant();
                foreach (var e in new[] { ".dll", ".ocx", ".sys" }) if (d.EndsWith(e)) { d = d.Substring(0, d.Length - 4); break; }
                foreach (var (n, o) in funk) deler.Add($"{d}.{(n ?? "ord" + o).ToLowerInvariant()}");
            }
            return string.Concat(MD5.Create().ComputeHash(Encoding.ASCII.GetBytes(string.Join(",", deler))).Select(b => b.ToString("x2")));
        });

        // Eksporter
        var eksporter = new List<string>();
        if (antRva > 0 && U32(kataloger) is var expRva && expRva != 0 && TilFil(expRva) is { } exp)
        {
            pe["dll_name"] = Ztekst(TilFil(U32(exp + 12)), 256);
            pe["export_timestamp"] = (long)U32(exp + 4);
            long antNavn = U32(exp + 24);
            if (TilFil(U32(exp + 32)) is { } navnTab)
                for (int i = 0; i < System.Math.Min(antNavn, 16384); i++)
                    if (Ztekst(TilFil(U32(navnTab + i * 4)), 256) is { } n) eksporter.Add(n);
        }
        pe["number_of_exports"] = (long)eksporter.Count;
        pe["exports"] = (Funksjon)((_, a) => a.Length > 0 && a[0] is string n ? (eksporter.Contains(n) ? 1L : 0L) : null);

        // Signatur (bare om den finnes; gyldigheten sjekkes av Windows andre steder)
        long sikkerhet = antRva > 4 ? U32(kataloger + 4 * 8 + 4) : 0;
        pe["number_of_signatures"] = sikkerhet > 0 ? 1L : 0L;
        pe["is_signed"] = sikkerhet > 0 ? 1L : 0L;
        pe["version_info"] = new Dictionary<string, object?>();
        pe["number_of_resources"] = 0L;
        pe["is_dll"] = (Funksjon)((_, _) => (kjennetegn & 0x2000) != 0 ? 1L : 0L);
        pe["is_32bit"] = (Funksjon)((_, _) => magic == 0x10b ? 1L : 0L);
        pe["is_64bit"] = (Funksjon)((_, _) => er64 ? 1L : 0L);
        pe["overlay"] = Overlay(sek, k.Filstorrelse);
        return pe;
    }

    private static Struktur Overlay(List<(string Navn, long Va, long Vs, long Ptr, long Str)> sek, long storrelse)
    {
        long slutt = sek.Count == 0 ? 0 : sek.Max(s => s.Ptr + s.Str);
        return slutt > 0 && slutt < storrelse
            ? new Struktur { ["offset"] = slutt, ["size"] = storrelse - slutt }
            : new Struktur { ["offset"] = 0L, ["size"] = 0L };
    }

    internal static string Tall(object? o) => o switch { double d => d.ToString(CultureInfo.InvariantCulture), _ => o?.ToString() ?? "udefinert" };
}
