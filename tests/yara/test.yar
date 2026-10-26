import "pe"
import "math"
import "hash"
import "time"
import "string"
import "console"

// ---- strenger og modifikatorer ----
rule T_ascii { strings: $a = "hello" condition: $a }
rule T_nocase { strings: $a = "HeLLo" nocase condition: $a }
rule T_wide { strings: $a = "wide" wide condition: $a }
rule T_wide_ascii { strings: $a = "both" wide ascii condition: #a == 2 }
rule T_fullword { strings: $a = "word" fullword condition: $a }
rule T_xor { strings: $a = "secret" xor condition: $a }
rule T_xor_range { strings: $a = "secret" xor(1-3) condition: $a }
rule T_b64 { strings: $a = "This program cannot" base64 condition: $a }
rule T_b64wide { strings: $a = "base64wide!" base64wide condition: $a }
rule T_escape { strings: $a = "tab\there\x41\"q" condition: $a }
rule T_private { strings: $a = "hello" private condition: $a }

// ---- hex ----
rule T_hex { strings: $h = { 4D 5A } condition: $h at 0 }
rule T_hex_wild { strings: $h = { 68 ?? 6C 6C 6F } condition: $h }
rule T_hex_nibble { strings: $h = { 6? 65 6C [1] 6F } condition: $h }
rule T_hex_jump { strings: $h = { 68 65 [2-4] 20 77 } condition: $h }
rule T_hex_jump_open { strings: $h = { 50 4B 03 04 [-] 50 4B 01 02 } condition: $h }
rule T_hex_alt { strings: $h = { 68 ( 65 | 61 ) 6C ( 6C | 6F 6F ) } condition: $h }
rule T_hex_not { strings: $h = { 68 ~66 6C } condition: $h }
rule T_hex_alt_nested { strings: $h = { 73 ( 65 ( 63 | 78 ) | 61 ) } condition: #h >= 1 }

// ---- regex ----
rule T_re { strings: $r = /h[a-e]llo\s+w/ condition: $r }
rule T_re_i { strings: $r = /HELLO/i condition: $r }
rule T_re_alt { strings: $r = /(cat|dog)fish/ condition: $r }
rule T_re_rep { strings: $r = /ab{2,3}c/ condition: $r }
rule T_re_dot_s { strings: $r = /line1.line2/s condition: $r }
rule T_re_dot { strings: $r = /line1.line2/ condition: $r }
rule T_re_anchor { strings: $r = /^MZ/ condition: $r }
rule T_re_hex { strings: $r = /\x50\x4b\x03\x04/ condition: $r }
rule T_re_class { strings: $r = /[0-9]{4}-[0-9]{2}/ condition: $r }
rule T_re_wide { strings: $r = /wide/ wide condition: $r }

// ---- betingelser ----
rule T_count { strings: $a = "hello" condition: #a >= 2 }
rule T_count_in { strings: $a = "hello" condition: #a in (0..100) == 1 }
rule T_at { strings: $a = "MZ" condition: $a at 0 }
rule T_in { strings: $a = "hello" condition: $a in (0..50) }
rule T_offset { strings: $a = "hello" condition: @a[1] < 20 }
rule T_offset2 { strings: $a = "hello" condition: @a[2] > @a[1] }
rule T_len { strings: $r = /ab+c/ condition: !r[1] == 4 }
rule T_any { strings: $a = "nope1" $b = "hello" condition: any of them }
rule T_all { strings: $a = "nope1" $b = "hello" condition: all of them }
rule T_none { strings: $a = "nope1" $b = "nope2" condition: none of them }
rule T_n_of { strings: $a1 = "hello" $a2 = "world" $a3 = "nope" condition: 2 of ($a*) }
rule T_pct { strings: $a1 = "hello" $a2 = "world" $a3 = "nope" condition: 50% of them }
rule T_of_in { strings: $a = "hello" $b = "world" condition: any of them in (0..10) }
rule T_of_at { strings: $a = "MZ" $b = "PK" condition: any of them at 0 }
rule T_for_of { strings: $a = "hello" $b = "world" condition: for all of them : ( # > 0 ) }
rule T_for_of2 { strings: $a = "hello" $b = "world" condition: for any of ($a, $b) : ( @ < 100 ) }
rule T_for_in { strings: $a = "hello" condition: for any i in (1..#a) : ( @a[i] > 30 ) }
rule T_for_in2 { condition: for all i in (0, 1, 2) : ( uint8(i) != 0xFF ) }
rule T_for_n { strings: $a = "hello" condition: for 2 i in (1..#a) : ( @a[i] >= 0 ) }
rule T_filesize { condition: filesize > 100 and filesize < 10MB }
rule T_uint { condition: uint16(0) == 0x5A4D }
rule T_uint_be { condition: uint16be(0) == 0x4D5A }
rule T_uint32 { condition: uint32(0) == 0x04034B50 }
rule T_int8 { condition: int8(filesize - 1) < 0 }
rule T_arith { condition: (filesize % 2 == 0) or (filesize * 2 - 1) \ 3 > 0 }
rule T_bits { condition: (uint8(0) & 0x0F) | 1 == (uint8(0) & 0x0F) | 1 and (uint8(0) ^ uint8(0)) == 0 and ~0 == -1 and (1 << 4) >> 2 == 4 }
rule T_not { strings: $a = "nope" condition: not $a }
rule T_defined { condition: defined pe.number_of_sections }
rule T_and_or { strings: $a = "hello" $b = "nope" condition: $a and ($b or true) }

// ---- tekstoperatorer ----
rule T_contains { condition: pe.is_pe and pe.dll_name contains "Core" }
rule T_text_ops { condition: "Hello" icontains "hell" and "abc" startswith "a" and "abc" endswith "bc" and "ABC" iequals "abc" and "x123" matches /x[0-9]+/ }

// ---- regelreferanser ----
rule T_not_exist_dummy { condition: false }
private rule P_hello { strings: $a = "hello" condition: $a }
rule T_ref { condition: P_hello and not T_not_exist_dummy }
rule T_ruleset { condition: any of (T_hex*) }

// ---- moduler ----
rule T_math_entropy { condition: math.entropy(0, filesize) > 7.0 }
rule T_math_low { condition: math.entropy(0, filesize) < 4.0 }
rule T_math_mean { condition: math.mean(0, filesize) > 100.0 }
rule T_math_count { condition: math.count(0x41) > 5 }
rule T_hash_md5 { condition: hash.md5(0, 5) == "5d41402abc4b2a76b9719d911017c592" }
rule T_hash_sha256 { condition: hash.sha256(0, 5) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" }
rule T_hash_crc { condition: hash.crc32(0, 5) == 0x3610a686 }
rule T_string_toint { condition: string.to_int("1234") == 1234 and string.length("abc") == 3 }
rule T_time { condition: time.now() > 1600000000 }

rule T_pe { condition: pe.is_pe }
rule T_pe_dll { condition: pe.is_dll() }
rule T_pe_64 { condition: pe.is_64bit() }
rule T_pe_machine { condition: pe.machine == pe.MACHINE_I386 or pe.machine == pe.MACHINE_AMD64 }
rule T_pe_sections { condition: pe.number_of_sections >= 2 and pe.sections[0].name == ".text" }
rule T_pe_sec_loop { condition: for any s in pe.sections : ( s.name == ".rsrc" ) }
rule T_pe_imports { condition: pe.imports("mscoree.dll") }
rule T_pe_imports_fn { condition: pe.imports("mscoree.dll", "_CorDllMain") }
rule T_pe_exports { condition: pe.number_of_exports > 0 }
rule T_pe_ep { condition: pe.entry_point > 0 }
rule T_pe_sub { condition: pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI or pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI }
rule T_pe_char { condition: pe.characteristics & pe.DLL }
rule T_pe_dd { condition: pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 }
rule T_pe_ts { condition: pe.timestamp > 0 }
rule T_pe_imphash { condition: pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" }
rule T_pe_rva { condition: pe.rva_to_offset(pe.sections[0].virtual_address) == pe.sections[0].raw_data_offset }
rule T_pe_secidx { condition: pe.section_index(".text") == 0 }
rule T_pe_overlay { condition: pe.overlay.size > 0 }

// ---- mer wide/regex ----
rule T_re_wide2 { strings: $r = /w[a-z]+e/ wide ascii condition: #r == 2 }
rule T_re_wide_q { strings: $r = /bo?th/ wide condition: $r }
rule T_re_fullword { strings: $r = /wor[a-z]/ fullword condition: $r }
rule T_wide_nocase { strings: $a = "WIDE" wide nocase condition: $a }
rule T_xor_wide { strings: $a = "secret" xor wide condition: $a }
rule T_hopp_stor { strings: $h = { 4D 5A [10-200] 68 65 6C 6C 6F } condition: $h }
rule T_count_range { strings: $a = "h" condition: #a in (0..20) >= 2 }
rule T_at_expr { strings: $a = "hello" condition: $a at (filesize - 5) }
rule T_of_rules { condition: 2 of (T_ascii, T_hex, T_wide) }
rule T_entry { condition: entrypoint >= 0 or true }
rule T_for_of_at { strings: $a = "hello" $b = "MZ" condition: for any of them : ( $ at 0 ) }
rule T_neg { condition: -1 < 0 and 10 \ 3 == 3 and 7 % 4 == 3 }
rule T_str_cmp { condition: pe.sections[0].name != ".data" }
rule T_float { condition: math.entropy(0, filesize) >= 0.0 and 1.5 > 1 }
rule T_math_dev { condition: math.deviation(0, filesize, 127.5) > 10.0 }
rule T_math_serial { condition: math.serial_correlation(0, filesize) < 0.5 }
rule T_math_pi { condition: math.monte_carlo_pi(0, filesize) < 0.5 }
rule T_math_inrange { condition: math.in_range(2.0, 1.0, 3.0) and math.max(1, 5) == 5 and math.min(1, 5) == 1 and math.abs(-3) == 3 }
rule T_math_pct { condition: math.percentage(0x00) > 0.5 }
rule T_math_mode { condition: math.mode() == 0 }
rule T_hash_sha1 { condition: hash.sha1(0, filesize) != "" }
rule T_hash_checksum { condition: hash.checksum32(0, 5) == 532 }

// ---- kjeder (lange hopp) ----
rule T_kjede_zip { strings: $h = { 50 4B 03 04 [-] 61 2E 74 78 74 } condition: $h }
rule T_kjede_lang { strings: $h = { 4D 5A [300-5000] 50 45 00 00 } condition: $h }
rule T_kjede_3 { strings: $h = { 68 65 6C 6C 6F [-] 77 6F 72 6C 64 [0-500] 68 65 6C 6C 6F } condition: #h >= 1 }
rule T_kjede_mangler { strings: $h = { 4D 5A [-] 4E 4F 50 45 } condition: $h }
