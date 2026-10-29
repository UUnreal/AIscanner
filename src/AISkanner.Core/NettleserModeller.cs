using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// AI-modeller som nettleserne laster ned og kjører lokalt (Gemini Nano i Chrome, språkmodell i Edge,
/// tale, oversettelse, tekstgjenkjenning). Ser i alle Chromium-nettlesere og alle kanaler (Beta, Dev, Canary).
/// Kjente mapper får navn. Andre mapper med modellfiler i nettleserdataene blir funnet på innholdet og er ukjente (røde).
/// Leser bare mappenavn, størrelser og datoer, og de første bytene av store filer.
/// </summary>
public sealed partial class Skanner
{
    private static readonly (string Nettleser, string Sti)[] Nettleserdata =
    {
        ("Chrome", @"%LOCALAPPDATA%\Google\Chrome\User Data"),
        ("Chrome Beta", @"%LOCALAPPDATA%\Google\Chrome Beta\User Data"),
        ("Chrome Dev", @"%LOCALAPPDATA%\Google\Chrome Dev\User Data"),
        ("Chrome Canary", @"%LOCALAPPDATA%\Google\Chrome SxS\User Data"),
        ("Edge", @"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
        ("Edge Beta", @"%LOCALAPPDATA%\Microsoft\Edge Beta\User Data"),
        ("Edge Dev", @"%LOCALAPPDATA%\Microsoft\Edge Dev\User Data"),
        ("Edge Canary", @"%LOCALAPPDATA%\Microsoft\Edge SxS\User Data"),
        ("Brave", @"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"%LOCALAPPDATA%\Vivaldi\User Data"),
        ("Opera", @"%APPDATA%\Opera Software\Opera Stable"),
        ("Opera GX", @"%APPDATA%\Opera Software\Opera GX Stable"),
        ("Opera Developer", @"%APPDATA%\Opera Software\Opera Developer"),
    };

    /// <summary>Kjente mapper der nettleserne legger AI-modeller. true = en språkmodell (den viktige).</summary>
    private static readonly Dictionary<string, (string Hva, bool Sprak)> KjenteNettleserModeller = new(StringComparer.OrdinalIgnoreCase)
    {
        ["OptGuideOnDeviceModel"] = ("Gemini Nano, språkmodell", true),
        ["EdgeLLMOnDeviceModel"] = ("språkmodell (Phi)", true),
        ["EdgeOnDeviceModel"] = ("språkmodell", true),
        ["OptGuideOnDeviceClassifierModel"] = ("AI som vurderer innhold (svindel og sikkerhet)", false),
        ["optimization_guide_model_store"] = ("små AI-modeller for nettleserfunksjoner", false),
        ["OnDeviceHeadSuggestModel"] = ("AI for søkeforslag", false),
        ["TranslateKit"] = ("oversettelse på PC-en", false),
        ["screen_ai"] = ("tekstgjenkjenning i bilder og PDF (OCR)", false),
        ["SODA"] = ("tale til tekst (Live Caption)", false),
        ["SODALanguagePacks"] = ("språkpakker for tale til tekst", false),
        ["WasmTtsEngine"] = ("tekst til tale", false),
        // Edge sine egne småmodeller. Kilde: https://dev.to/jacquesgariepy/inside-chromes-edges-silent-4gb-ai-install-a-complete-hands-on-investigation-54g2
        ["AutofillAiModelCache"] = ("AI for utfylling av skjemaer", false),
        ["ProvenanceDataTensors"] = ("AI som vurderer bilder mot svindel", false),
        ["Edge Techscam Detection"] = ("AI som oppdager svindelsider", false),
    };

    private static readonly Regex ModellAktigMappe = new(@"model|llm|onnx|genai|ondevice|\bai\b|ml_", RegexOptions.IgnoreCase);

    private void InnebygdAi()
    {
        // De kjente, og andre Chromium-nettlesere som er funnet (de har samme mapper for modeller)
        var alle = Nettleserdata.Select(x => (x.Nettleser, Sti: Utvid(x.Sti))).ToList();
        foreach (var (navn, sti) in ChromiumRotter())
            if (sti.EndsWith("User Data", StringComparison.OrdinalIgnoreCase) && !alle.Any(x => x.Sti.Equals(sti, StringComparison.OrdinalIgnoreCase))) alle.Add((navn, sti));
        AndreNettleseresAi();
        foreach (var (nettleser, rotSti) in alle)
        {
            var rot = Utvid(rotSti);
            if (!Directory.Exists(rot)) continue;
            // Øverste nivå og hver profil (Default, Profile 1 osv.)
            var mapper = Mapper(rot).ToList();
            foreach (var profil in mapper.Where(m => Regex.IsMatch(Path.GetFileName(m), @"^(Default|Profile \d+|Guest Profile)$")).ToList())
                mapper.AddRange(Mapper(profil));

            var sprak = new List<string>();
            var andre = new List<string>();
            var ukjente = new List<string>();
            long sprakStorrelse = 0;
            string? sprakVersjon = null;
            DateTime? forst = null, sist = null;
            void Tider(DateTime? f, DateTime? s)
            {
                if (f != null && (forst == null || f < forst)) forst = f;
                if (s != null && (sist == null || s > sist)) sist = s;
            }

            foreach (var d in mapper)
            {
                var navn = Path.GetFileName(d);
                bool kjent = KjenteNettleserModeller.TryGetValue(navn, out var info);
                if (!kjent && !ModellAktigMappe.IsMatch(navn)) continue;
                var filer = Plattform.Filer(d, "*", 4).Take(5000).ToList();
                long storrelse = filer.Sum(f => f.Length);
                if (storrelse < 1024 * 1024) continue;
                if (!kjent)
                {
                    // Ukjent mappe: tell den bare hvis innholdet faktisk er AI-modeller
                    var modeller = filer.Where(f => f.Length > 1024 * 1024 && (f.Extension is ".tflite" or ".onnx" or ".gguf" || ModellFormat.Gjenkjenn(f.FullName) != null)).ToList();
                    if (modeller.Count == 0) continue;
                    foreach (var m in modeller.Take(20)) ukjente.Add($"Fil: {m.FullName} · {Rapport.Storrelse(m.Length)} · endret {Tid(m.LastWriteTime)}");
                    continue;
                }
                var opprettet = filer.Count > 0 ? filer.Min(f => f.CreationTime) : Directory.GetCreationTime(d);
                var endret = filer.Count > 0 ? filer.Max(f => f.LastWriteTime) : Directory.GetLastWriteTime(d);
                var linje = $"Mappe: {d} · {info.Hva} · {Rapport.Storrelse(storrelse)} · lastet ned {Tid(opprettet)}{(endret.Date != opprettet.Date ? $" · oppdatert {Tid(endret)}" : "")}";
                if (info.Sprak)
                {
                    // Nettleseren legger modellen i en mappe som heter det samme som versjonen (f.eks. 2025.8.8.1141)
                    sprakVersjon ??= Mapper(d).Select(x => Path.GetFileName(x) ?? "").Where(n => Regex.IsMatch(n, @"^\d+(\.\d+)+$"))
                        .OrderByDescending(n => n, Comparer<string>.Create((x, y) => new Version(Kort(x)).CompareTo(new Version(Kort(y))))).FirstOrDefault();
                    sprakStorrelse += storrelse;
                    Tider(opprettet, endret);
                    sprak.Add(linje);
                    // Selve modellfilene, så det er lett å se hvor AI-en ligger
                    foreach (var f in filer.Where(f => f.Length > 10 * 1024 * 1024).OrderByDescending(f => f.Length).Take(10))
                        sprak.Add($"Fil: {f.FullName} · {Rapport.Storrelse(f.Length)}");
                }
                else andre.Add(linje);
            }

            var familie = nettleser.Split(' ')[0];
            var regel = _regler.NettleserInnebygd.FirstOrDefault(r => r.Nettleser.Equals(familie, StringComparison.OrdinalIgnoreCase));
            var policy = regel != null ? LesPolicy(regel.PolicyNokkel, regel.PolicyVerdi) : null;
            bool blokkert = policy?.Verdi == 1;

            // Status for AI-API-ene (bare Chrome og Edge har dem)
            ApiStatus? api = familie is "Chrome" or "Edge"
                ? NettleserApiStatus(nettleser, rot, sprak.Count > 0, mapper.Any(m => Path.GetFileName(m).Equals("OptGuideOnDeviceClassifierModel", StringComparison.OrdinalIgnoreCase)), blokkert)
                : null;
            Funn? hoved = null;

            if (sprak.Count > 0)
            {
                var navn = regel != null ? regel.Navn.Replace(familie, nettleser) : $"Språkmodell i {nettleser}";
                var f = LeggTil(navn, LeverandorKategori + " (nettleser)", Risiko.Gul,
                    regel?.HvorforEnkelt ?? $"{nettleser} har lastet ned sin egen AI-modell. Nettsider og utvidelser kan bruke den.", nettleser, null,
                    enkelt: regel?.Enkelt);
                f.Bruk = $"Ligger på PC-en ({Rapport.Storrelse(sprakStorrelse)}), lastet ned {Tid(forst)}.";
                f.Tidspunkt(forst, sist);
                foreach (var l in sprak) f.Detalj(l);
                f.LeggTilModeller(1);   // én språkmodell, selv om den består av flere filer
                f.SettVersjon(sprakVersjon, "modellmappa i nettleseren");
                hoved = f;
                if (blokkert) f.Advarsel("IT har blokkert modellen, men den ligger fortsatt på disk.");
                else if (policy == null) f.Merknad("Ingen regel fra IT. Nettleseren bestemmer selv om AI-modellen lastes ned.");
                else f.Merknad($"IT tillater lokal AI ({regel!.PolicyVerdi}={policy.Value.Verdi}).");
            }
            else if (regel != null && blokkert)
            {
                var f = LeggTil(regel.Navn.Replace(familie, nettleser), LeverandorKategori + " (nettleser)", Risiko.Gronn, regel.HvorforEnkelt ?? regel.Hvorfor, nettleser, null, enkelt: regel.Enkelt);
                f.Bruk = "Blokkert av IT, og ingen modell ligger på PC-en.";
                hoved = f;
            }

            if (andre.Count > 0)
            {
                var f = LeggTil($"Andre AI-modeller i {nettleser}", LeverandorKategori + " (nettleser)", Risiko.Gronn,
                    $"{nettleser} har lastet ned små AI-modeller som kjører på PC-en, f.eks. for tale, oversettelse og tekstgjenkjenning.", nettleser, null,
                    enkelt: "Små AI-modeller i nettleseren");
                f.Bruk = $"{andre.Count} {(andre.Count == 1 ? "funksjon" : "funksjoner")}: {string.Join(", ", andre.Select(a => a.Split(new[] { " · " }, StringSplitOptions.None)[1]).Take(3))}{(andre.Count > 3 ? " …" : "")}.";
                foreach (var l in andre) f.Detalj(l);
                f.LeggTilInnebygde(andre.Count);
                hoved ??= f;
            }

            if (api != null && hoved != null)
            {
                foreach (var l in api.Linjer) hoved.Detalj(l);
                foreach (var m in api.Merk) hoved.Merknad(m);
                var pa = api.Linjer.Where(l => Regex.IsMatch(l, @"· (på|slått på)")).Select(l => l.Substring(8, l.IndexOf(" · ") - 8)).ToList();
                if (pa.Count > 0 && sprak.Count > 0) hoved.Bruk += $" Nettsider kan bruke: {string.Join(", ", pa)}.";
            }
            if (api != null && api.Manuelt.Count > 0)
            {
                var f = LeggTil($"AI slått på manuelt i {nettleser}", "Skygge-AI (nettleserflagg)", Risiko.Rod,
                    $"Noen har slått på AI-funksjoner i {nettleser} som ikke er på som standard. De kjører lokalt uten at IT styrer dem.", nettleser, null,
                    enkelt: "AI-flagg slått på i nettleseren");
                f.Bruk = $"{api.Manuelt.Count} {(api.Manuelt.Count == 1 ? "flagg" : "flagg")} endret: {string.Join(", ", api.Manuelt.Select(m => m.Substring(7, m.IndexOf(" · ") - 7)).Take(3))}{(api.Manuelt.Count > 3 ? " …" : "")}.";
                foreach (var l in api.Manuelt) f.Detalj(l);
                foreach (var l in api.Linjer) f.Detalj(l);
            }

            if (ukjente.Count > 0)
            {
                var f = LeggTil($"Ukjent AI-modell i {nettleser}", LeverandorKategori + " (nettleser)", Risiko.Rod,
                    "AI-modellfiler i nettleserdataene som ikke hører til nettleserens kjente funksjoner. Kan komme fra en utvidelse eller et nettsted.", nettleser, null,
                    enkelt: "Ukjent AI i nettleseren");
                f.Bruk = $"{ukjente.Count} {(ukjente.Count == 1 ? "modellfil" : "modellfiler")}.";
                foreach (var l in ukjente) f.Detalj(l);
                f.LeggTilModeller(ukjente.Count);
            }
        }
    }

    // Version tåler høyst fire ledd
    private static string Kort(string v) => string.Join(".", v.Split('.').Take(4).Select(x => x.Length > 9 ? x.Substring(0, 9) : x));
}
