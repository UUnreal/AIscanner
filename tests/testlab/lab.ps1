# Testlab: en ren Windows-maskin i GitHub Actions får ekte AI installert (Ollama, llama.cpp, Python/transformers,
# AI-agenter fra npm) og mange ekte modeller fra Hugging Face og Ollama. Skanneren kjøres før og etter.
# Resultat: hva som ble funnet mot fasit, hva den rene maskinen ga (falske funn?), og alle spor AI-ene la igjen.
param([int]$Hf = 100, [int]$MaksMb = 60, [string]$Ut = "$env:RUNNER_TEMP\lab")
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Ut | Out-Null
$cli = "src/AISkanner.Cli/bin/Release/net8.0/AISkanner.Cli.exe"
if (-not (Test-Path $cli)) { $cli = (Get-ChildItem src/AISkanner.Cli/bin/Release -Recurse -Filter AISkanner.Cli.exe | Select-Object -First 1).FullName }
function Steg($t) { "::group::$t"; $script:stegStart = Get-Date }
function Ferdig { "::endgroup::"; "  ($([int]((Get-Date) - $script:stegStart).TotalSeconds) s)" }
function Skann($navn) { & $cli @args 2> "$Ut\$navn-logg.txt" | Out-File "$Ut\$navn.json" -Encoding utf8; Get-Content "$Ut\$navn.json" -Raw | ConvertFrom-Json }

# Øyeblikksbilde av alt som kan bli spor: mapper, registernøkler, programmer, tjenester, porter, prosesser, oppgaver, brannmur, miljø
function Bilde {
  $b = [ordered]@{}
  $rotter = @($env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA, "$env:LOCALAPPDATA\Programs", $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)})
  $b.Mapper = $rotter | ForEach-Object { Get-ChildItem $_ -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName; Get-ChildItem $_.FullName -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object FullName } } | Sort-Object -Unique
  $b.Register = 'HKCU:\Software', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node', 'HKCU:\Software\Classes' | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue | ForEach-Object Name } | Sort-Object -Unique
  $b.Programmer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue | Where-Object DisplayName | ForEach-Object { "$($_.DisplayName) | $($_.Publisher) | $($_.InstallLocation)" } } | Sort-Object -Unique
  $b.Oppstart = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object { $k = $_; (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object Name -notlike 'PS*' | ForEach-Object { "$k | $($_.Name) | $($_.Value)" } }
  $b.Snarveier = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" | ForEach-Object { Get-ChildItem $_ -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object FullName }
  $b.Tjenester = Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) | $($_.PathName)" }
  $b.Porter = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) | $((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path)" } | Sort-Object -Unique
  $b.Prosesser = Get-Process | Where-Object Path | ForEach-Object Path | Sort-Object -Unique
  $b.Oppgaver = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }
  $b.Brannmur = Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { "$($_.DisplayName) | $($_.Direction) | $($_.Action)" } | Sort-Object -Unique
  $b.Miljo = [Environment]::GetEnvironmentVariables('User').Keys + [Environment]::GetEnvironmentVariables('Machine').Keys | Sort-Object -Unique
  $b.Sti = ([Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')).Split(';') | Where-Object { $_ } | Sort-Object -Unique
  $b.Hendelseslogger = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object LogName
  $b.Modellfiler = Get-ChildItem $env:USERPROFILE -Recurse -File -Force -ErrorAction SilentlyContinue -Include *.gguf, *.safetensors, *.onnx, *.pt, *.pth, *.ckpt, *.bin, *.h5, *.keras, *.tflite, *.pkl, *.llamafile | Where-Object { $_.Length -gt 1KB -and $_.FullName -notmatch '\\(node_modules|site-packages)\\' } | ForEach-Object FullName
  $b
}

Steg 'Øyeblikksbilde før'; $for = Bilde; Ferdig
Steg 'Skann ren maskin (fasit: ingen AI installert av laben)'; $ren = Skann ren; Ferdig

# ---------- Installer ekte AI ----------
$installert = [System.Collections.Generic.List[object]]::new()
$ruMonster = 'gigachat|ai-sage|ai-forever|yandex|t-tech|t-lite|cotype|mtsair|vikhr|ruadapt|rugpt|fred-t5'
$kinaMonster = 'qwen|deepseek|glm|baichuan|internlm|minicpm|openbmb|01-ai|hunyuan|ernie|minimax|kimi|moonshot|stepfun|baai|thenlper|alibaba|thudm|bge-|gte-'
function Notér($navn, $sok, $hva, $kina = ($navn -match $kinaMonster -and $navn -notmatch $ruMonster), $ru = ($navn -match $ruMonster)) { $installert.Add([pscustomobject]@{ Navn = $navn; Sok = @($sok); Hva = $hva; Kina = [bool]$kina; Russland = [bool]$ru }) }

Steg 'Ollama (offisiell installasjon) + modeller'
$env:OLLAMA_KEEP_ALIVE = '60m'
Invoke-WebRequest https://ollama.com/download/OllamaSetup.exe -OutFile "$Ut\OllamaSetup.exe"
# Ikke -Wait: i PowerShell 7 venter den også på barneprosesser, og installasjonen starter Ollama-appen som aldri avslutter
$inst = Start-Process "$Ut\OllamaSetup.exe" -ArgumentList '/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES' -PassThru
if (-not $inst.WaitForExit(600000)) { '::warning::Ollama-installasjonen brukte over 10 min' }
$ollama = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
if (-not (Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction SilentlyContinue)) { Start-Process $ollama serve -WindowStyle Hidden; Start-Sleep 5 }
Notér 'Ollama' @('Ollama') 'program + server på 11434'
foreach ($m in 'all-minilm:22m', 'smollm2:135m', 'gemma3:270m', 'qwen2.5:0.5b', 'qwen3:0.6b', 'llama3.2:1b', 'nomic-embed-text', 'granite-embedding:30m', 'snowflake-arctic-embed:22m', 'deepseek-r1:1.5b', 'qwen2.5-coder:0.5b', 'deepseek-coder:1.3b', 'qwen3-embedding:0.6b') {
  & $ollama pull $m 2>&1 | Select-Object -Last 1
  if ($LASTEXITCODE -eq 0) { Notér "Ollama-modell $m" @($m, ($m -replace ':latest$')) 'Ollama-modell' }
}
# To modeller lastet i minnet (skal vises som «lastet nå»)
foreach ($m in 'smollm2:135m', 'llama3.2:1b') { Invoke-RestMethod http://127.0.0.1:11434/api/generate -Method Post -Body (@{ model = $m; prompt = 'hei'; stream = $false; options = @{ num_predict = 1 } } | ConvertTo-Json) -TimeoutSec 300 | Out-Null }
Ferdig

Steg 'Hugging Face: mange ekte modeller'
python -m pip install -q huggingface_hub transformers torch --index-url https://download.pytorch.org/whl/cpu --extra-index-url https://pypi.org/simple
python -m pip install -q openai anthropic langchain-core llama-index-core ollama mcp
python tests/testlab/hent-modeller.py $Hf $MaksMb "$Ut\hf-fasit.json"
$hfFasit = Get-Content "$Ut\hf-fasit.json" -Raw | ConvertFrom-Json
foreach ($h in $hfFasit) { Notér "HF $($h.repo)" @($h.repo) "Hugging Face ($($h.formater -join ', ')) $($h.arkitektur)" $h.kina $h.russland }
foreach ($p in 'openai', 'anthropic', 'langchain-core', 'llama-index-core', 'ollama', 'mcp', 'transformers', 'torch') { Notér "Python-pakke $p" @($p) 'AI-bibliotek i Python' }
Ferdig

Steg 'llama.cpp server + løse GGUF-filer i Nedlastinger (merket «fra Internett»)'
$dl = "$env:USERPROFILE\Downloads"; New-Item -ItemType Directory -Force $dl | Out-Null
$rel = Invoke-RestMethod https://api.github.com/repos/ggml-org/llama.cpp/releases/latest -Headers @{ Authorization = "Bearer $env:GH_TOKEN" }
$zip = $rel.assets | Where-Object name -match 'bin-win-cpu-x64\.zip$' | Select-Object -First 1
Invoke-WebRequest $zip.browser_download_url -OutFile "$Ut\llama.zip"; Expand-Archive "$Ut\llama.zip" "$env:USERPROFILE\llama.cpp" -Force
$gguf = Get-ChildItem "$env:USERPROFILE\.cache\huggingface\hub" -Recurse -Filter *.gguf | Sort-Object Length | Select-Object -First 3
foreach ($g in $gguf) {
  $mal = Join-Path $dl $g.Name; Copy-Item $g.FullName $mal
  Set-Content $mal -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://huggingface.co/`r`nHostUrl=https://huggingface.co/models/$($g.Name)"
  Notér "Løs GGUF $($g.Name)" @($g.Name) 'GGUF i Nedlastinger med nedlastingsmerke'
}
# Kinesisk modell med nytt navn: skal kjennes igjen fra innholdet (GGUF-metadata), ikke filnavnet
$qwen = Get-ChildItem "$env:USERPROFILE\.cache\huggingface\hub" -Recurse -Filter *.gguf | Where-Object FullName -match 'qwen|deepseek' | Sort-Object Length | Select-Object -First 1
if ($qwen) { New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\prosjekt" | Out-Null; Copy-Item $qwen.FullName "$env:USERPROFILE\Documents\prosjekt\notater-final.dat"; Copy-Item $qwen.FullName "$dl\assistent.gguf"
  Notér "Omdøpt kinesisk GGUF ($($qwen.Name) → assistent.gguf)" @('assistent.gguf') 'kinesisk modell med nøytralt navn' $true
  Notér "Forkledd kinesisk GGUF ($($qwen.Name) → notater-final.dat)" @('notater-final.dat') 'kinesisk modell med feil filendelse' $true }
$server = Get-ChildItem "$env:USERPROFILE\llama.cpp" -Recurse -Filter llama-server.exe | Select-Object -First 1
if ($server -and $gguf) { Start-Process $server.FullName -ArgumentList '-m', "`"$(Join-Path $dl $gguf[0].Name)`"", '--host', '0.0.0.0', '--port', '8080' -WindowStyle Hidden; Notér 'llama.cpp-server' @('llama.cpp', 'llama-server') 'server på 0.0.0.0:8080' }
Ferdig

Steg 'Python med transformers som holder en modell i minnet'
$py = "import time; from transformers import AutoModel; AutoModel.from_pretrained('hf-internal-testing/tiny-random-gpt2'); time.sleep(3600)"
Start-Process python -ArgumentList '-c', "`"$py`"" -WindowStyle Hidden
Notér 'Python + transformers (kjører)' @('transformers') 'Python-prosess med modell lastet'
Ferdig

Steg 'AI-agenter fra npm (installert, ikke startet)'
foreach ($p in '@anthropic-ai/claude-code', '@openai/codex', '@google/gemini-cli') { npm install -g $p --silent 2>&1 | Select-Object -Last 1; Notér "Agent $p" @($p, ($p -split '/')[-1]) 'AI-agent installert med npm' }
Ferdig

Steg 'Trygge «ondsinnede» modeller (lages som byte, åpnes aldri)'
python -I tests/testlab/lag-farlige.py "$dl\lab-farlige"
$farlige = Get-Content "$dl\farlige-fasit.json" -Raw | ConvertFrom-Json
Ferdig

Start-Sleep 20
Steg 'Øyeblikksbilde etter'; $etter = Bilde; Ferdig
Steg 'Skann maskinen med AI'; $med = Skann med; Ferdig

# ---------- Sammenlign ----------
function Tekst($f) { (($f | ConvertTo-Json -Depth 8 -Compress) -replace '\\\\', '\') }
$funnTekst = @($med.funn | ForEach-Object { [pscustomobject]@{ F = $_; T = (Tekst $_) } })
$r = [System.Text.StringBuilder]::new()
function L($s) { [void]$r.AppendLine($s) }
L "# Testlab $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $(git rev-parse --short HEAD)"
L ""
$treff = foreach ($i in $installert) {
  $hit = $funnTekst | Where-Object { $t = $_.T; @($i.Sok | Where-Object { $t.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count } | Select-Object -First 1
  [pscustomobject]@{ Navn = $i.Navn; Hva = $i.Hva; Kina = $i.Kina; Russland = $i.Russland; KinaMerket = [bool]($hit -and ($hit.F.kommerFraLand -eq 'CN' -or $hit.T -match 'Kina')); RuMerket = [bool]($hit -and ($hit.F.kommerFraLand -eq 'RU' -or $hit.T -match 'Russland')); Funnet = [bool]$hit; Risiko = $hit.F.risiko; Som = $hit.F.navn; Land = $hit.F.kommerFraLand; Fra = $hit.F.kommerFra }
}
$ok = @($treff | Where-Object Funnet).Count
L "## Funnet: $ok av $($installert.Count) ting laben installerte"
L ""; L "| | Installert | Hva | Skanneren kalte det | Risiko | Kommer fra |"; L "|---|---|---|---|---|---|"
foreach ($t in $treff | Sort-Object Funnet, Navn) { L "| $(if ($t.Funnet) { '✅' } else { '❌' }) | $($t.Navn) | $($t.Hva) | $($t.Som) | $($t.Risiko) | $($t.Fra) $($t.Land) |" }

$kina = @($treff | Where-Object Kina)
$kinaFunnet = @($kina | Where-Object Funnet); $kinaMerket = @($kina | Where-Object { $_.Funnet -and $_.KinaMerket })
L ""; L "## Kinesiske modeller: $($kinaFunnet.Count) av $($kina.Count) funnet, $($kinaMerket.Count) merket Kina"
L ""; L "| | Modell | Funnet som | Risiko | Merket Kina |"; L "|---|---|---|---|---|"
foreach ($t in $kina | Sort-Object Funnet, Navn) { L "| $(if ($t.Funnet -and $t.KinaMerket) { '✅' } elseif ($t.Funnet) { '⚠️' } else { '❌' }) | $($t.Navn) | $($t.Som) | $($t.Risiko) | $(if ($t.KinaMerket) { 'ja' } else { 'nei' }) |" }
$ru = @($treff | Where-Object Russland)
L ""; L "## Russiske modeller: $(@($ru | Where-Object Funnet).Count) av $($ru.Count) funnet, $(@($ru | Where-Object RuMerket).Count) merket Russland"
L ""; L "| | Modell | Funnet som | Risiko | Merket Russland |"; L "|---|---|---|---|---|"
foreach ($t in $ru | Sort-Object Funnet, Navn) { L "| $(if ($t.Funnet -and $t.RuMerket) { '✅' } elseif ($t.Funnet) { '⚠️' } else { '❌' }) | $($t.Navn) | $($t.Som) | $($t.Risiko) | $(if ($t.RuMerket) { 'ja' } else { 'nei' }) |" }
if (Test-Path "$Ut\opphav-telling.json") {
  L ""; L "## Hvor mange modeller finnes (Hugging Face-API, nå)"; L ""; L "| Organisasjon / søk | Land | Modeller | Nedlastinger siste 30 d |"; L "|---|---|---|---|"
  (Get-Content "$Ut\opphav-telling.json" -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { L "| $($_.Name) | $($_.Value.land) | $($_.Value.modeller)$($_.Value.feil) | $($_.Value.nedlastinger30d) |" }
}
L ""; L "## Farlige testmodeller"
L ""; L "| | Fil | Angrep | Forventet | Skanneren |"; L "|---|---|---|---|---|"
$farligOk = 0
foreach ($f in $farlige) {
  $hit = $funnTekst | Where-Object { $_.T.IndexOf($f.navn, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1
  $rod = $hit -and $hit.F.risiko -eq 'rod' -and $hit.T -match 'farlig|ondsinnet|kjører kode|kjorer|Lambda|CVE'
  $riktig = if ($f.forventet -eq 'rod') { $rod } else { -not $rod }
  if ($riktig) { $farligOk++ }
  L "| $(if ($riktig) { '✅' } else { '❌' }) | $($f.navn) | $($f.hva) | $($f.forventet) | $(if ($hit) { "$($hit.F.risiko): $($hit.F.navn)" } else { 'ikke funnet' }) |"
}
L ""; L "Farlige testmodeller riktig: $farligOk av $($farlige.Count)"

L ""; L "## Ren maskin (før laben installerte noe): $(@($ren.funn).Count) funn"
L "Alt her er enten ekte AI som GitHub har på maskinen, eller falske funn. Hvert funn må ha bevis."
foreach ($f in $ren.funn) { L "- **$($f.risiko)** $($f.navn) · $($f.type) · $((@($f.hvor) + @($f.detaljer) | Select-Object -First 2) -join ' · ')" }

L ""; L "## Funn som bare kom etter laben, men ikke er i fasit (nye spor eller falske funn)"
$kjent = $installert | ForEach-Object Sok
$renNavn = @($ren.funn | ForEach-Object navn)
foreach ($x in $funnTekst | Where-Object { $_.F.navn -notin $renNavn }) { $t = $x.T; if (-not ($kjent | Where-Object { $t.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) { L "- **$($x.F.risiko)** $($x.F.navn) · $($x.F.type)" } }
[IO.File]::WriteAllText("$Ut\rapport.md", $r.ToString())

# Spor: alt som er nytt etter installasjonen (grunnlag for nye regler)
$s = [System.Text.StringBuilder]::new()
foreach ($k in $etter.Keys) {
  $ny = @(Compare-Object @($for[$k] | Where-Object { $_ }) @($etter[$k] | Where-Object { $_ }) | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
  [void]$s.AppendLine("## $k ($($ny.Count) nye)"); $ny | Select-Object -First 600 | ForEach-Object { [void]$s.AppendLine("  $_") }
}
[IO.File]::WriteAllText("$Ut\spor.txt", $s.ToString())
Get-Content "$Ut\rapport.md" | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
"## Spor (antall nye per kilde)" | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
Select-String -Path "$Ut\spor.txt" -Pattern '^## ' | ForEach-Object { "- $($_.Line.TrimStart('# '))" } | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
Get-Content "$Ut\rapport.md" | Select-Object -First 8
exit 0
