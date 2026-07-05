<#
.SYNOPSIS
    Wluz Analyzer v6.7.1 - Motor de Inspección Molecular y Clasificación en Bloques.
.DESCRIPTION
    Escanea archivos .jar buscando firmas exactas combinadas y clasifica los resultados
    mostrando primero los mods limpios/verificados y al final las alertas de cheats.
#>

param(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]$ModsPath
)

$GLOBAL:CACHE_MODRINTH = [System.Collections.Concurrent.ConcurrentDictionary[string, psobject]]::new()

# BANCO DE FIRMAS MOLECULARES ESTRICTAS
$CheatSignatures = @{
    'Packages' = @(
        'net/wurstclient', 'meteordevelopment/meteorclient', 'me/rigamortis/sigma',
        'me/zero/alpine', 'com/aristois', 'net/ccbluex/liquidbounce',
        'me/kaimson/rusherhack', 'dev/sxmurxy/artemis', 'org/kamiblue', 'net/novoline'
    )
    'GrimClient'   = @('ops/ec/base/options/BooleanOption', 'ops/ec/base/options/ModeOption', 'ops/ec/base/options/NumberOption')
    'Novoware'     = @('a/c/gui/ClickGuiScreen', 'com/customblocks/mixin/a/y', 'a/I/b.class')
    'DarkisClient' = @('com/target/mod/compat/a/c/c/ConfigX', 'b/ActivityScheduler', 'com/target/mod/compat/a/c/c/EventZ')
    
    'Keywords' = @(
        'killaura', 'kill_aura', 'aimbot', 'autoclicker', 'chestesp', 'tracers', 
        'speedhack', 'antiknockback', 'anti_kb', 'freecam', 'scaffold'
    )
}

function Get-FileHashSha1 {
    param([string]$Path)
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $hashBytes = $sha1.ComputeHash($stream)
        $stream.Close(); $sha1.Dispose()
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    } catch { return $null }
}

# ESCANER DE DEPENDENCIAS INTERNAS (Jars dentro de Jars)
function Analyze-JarStream {
    param([System.IO.Stream]$Stream, [ref]$Analysis)
    
    $hasRootA = $false; $hasRootB = $false; $hasRootC = $false
    
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($Stream, [System.IO.Compression.ZipArchiveMode]::Read)
        foreach ($entry in $zip.Entries) {
            $fullName = $entry.FullName

            if ($fullName -like '*.class') {
                if ($fullName -eq 'b/A.class') { $hasRootA = $true }
                if ($fullName -eq 'b/B.class') { $hasRootB = $true }
                if ($fullName -eq 'b/C.class') { $hasRootC = $true }

                foreach ($grim in $CheatSignatures.GrimClient) {
                    if ($fullName.Contains($grim)) {
                        $Analysis.Value.SpecificMalware = "GRIM CLIENT ENCONTRADO"
                        [void]$Analysis.Value.DetectedCheats.Add("Inyección Grim ($grim)")
                    }
                }
                foreach ($novo in $CheatSignatures.Novoware) {
                    if ($fullName.Contains($novo)) {
                        $Analysis.Value.SpecificMalware = "NOVOWARE ENCONTRADO"
                        [void]$Analysis.Value.DetectedCheats.Add("Estructura Novoware ($novo)")
                    }
                }
                foreach ($darkis in $CheatSignatures.DarkisClient) {
                    if ($fullName.Contains($darkis) -or $fullName.StartsWith($darkis)) {
                        $Analysis.Value.SpecificMalware = "DARKIS CLIENT ENCONTRADO"
                        [void]$Analysis.Value.DetectedCheats.Add("Módulo Darkis ($darkis)")
                    }
                }
                foreach ($pkg in $CheatSignatures.Packages) {
                    if ($fullName -like "*$pkg*") { 
                        [void]$Analysis.Value.DetectedCheats.Add("Paquete Cheat: $pkg") 
                    }
                }

                if ($entry.Length -gt 0 -and $entry.Length -lt 1.5MB) {
                    try {
                        $eStream = $entry.Open(); $ms = [System.IO.MemoryStream]::new(); $eStream.CopyTo($ms)
                        $bytes = $ms.ToArray(); $eStream.Close(); $ms.Close()
                        if ($bytes.Length -gt 0) {
                            $rawText = [System.Text.Encoding]::ASCII.GetString($bytes)
                            $cleanText = [regex]::Replace($rawText, '[^\x20-\x7E]', ' ')
                            foreach ($kw in $CheatSignatures.Keywords) {
                                if ($cleanText -match "\b$kw\b") { [void]$Analysis.Value.DetectedCheats.Add("Módulo Interno: $kw") }
                            }
                        }
                    } catch {}
                }
            }
        }
        if ($hasRootA -and $hasRootB -and $hasRootC) {
            $Analysis.Value.SpecificMalware = "NOVOWARE ENCONTRADO"
            [void]$Analysis.Value.DetectedCheats.Add("Inyector Camuflado (b/A+b/B)")
        }
        $zip.Dispose()
    } catch {}
}

function Analyze-JarInternals {
    param([string]$JarPath)
    
    $detectedCheats = [System.Collections.Generic.HashSet[string]]::new()
    $obfuscationSet = [System.Collections.Generic.HashSet[string]]::new()

    $analysis = @{
        Name             = [System.IO.Path]::GetFileNameWithoutExtension($JarPath)
        FileName         = [System.IO.Path]::GetFileName($JarPath)
        Loader           = 'Unknown'
        Type             = 'Mod'
        DetectedCheats   = $detectedCheats
        ObfuscationTypes = $obfuscationSet
        ExtractedUrl     = $null
        ExtractedSource  = 'DESCONOCIDO'
        SpecificMalware  = $null
    }

    $hasRootA = $false; $hasRootB = $false; $hasRootC = $false

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        $entries = $zip.Entries

        if ($entries | Where-Object { $_.FullName -eq 'fabric.mod.json' }) { 
            $analysis.Loader = 'Fabric' 
            try {
                $r = [System.IO.StreamReader]::new(($entries | Where-Object { $_.FullName -eq 'fabric.mod.json' }).Open())
                $json = $r.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
                $r.Close()
                if ($json.contact.homepage) { $analysis.ExtractedUrl = "$($json.contact.homepage)" }
            } catch {}
        }
        elseif ($entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' }) { 
            $analysis.Loader = 'Forge' 
            try {
                $r = [System.IO.StreamReader]::new(($entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' }).Open())
                $toml = $r.ReadToEnd()
                $r.Close()
                if ($toml -match 'displayURL\s*=\s*"([^"]+)"') { $analysis.ExtractedUrl = "$($Matches[1])" }
            } catch {}
        }

        foreach ($entry in $entries) {
            $fullName = $entry.FullName

            if ($fullName -like '*.jar' -or $fullName -like 'META-INF/jars/*.jar') {
                try {
                    $jarStream = $entry.Open()
                    $memStream = [System.IO.MemoryStream]::new()
                    $jarStream.CopyTo($memStream)
                    [void]$memStream.Seek(0, [System.IO.SeekOrigin]::Begin)
                    $jarStream.Close()
                    
                    Analyze-JarStream -Stream $memStream -Analysis ([ref]$analysis)
                    $memStream.Close()
                } catch {}
            }

            if ($fullName -like '*.class') { 
                if ($fullName -eq 'b/A.class') { $hasRootA = $true }
                if ($fullName -eq 'b/B.class') { $hasRootB = $true }
                if ($fullName -eq 'b/C.class') { $hasRootC = $true }

                foreach ($grim in $CheatSignatures.GrimClient) {
                    if ($fullName.Contains($grim)) {
                        $analysis.SpecificMalware = "GRIM CLIENT ENCONTRADO"
                        [void]$analysis.DetectedCheats.Add("Inyección Grim ($grim)")
                    }
                }
                foreach ($novo in $CheatSignatures.Novoware) {
                    if ($fullName.Contains($novo)) {
                        $analysis.SpecificMalware = "NOVOWARE ENCONTRADO"
                        [void]$analysis.DetectedCheats.Add("Estructura Novoware ($novo)")
                    }
                }
                foreach ($darkis in $CheatSignatures.DarkisClient) {
                    if ($fullName.Contains($darkis) -or $fullName.StartsWith($darkis)) {
                        $analysis.SpecificMalware = "DARKIS CLIENT ENCONTRADO"
                        [void]$analysis.DetectedCheats.Add("Falsificación Target/Compat ($darkis)")
                    }
                }
                foreach ($pkg in $CheatSignatures.Packages) {
                    if ($fullName -like "*$pkg*") { 
                        [void]$analysis.DetectedCheats.Add("Paquete Cheat: $pkg") 
                    }
                }

                if ($entry.Length -gt 0 -and $entry.Length -lt 1.5MB) {
                    try {
                        $stream = $entry.Open(); $ms = [System.IO.MemoryStream]::new(); $stream.CopyTo($ms)
                        $bytes = $ms.ToArray(); $stream.Close(); $ms.Close()
                        if ($bytes.Length -gt 0) {
                            $rawText = [System.Text.Encoding]::ASCII.GetString($bytes)
                            $cleanText = [regex]::Replace($rawText, '[^\x20-\x7E]', ' ')
                            foreach ($kw in $CheatSignatures.Keywords) {
                                if ($cleanText -match "\b$kw\b") { [void]$analysis.DetectedCheats.Add("Módulo de Combate: $kw") }
                            }
                            if ($cleanText -match '(https?://[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*)') {
                                $foundUrl = "$($Matches[1])".Trim()
                                if ($foundUrl -notmatch 'schemas\.microsoft|fabricmc\.net|spongepowered|minecraftforge') {
                                    $analysis.ExtractedUrl = $foundUrl
                                }
                            }
                        }
                    } catch {}
                }
            }
        }

        if ($hasRootA -and $hasRootB -and $hasRootC) {
            $analysis.SpecificMalware = "NOVOWARE ENCONTRADO"
            [void]$analysis.DetectedCheats.Add("Inyector Camuflado en Raíz (b/A+b/B)")
        }

        if ($analysis.ExtractedUrl) {
            if ($analysis.ExtractedUrl -match 'github\.com') { $analysis.ExtractedSource = 'GitHub' }
            elseif ($analysis.ExtractedUrl -match 'discord') { $analysis.ExtractedSource = 'Discord Source' }
            elseif ($analysis.ExtractedUrl -match 'modrinth') { $analysis.ExtractedSource = 'Modrinth' }
            elseif ($analysis.ExtractedUrl -match 'curseforge') { $analysis.ExtractedSource = 'CurseForge' }
            else { $analysis.ExtractedSource = 'Origen Web Remoto' }
        }

        $zip.Dispose()
    } catch {}

    return $analysis
}

function Get-OriginByHash {
    param([string]$Sha1)
    $result = @{ Source = 'DESCONOCIDO'; Url = '' }
    if ([string]::IsNullOrWhiteSpace($Sha1)) { return $result }
    if ($GLOBAL:CACHE_MODRINTH.ContainsKey($Sha1)) { return $GLOBAL:CACHE_MODRINTH[$Sha1] }
    try {
        $uri = "https://api.modrinth.com/v2/version_file/$Sha1`?algorithm=sha1"
        $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers @{ 'User-Agent' = 'WluzAnalyzer/6.7' } -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($resp -and $resp.project_id) {
            $pUri = "https://api.modrinth.com/v2/project/$($resp.project_id)"
            $proj = Invoke-RestMethod -Uri $pUri -Method Get -Headers @{ 'User-Agent' = 'WluzAnalyzer/6.7' } -TimeoutSec 2 -ErrorAction SilentlyContinue
            $result.Source = 'Modrinth'
            $result.Url = "https://modrinth.com/mod/$($proj.slug)"
            $GLOBAL:CACHE_MODRINTH[$Sha1] = $result
            return $result
        }
    } catch {}
    return $result
}

# --- CONTROLADOR CENTRAL INTERFAZ DE CONSOLA ---
if ([string]::IsNullOrWhiteSpace($ModsPath)) {
    Clear-Host
    Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│                 WLUZ ANALYZER v6.7.1                        │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    $ModsPath = Read-Host " -> Ingresa la ruta de la carpeta de mods"
}

if (-not (Test-Path $ModsPath)) { Write-Host "[!] Ruta inválida." -ForegroundColor Red; exit 1 }
$Files = Get-ChildItem -Path $ModsPath -Filter '*.jar' -File
if ($Files.Count -eq 0) { Write-Host "[!] No se encontraron archivos .jar." -ForegroundColor Yellow; exit 0 }

Write-Host "`nEjecutando escaneo molecular avanzado (Analizando archivos)..." -ForegroundColor Gray

# Listas para almacenar los resultados en memoria
$VerifiedList = [System.Collections.Generic.List[psobject]]::new()
$CheatList    = [System.Collections.Generic.List[psobject]]::new()

foreach ($File in $Files) {
    # Feedback visual rápido mientras procesa en silencio
    Write-Host "." -NoNewline -ForegroundColor Gray
    
    $Sha1 = Get-FileHashSha1 -Path $File.FullName
    $Analysis = Analyze-JarInternals -JarPath $File.FullName
    
    if (-not $Analysis.SpecificMalware -and $Analysis.DetectedCheats.Count -eq 0) {
        $Origin = Get-OriginByHash -Sha1 $Sha1
        if ($Origin.Source -ne 'DESCONOCIDO') {
            $Analysis.ExtractedSource = $Origin.Source
            $Analysis.ExtractedUrl = $Origin.Url
        }
    }

    # Determinamos estado
    if ($Analysis.SpecificMalware -or $Analysis.DetectedCheats.Count -gt 0) {
        $Analysis.Add('Status', 'CHEAT')
        $CheatList.Add($Analysis)
    } else {
        if ($Analysis.ExtractedSource -ne 'DESCONOCIDO') {
            $Analysis.Add('Status', 'VERIFIED')
        } else {
            $Analysis.Add('Status', 'PASSED')
        }
        $VerifiedList.Add($Analysis)
    }
}

Write-Host "`n`n=================== REPORTE DE INSPECCIÓN ===================" -ForegroundColor Cyan

# 1. BLOQUE DE MODS VERIFICADOS / LIMPIOS primero
Write-Host "`n[+] ARCHIVOS VERIFICADOS Y LIMPIOS (`$($VerifiedList.Count))" -ForegroundColor Green
Write-Host "-------------------------------------------------------------" -ForegroundColor Green
foreach ($Mod in $VerifiedList) {
    if ($Mod.Status -eq 'VERIFIED') {
        Write-Host " [+] " -NoNewline -ForegroundColor Gray
        Write-Host "$($Mod.FileName.PadRight(45)) " -NoNewline -ForegroundColor Green
        Write-Host "[VERIFIED]" -NoNewline -ForegroundColor DarkGreen
        if ($Mod.ExtractedUrl) { Write-Host " -> $($Mod.ExtractedUrl)" -ForegroundColor DarkCyan } else { Write-Host "" }
    } else {
        Write-Host " [+] " -NoNewline -ForegroundColor Gray
        Write-Host "$($Mod.FileName.PadRight(45)) " -NoNewline -ForegroundColor White
        Write-Host "[PASSED / LIMPIO]" -ForegroundColor Gray
    }
}

# 2. BLOQUE DE ALERTAS CRÍTICAS (CHEATS) al final
if ($CheatList.Count -gt 0) {
    Write-Host "`n`n⚠️ ADVERTENCIAS Y ALERTAS CRÍTICAS DE CHEATS (`$($CheatList.Count))" -ForegroundColor Red
    Write-Host "-------------------------------------------------------------" -ForegroundColor Red
    foreach ($Cheat in $CheatList) {
        $Title = if ($Cheat.SpecificMalware) { $Cheat.SpecificMalware } else { "CHEAT ENCONTRADO" }
        Write-Host "┌─[ ALERTA CRÍTICA: CHEAT ENCONTRADO ]──────────────────────────────────┐" -ForegroundColor Red
        Write-Host "│ Archivo:    " -NoNewline -ForegroundColor Gray; Write-Host $Cheat.FileName -ForegroundColor White
        Write-Host "│ Veredicto:  " -NoNewline -ForegroundColor Gray; Write-Host "⚠️  $Title ⚠️" -ForegroundColor Black -BackgroundColor Red
        Write-Host "│ Evidencias: " -NoNewline -ForegroundColor Gray; Write-Host ($Cheat.DetectedCheats -join ' | ') -ForegroundColor DarkRed
        if ($Cheat.ExtractedSource -ne 'DESCONOCIDO') {
            Write-Host "│ Origen:     " -NoNewline -ForegroundColor Gray; Write-Host "$($Cheat.ExtractedSource)" -ForegroundColor White
            if ($Cheat.ExtractedUrl) { Write-Host "│ Enlace:     " -NoNewline -ForegroundColor Gray; Write-Host $Cheat.ExtractedUrl -ForegroundColor DarkCyan }
        }
        Write-Host "└────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
    }
} else {
    Write-Host "`n`n[🎉] ¡Excelente! No se detectaron amenazas ni modificaciones sospechosas." -ForegroundColor Cyans
}