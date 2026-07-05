<#
.SYNOPSIS
    ModAnalyzer - Escaner de mods de Minecraft (Fabric/Forge) para detectar cheats/hacks.

.DESCRIPTION
    Analiza cada .jar de una carpeta:
      1) Calcula SHA1 y lo consulta contra la API pública de Modrinth (mods verificados).
      2) Si no aparece en Modrinth, abre el .jar y escanea los .class buscando:
         - Firmas de paquetes de clientes de cheat conocidos (open source: Wurst, Impact,
           Meteor, Sigma, Aristois, LiquidBounce, Novoline, Rusherhack, etc.)
         - Palabras clave de comportamiento típico de cheats (killaura, esp, xray, etc.)
         - Señales de ofuscación agresiva (nombres de clase de 1-2 letras en masa)
      3) Clasifica cada mod como VERIFIED (verde), CHEAT (rojo) o UNKNOWN (amarillo).

.NOTES
    LIMITACIONES IMPORTANTES (léelas):
    - Esto es deteccion heuristica/por firmas, NO un antivirus certificado.
    - Un cheat privado, custom, con nombres de clase genericos y sin las firmas conocidas
      de abajo puede pasar como UNKNOWN. Ningun scanner (ni los comerciales) tiene una
      base de datos 100% completa, porque salen cheats nuevos todo el tiempo.
    - "UNKNOWN" no significa "seguro", significa "no coincide con nada conocido ni con
      Modrinth". Revisa esos manualmente (de donde lo bajaste, quien lo hizo, etc).
    - Los falsos positivos son posibles: algunos mods legitimos (ej. mods de macros,
      QoL de combate, o herramientas de desarrollo) pueden usar palabras similares.
      Revisa el detalle de "Matches" antes de acusar a alguien.

.PARAMETER ModsPath
    Ruta de la carpeta donde estan los .jar de los mods.

.PARAMETER ReportPath
    Ruta donde se guarda el reporte en texto/CSV. Por defecto se crea junto al script.

.PARAMETER SkipOnline
    Si se especifica, no consulta Modrinth (util si no tienes internet).

.EXAMPLE
    .\ModAnalyzer.ps1 -ModsPath "C:\Users\Papi\AppData\Roaming\.minecraft\mods"

.EXAMPLE
    # Uso local sin especificar ruta -> el script la pide de forma interactiva
    .\ModAnalyzer.ps1

.EXAMPLE
    # Uso remoto (una vez subido a GitHub), pide la ruta de forma interactiva:
    powershell -command "irm 'https://raw.githubusercontent.com/TUUSUARIO/TUREPO/main/HabibiModAnalyzer.ps1' | iex"
#>

param(
    [string]$ModsPath,

    [string]$ReportPath,

    [switch]$SkipOnline
)

# Si se ejecuta via "irm URL | iex" no hay forma comoda de pasar -ModsPath,
# asi que si no vino por parametro, se pregunta de forma interactiva.
if ([string]::IsNullOrWhiteSpace($ModsPath)) {
    Write-Host ""
    Write-Host "=== HabibiModAnalyzer ===" -ForegroundColor Cyan
    $ModsPath = Read-Host "Pega la ruta de tu carpeta de mods (ej: C:\Users\TuUsuario\AppData\Roaming\.minecraft\mods)"
}

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    # $PSScriptRoot esta vacio cuando el script corre via iex, asi que se usa el directorio actual
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $baseDir "mod_scan_report.csv"
}

# ============================================================
#  BASE DE FIRMAS CONOCIDAS
# ============================================================

# Paquetes base de clientes de cheat open-source conocidos.
# Si un .class dentro del jar pertenece a uno de estos paquetes, es una senal MUY fuerte.
$KnownCheatPackages = @(
    'net/wurstclient',
    'meteordevelopment/meteorclient',
    'me/rigamortis/sigma',
    'me/zero/alpine',
    'com/aristois',
    'net/ccbluex/liquidbounce',
    'me/kaimson/rusherhack',
    'dev/sxmurxy/artemis',
    'me/rigamortis/wolfehacks',
    'wtf/spare/skillet',
    'org/kamiblue',
    'net/novoline',
    'baritone/api/utils/input',  # baritone en si es "solo" pathfinding, se marca como sospechoso, no cheat directo
    'xyz/derkades/salhack',
    'me/gato/nursultanclient'
)

# Palabras clave de comportamiento tipico de cheats, buscadas en strings dentro del .class
# (nombres de metodos, campos, literales de texto embebidos en el bytecode)
$SuspiciousKeywords = @(
    'killaura', 'kill_aura', 'aimbot', 'autoclicker', 'auto_clicker',
    'wallhack', 'xray', 'x-ray', 'esp', 'chestesp', 'tracers',
    'nofall', 'no_fall', 'speedhack', 'speed_hack', 'flighthack',
    'antiknockback', 'anti_kb', 'freecam', 'nuker', 'fastbreak',
    'scaffoldwalk', 'timerchanger', 'packetspoof', 'reach_hack',
    'hitboxexpand', 'triggerbot', 'trigger_bot', 'autototem',
    'bhop_hack', 'velocityhack', 'critsploit', 'fakelag', 'blink_hack'
)

# Excepciones: strings que contienen alguna keyword pero suelen aparecer en mods legitimos
# (ej. mods "anti-cheat" del lado servidor, o mods que MITIGAN estas cosas)
$FalsePositiveHints = @(
    'anticheat', 'anti-cheat', 'nocheatplus', 'anti_hack_detector'
)

# ============================================================
#  FUNCIONES
# ============================================================

function Get-Sha1Hash {
    param([string]$FilePath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $hashBytes = $sha1.ComputeHash($stream)
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $stream.Close()
        $sha1.Dispose()
    }
}

function Test-ModrinthVerified {
    param([string]$Sha1Hash)

    $result = [PSCustomObject]@{
        Found       = $false
        ProjectName = $null
        ProjectUrl  = $null
        VersionName = $null
    }

    try {
        $uri = "https://api.modrinth.com/v2/version_file/$Sha1Hash`?algorithm=sha1"
        $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers @{ 'User-Agent' = 'ModAnalyzer/1.0 (local scan tool)' } -TimeoutSec 10 -ErrorAction Stop

        if ($resp -and $resp.project_id) {
            $projUri = "https://api.modrinth.com/v2/project/$($resp.project_id)"
            $proj = Invoke-RestMethod -Uri $projUri -Method Get -Headers @{ 'User-Agent' = 'ModAnalyzer/1.0 (local scan tool)' } -TimeoutSec 10 -ErrorAction Stop

            $result.Found       = $true
            $result.ProjectName = $proj.title
            $result.ProjectUrl  = "https://modrinth.com/mod/$($proj.slug)"
            $result.VersionName = $resp.name
        }
    }
    catch {
        # 404 = no encontrado en Modrinth. Cualquier otro error de red se ignora silenciosamente
        # y el mod cae en analisis local (no se asume culpable por fallo de red).
        $result.Found = $false
    }

    return $result
}

function Get-ClassEntries {
    param([string]$JarPath)

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        $entries = $zip.Entries | Where-Object { $_.FullName -like '*.class' }
        return @{ Zip = $zip; Entries = $entries }
    }
    catch {
        return @{ Zip = $null; Entries = @() }
    }
}

function Get-StringsFromClassBytes {
    param([byte[]]$Bytes, [int]$MinLength = 5)

    # Extrae secuencias ASCII imprimibles del bytecode (equivalente a "strings" de linux)
    # Esto captura literales de texto embebidos: nombres de metodos, logs, comentarios de debug, etc.
    $results = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder

    foreach ($b in $Bytes) {
        if ($b -ge 32 -and $b -le 126) {
            [void]$sb.Append([char]$b)
        }
        else {
            if ($sb.Length -ge $MinLength) {
                $results.Add($sb.ToString())
            }
            $sb.Clear() | Out-Null
        }
    }
    if ($sb.Length -ge $MinLength) { $results.Add($sb.ToString()) }

    return $results
}

function Test-SuspiciousJar {
    param([string]$JarPath)

    $finding = [PSCustomObject]@{
        IsSuspicious       = $false
        MatchedPackages    = @()
        MatchedKeywords    = @()
        ObfuscationScore   = 0
        TotalClasses       = 0
        ShortNamedClasses  = 0
    }

    $zipInfo = Get-ClassEntries -JarPath $JarPath
    if (-not $zipInfo.Zip) { return $finding }

    try {
        $finding.TotalClasses = $zipInfo.Entries.Count
        $matchedPkgs = New-Object System.Collections.Generic.HashSet[string]
        $matchedKw   = New-Object System.Collections.Generic.HashSet[string]

        foreach ($entry in $zipInfo.Entries) {

            # --- 1) Chequeo de paquete/ruta de clase contra firmas conocidas ---
            foreach ($pkg in $KnownCheatPackages) {
                if ($entry.FullName -like "*$pkg*") {
                    [void]$matchedPkgs.Add($pkg)
                }
            }

            # --- 2) Heuristica de ofuscacion: nombre de clase muy corto (a.class, b$c.class) ---
            $shortName = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
            if ($shortName.Length -le 2) {
                $finding.ShortNamedClasses++
            }

            # --- 3) Escaneo de strings dentro del .class (solo si el jar no es enorme, para performance) ---
            if ($entry.Length -lt 2MB) {
                $stream = $entry.Open()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $bytes = $ms.ToArray()
                $stream.Close(); $ms.Close()

                $strings = Get-StringsFromClassBytes -Bytes $bytes
                $lowerStrings = $strings | ForEach-Object { $_.ToLowerInvariant() }

                foreach ($kw in $SuspiciousKeywords) {
                    $hit = $lowerStrings | Where-Object { $_ -like "*$kw*" } | Select-Object -First 1
                    if ($hit) {
                        # Descarta si el mismo string contiene una pista de falso positivo
                        $isFalsePositive = $false
                        foreach ($fp in $FalsePositiveHints) {
                            if ($hit -like "*$fp*") { $isFalsePositive = $true; break }
                        }
                        if (-not $isFalsePositive) {
                            [void]$matchedKw.Add($kw)
                        }
                    }
                }
            }
        }

        $finding.MatchedPackages = @($matchedPkgs)
        $finding.MatchedKeywords = @($matchedKw)

        if ($finding.TotalClasses -gt 0) {
            $finding.ObfuscationScore = [math]::Round((($finding.ShortNamedClasses / $finding.TotalClasses) * 100), 1)
        }

        # Se marca como sospechoso si:
        #  - matchea un paquete de cheat conocido, o
        #  - matchea 2+ keywords de comportamiento (1 sola keyword puede ser coincidencia), o
        #  - tiene >70% de clases con nombre de 1-2 letras Y ademas matchea al menos 1 keyword
        if ($finding.MatchedPackages.Count -gt 0) {
            $finding.IsSuspicious = $true
        }
        elseif ($finding.MatchedKeywords.Count -ge 2) {
            $finding.IsSuspicious = $true
        }
        elseif ($finding.ObfuscationScore -gt 70 -and $finding.MatchedKeywords.Count -ge 1) {
            $finding.IsSuspicious = $true
        }
    }
    finally {
        $zipInfo.Zip.Dispose()
    }

    return $finding
}

# ============================================================
#  MAIN
# ============================================================

if (-not (Test-Path $ModsPath)) {
    Write-Host "La ruta '$ModsPath' no existe." -ForegroundColor Red
    exit 1
}

$jars = Get-ChildItem -Path $ModsPath -Filter '*.jar' -File -ErrorAction SilentlyContinue

if (-not $jars -or $jars.Count -eq 0) {
    Write-Host "No se encontraron archivos .jar en '$ModsPath'." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   MOD ANALYZER - Escaneando $($jars.Count) mod(s)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$report = New-Object System.Collections.Generic.List[PSCustomObject]

foreach ($jar in $jars) {

    Write-Host "Analizando: $($jar.Name) ..." -ForegroundColor Gray

    $sha1 = Get-Sha1Hash -FilePath $jar.FullName

    $modrinthResult = [PSCustomObject]@{ Found = $false }
    if (-not $SkipOnline) {
        $modrinthResult = Test-ModrinthVerified -Sha1Hash $sha1
    }

    $status      = 'UNKNOWN'
    $color       = 'Yellow'
    $source      = 'Desconocido'
    $detail      = ''

    if ($modrinthResult.Found) {
        $status = 'VERIFIED'
        $color  = 'Green'
        $source = $modrinthResult.ProjectUrl
        $detail = "Modrinth: $($modrinthResult.ProjectName) ($($modrinthResult.VersionName))"
    }
    else {
        $suspicious = Test-SuspiciousJar -JarPath $jar.FullName

        if ($suspicious.IsSuspicious) {
            $status = 'CHEAT'
            $color  = 'Red'
            $parts = @()
            if ($suspicious.MatchedPackages.Count -gt 0) {
                $parts += "Paquetes de cheat conocidos: $($suspicious.MatchedPackages -join ', ')"
            }
            if ($suspicious.MatchedKeywords.Count -gt 0) {
                $parts += "Keywords sospechosas: $($suspicious.MatchedKeywords -join ', ')"
            }
            if ($suspicious.ObfuscationScore -gt 70) {
                $parts += "Ofuscacion alta ($($suspicious.ObfuscationScore)% de clases con nombre de 1-2 letras)"
            }
            $detail = $parts -join ' | '
        }
        else {
            $status = 'UNKNOWN'
            $color  = 'Yellow'
            $detail = "No esta en Modrinth y no matchea firmas conocidas. Clases: $($suspicious.TotalClasses), Ofuscacion: $($suspicious.ObfuscationScore)%"
        }
    }

    $label = switch ($status) {
        'VERIFIED' { 'VERIFIED' }
        'CHEAT'    { 'CHEAT' }
        default    { 'UNKNOWN' }
    }

    Write-Host ("  [{0}] {1}" -f $label, $jar.Name) -ForegroundColor $color
    if ($detail) { Write-Host "        -> $detail" -ForegroundColor DarkGray }
    Write-Host ""

    $report.Add([PSCustomObject]@{
        Archivo   = $jar.Name
        SHA1      = $sha1
        Estado    = $status
        Fuente    = $source
        Detalle   = $detail
    })
}

# ------------------------------------------------------------
#  RESUMEN
# ------------------------------------------------------------
$verifiedCount = ($report | Where-Object { $_.Estado -eq 'VERIFIED' }).Count
$cheatCount    = ($report | Where-Object { $_.Estado -eq 'CHEAT' }).Count
$unknownCount  = ($report | Where-Object { $_.Estado -eq 'UNKNOWN' }).Count

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  RESUMEN" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ("  Verificados : {0}" -f $verifiedCount) -ForegroundColor Green
Write-Host ("  Cheats      : {0}" -f $cheatCount) -ForegroundColor Red
Write-Host ("  Desconocidos: {0}" -f $unknownCount) -ForegroundColor Yellow
Write-Host ""

$report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host "Reporte guardado en: $ReportPath" -ForegroundColor Cyan
Write-Host ""

if ($cheatCount -gt 0) {
    Write-Host "ATENCION: revisa manualmente los mods marcados como CHEAT antes de tomar" -ForegroundColor Yellow
    Write-Host "cualquier accion (expulsar/banear). Esto es deteccion heuristica, no prueba legal." -ForegroundColor Yellow
    Write-Host ""
}
