#Requires -Version 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ErrorActionPreference = 'Stop'

$endpointsUrl = 'https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/endpoints.txt'
$resolversUrl = 'https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/resolvers.txt'
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

function Get-TextLines {
    param(
        [Parameter(Mandatory = $true)][string]$Url
    )

    $content = (Invoke-WebRequest -Uri ("{0}?v={1}" -f $Url, $ts) -UseBasicParsing).Content
    if ($null -eq $content) { return @() }

    return @(
        $content -split "`r?`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
    )
}

function Get-GeoInfo {
    try {
        $geo = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 5 -UseBasicParsing
        return [pscustomobject]@{
            Ip     = if ($geo.ip) { $geo.ip } else { 'Unknown' }
            Org    = if ($geo.org) { ($geo.org -replace ',', '') } else { 'Unknown ISP' }
            Region = if ($geo.city -or $geo.country) { ("{0} {1}" -f $geo.city, $geo.country).Trim() } else { 'Unknown Region' }
        }
    }
    catch {
        return [pscustomobject]@{
            Ip     = 'Unknown'
            Org    = 'Unknown ISP'
            Region = 'Unknown Region'
        }
    }
}

function Parse-Resolver {
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )

    $parts = $Line -split '\|', 3
    if ($parts.Count -lt 3) { return $null }

    return [pscustomobject]@{
        Name    = $parts[0].Trim()
        Type    = $parts[1].Trim().ToUpperInvariant()
        Address = $parts[2].Trim()
    }
}

function Invoke-CurlProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$DohUrl,
        [string]$ResolveHost,
        [string]$ResolveIp
    )

    $curlArgs = @(
        '-s',
        '-o', 'NUL',
        '-w', '%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_starttransfer}|%{time_total}',
        '-m', '10'
    )

    if ($DohUrl) {
        $curlArgs += @('--doh-url', $DohUrl)
    }

    if ($ResolveHost -and $ResolveIp) {
        $curlArgs += @('--resolve', ('{0}:443:{1}' -f $ResolveHost, $ResolveIp))
    }

    $curlArgs += $Url

    $output = & curl.exe @curlArgs
    $exitCode = $LASTEXITCODE

    $parts = @($output -split '\|', 5)
    while ($parts.Count -lt 5) { $parts += '' }

    [pscustomobject]@{
        CurlExit          = $exitCode
        HttpCode          = $parts[0]
        RemoteIp          = if ([string]::IsNullOrWhiteSpace($parts[1])) { 'N/A' } else { $parts[1] }
        TimeNameLookupRaw = $parts[2]
        TimeStartRaw      = $parts[3]
        TimeTotalRaw      = $parts[4]
    }
}

function Format-Seconds {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

    $normalized = $Value -replace ',', '.'
    if ($normalized -eq '0' -or $normalized -eq '0.000' -or $normalized -eq '0.000000') { return '' }

    try {
        return ([double]::Parse($normalized, [System.Globalization.CultureInfo]::InvariantCulture)).ToString('0.000000', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        return ''
    }
}

try {
    $endpointLines = Get-TextLines -Url $endpointsUrl
}
catch {
    Write-Host "[-] Error fetching endpoints: $($_.Exception.Message)" -ForegroundColor Yellow
    return
}

$endpoints = @(
    foreach ($line in $endpointLines) {
        if (-not $line.StartsWith('http')) { continue }
        try {
            $uri = [uri]$line
            if ($uri.Scheme -in @('http', 'https') -and $uri.Host) { $line }
        }
        catch {}
    }
)

if ($endpoints.Count -eq 0) {
    Write-Host '[-] Critical: Failed to load valid endpoints from repository.' -ForegroundColor Red
    return
}

try {
    $resolverLines = Get-TextLines -Url $resolversUrl
}
catch {
    Write-Host "[-] Error fetching resolvers: $($_.Exception.Message)" -ForegroundColor Yellow
    return
}

$resolvers = @(
    foreach ($line in $resolverLines) {
        if ($line -notmatch '\|') { continue }
        $resolver = Parse-Resolver -Line $line
        if ($resolver) { $resolver }
    }
)

if ($resolvers.Count -eq 0) {
    Write-Host '[-] Critical: Failed to load resolvers from repository.' -ForegroundColor Red
    return
}

$geo = Get-GeoInfo

$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$fileName = "worm_results_$timestamp.csv"
$filePath = Join-Path -Path (Get-Location) -ChildPath $fileName

$csvHeader = '"REGION";"ISP";"ENDPOINT";"RESOLVER";"IP";"STATUS";"DNS, сек.";"Ожидание ответа, сек.";"Общее время, сек.";"BLOCKED";"CURL_EXIT"'
[System.IO.File]::WriteAllText($filePath, "$csvHeader`r`n", [System.Text.Encoding]::UTF8)

Write-Host ''
Write-Host '===================================================================================================='
Write-Host " [i] WORM PROBE: LLM API CENSORSHIP AND DNS TEST"
Write-Host " [i] Region: $($geo.Region) | ISP: $($geo.Org) | IP: $($geo.Ip)"
Write-Host '===================================================================================================='
[Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | {5}", 'API ENDPOINT', 'RESOLVER', 'IP', 'STAT', 'DNS / RSP / TOT (sec)', 'BLOCKED?')
Write-Host '----------------------------------------------------------------------------------------------------'

foreach ($u in $endpoints) {
    try {
        $uri = [uri]$u
        $hostName = $uri.Host
    }
    catch {
        continue
    }

    foreach ($resolver in $resolvers) {
        $probe = $null

        if ($resolver.Type -eq 'SYS') {
            $probe = Invoke-CurlProbe -Url $u
        }
        elseif ($resolver.Type -eq 'DOH') {
            $probe = Invoke-CurlProbe -Url $u -DohUrl $resolver.Address
        }
        elseif ($resolver.Type -eq 'UDP') {
            try {
                $dnsAnswer = Resolve-DnsName -Name $hostName -Server $resolver.Address -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                    Where-Object { $_.Type -eq 'A' } |
                    Select-Object -First 1

                if ($dnsAnswer -and $dnsAnswer.IPAddress) {
                    $probe = Invoke-CurlProbe -Url $u -ResolveHost $hostName -ResolveIp $dnsAnswer.IPAddress
                }
                else {
                    $probe = [pscustomobject]@{
                        CurlExit          = 998
                        HttpCode          = '000'
                        RemoteIp          = 'N/A'
                        TimeNameLookupRaw = '0'
                        TimeStartRaw      = '0'
                        TimeTotalRaw      = '0'
                    }
                }
            }
            catch {
                $probe = [pscustomobject]@{
                    CurlExit          = 997
                    HttpCode          = '000'
                    RemoteIp          = 'N/A'
                    TimeNameLookupRaw = '0'
                    TimeStartRaw      = '0'
                    TimeTotalRaw      = '0'
                }
            }
        }
        else {
            continue
        }

        $st = $probe.HttpCode
        $ip = $probe.RemoteIp

        if ($st -eq '000' -or [string]::IsNullOrWhiteSpace($st)) {
            $status = 'ERR'
            $dnsSec = ''
            $rspSec = ''
            $totSec = ''
            $tmDisp = 'TIMEOUT'
            $blocked = 'YES'
            [Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | [!] YES", $hostName, $resolver.Name, $ip, $status, $tmDisp)
        }
        else {
            $status = $st
            $dnsSec = Format-Seconds -Value $probe.TimeNameLookupRaw
            $rspSec = Format-Seconds -Value $probe.TimeStartRaw
            $totSec = Format-Seconds -Value $probe.TimeTotalRaw
            $tmDisp = if ($totSec) { "$dnsSec / $rspSec / $totSec" } else { 'N/A' }
            $blocked = 'NO'
            [Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | [OK] NO", $hostName, $resolver.Name, $ip, $status, $tmDisp)
        }

        $row = '"{0}";"{1}";"{2}";"{3}";"{4}";"{5}";"{6}";"{7}";"{8}";"{9}";"{10}"' -f `
            $geo.Region, $geo.Org, $hostName, $resolver.Name, $ip, $status, $dnsSec, $rspSec, $totSec, $blocked, $probe.CurlExit

        [System.IO.File]::AppendAllText($filePath, "$row`r`n", [System.Text.Encoding]::UTF8)
    }

    Write-Host '----------------------------------------------------------------------------------------------------'
}

$formUrl = 'https://docs.google.com/forms/d/e/1FAIpQLScbs8FDq1k3GQAAjJM_N2IHgXBvTjKRPcd_AmdvS5Kz2NJQfQ/formResponse'
& curl.exe -s --data-urlencode ("entry.1081274956@{0}" -f $filePath) $formUrl -o NUL | Out-Null

Write-Host "[+] CSV сохранен: $filePath"
Write-Host '[+] Данные успешно отправлены в Google Forms.'
