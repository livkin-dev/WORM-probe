[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$eUrl = 'https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/endpoints.txt'
$rUrl = 'https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/resolvers.txt'
$ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()

# Надёжная очистка URL для совместимости с PowerShell 5.1
$zwsp  = [char]0x200B
$zwnj  = [char]0x200C
$zwj   = [char]0x200D
$bom   = [char]0xFEFF

$eBase = $eUrl.Replace("`r","").Replace("`n","").Replace("`t","").Replace($zwsp,"").Replace($zwnj,"").Replace($zwj,"").Replace($bom,"").Trim()
$rBase =$rUrl.Replace("`r","").Replace("`n","").Replace("`t","").Replace($zwsp,"").Replace($zwnj,"").Replace($zwj,"").Replace($bom,"").Trim()

$eReq = '{0}?v={1}' -f $eBase, $ts
$rReq = '{0}?v={1}' -f $rBase, $ts

# Загрузка эндпоинтов
$endpoints = @()
try {
    $rawE = (Invoke-WebRequest -Uri $eReq -UseBasicParsing).Content
    foreach ($line in ($rawE -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -and $trimmed.StartsWith("http")) {
            try {
                $null = [uri]::new($trimmed)
                $endpoints += $trimmed
            } catch {}
        }
    }
} catch {
    Write-Host "[-] Error fetching endpoints: $_" -ForegroundColor Yellow
}

if ($endpoints.Count -eq 0) {
    Write-Host "[-] Critical: Failed to load valid endpoints from repository." -ForegroundColor Red
    return
}

# Загрузка резолверов
$resolvers = @()
try {
    $rawR = (Invoke-WebRequest -Uri $rReq -UseBasicParsing).Content
    foreach ($line in ($rawR -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -and $trimmed.Contains("|")) {
            $resolvers += $trimmed
        }
    }
} catch {
    Write-Host "[-] Error fetching resolvers: $_" -ForegroundColor Yellow
}

if ($resolvers.Count -eq 0) {
    Write-Host "[-] Critical: Failed to load resolvers from repository." -ForegroundColor Red
    return
}

try { 
    $geo = Invoke-RestMethod -Uri "https://ipinfo.io/json" -TimeoutSec 5 -UseBasicParsing
    $myIp = $geo.ip
    $myOrg = $geo.org -replace ',',''
    $myReg = "$($geo.city) $($geo.country)" 
} catch { 
    $myIp = "Unknown"
    $myOrg = "Unknown ISP"
    $myReg = "Unknown Region" 
}

$f = "worm_results_$(Get-Date -UFormat %s).csv"
$csvHeader = '"REGION";"ISP";"ENDPOINT";"RESOLVER";"IP";"STATUS";"DNS, сек.";"Ожидание ответа, сек.";"Общее время, сек.";"BLOCKED"'
[System.IO.File]::WriteAllText("$f", "$csvHeader`n", [System.Text.Encoding]::UTF8)

Write-Host "`n===================================================================================================="
Write-Host " [i] WORM PROBE: LLM API CENSORSHIP AND DNS TEST"
Write-Host " [i] Region: $myReg | ISP: $myOrg | IP: $myIp"
Write-Host "===================================================================================================="
[Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | {5}", "API ENDPOINT", "RESOLVER", "IP", "STAT", "DNS / RSP / TOT (sec)", "BLOCKED?")
Write-Host "----------------------------------------------------------------------------------------------------"

foreach ($u in $endpoints) { 
    try {
        $d = ([uri]$u).Host
    } catch {
        continue
    }

    foreach ($res in $resolvers) { 
        $p = $res -split '\|', 3
        if ($p.Count -lt 3) { continue }

        $rn = $p[0]
        $rt = $p[1]
        $ra = $p[2]
        
        if ($rt -eq "SYS") { 
            $out = curl.exe -s -o NUL -w "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_starttransfer}|%{time_total}" -m 10 $u 
        } elseif ($rt -eq "DoH") { 
            $out = curl.exe -s --doh-url $ra -o NUL -w "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_starttransfer}|%{time_total}" -m 10 $u 
        } elseif ($rt -eq "UDP") { 
            try { 
                $dip = (Resolve-DnsName -Name $d -Server $ra -Type A -ErrorAction Stop | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1).IPAddress
                if ($dip) { 
                    $out = curl.exe -s --resolve "$($d):443:$dip" -o NUL -w "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_starttransfer}|%{time_total}" -m 10 $u 
                } else { 
                    $out = curl.exe -s -o NUL -w "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_starttransfer}|%{time_total}" -m 10 $u 
                } 
            } catch { 
                $out = "000||0|0|0" 
            } 
        } else {
            continue
        }
        
        $parts = $out -split '\|', 5
        $st = if ($parts.Count -gt 0) { $parts[0] } else { "000" }
        $ip = if ($parts.Count -gt 1) { $parts[1] } else { "N/A" }
        $td = if ($parts.Count -gt 2) { $parts[2] -replace ',', '.' } else { "0" }
        $tr = if ($parts.Count -gt 3) { $parts[3] -replace ',', '.' } else { "0" }
        $tt = if ($parts.Count -gt 4) { $parts[4] -replace ',', '.' } else { "0" }
        
        if ([string]::IsNullOrWhiteSpace($ip)) { $ip = "N/A" }
        
        if ($st -eq "000" -or [string]::IsNullOrWhiteSpace($st)) {
            $st = "ERR"
            $td_sec = ""
            $tr_sec = ""
            $tt_sec = ""
            $tm_disp = "TIMEOUT"
            $b = "YES"
            [Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | [!] YES", $d, $rn, $ip, $st, $tm_disp)
        } else {
            if (![string]::IsNullOrWhiteSpace($tt) -and $tt -ne "0" -and $tt -ne "0.000") { 
                $td_sec = ([double]::Parse($td, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
                $tr_sec = ([double]::Parse($tr, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
                $tt_sec = ([double]::Parse($tt, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
                $tm_disp = "$td_sec / $tr_sec / $tt_sec" 
            } else { 
                $td_sec = ""; $tr_sec = ""; $tt_sec = ""; $tm_disp = "N/A" 
            }
            $b = "NO"
            [Console]::WriteLine("{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | [OK] NO", $d, $rn, $ip, $st, $tm_disp)
        }
        
        $row = "`"$myReg`";`"$myOrg`";`"$d`";`"$rn`";`"$ip`";`"$st`";`"$td_sec`";`"$tr_sec`";`"$tt_sec`";`"$b`""
        [System.IO.File]::AppendAllText("$f", "$row`n", [System.Text.Encoding]::UTF8)
    } 
    Write-Host "----------------------------------------------------------------------------------------------------" 
}

$url = "https://docs.google.com/forms/d/e/1FAIpQLScbs8FDq1k3GQAAjJM_N2IHgXBvTjKRPcd_AmdvS5Kz2NJQfQ/formResponse"
curl.exe -s --data-urlencode "entry.1081274956@$f" $url -o NUL
$fp = (Get-Item "$f").FullName
Write-Host "[+] CSV сохранен: $fp"
Write-Host "[+] Данные успешно отправлены в Google Forms."
