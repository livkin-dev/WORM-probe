$ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()
$eUrl = "https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/endpoints.txt"
$rUrl = "https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/resolvers.txt"

# Загрузка эндпоинтов
try {
    $rawEndpoints = (Invoke-RestMethod -Uri "$eUrl?v=$ts" -TimeoutSec 10) -split "`r?`n"
    $endpoints = @()
    foreach ($line in $rawEndpoints) {
        $trimmed = $line.Trim()
        if ($trimmed -and $trimmed.StartsWith("http")) {
            $endpoints += $trimmed
        }
    }
} catch {
    $endpoints = @()
}

if ($endpoints.Count -eq 0) {
    $endpoints = @("https://chatgpt.com", "https://api.anthropic.com", "https://play.google.com")
}

# Загрузка резолверов
try {
    $rawResolvers = (Invoke-RestMethod -Uri "$rUrl?v=$ts" -TimeoutSec 10) -split "`r?`n"
    $resolvers = @()
    foreach ($line in $rawResolvers) {
        $trimmed = $line.Trim()
        if ($trimmed -and $trimmed.Contains("|")) {
            $resolvers += $trimmed
        }
    }
} catch {
    $resolvers = @()
}

if ($resolvers.Count -eq 0) {
    $resolvers = @(
        "System|SYS|",
        "Cloudflare|DoH|https://cloudflare-dns.com/dns-query",
        "Yandex_UDP|UDP|77.88.8.8"
    )
}

try { 
    $geo = Invoke-RestMethod -Uri "https://ipinfo.io/json" -TimeoutSec 5
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
Out-File -FilePath "$f" -InputObject $csvHeader -Encoding utf8

Write-Host "`n===================================================================================================="
Write-Host " 📡 WORM PROBE: LLM API CENSORSHIP & DNS TEST"
Write-Host " 🌍 Region: $myReg | ISP: $myOrg \vert{} IP:$myIp"
Write-Host "===================================================================================================="
"{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | {5}" -f "API ENDPOINT","RESOLVER","IP","STAT","DNS / RSP / TOT (sec)","BLOCKED?"
Write-Host "----------------------------------------------------------------------------------------------------"

foreach ($u in$endpoints) { 
    $d = ([uri]$u).Host
    foreach ($res in$resolvers) { 
        $p =$res.Split('|')
        $rn =$p[0]; $rt =$p[1]; $ra =$p[2]
        
        if ($rt -eq "SYS") { 
            $out = curl.exe -s -o NUL -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 $u 
        } elseif ($rt -eq "DoH") { 
            $out = curl.exe -s --doh-url$ra -o NUL -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 $u 
        } elseif ($rt -eq "UDP") { 
            try { 
                $dip = (Resolve-DnsName -Name$d -Server $ra -Type A -ErrorAction Stop \vert{} Where-Object {$_.Type -eq 'A'} | Select-Object -First 1).IPAddress
                if ($dip) { 
                    $out = curl.exe -s --resolve "$($d):443:$dip" -o NUL -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 $u 
                } else { 
                    $out = curl.exe -s -o NUL -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 $u 
                } 
            } catch { 
                $out = "000::0:0:0" 
            } 
        }
        
        $st = ($out -split ':')[0]
        $ip = ($out -split ':')[1]
        $td = ($out -split ':')[2] -replace ',', '.'
        $tr = ($out -split ':')[3] -replace ',', '.'
        $tt = ($out -split ':')[4] -replace ',', '.'
        
        if ([string]::IsNullOrWhiteSpace($ip)) {$ip = "N/A" }
        
        if (![string]::IsNullOrWhiteSpace($tt) -and $tt -ne "0" -and $tt -ne "0.000") { 
            $td_sec = ([double]::Parse($td, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
            $tr_sec = ([double]::Parse($tr, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
            $tt_sec = ([double]::Parse($tt, [System.Globalization.CultureInfo]::InvariantCulture)).ToString("0.000000", [System.Globalization.CultureInfo]::InvariantCulture)
            $tm_disp = "$td_sec / $tr_sec / $tt_sec" 
        } else { 
            $td_sec = ""; $tr_sec = ""; $tt_sec = ""; $tm_disp = "N/A" 
        }
        
        if ($st -eq "000" -or [string]::IsNullOrWhiteSpace($st)) {$b = "YES"
            "{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | ⚠️ YES" -f $d,$rn,$ip,"ERR",$tm_disp 
        } else { 
            $b = "NO"
            "{0,-28} | {1,-12} | {2,-15} | {3,-4} | {4,-21} | ✅ NO" -f $d,$rn,$ip,$st,$tm_disp 
        }
        
        $row = "`"$myReg`";`"$myOrg`";`"$d`";`"$rn`";`"$ip`";`"$st`";`"$td_sec`";`"$tr_sec`";`"$tt_sec`";`"$b`""
        Out-File -FilePath "$f" -InputObject $row -Append -Encoding utf8
    } 
    Write-Host "----------------------------------------------------------------------------------------------------" 
}

$url = "https://docs.google.com/forms/d/e/1FAIpQLScbs8FDq1k3GQAAjJM_N2IHgXBvTjKRPcd_AmdvS5Kz2NJQfQ/formResponse"
curl.exe -s --data-urlencode "entry.1081274956@$f" $url -o NUL
$fp = (Get-Item "$f").FullName
Write-Host "✅ CSV сохранен: $fp"
Write-Host "✅ Данные успешно отправлены в Google Forms."
