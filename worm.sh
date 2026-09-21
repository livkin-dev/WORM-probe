#!/bin/bash
TS=$(date +%s)
ENDPOINTS_URL="https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/endpoints.txt?v=$TS"
RESOLVERS_URL="https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/resolvers.txt?v=$TS"

# Загрузка эндпоинтов
ENDPOINTS=()
IFS=$'\n'
for line in $(curl -s -m 10 "$ENDPOINTS_URL" | tr -d '\r'); do
    line=$(echo "$line" | xargs)
    [[ -n "$line" && "$line" =~ ^http ]] && ENDPOINTS+=("$line")
done
unset IFS

if [ ${#ENDPOINTS[@]} -eq 0 ]; then
    ENDPOINTS=("https://chatgpt.com" "https://api.anthropic.com" "https://play.google.com")
fi

# Загрузка резолверов
RESOLVERS=()
IFS=$'\n'
for line in $(curl -s -m 10 "$RESOLVERS_URL" | tr -d '\r'); do
    line=$(echo "$line" | xargs)
    [[ -n "$line" && "$line" == *\|* ]] && RESOLVERS+=("$line")
done
unset IFS

if [ ${#RESOLVERS[@]} -eq 0 ]; then
    RESOLVERS=("System|SYS|" "Cloudflare|DoH|https://cloudflare-dns.com/dns-query" "Yandex_UDP|UDP|77.88.8.8")
fi

CSV_FILE="worm_results_$(date +%s).csv"
GEO=$(curl -s -m 5 https://ipinfo.io/json 2>/dev/null)
MY_IP=$(echo "$GEO" | grep -m1 '"ip"' | cut -d'"' -f4)
MY_ORG=$(echo "$GEO" | grep -m1 '"org"' | cut -d'"' -f4 | sed 's/,//g')
MY_CITY=$(echo "$GEO" | grep -m1 '"city"' | cut -d'"' -f4)
MY_COUNTRY=$(echo "$GEO" | grep -m1 '"country"' | cut -d'"' -f4)
[ -z "$MY_IP" ] && MY_IP="Unknown" && MY_ORG="Unknown ISP" && MY_CITY="Unknown" && MY_COUNTRY="Region"
MY_REG="${MY_CITY} ${MY_COUNTRY}"

echo '"REGION";"ISP";"ENDPOINT";"RESOLVER";"IP";"STATUS";"DNS, сек.";"Ожидание ответа, сек.";"Общее время, сек.";"BLOCKED"' > "$CSV_FILE"

printf "\n====================================================================================================\n"
printf " 📡 WORM PROBE: LLM API CENSORSHIP & DNS TEST\n"
printf " 🌍 Region: %s | ISP: %s | IP: %s\n" "$MY_REG" "$MY_ORG" "$MY_IP"
printf "====================================================================================================\n"
printf "%-28s | %-12s | %-15s | %-4s | %-21s | %s\n" "API ENDPOINT" "RESOLVER" "IP" "STAT" "DNS / RSP / TOT (sec)" "BLOCKED?"
printf -- "----------------------------------------------------------------------------------------------------\n"

for u in "${ENDPOINTS[@]}"; do
  d=$(echo "$u" | awk -F/ '{print $3}')
  for r in "${RESOLVERS[@]}"; do
    rn=$(echo "$r" | cut -d'|' -f1); rt=$(echo "$r" | cut -d'|' -f2); ra=$(echo "$r" | cut -d'|' -f3)
    if [ "$rt" = "SYS" ]; then res=$(curl -s -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u")
    elif [ "$rt" = "DoH" ]; then res=$(curl -s --doh-url "$ra" -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u")
    elif [ "$rt" = "UDP" ]; then dip=$(dig @"$ra" +short "$d" A 2>/dev/null | grep -m1 -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'); if [ -n "$dip" ]; then res=$(curl -s --resolve "$d:443:$dip" -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u"); else res="000::0:0:0"; fi; fi
    
    st=$(echo "$res" | cut -d: -f1); ip=$(echo "$res" | cut -d: -f2)
    [ -z "$ip" ] && ip="N/A"
    
    if [ "$st" = "000" ] || [ -z "$st" ]; then 
        st="ERR"
        td_sec=""
        tr_sec=""
        tt_sec=""
        tm_disp="TIMEOUT"
        b="YES"
        printf "%-28s | %-12s | %-15s | %-4s | %-21s | ⚠️ YES\n" "$d" "$rn" "$ip" "$st" "$tm_disp"
    else 
        td=$(echo "$res" | cut -d: -f3 | tr ',' '.')
        tr=$(echo "$res" | cut -d: -f4 | tr ',' '.')
        tt=$(echo "$res" | cut -d: -f5 | tr ',' '.')
        
        if [ -n "$tt" ] && [ "$tt" != "0" ] && [ "$tt" != "0.000" ]; then 
            td_sec=$(awk -v t="$td" 'BEGIN {printf "%.6f", t}')
            tr_sec=$(awk -v t="$tr" 'BEGIN {printf "%.6f", t}')
            tt_sec=$(awk -v t="$tt" 'BEGIN {printf "%.6f", t}')
            tm_disp="${td_sec} / ${tr_sec} / ${tt_sec}"
        else 
            td_sec=""
            tr_sec=""
            tt_sec=""
            tm_disp="N/A"
        fi
        b="NO"
        printf "%-28s | %-12s | %-15s | %-4s | %-21s | ✅ NO\n" "$d" "$rn" "$ip" "$st" "$tm_disp"
    fi
    
    echo "\"$MY_REG\";\"$MY_ORG\";\"$d\";\"$rn\";\"$ip\";\"$st\";\"$td_sec\";\"$tr_sec\";\"$tt_sec\";\"$b\"" >> "$CSV_FILE"
  done
  printf -- "----------------------------------------------------------------------------------------------------\n"
done

curl -s --data-urlencode "entry.1081274956@${CSV_FILE}" "https://docs.google.com/forms/d/e/1FAIpQLScbs8FDq1k3GQAAjJM_N2IHgXBvTjKRPcd_AmdvS5Kz2NJQfQ/formResponse" > /dev/null
printf "✅ CSV сохранен: %s/%s\n✅ Данные успешно отправлены в Google Forms.\n" "$(pwd)" "$CSV_FILE"
