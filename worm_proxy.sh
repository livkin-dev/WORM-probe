#!/bin/bash
# Использование:
# PROXY_URL="socks5h://LOGIN__cr.ru;sessid.test01;sessttl.5:PASS@gw.dataimpulse.com:824" bash worm_proxy.sh

TS=$(date +%s)
ENDPOINTS_URL="https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/endpoints.txt?v=$TS"
RESOLVERS_URL="https://raw.githubusercontent.com/livkin-dev/WORM-probe/main/resolvers.txt?v=$TS"

CURL_PROXY_ARG=()
[ -n "$PROXY_URL" ] && CURL_PROXY_ARG=(-x "$PROXY_URL")

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
    RESOLVERS=("System|SYS|" "Cloudflare|DoH|https://cloudflare-dns.com/dns-query" "Yandex_TCP|TCP|77.88.8.8")
fi

CSV_FILE="worm_results_$(date +%s).csv"

# Определение GEO через прокси (используем ip-api.com, т.к. у ipinfo жестче лимиты на shared IP)
GEO=$(curl -s -m 8 "${CURL_PROXY_ARG[@]}" "http://ip-api.com/json" 2>/dev/null)
MY_IP=$(echo "$GEO" | grep -m1 '"query"' | cut -d'"' -f4)
MY_ORG=$(echo "$GEO" | grep -m1 '"as"' | cut -d'"' -f4 | sed 's/[",;]//g')
MY_CITY=$(echo "$GEO" | grep -m1 '"city"' | cut -d'"' -f4)
MY_COUNTRY=$(echo "$GEO" | grep -m1 '"countryCode"' | cut -d'"' -f4)
[ -z "$MY_IP" ] && MY_IP="Unknown" && MY_ORG="Unknown ISP" && MY_CITY="Unknown" && MY_COUNTRY="Region"
MY_REG="${MY_CITY} ${MY_COUNTRY}"

echo '"REGION";"ISP";"ENDPOINT";"RESOLVER";"IP";"STATUS";"DNS, сек.";"Ожидание ответа, сек.";"Общее время, сек.";"BLOCKED"' > "$CSV_FILE"

printf "\n====================================================================================================\n"
printf " 📡 WORM PROBE: LLM API CENSORSHIP & DNS TEST\n"
printf " 🌍 Region: %s | ISP: %s | IP: %s\n" "$MY_REG" "$MY_ORG" "$MY_IP"
printf "====================================================================================================\n"
printf "%-28s | %-12s | %-15s | %-4s | %-21s | %s\n" "API ENDPOINT" "RESOLVER" "IP" "STAT" "DNS / RSP / TOT (sec)" "BLOCKED?"
printf -- "----------------------------------------------------------------------------------------------------\n"

# Вспомогательная функция для DNS-over-TCP через SOCKS5 (Python)
resolve_dns_tcp() {
    local dns_server="$1"
    local domain="$2"
    python3 - "$PROXY_URL" "$dns_server" "$domain" << 'EOF'
import sys, socket, struct, random
from urllib.parse import urlparse

proxy_url, dns_ip, domain = sys.argv[1], sys.argv[2], sys.argv[3]

def build_dns_query(dom):
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in dom.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1) # Type A, Class IN
    payload = header + question
    return struct.pack(">H", len(payload)) + payload

try:
    if proxy_url:
        import socks
        u = urlparse(proxy_url)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, u.hostname, u.port, True, u.username, u.password)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((dns_ip, 53))
    s.sendall(build_dns_query(domain))
    resp_len_bytes = s.recv(2)
    if len(resp_len_bytes) < 2: sys.exit(1)
    resp_len = struct.unpack(">H", resp_len_bytes)[0]
    data = b""
    while len(data) < resp_len:
        chunk = s.recv(resp_len - len(data))
        if not chunk: break
        data += chunk
    s.close()
    # Простой парсинг последнего A-записи (Type 1, Class 1, len 4)
    idx = 12
    while data[idx] != 0: idx += data[idx] + 1
    idx += 5
    ancount = struct.unpack(">H", data[6:8])[0]
    for _ in range(ancount):
        if (data[idx] & 0xC0) == 0xC0: idx += 2
        else:
            while data[idx] != 0: idx += data[idx] + 1
            idx += 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[idx:idx+10])
        idx += 10
        if rtype == 1 and rdlen == 4:
            print(".".join(map(str, data[idx:idx+4])))
            sys.exit(0)
        idx += rdlen
except Exception:
    pass
EOF
}

for u in "${ENDPOINTS[@]}"; do
  d=$(echo "$u" | awk -F/ '{print $3}')
  for r in "${RESOLVERS[@]}"; do
    rn=$(echo "$r" | cut -d'|' -f1); rt=$(echo "$r" | cut -d'|' -f2); ra=$(echo "$r" | cut -d'|' -f3)
    
    if [ "$rt" = "SYS" ]; then
        res=$(curl -s "${CURL_PROXY_ARG[@]}" -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u")
    elif [ "$rt" = "DoH" ]; then
        res=$(curl -s "${CURL_PROXY_ARG[@]}" --doh-url "$ra" -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u")
    elif [ "$rt" = "UDP" ] || [ "$rt" = "TCP" ]; then
        # Принудительно используем TCP/53 поверх SOCKS5, т.к. UDP в DataImpulse закрыт
        dip=$(resolve_dns_tcp "$ra" "$d")
        if [ -n "$dip" ]; then
            res=$(curl -s "${CURL_PROXY_ARG[@]}" --resolve "$d:443:$dip" -o /dev/null -w "%{http_code}:%{remote_ip}:%{time_namelookup}:%{time_starttransfer}:%{time_total}" -m 10 "$u")
            # Подменяем remote_ip прокси на реальный отрезолвленный IP целевого сервера
            res=$(echo "$res" | awk -F: -v real_ip="$dip" 'BEGIN{OFS=":"} {$2=real_ip; print}')
        else
            res="000::0:0:0"
        fi
    fi
    
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

# На время локальных тестов отправка в Google Forms отключена
# curl -s --data-urlencode "entry.1081274956@${CSV_FILE}" "https://docs.google.com/forms/d/e/1FAIpQLScbs8FDq1k3GQAAjJM_N2IHgXBvTjKRPcd_AmdvS5Kz2NJQfQ/formResponse" > /dev/null
printf "✅ CSV сохранен: %s/%s\n" "$(pwd)" "$CSV_FILE"