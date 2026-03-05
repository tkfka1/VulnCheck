
#!/bin/bash

# ==========================================
# 1. 로그 및 환경 설정
# ==========================================
LOG_FILE="vuln_fix_$(date +%Y%m%d_%H%M%S).log"

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

log_header() {
    echo -e "\n=========================================" >> "$LOG_FILE"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 항목 실행: $1" >> "$LOG_FILE"
    echo -e "=========================================" >> "$LOG_FILE"
}

log_change() {
    local label=$1
    local before=$2
    local after=$3
    echo -e "  * $label" >> "$LOG_FILE"
    echo -e "    - [변경 전]: $before" >> "$LOG_FILE"
    echo -e "    - [변경 후]: $after" >> "$LOG_FILE"
}

# 상태 확인용 헬퍼 함수
get_perm() { stat -c "%a (%U:%G)" "$1" 2>/dev/null || echo "파일없음"; }
get_line() { grep -E "$2" "$1" 2>/dev/null | head -n 1 || echo "설정없음"; }

# ==========================================
# 2. 리소스 점검 함수
# ==========================================
test_1() {
    log_info "CPU 사용률 점검:"
    if command -v mpstat &> /dev/null; then
        mpstat | grep 'all' | awk '{print "  User: "$3"%  System: "$5"%  Idle: "$12"%"}' | tee -a "$LOG_FILE"
    else
        log_info "  mpstat 미설치 (dnf install sysstat 필요)"
    fi
}

test_2() {
    log_info "메모리 사용률 점검:"
    free -m | awk 'NR==2{printf "  Used: %sMB (%.2f%%)\n", $3, $3*100/$2 }' | tee -a "$LOG_FILE"
}

test_3() {
    log_info "디스크 사용률 점검:"
    df -h | awk '$NF=="/"{printf "  Used: %dGB (%.2f%%)\n", $3, $5}' | tee -a "$LOG_FILE"
}

# ==========================================
# 3. 서비스 취약점 점검 (SRV 시리즈)
# ==========================================

srv_001() {
    log_header "srv-001 (SNMP Community String)"
    local conf="/etc/snmp/snmpd.conf"
    if [ -f "$conf" ]; then
        local before=$(get_line "$conf" "community|com2sec")
        if echo "$before" | grep -Eq 'public|private'; then
            read -p "취약한 SNMP 문자열 발견. 변경할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                read -p "신규 문자열: " new_s
                sed -i.bak -E "s/(public|private)/$new_s/g" "$conf"
                systemctl restart snmpd 2>/dev/null
                log_change "SNMP 설정" "$before" "$(get_line "$conf" "community|com2sec")"
            fi
        fi
    else log_info "SNMP 설정 파일 없음."; fi
}

srv_004() {
    log_header "srv-004 (SMTP 서비스 비활성화)"
    for svc in postfix sendmail exim; do
        if systemctl is-active --quiet "$svc"; then
            read -p "$svc 실행 중. 중지할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                systemctl stop "$svc" && systemctl disable "$svc"
                log_change "$svc 서비스" "Active" "Inactive/Disabled"
            fi
        fi
    done
}

srv_005() {
    log_header "srv-005 (SMTP VRFY 제한)"
    local conf="/etc/postfix/main.cf"
    if [ -f "$conf" ]; then
        local before=$(get_line "$conf" "disable_vrfy_command")
        if [[ "$before" != *"yes"* ]]; then
            read -p "VRFY 명령어를 제한할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                echo "disable_vrfy_command = yes" >> "$conf"
                systemctl restart postfix
                log_change "VRFY 설정" "$before" "disable_vrfy_command = yes"
            fi
        fi
    fi
}

srv_007() {
    log_header "srv-007 (Postfix 취약 버전)"
    if command -v postconf &>/dev/null; then
        local ver=$(postconf mail_version | awk '{print $3}')
        log_info "현재 Postfix 버전: $ver"
        if [ "$ver" == "2.10.1" ]; then
            read -p "취약 버전입니다. 업데이트할까요? (yes/no): " res
            [ "$res" == "yes" ] && dnf update postfix -y && log_change "Postfix 버전" "$ver" "Updated"
        fi
    fi
}

srv_010() {
    log_header "srv-010 (Postsuper 권한)"
    local target="/usr/sbin/postsuper"
    if [ -f "$target" ]; then
        local before=$(get_perm "$target")
        if [[ "$before" == *x ]]; then
            read -p "기타 사용자 실행 권한을 제거할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                chmod o-x "$target"
                log_change "Postsuper 권한" "$before" "$(get_perm "$target")"
            fi
        fi
    fi
}

srv_026() {
    log_header "srv-026 (Root SSH 제한)"
    local conf="/etc/ssh/sshd_config"
    local before=$(get_line "$conf" "^PermitRootLogin")
    if [[ "$before" == *"yes"* ]] || [[ "$before" == "설정없음" ]]; then
        read -p "Root 접속을 차단(no)할까요? (yes/no): " res
        if [ "$res" == "yes" ]; then
            sed -i.bak -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$conf"
            systemctl restart sshd
            log_change "SSH Root 접속" "$before" "$(get_line "$conf" "^PermitRootLogin")"
        fi
    fi
}

srv_063() {
    log_header "srv-063 (DNS Recursion)"
    local conf="/etc/named.conf"
    if [ -f "$conf" ]; then
        local before=$(get_line "$conf" "recursion")
        if [[ "$before" == *"yes"* ]]; then
            read -p "DNS 재귀 쿼리를 차단할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                sed -i.bak 's/recursion yes/recursion no/' "$conf"
                systemctl restart named
                log_change "DNS Recursion" "$before" "recursion no"
            fi
        fi
    fi
}

srv_064() {
    log_header "srv-064 (DNS 취약 버전)"
    if command -v named &>/dev/null; then
        local ver=$(named -v | awk '{print $2}')
        log_info "BIND 버전: $ver"
        if [[ "$ver" == *"9.11.4-P2"* ]]; then
            read -p "취약 버전 업데이트할까요? (yes/no): " res
            [ "$res" == "yes" ] && dnf update bind -y && log_change "BIND 버전" "$ver" "Updated"
        fi
    fi
}

srv_066() {
    log_header "srv-066 (DNS Zone Transfer)"
    local conf="/etc/named.conf"
    if [ -f "$conf" ] && ! grep -q "allow-transfer" "$conf"; then
        read -p "Zone Transfer를 제한(none)할까요? (yes/no): " res
        if [ "$res" == "yes" ]; then
            sed -i.bak '/options {/a \        allow-transfer { none; };' "$conf"
            systemctl restart named
            log_change "Zone Transfer" "설정없음" "allow-transfer { none; };"
        fi
    fi
}

srv_081() {
    log_header "srv-081 (Cron 권한 설정)"
    local files=("/etc/cron.allow" "/etc/cron.deny" "/var/spool/cron")
    for f in "${files[@]}"; do
        if [ -e "$f" ]; then
            local b=$(get_perm "$f")
            local target="600"
            [ -d "$f" ] && target="700"
            read -p "$f 권한을 $target으로 변경할까요? (yes/no): " res
            if [ "$res" == "yes" ]; then
                chmod "$target" "$f"
                log_change "$f 권한" "$b" "$(get_perm "$f")"
            fi
        fi
    done
}

srv_087() {
    log_header "srv-087 (C 컴파일러 제한)"
    for comp in gcc cc; do
        local path=$(command -v $comp)
        if [ -n "$path" ]; then
            local b=$(get_perm "$path")
            if [ "${b:2:1}" != "0" ]; then
                read -p "$comp 실행 권한을 일반인에게서 뺏을까요? (yes/no): " res
                if [ "$res" == "yes" ]; then
                    chmod o-x "$path"
                    log_change "$comp 권한" "$b" "$(get_perm "$path")"
                fi
            fi
        fi
    done
}

srv_092() {
    log_header "srv-092 (사용자 홈 디렉터리)"
    users=$(awk -F: '$7 !~ /nologin|false/ {print $1":"$6}' /etc/passwd)
    for u in $users; do
        IFS=':' read -r user home <<< "$u"
        if [ ! -d "$home" ]; then
            read -p "$user 홈 디렉터리 생성할까요? (yes/no): " res
            [ "$res" == "yes" ] && mkdir -p "$home" && chown "$user:$user" "$home" && chmod 700 "$home" && log_change "$user 홈 생성" "없음" "700"
        fi
    done
}

srv_095() {
    log_header "srv-095 (소유자 없는 파일)"
    find / -xdev \( -nouser -o -nogroup \) -print > /tmp/no_owner.txt 2>/dev/null
    if [ -s /tmp/no_owner.txt ]; then
        read -p "유령 파일 발견. 소유권 이전할까요? (yes/no): " res
        if [ "$res" == "yes" ]; then
            read -p "관리자 계정명: " admin
            while read -r f; do
                local b=$(get_perm "$f")
                chown "$admin:$admin" "$f" 2>/dev/null
                log_change "소유권 변경: $f" "$b" "$(get_perm "$f")"
            done < /tmp/no_owner.txt
        fi
    fi
}

srv_096() {
    log_header "srv-096 (환경설정 파일 권한)"
    local envs=(".profile" ".bashrc" ".bash_profile" ".kshrc" ".cshrc")
    for u in $(cut -d: -f1 /etc/passwd); do
        local home=$(getent passwd "$u" | cut -d: -f6)
        for e in "${envs[@]}"; do
            local target="$home/$e"
            if [ -f "$target" ]; then
                local b=$(get_perm "$target")
                if [ "$(stat -c %a "$target" | cut -c 3)" != "0" ]; then
                    read -p "$target 타인 권한 제거할까요? (yes/no): " res
                    if [ "$res" == "yes" ]; then
                        chmod o-rwx "$target"
                        log_change "환경파일 수정: $target" "$b" "$(get_perm "$target")"
                    fi
                fi
            fi
        done
    done
}

srv_133() {
    log_header "srv-133 (Cron 계정 제한)"
    if [ ! -f /etc/cron.allow ]; then
        read -p "cron.allow 파일을 생성할까요? (yes/no): " res
        if [ "$res" == "yes" ]; then
            touch /etc/cron.allow && chmod 600 /etc/cron.allow && echo "root" > /etc/cron.allow
            log_change "Cron 제한" "없음" "600 (root only)"
        fi
    fi
}

srv_163() {
    log_header "srv-163 (경고 배너)"
    local ssh_c="/etc/ssh/sshd_config"
    if ! grep -q "^Banner" "$ssh_c"; then
        read -p "접속 배너를 설정할까요? (yes/no): " res
        if [ "$res" == "yes" ]; then
            echo "Authorized users only." > /etc/issue.net
            echo "Banner /etc/issue.net" >> "$ssh_c"
            systemctl restart sshd
            log_change "배너 설정" "없음" "Banner /etc/issue.net"
        fi
    fi
}

# ==========================================
# 4. 메뉴 인터페이스
# ==========================================
while true; do
    echo -e "\n========================================="
    echo "  AL2023 취약점 점검 & 조치 (Full Log Mode)"
    echo "  로그: $LOG_FILE"
    echo "========================================="
    echo " 1001-3. 리소스 점검 (CPU/MEM/DISK)"
    echo " 1. srv-001 (SNMP)     4. srv-004 (SMTP)"
    echo " 5. srv-005 (VRFY)     7. srv-007 (SMTP ver)"
    echo " 10. srv-010 (Queue)   26. srv-026 (Root SSH)"
    echo " 63. srv-063 (DNS rec) 64. srv-064 (DNS ver)"
    echo " 66. srv-066 (DNS zone) 81. srv-081 (Cron perm)"
    echo " 87. srv-087 (Compiler) 92. srv-092 (Home dir)"
    echo " 95. srv-095 (Ghost)   96. srv-096 (Env perm)"
    echo " 133. srv-133 (Cron limit) 163. srv-163 (Banner)"
    echo " 99. [전체 항목 순차 실행]"
    echo " 0. 종료"
    echo "========================================="
    read -p "선택: " choice

    case $choice in
        1001) test_1 ;; 1002) test_2 ;; 1003) test_3 ;;
        1) srv_001 ;; 4) srv_004 ;; 5) srv_005 ;; 7) srv_007 ;; 10) srv_010 ;;
        26) srv_026 ;; 63) srv_063 ;; 64) srv_064 ;; 66) srv_066 ;; 81) srv_081 ;;
        87) srv_087 ;; 92) srv_092 ;; 95) srv_095 ;; 96) srv_096 ;; 133) srv_133 ;;
        163) srv_163 ;;
        99)
            test_1; test_2; test_3; srv_001; srv_004; srv_005; srv_007; srv_010;
            srv_026; srv_063; srv_064; srv_066; srv_081; srv_087; srv_092; srv_095;
            srv_096; srv_133; srv_163;
            log_info "전체 점검 완료." ;;
        0) log_info "프로그램 종료."; break ;;
        *) echo "잘못된 선택입니다." ;;
    esac
done
