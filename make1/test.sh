#!/bin/bash

# 점검 항목 메뉴 스크립트

# 함수 정의
test_1() {
    echo "CPU 사용률 점검:"
    mpstat | grep 'all' | awk '{print "  User: "$3"%  System: "$5"%  Idle: "$12"%"}'
}

test_2() {
    echo "메모리 사용률 점검:"
    free -m | awk 'NR==2{printf "  Used: %sMB (%.2f%%)\n", $3, $3*100/$2 }'
}

test_3() {
    echo "디스크 사용률 점검:"
    df -h | awk '$NF=="/"{printf "  Used: %dGB (%.2f%%)\n", $3, $5}'
}
srv_001() {
    echo "Checking SNMP Community String settings (srv-001):"

    snmp_service_status=$(netstat -uln | grep ':161 ')
    if [ -z "$snmp_service_status" ]; then
        echo "SNMP service is not running on UDP port 161."
        return
    else
        echo "SNMP service is active on UDP port 161."
    fi

    if [ -f /etc/snmp/snmpd.conf ]; then
        echo "/etc/snmp/snmpd.conf exists."
        community_strings=$(grep -E 'community|com2sec' /etc/snmp/snmpd.conf)
        if [ -z "$community_strings" ]; then
            echo "No SNMP Community Strings found in /etc/snmp/snmpd.conf."
        else
            echo "SNMP Community Strings found:"
            echo "$community_strings"
            insecure_strings=$(echo "$community_strings" | grep -E 'public|private')
            if [ -n "$insecure_strings" ]; then
                echo "Warning: Insecure SNMP Community Strings (public/private) found."
                read -p "Do you want to replace these strings with a secure string? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    read -p "Enter a new secure SNMP Community String: " new_string
                    sed -i.bak -E "s/(public|private)/$new_string/g" /etc/snmp/snmpd.conf
                    echo "Replaced insecure strings with $new_string."
                else
                    echo "Skipped replacing insecure strings."
                fi
            else
                echo "No insecure SNMP Community Strings (public/private) found."
            fi
        fi
    else
        echo "Warning: /etc/snmp/snmpd.conf does not exist."
    fi
}

srv_004() {
    echo "Checking for unnecessary SMTP services (srv-004):"

    smtp_process=$(ps -ef | grep -E 'sendmail|postfix|exim' | grep -v grep)
    if [ -z "$smtp_process" ]; then
        echo "No SMTP service (sendmail, postfix, exim) is running."
        return
    else
        echo "SMTP service is running:"
        echo "$smtp_process"
    fi

    smtp_port=$(netstat -lnt | grep ':25 ')
    if [ -n "$smtp_port" ]; then
        echo "SMTP service is listening on port 25."
        read -p "Do you want to stop the SMTP service? (yes/no): " response
        if [ "$response" == "yes" ]; then
            if [[ "$smtp_process" == *"postfix"* ]]; then
                systemctl stop postfix
                systemctl disable postfix
                echo "Postfix service stopped and disabled."
            elif [[ "$smtp_process" == *"sendmail"* ]]; then
                systemctl stop sendmail
                systemctl disable sendmail
                echo "Sendmail service stopped and disabled."
            elif [[ "$smtp_process" == *"exim"* ]]; then
                systemctl stop exim
                systemctl disable exim
                echo "Exim service stopped and disabled."
            fi
        else
            echo "Skipped stopping the SMTP service."
        fi
    else
        echo "SMTP service is not listening on port 25."
    fi
}

srv_005() {
    echo "Checking Postfix configuration for disable_vrfy_command (srv-005):"

    # Postfix 프로세스 확인
    postfix_process=$(ps -ef | grep postfix | grep -v grep)
    if [ -z "$postfix_process" ]; then
        echo "Postfix service is not running."
        return
    else
        echo "Postfix service is running:"
        echo "$postfix_process"
    fi

    # /etc/postfix/main.cf 파일 확인
    if [ -f /etc/postfix/main.cf ]; then
        echo "/etc/postfix/main.cf exists."
        if grep -q '^disable_vrfy_command = yes' /etc/postfix/main.cf; then
            echo "Postfix is already configured to disable VRFY command."
        else
            echo "Warning: Postfix is not configured to disable VRFY command."
            read -p "Do you want to add 'disable_vrfy_command = yes' to /etc/postfix/main.cf? (yes/no): " response
            if [ "$response" == "yes" ]; then
                echo "disable_vrfy_command = yes" >> /etc/postfix/main.cf
                systemctl restart postfix
                echo "Added 'disable_vrfy_command = yes' and restarted Postfix."
            else
                echo "Skipped configuring Postfix to disable VRFY command."
            fi
        fi
    else
        echo "Warning: /etc/postfix/main.cf does not exist."
    fi
}

srv_007() {
    echo "Checking for vulnerable version of Postfix (srv-007):"

    # Postfix 프로세스 확인
    postfix_process=$(ps -ef | grep postfix | grep -v grep)
    if [ -z "$postfix_process" ]; then
        echo "Postfix service is not running."
        return
    else
        echo "Postfix service is running:"
        echo "$postfix_process"
    fi

    # Postfix 버전 확인
    postfix_version=$(postconf mail_version | awk '{print $3}')
    echo "Postfix version: $postfix_version"

    # 취약한 버전 확인
    vulnerable_version="2.10.1"
    if [ "$postfix_version" == "$vulnerable_version" ]; then
        echo "Warning: You are using a vulnerable version of Postfix ($postfix_version)."
        echo "It is recommended to upgrade to a newer version."

        read -p "Do you want to upgrade Postfix now? (yes/no): " response
        if [ "$response" == "yes" ]; then
            # 업그레이드 명령어 (예: yum 사용)
            echo "Upgrading Postfix..."
            echo "YUM 을 사용할 수 없습니다"
            # yum update postfix -y
            # echo "Postfix upgraded. Please check the version again."
        else
            echo "Skipped upgrading Postfix."
        fi
    else
        echo "Postfix version is not vulnerable."
    fi
}


srv_010() {
    echo "Checking Postfix mail queue processing permissions (srv-010):"

    # Postfix 프로세스 확인
    postfix_process=$(ps -ef | grep postfix | grep -v grep)
    if [ -z "$postfix_process" ]; then
        echo "Postfix service is not running."
        return
    else
        echo "Postfix service is running:"
        echo "$postfix_process"
    fi

    # postsuper 파일 권한 확인
    postsuper_path="/usr/sbin/postsuper"
    if [ -f "$postsuper_path" ]; then
        echo "$postsuper_path exists."
        ls -l $postsuper_path
        postsuper_permissions=$(stat -c %A $postsuper_path)
        if [[ "$postsuper_permissions" == *x ]]; then
            echo "Warning: $postsuper_path has execute permission for others."
            read -p "Do you want to remove the execute permission for others? (yes/no): " response
            if [ "$response" == "yes" ]; then
                chmod o-x $postsuper_path
                echo "Removed execute permission for others on $postsuper_path."
            else
                echo "Skipped changing permissions for $postsuper_path."
            fi
        else
            echo "$postsuper_path permissions are correct."
        fi
    else
        echo "Warning: $postsuper_path does not exist."
    fi
}

srv_026() {
    echo "Checking root remote login restriction (srv-026):"

    sshd_config_file="/etc/ssh/sshd_config"
    alt_sshd_config_file="/opt/ssh/etc/sshd_config"

    check_sshd_config() {
        config_file=$1
        if [ -f $config_file ]; then
            echo "$config_file exists."
            if grep -q '^#PermitRootLogin' $config_file; then
                echo "Warning: PermitRootLogin option is commented out in $config_file."
                read -p "Do you want to set 'PermitRootLogin no' in $config_file? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    sed -i.bak '/^#PermitRootLogin/ s/#PermitRootLogin.*/PermitRootLogin no/' $config_file
                    systemctl restart sshd
                    echo "Set 'PermitRootLogin no' in $config_file and restarted SSH service."
                else
                    echo "Skipped setting 'PermitRootLogin no' in $config_file."
                fi
            elif grep -q '^PermitRootLogin yes' $config_file; then
                echo "Warning: PermitRootLogin is set to yes in $config_file."
                read -p "Do you want to change it to 'PermitRootLogin no'? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    sed -i.bak '/^PermitRootLogin yes/ s/PermitRootLogin yes/PermitRootLogin no/' $config_file
                    systemctl restart sshd
                    echo "Changed 'PermitRootLogin yes' to 'PermitRootLogin no' in $config_file and restarted SSH service."
                else
                    echo "Skipped changing 'PermitRootLogin yes' to 'PermitRootLogin no' in $config_file."
                fi
            else
                echo "PermitRootLogin is properly set in $config_file."
            fi
        else
            echo "Warning: $config_file does not exist."
        fi
    }

}
srv_063() {
    echo "Checking DNS recursive query settings (srv-063):"

    named_config_file="/etc/named.conf"

    # DNS 프로세스 확인
    named_process=$(ps -ef | grep named | grep -v grep)
    if [ -z "$named_process" ]; then
        echo "DNS service is not running."
        return
    else
        echo "DNS service is running:"
        echo "$named_process"
    fi

    # /etc/named.conf 파일 확인
    if [ -f $named_config_file ]; then
        echo "$named_config_file exists."
        if grep -q 'recursion yes' $named_config_file; then
            echo "Warning: DNS is configured to allow recursive queries."
            read -p "Do you want to set 'recursion no' in $named_config_file? (yes/no): " response
            if [ "$response" == "yes" ]; then
                sed -i.bak '/recursion yes/ s/recursion yes/recursion no/' $named_config_file
                systemctl restart named
                echo "Set 'recursion no' in $named_config_file and restarted DNS service."
            else
                echo "Skipped setting 'recursion no' in $named_config_file."
            fi
        else
            echo "DNS is not configured to allow recursive queries."
        fi
    else
        echo "Warning: $named_config_file does not exist."
    fi
}
srv_064() {
    echo "Checking for vulnerable version of DNS service (srv-064):"

    # BIND 버전 확인
    bind_version=$(named -v 2>/dev/null | awk '{print $2}')
    if [ -z "$bind_version" ]; then
        echo "BIND service is not running or not installed."
        return
    else
        echo "BIND version: $bind_version"
    fi

    # 취약한 버전 확인
    vulnerable_versions=("9.11.4-P2")
    secure_versions=("9.11.22" "9.16.6" "9.17.4")

    for v in "${vulnerable_versions[@]}"; do
        if [[ "$bind_version" == *"$v"* ]]; then
            echo "Warning: You are using a vulnerable version of BIND ($bind_version)."
            echo "It is recommended to upgrade to one of the following versions: ${secure_versions[*]}"

            read -p "Do you want to upgrade BIND now? (yes/no): " response
            if [ "$response" == "yes" ]; then
                # 업그레이드 명령어 (예: yum 사용)
                echo "Upgrading BIND..."
                yum update bind -y
                echo "BIND upgraded. Please check the version again."
            else
                echo "Skipped upgrading BIND."
            fi
            return
        fi
    done

    echo "BIND version is not vulnerable."
}
srv_066() {
    echo "Checking DNS zone transfer settings (srv-066):"

    named_config_file="/etc/named.conf"
    rfc1912_zones_file="/etc/named.rfc1912.zones"
    named_boot_file="/etc/named.boot"

    # DNS 프로세스 확인
    named_process=$(ps -ef | grep named | grep -v grep)
    if [ -z "$named_process" ]; then
        echo "DNS service is not running."
        return
    else
        echo "DNS service is running:"
        echo "$named_process"
    fi

    # /etc/named.conf 파일의 allow-transfer 설정 확인
    if [ -f $named_config_file ]; then
        echo "$named_config_file exists."
        if ! grep -q 'allow-transfer' $named_config_file; then
            echo "Warning: allow-transfer setting is not found in $named_config_file."
            read -p "Do you want to add 'allow-transfer { none; };' to $named_config_file? (yes/no): " response
            if [ "$response" == "yes" ]; then
                sed -i.bak '/options {/a\        allow-transfer { none; };' $named_config_file
                systemctl restart named
                echo "Added 'allow-transfer { none; };' to $named_config_file and restarted DNS service."
            else
                echo "Skipped adding 'allow-transfer { none; };' to $named_config_file."
            fi
        else
            echo "allow-transfer setting is found in $named_config_file."
        fi
    else
        echo "Warning: $named_config_file does not exist."
    fi

    # /etc/named.rfc1912.zones 파일의 allow-transfer 설정 확인
    if [ -f $rfc1912_zones_file ]; then
        echo "$rfc1912_zones_file exists."
        if ! grep -q 'allow-transfer' $rfc1912_zones_file; then
            echo "Warning: allow-transfer setting is not found in $rfc1912_zones_file."
            read -p "Do you want to add 'allow-transfer { none; };' to $rfc1912_zones_file? (yes/no): " response
            if [ "$response" == "yes" ]; then
                echo "allow-transfer { none; };" >> $rfc1912_zones_file
                systemctl restart named
                echo "Added 'allow-transfer { none; };' to $rfc1912_zones_file and restarted DNS service."
            else
                echo "Skipped adding 'allow-transfer { none; };' to $rfc1912_zones_file."
            fi
        else
            echo "allow-transfer setting is found in $rfc1912_zones_file."
        fi
    else
        echo "Warning: $rfc1912_zones_file does not exist."
    fi

    # /etc/named.boot 파일의 xfrnets 설정 확인
    if [ -f $named_boot_file ]; then
        echo "$named_boot_file exists."
        if ! grep -q 'xfrnets' $named_boot_file; then
            echo "Warning: xfrnets setting is not found in $named_boot_file."
            read -p "Do you want to add 'xfrnets 0.0.0.0/0;' to $named_boot_file? (yes/no): " response
            if [ "$response" == "yes" ]; then
                echo "xfrnets 0.0.0.0/0;" >> $named_boot_file
                systemctl restart named
                echo "Added 'xfrnets 0.0.0.0/0;' to $named_boot_file and restarted DNS service."
            else
                echo "Skipped adding 'xfrnets 0.0.0.0/0;' to $named_boot_file."
            fi
        else
            echo "xfrnets setting is found in $named_boot_file."
        fi
    else
        echo "Warning: $named_boot_file does not exist."
    fi
}

srv_081() {
    echo "Checking cron and at file permissions (srv-081):"

    check_permission() {
        file=$1
        expected_permission=$2
        description=$3

        if [ -f $file ]; then
            echo "$file exists."
            ls -l $file
            actual_permission=$(stat -c %a $file)
            if [ "$actual_permission" -lt "$expected_permission" ]; then
                echo "  Warning: $file permissions are less than $expected_permission (current: $actual_permission)."
                echo "  $description"
                read -p "Do you want to set the correct permissions to $expected_permission? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    chmod $expected_permission $file
                    echo "  $file permissions set to $expected_permission."
                else
                    echo "  Skipped setting permissions for $file."
                fi
            else
                echo "  $file permissions are correct."
            fi
        else
            echo "Warning: $file does not exist."
        fi
    }

    check_directory_permission() {
        dir=$1
        expected_permission=$2

        if [ -d $dir ]; then
            echo "$dir exists."
            ls -ld $dir
            actual_permission=$(stat -c %a $dir)
            if [ "$actual_permission" != "$expected_permission" ]; then
                echo "  Warning: $dir permissions are not $expected_permission (current: $actual_permission)."
                read -p "Do you want to set the correct permissions? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    chmod $expected_permission $dir
                    echo "  $dir permissions set to $expected_permission."
                else
                    echo "  Skipped setting permissions for $dir."
                fi
            else
                echo "  $dir permissions are correct."
            fi
        else
            echo "Warning: $dir does not exist."
        fi
    }

    check_permission "/etc/cron.allow" "600" "Root only access for cron.allow file."
    check_permission "/etc/cron.deny" "600" "Root only access for cron.deny file."
    check_directory_permission "/var/spool/cron" "700"
    check_permission "/etc/at/deny" "640" "Set permissions for at.deny file to 640."
}

srv_087() {
    echo "Checking C compiler permissions (srv-087):"

    check_compiler_permission() {
        compiler=$1
        if command -v $compiler &> /dev/null; then
            compiler_path=$(command -v $compiler)
            echo "$compiler found at $compiler_path."
            ls -l $compiler_path
            if [ "$(stat -c %A $compiler_path | cut -c 10)" == "x" ]; then
                echo "  Warning: $compiler_path has execute permission for others."
                read -p "Do you want to remove the execute permission for others? (yes/no): " response
                if [ "$response" == "yes" ]; then
                    chmod o-x $compiler_path
                    echo "  Removed execute permission for others on $compiler_path."
                else
                    echo "  Skipped changing permissions for $compiler_path."
                fi
            else
                echo "  $compiler_path permissions are correct."
            fi
        else
            echo "Warning: $compiler not found."
        fi
    }

    check_compiler_permission "gcc"
    check_compiler_permission "cc"
}
srv_092() {
    echo "Checking user home directory settings (srv-092):"

    # 사용자 목록 가져오기
    users=$(awk -F: '$7 != "/sbin/nologin" && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" {print $1":"$6":"$7}' /etc/passwd)

    for user_info in $users; do
        IFS=':' read -r username homedir shell <<< "$user_info"
        
        # 홈 디렉터리 존재 여부 확인
        if [ ! -d "$homedir" ]; then
            echo "Warning: Home directory for user $username does not exist."
            read -p "Do you want to create the home directory $homedir for user $username? (yes/no): " response
            if [ "$response" == "yes" ]; then
                mkdir -p "$homedir"
                chown "$username":"$username" "$homedir"
                chmod 700 "$homedir"
                echo "Created home directory $homedir for user $username."
            else
                echo "Skipped creating home directory $homedir for user $username."
            fi
        else
            echo "Home directory for user $username exists."
        fi

        # 홈 디렉터리 소유자 확인
        owner=$(stat -c '%U' "$homedir")
        if [ "$owner" != "$username" ]; then
            echo "Warning: Owner of home directory $homedir is not $username."
            read -p "Do you want to change the owner of $homedir to $username? (yes/no): " response
            if [ "$response" == "yes" ]; then
                chown "$username":"$username" "$homedir"
                echo "Changed owner of home directory $homedir to $username."
            else
                echo "Skipped changing owner of home directory $homedir."
            fi
        else
            echo "Owner of home directory $homedir is correct."
        fi

        # others 쓰기 권한 확인
        permissions=$(stat -c '%A' "$homedir")
        if [[ "$permissions" == *"w"* ]]; then
            echo "Warning: Home directory $homedir has write permission for others."
            read -p "Do you want to remove write permission for others from $homedir? (yes/no): " response
            if [ "$response" == "yes" ]; then
                chmod o-w "$homedir"
                echo "Removed write permission for others from $homedir."
            else
                echo "Skipped removing write permission for others from $homedir."
            fi
        else
            echo "Home directory $homedir does not have write permission for others."
        fi
    done
}

srv_095() {
    echo "Checking for files with non-existent owners and groups (srv-095):"

    # 존재하지 않는 사용자 및 그룹을 가진 파일 찾기
    find / -xdev \( -nouser -o -nogroup \) -print > /tmp/non_existent_owners.txt

    if [ ! -s /tmp/non_existent_owners.txt ]; then
        echo "No files with non-existent owners or groups found."
        rm /tmp/non_existent_owners.txt
        return
    fi

    echo "Files with non-existent owners or groups:"
    head -n 10 /tmp/non_existent_owners.txt
    echo "..."
    echo "Full list is saved in /tmp/non_existent_owners.txt."

    read -p "Do you want to change the owner of these files to a valid user? (yes/no): " response
    if [ "$response" == "yes" ]; then
        read -p "Enter the username to set as the new owner: " new_owner
        if id -u "$new_owner" >/dev/null 2>&1; then
            while IFS= read -r file; do
                chown "$new_owner":"$new_owner" "$file"
                echo "Changed owner of $file to $new_owner."
            done < /tmp/non_existent_owners.txt
        else
            echo "User $new_owner does not exist."
        fi
    else
        echo "Skipped changing the owner of files."
    fi

    rm /tmp/non_existent_owners.txt
}


srv_096() {
    echo "Checking user environment file permissions (srv-096):"

    check_user_env_permission() {
        user=$1
        env_files=(".profile" ".bashrc" ".bash_profile" ".kshrc" ".cshrc" ".login" ".exrc" ".netrc")

        for file in "${env_files[@]}"; do
            user_file="/home/$user/$file"
            if [ -f $user_file ]; then
                echo "$user_file exists."
                ls -l $user_file
                if [ "$(stat -c %A $user_file | cut -c 10)" != "-" ]; then
                    echo "  Warning: $user_file has permissions for others."
                    read -p "Do you want to remove the permissions for others? (yes/no): " response
                    if [ "$response" == "yes" ]; then
                        chmod o-rwx $user_file
                        echo "  Removed permissions for others on $user_file."
                    else
                        echo "  Skipped changing permissions for $user_file."
                    fi
                else
                    echo "  $user_file permissions are correct."
                fi
            else
                echo "Warning: $user_file does not exist."
            fi
        done
    }

    for user in $(cut -f1 -d: /etc/passwd); do
        check_user_env_permission $user
    done
}


srv_133() {
    echo "Checking cron service account restrictions (srv-133):"

    if [ -f /etc/cron.allow ]; then
        echo "/etc/cron.allow exists."
        ls -l /etc/cron.allow
    else
        echo "Warning: /etc/cron.allow does not exist."
        echo "  This means all users can access cron, which is a security risk."
        read -p "Do you want to create /etc/cron.allow and restrict access? (yes/no): " response
        if [ "$response" == "yes" ]; then
            touch /etc/cron.allow
            chmod 600 /etc/cron.allow
            echo "  /etc/cron.allow created and permissions set to 600."
            echo "  Add allowed users to /etc/cron.allow."
        else
            echo "  Skipped creating /etc/cron.allow."
        fi
    fi
}
srv_163() {
    echo "Checking system usage warning banner settings (srv-163):"

    sshd_config_file="/etc/ssh/sshd_config"
    issue_net_file="/etc/issue.net"
    issue_file="/etc/issue"
    motd_file="/etc/motd"

    # SSH 배너 설정 확인
    if [ -f $sshd_config_file ]; then
        echo "$sshd_config_file exists."
        if ! grep -q '^Banner' $sshd_config_file; then
            echo "Warning: SSH banner is not set in $sshd_config_file."
            read -p "Do you want to set the SSH banner? (yes/no): " response
            if [ "$response" == "yes" ]; then
                echo "Banner /etc/issue.net" >> $sshd_config_file
                systemctl restart sshd
                echo "Set 'Banner /etc/issue.net' in $sshd_config_file and restarted SSH service."
            else
                echo "Skipped setting SSH banner."
            fi
        else
            echo "SSH banner is already set in $sshd_config_file."
        fi
    else
        echo "Warning: $sshd_config_file does not exist."
    fi

    # /etc/issue.net 파일 설정 확인
    if [ ! -f $issue_net_file ]; then
        echo "Warning: $issue_net_file does not exist."
        read -p "Do you want to create /etc/issue.net with a default warning message? (yes/no): " response
        if [ "$response" == "yes" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > $issue_net_file
            echo "Created $issue_net_file with a default warning message."
        else
            echo "Skipped creating $issue_net_file."
        fi
    else
        echo "$issue_net_file exists."
    fi

    # /etc/issue 파일 설정 확인
    if [ ! -f $issue_file ]; then
        echo "Warning: $issue_file does not exist."
        read -p "Do you want to create /etc/issue with a default warning message? (yes/no): " response
        if [ "$response" == "yes" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > $issue_file
            echo "Created $issue_file with a default warning message."
        else
            echo "Skipped creating $issue_file."
        fi
    else
        echo "$issue_file exists."
    fi

    # /etc/motd 파일 설정 확인
    if [ ! -f $motd_file ]; then
        echo "Warning: $motd_file does not exist."
        read -p "Do you want to create /etc/motd with a default warning message? (yes/no): " response
        if [ "$response" == "yes" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > $motd_file
            echo "Created $motd_file with a default warning message."
        else
            echo "Skipped creating $motd_file."
        fi
    else
        echo "$motd_file exists."
    fi
}

#!/bin/bash

# 메뉴 출력
echo "점검 항목을 선택하세요:"
echo "1001. CPU 사용률 점검"
echo "1002. 메모리 사용률 점검"
echo "1003. 디스크 사용률 점검"
echo "1. srv-001 점검 (SNMP Community String 설정 확인)"
echo "4. srv-004 점검 (불필요한 SMTP 서비스 실행)"
echo "5. srv-005 점검 (SMTP 서비스의 expn/vrfy 명령어 실행 제한 미비)"
echo "7. srv-007 점검 (취약한 버전의 SMTP 서비스 사용)"
echo "10. srv-010 점검 (SMTP 서비스의 메일 queue 처리 권한 설정 미흡)"
echo "26. srv-026 점검 (root 계정 원격 접속 제한 미비)"
echo "63. srv-063 점검 (DNS Recursive Query 설정 미흡)"
echo "64. srv-064 점검 (취약한 버전의 DNS 서비스 사용)"
echo "66. srv-066 점검 (DNS Zone Transfer 설정 미흡)"
echo "81. srv-081 점검 (cron 파일 권한 확인)"
echo "87. srv-087 점검 (C 컴파일러 권한 확인)"
echo "92. srv-92 점검 (사용자 홈 디렉터리 설정 미흡)"
echo "95. srv-95 점검 (존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 존재)"
echo "96. srv-096 점검 (사용자 환경파일 권한 확인)"
echo "133. srv-133 점검 (Cron 서비스 계정 제한)"
echo "163. srv-163 점검 (시스템 사용 주의사항 미출력)"

# 사용자 입력 받기
read -p "선택: " choice

# 선택에 따라 함수 실행
case $choice in
    1001)
        test_1
        ;;
    1002)
        test_2
        ;;
    1003)
        test_3
        ;;
    1)
        srv_001
        ;;
    4)
        srv_004
        ;;
    5)
        srv_005
        ;;
    7)
        srv_007
        ;;
    10)
        srv_010
        ;;
    26)
        srv_026
        ;;
    63)
        srv_063
        ;;
    64)
        srv_064
        ;;
    66)
        srv_066
        ;;
    81)
        srv_081
        ;;
    87)
        srv_087
        ;;
    92)
        srv_092
        ;;
    95)
        srv_095
        ;;
    96)
        srv_096
        ;;
    133)
        srv_133
        ;;
    163)
        srv_163
        ;;
    *)
        echo "잘못된 선택입니다."
        ;;
esac

echo "점검 완료"

