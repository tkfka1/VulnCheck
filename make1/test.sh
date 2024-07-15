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

# 메뉴 출력
echo "점검 항목을 선택하세요:"
echo "1001. CPU 사용률 점검"
echo "1002. 메모리 사용률 점검"
echo "1003. 디스크 사용률 점검"
echo "1. srv-001 점검 (SNMP Community String 설정 확인)"
echo "81. srv-081 점검 (cron 파일 권한 확인)"
echo "87. srv-087 점검 (C 컴파일러 권한 확인)"
echo "96. srv-096 점검 (사용자 환경파일 권한 확인)"
echo "133. srv-133 점검 (Cron 서비스 계정 제한)"

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
    81)
        srv_081
        ;;
    87)
        srv_087
        ;;
    96)
        srv_096
        ;;
    *)
        echo "잘못된 선택입니다."
        ;;
esac

echo "점검 완료"
