#!/bin/bash

usageHint() {
    echo "Usage: $ ./runHoneypot.sh <honeypot_name> [option]"
    echo "Option: <--ip=\"\"> <--port=\"\"> <--username=\"\"> <--password=\"\"> <--options=\"\"> <--config=\"\">"
}

# 获取命令行参数
args=("$@")
command="${args[0]}"
exe_command=""

if [[ $command == "-h" || $command == "--help" ]]; then
    usageHint
    exit 0
fi

if [[ $command == "http_server" || $command == "sshserver" || $command == "ftp_server" ]]; then
    exe_command="python3 ./honeypots/$command.py"
    for ((i=1; i<${#args[@]}; i++)); do
        arg="${args[$i]}"

        case $arg in
            --ip=*)
                ip="${arg#*=}"
                exe_command="$exe_command --ip=\"$ip\""
                ;;
            --port=*)
                port="${arg#*=}"
                exe_command="$exe_command --port=\"$port\""
                ;;
            --username=*)
                username="${arg#*=}"
                exe_command="$exe_command --username=\"$username\""
                ;;
            --password=*)
                password="${arg#*=}"
                exe_command="$exe_command --password=\"$password\""
                ;;
            --options=*)
                options="${arg#*=}"
                exe_command="$exe_command --options=\"$options\""
                ;;
            --config=*)
                config="${arg#*=}"
                exe_command="$exe_command --config=\"$config\""
                ;;
            --help)
                usageHint
                exit 0
                ;;
            -h)
                usageHint
                exit 0
                ;;
            *)
                echo "未知参数: $arg"
                usageHint
                exit 1
                ;;
        esac
        
    done
else
    usageHint
    echo "No Honeypot named $command"
    echo "Available Honeypots: http_server, sshserver, ftp_server"
    exit 1
fi

# 执行命令
echo -e "\033[32m$exe_command\033[0m"
eval $exe_command