
#!/bin/bash

print_green() {
    BOLD_GREEN=$(tput bold ; tput setaf 2)
    NORMAL=$(tput sgr0)
    echo "${BOLD_GREEN}$1${NORMAL}"
}

print_yellow() {
    BOLD_YELLOW=$(tput bold ; tput setaf 3)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_red() {
    BOLD_YELLOW=$(tput bold ; tput setaf 1)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_blue() {
    BOLD_YELLOW=$(tput bold ; tput setaf 4)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_delimiter() {
    echo
    echo "-------------------------------------------------------------------------------"
    echo
}

clear
print_delimiter
print_yellow "DP ID?"
read DP
print_delimiter
python3 jok3r.py db mission
clear
print_delimiter
print_red "Kick-Off launcher"
print_delimiter
print_yellow "Target/IP?"
print_delimiter
echo ""
read URL
print_blue "Launching WAF detector on $URL and saving results on database $DP..."
sleep 3
python3 jok3r.py attack -t $URL -s http --add2db $DP --profile waf-checker --fast

#check for CVE-2020-5902 
print_delimiter
print_red "Checking for CVE-2020-5902..."
curl -sk 'https://{URL}/tmui/login.jsp/..;/tmui/util/getTabSet.jsp?tabId=Vulnerable' | grep -q Vulnerable && print_red "Vulnerable" || print_green "Not Vulnerable"

exit 0
