#!/bin/bash
clear
python3 jok3r.py db mission
echo
"##########################################################################################"
echo "# Kick-Off launcher                                               
                       #"
echo
"##########################################################################################"
echo -n "#Target/IP?"
echo ""
read URL
echo -n "Launching WAF detector on $URL and saving on database $DP..."
sleep 3
python3 jok3r.py attack -t $URL --add2db $DP --profile waf-checker --fast
