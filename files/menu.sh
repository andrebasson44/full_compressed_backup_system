#!/bin/bash

# Purpose: Display various options to operator using menus
# Author: Vivek Gite < vivek @ nixcraft . com > under GPL v2.0+
# Ammended: Andre Basson
# ---------------------------------------------------------------------------
# capture CTRL+C, CTRL+Z and quit signals using the trap
trap 'echo -e "\nSorry! Not allowed.\nPress [Enter] key to continue..."' SIGINT
trap 'echo -e "\nSorry! Not allowed.\nPress [Enter] key to continue..."'  SIGQUIT
trap 'echo -e "\nSorry! Not allowed.\nPress [Enter] key to continue..."' SIGTSTP
 
# display message and pause 
function pause() {
	local m="$@"		#capture all positional parameters passed in an array, e.g. { s1, s2, .. }
	echo "$m"
	read -p "Press [Enter] key to continue..." key
}
 
##infinite loop (dependent on user key-press)
#   note: ':' = short for null-command (does nothing, and exit status is always true (0))
#
while :
do
	# show menu
	clear
	echo "---------------------------------"
	echo "	     M A I N - M E N U"
	echo "---------------------------------"
	echo "1. Show current date/time"
	echo "2. Show what users are doing"
	echo "3. Show top memory & cpu eating process"
	echo "4. Show network stats"
	echo "5. Exit"
	echo "---------------------------------"
	read -r -p "Enter your choice [1-5] : " keypress
	
	# take action
	case $keypress in
		1) pause "$(date)";;
		2) w| less;;
		3) echo '*** Top 10 Memory eating process:'; ps -auxf | sort -nr -k 4 | head -10; 
		   echo; echo '*** Top 10 CPU eating process:';ps -auxf | sort -nr -k 3 | head -10; 
		   echo;  pause;;
		4) netstat -s | less;;
		5) break;;
		*) pause "Select between 1 to 5 only"
	esac
done