#!/bin/bash

## Locate and kill a process with a particular signature running in memory - if such a process exists.
## 
#  REQUIREMENTS:	Uses programs ps, grep, sed and awk.
#
#  VERSION: 	
#					1.0: 	original version
#							STATUS: testing...
#
#  INPUT:			searchPattern ($1)	- a regular expression by which to match the process
#  OUTPUT:			exit status (0 = succesful kill or no process found, 1 = unsuccesful kill and/or errors)
#
#  INSTRUCTIONS:
#
#  -----------------------------------------------------------------------------------------------------------------

echo -e "\nDEBUG: Entered script killProc.sh"
echo -e "\nDEBUG: killProc.sh has PID: $BASHPID		and its Parent Process ID (PPID): $PPID"
read -p "DEBUG: Press [Enter] key to continue..." key

#********************** AMMENDMNETS TO MAKE:
#							1. killProc.sh must receive regex to match process to kill (eg. regex="$1", regex="full_backup_PULL-version_v1.282.sh")
#							2. killProc.sh must receive the PPID of the caller  (eg. callerPPID="$2")
#							3. killProc.sh must calc caller's PID (eg. callerPID="$PPID")
#							4. killProc.sh must kill process(es) with a PID < callerPPID and PID > callerPID, to prevent incorrectly killing caller or its parent.							
#**********************

##CONFIRM CORRECT (1) NO. INPUT PARAMETERS
#
if [[ $# != 1 ]]
then
  echo -e "\nMissing search pattern (regex) input parameter"
  echo -e   "Syntax ex.: PID=$(/bin/bash /path/to/getRsyncPID.sh "regex") \n"
  exit 1
fi

##VARIABLES
##retrieve regular expression (from command line argument) by which to match (find) the process in memory
#
regex="$1"										#e.g. regex="rsync.*($sourceDir)+.*($targetDir)+"

#echo -e "\nDEBUG: regex = $regex"
#read -p "DEBUG: Press [Enter] key to continue..." key

#initial check for an instance matching $regex running in memory - a process ID (PID) will exist if so
PID="$(ps -afx -o pid,cmd | grep -vi 'color' | grep -E $regex | sed -n '1p' | awk '{ print $1 }')"	
		# where:
		# 	ps -afx -o pid,cmd	(echo all processes showing process ID & command)
		# 	|					(pipe output to next command)
		# 	grep -i "$regex"	(match input to case-insesitive (-i) pattern in regex)
		# 	|					(pipe output to next command)
		# 	grep -vi "color"	(exclude lines (-v) in input matching case-insesitive (-i) pattern of string 'color')
		# 	|					(pipe output to next command)
		# 	sed -n "1p"			(stream editor: print (p) to console, from input received, only the first (1) line)
		# 	|					(pipe output to next command)
		# 	awk '{ print $1 }'	(awk: print (echo to console) from input received, only the first variable (white-space delimited) - i.e. PID)

#PID_COPY=$PID	#reserve a copy of the initial process ID recorded (if any)

##WHILE LOOP VARs
#
MAX_LOOPS=10				#failsafe exit condition for while loop
LOOP_COUNT=1				#current loop iterance
SUCCESSFUL_KILLS=0			#current number of processes killed

# loop while a matching process has been found - killing those found on each iterance
while [[ ( $PID != "" ) || ( $LOOP_COUNT > $MAX_LOOPS ) ]]
do
  #echo -e "\nDEBUG: PID = $PID"
  #read -p "DEBUG: Press [Enter] key to continue..." key

  #attempt to kill (SIGKILL) the process - log the kill if succesful
  kill -9 $PID				
  if [[ $? == 0 ]]; then
    SUCCESSFUL_KILLS=$(($SUCCESSFUL_KILLS+1))		#increment actual kills completed
  fi
 
  #subprocesses might exit or popup - so check again prior to new loop
  PID="$(ps -afx -o pid,cmd | grep -vi 'color' | grep -E $regex | sed -n '1p' | awk '{ print $1 }')"
 
  LOOP_COUNT=$((LOOP_COUNT+1))	#increment counter
  sleep 0.2						#sleep/delay in seconds
  
done		#e/o while loop

##SET EXIT STATUS
#
if [[ $PID == "" ]]; then   
  exit 0		#process(es) either killed successfully or no regex matching process found
else  
  exit 1		#matching process(es) found (either correctly or incorrectly), but not terminated
fi



