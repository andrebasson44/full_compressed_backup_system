#!/bin/bash

## Locate and kill a process with a particular signature running in memory - if such a process exists.
## 
#  REQUIREMENTS:	Uses programs ps, grep, sed and awk.
#
#  VERSION: 	
#					1.0: 	original version
#							STATUS: *** ABOUT TO BE DEPRECATED IF FOUND THAT A FUNCTION IS GOOD ENOUGH ON ITS OWN ***
#
#  INPUT:			regex ($1)	- a regular expression by which to match the process
#					callerPPID	- Parent Process ID of the calling process
#
#  OUTPUT:			exit status (0 = succesful kill or no process found, 1 = unsuccesful kill and/or errors)
#
#  INSTRUCTIONS:
#
#  -----------------------------------------------------------------------------------------------------------------
##FUNCTIONS
#
# function top_level_parent_pid ()
#	A simple (recursive) script to get the top-level parent PID of any process number you give it 
#	(or the current shell if you leave out the PID argument):
#
function top_level_parent_pid () {
    # Look up the parent PID (PPID) of the given PID.
    pid=${1:-$$}					# syntax:  ${parameter:-word}  where symbol combo ':-' (without quotes) is used when you want to use a default value in case no value exists
									#	ie. if 'parameter' is null or unset, it will expand to 'word', otherwise it will expand to 'parameter',
									#	e.g. it will be similar to ${parameter} if 'parameter' is null or unset
									#	( more info at https://www.debuntu.org/how-to-bash-parameter-expansion-and-default-values/ )
    stat=($(</proc/${pid}/stat))	# /proc/pid/stat = array of tabspaced statistics from last reboot  [ alternatively: stat=($(cat /proc/$pid/stat))	]
    ppid=${stat[3]}					# 3rd element in array 'stat' = PPID 	[ alternatively:  ppid=$PPID ]

    # /sbin/init always has a PID of 1, so if you reach that (the recursion terminating condition), 
	# the current PID is the top-level parent (or highest ancestor). Otherwise, recursively keep looking.
    if [[ ${ppid} -eq 1 ]] ; then****
        echo ${pid}					# echoed to standard out (i.e. effectively 'returned' to caller where it can be saved to a variable)
    else
        top_level_parent_pid ${ppid}
    fi
	
	return
}


echo -e "\nDEBUG: Entered script killProc.sh"
#echo -e "\nDEBUG: killProc.sh has PID: $BASHPID		\nParent Process ID (PPID): $PPID	\nTop Level Parent Process ID: $(top_level_parent_pid)"
echo -e "\nDEBUG: killProc.sh has PID: $BASHPID		\nParent Process ID (PPID): $PPID	\nTop Level Parent Process ID: $(top_level_parent_pid $1)"
read -p "DEBUG: Press [Enter] key to continue..." key

#********************** AMMENDMNETS TO MAKE:
#							1. killProc.sh must receive regex to match process to kill (eg. regex="$1", regex="full_backup_PULL-version_v1.282.sh")
#							2. killProc.sh must receive the PPID of the caller  (eg. callerPPID="$2")
#							3. killProc.sh must calc caller's PID (eg. callerPID="$PPID")
#							4. killProc.sh must kill process(es) with a PID < callerPPID and PID > callerPID, to prevent incorrectly killing caller or its parent.							
#								> to fascilitate this, you will likely have to store all PIDs of current matching processes in an array
#								> then inside a while loop:
#									>> remove from the array the PIDs that has a callerPPID <= PID <= callerPID  									
#									>> if no PIDs remaining in array - terminate loop, no more PIDs to wipe!!
#									>> else... kill the first process with PID found remaining in array (array read from 0th element)										
#									>> read all processes again, and store matching process IDs in array (ie. overwriting previo)
#									>> repeat loop
#**********************

##CONFIRM CORRECT (1) NO. INPUT PARAMETERS
#
#if [[ $# < 2 ]]
if [[ $# != 1 ]]
then
  echo -e "\n Missing search input parameters\n"
  echo -e   "   eg.: PID=$(/path/to/killProc.sh \"regex\")
  #echo -e   "   eg.: PID=$(/path/to/killProc.sh \"regex\" \"callerPPID\")  
  echo -e   "        where:"
  echo -e   "			'regex' is the regular expression by which to match (find) a process running."
  echo -e   "			'callerPPID' is the Parent Process ID of the calling script or program.\n"  
  exit 1
fi

##VARIABLES
##retrieve regular expression (from command line argument) by which to match (find) the process in memory
#
regex="$1"										#e.g. regex="rsync.*($sourceDir)+.*($targetDir)+"
#CALLER_PPID="$2"								#
#CALLER_PID=$PID

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



