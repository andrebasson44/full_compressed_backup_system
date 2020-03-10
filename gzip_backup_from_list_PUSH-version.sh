#!/bin/bash
#
##OVERVIEW
 #========
 #DESCRIPTION:  Typical FULL (archiving) backup script, which syncs data - files and directories listed in ./toBackup.txt - from a location
  #              on the local host to another location on the local host, or between a location on the local host to another on a remote host.  
  #
  #              *** CURRENTLY NO DATA CAN BE BACKED UP (PULLED) FROM A REMOTE HOST ***
  #
  #             Some ammendments to the rest of the overview below may require ammendments yet to be applied.
  #
 #IMPORTANT:	
  #     A. In any scenario, this script caters for AT MOST one remote host (to which to PUSH)	at a time.
  #		  B. The script should be run with sudo/admin privaleges, so as to ensure proper execution at all times.
  #
  #			C. As part of the backup schema, the following file-directory structure is critical:
  #			        1. /path/to/script/backup-info
  #						- a 'backup-info' directory at the same path as where this script resides, with rwx access to sudo user
  # 							> this directory preserves the means by which to log both errors and rsync output.
  #					2. /path/to/script/files
  #						- a 'files' directory at the same path as where this script resides, with rwx access to sudo user
  #								> this directory must contain BASH scripts: fileExist.sh, getAddr.sh, and getRsyncPID.sh
  #								  which are critical to the functions of this script.
  #
  #			D. As a precaution - the program has been configured by default NOT to commence syncing if the source directory 
  #			   is empty (i.e. 0 byte size).  This is considered safest practice to avoid accidental deletion of content on the target.
  #
  #         See INSTRUCTIONS for more details.
  #
 #VERSIONS:     based on full_backup_PUSH-and-PULL-version_v1.287.sh 
  #
  #               v1.31: OVERALL STATUS: on initial assessment appears to be working well.
   #
  # 
 #INSTRUCTIONS:	Very little required to tweak for different backup scenarios 
  #				1. FOR USERS:  
  #					a) users of this script are to update variables ONLY AS FAR AS THE LINE INDICATING WHERE NOT TO TRESSPASS, and then only:
  #                          SOURCE HOST VARIABLES
  #                          TARGET HOST VARIALBES
  #
  #                  b) user may also choose to update the following two variables, but is not recommended (added security to leave as-is)
  #							sourceDirMayBeEmpty		#flag which indicates whether sync is dependant on content of SOURCE directory (default: 'no')
  #							targetDirMayBeEmpty		#flag which indicates whether sync is dependant on content of TARGET directory (default: 'no') 
  #
  #                  c) you cannot backup from a remote host (at this time), only one of the following:
  #                          - local host to local host
  #                          - local host to remote host  
  # 
 #REQUIREMENTS:	
  #				1. System software:
  #					a) *OPTIONAL:  A local, send-only SMTP server (e.g. Postfix) - no dedicated email or 3rd party SMTP server is required
  #						Postfix configured to forward all system-generated email sent to root, to skyqode@gmail.com  	
  #						(see documentation or https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-postfix-as-a-send-only-smtp-server-on-ubuntu-14-04)
  #					b) Rsync
  #					c) SSH - with hosts configured for RSA public/private key pair - 'sshKey' variable pointing to private key
  #                 d) Sufficient storage space for temporary archiving.
  #
  #				2. User software:
  #					a) Program path - if not in system path already - should be listed (see RESOURCE FILES section)
  #
 #
#

##FUNCTIONS
 #=========
 ## function top_level_parent_pid ()
  #	A simple (recursive) script to get the top-level parent PID of any process number you give it 
  #	(or the current shell if you leave out the PID argument), upto but not including the PID of 
  #	process /sbin/init (1) - the top-most process of all processes
  #
 function top_level_parent_pid () {
	#echo -e "\nDEBUG: inside function top_level_parent_pid ()"
	#read -p   "DEBUG: Press [Enter] key to continue#targetDir=/mnt/dycom_rsync_bkp1/backups_shared			#location (on local host) to backup to..." key

    # Look up the parent PID (PPID) of the given PID.
    local pid=${1:-$$}		#note: ${1} = $1	
							# syntax:  ${parameter:-word}  where symbol combo ':-' (without quotes) is used when you want to use a default value in case no value exists
							#	ie. if 'parameter' is null or unset, it will expand to 'word', otherwise it will expand to 'parameter',
							#	e.g. it will be similar to ${parameter} if 'parameter' is null or unset
							#	( more info at https://www.debuntu.org/how-to-bash-parameter-expansion-and-default-values/ )
    local stat=($(</proc/${pid}/stat))	# /proc/pid/stat = array of tabspaced statistics from last reboot  [ alternatively: stat=($(cat /proc/$pid/stat))	]
    local ppid=${stat[3]}					# 3rd element in array 'stat' = PPID 	[ alternatively:  ppid=$PPID ]

    # /sbin/init always has a PID of 1, so if you reach that (the recursion terminating condition), 
	# the current PID is the top-level parent (or highest ancestor). Otherwise, recursively keep looking.
    if [[ ${ppid} -eq 1 ]] ; then
        echo ${pid}					# echoed to standard out (i.e. effectively 'returned' to caller where it can be saved to a variable)
    else
        top_level_parent_pid ${ppid}
    fi
	
	return
 }

 ## function parent_pids ()
  #   A simple (recursive) script to retrieve (ie. set elements to array reference received) the current process ID (PID), 
  #   and all parent process IDs (all ancestors) of any process number you give it (or the current shell if you leave out 
  #   the PID argument), upto but not including the PID of process /sbin/init (1) - the top-most process of all processes
  #
 function parent_pids () {
  
  ##LOCAL VARIABLES
  # Determined by the number of arguments received
  #
  case $# in
    # if 1 arg. received from caller:    
    1)  if [[ $1 =~ ^[0-9]*$ ]]   #if arg ($1) is an integer, ie. $1 matches with regex pattern of an integer number ONLY
        then
          #$1 is likely a PID number; save this PID number
          local pid=$1            
        else
          #$1 is likely NOT a PID number
          local pid=$BASHPID          #default PID number is assumed to be the current running process's PID number; alt. local pid=$$

          #$1 is likely a ref. to an array - save it, but ONLY if it doesn't already exist (you don't want to overrite it on subsequent recursions of this function)
          if [[ -z "$ppidArrayRef" ]]; then 
            local -n ppidArrayRef=$1    #store reference to array ($1)
            ppidArrayRef[0]=$pid        #0th element must be the current process's ID number (subsequent elements to be parent PIDs recursively)
          fi
          
        fi;;         
    # if 2 args received from caller:    
    2)  if [[ $1 =~ ^[0-9]*$ ]]   #if arg ($1) is an integer 
        then
          #$1 is likely a PID number; $2 is likely a ref. to an array; save both
          local pid=$1
          local -n ppidArrayRef=$2
        else
          #must be a mistake, return to caller with error exit code (1)
          echo -e "\n FATAL ERROR: Function expects arg1 to be an integer, and arg2 to be a ref. to an array variable."
          return 1
          #exit 1
        fi;;
    # if any other number arguments received from caller:
    *)  echo -e "\nFATAL ERROR:  Incorrect number arguments received.  Terminating process."
        return 1
        #exit 1
        break;;
  esac      

  local stat=($(</proc/${pid}/stat))	# /proc/pid/stat = array of tabspaced statistics from last reboot  [ alternatively: stat=($(cat /proc/$pid/stat))	]
  local ppid=${stat[3]}					# 3rd element in array 'stat' = PPID 	[ alternatively:  ppid=$PPID ]      

  # /sbin/init always has a PID of 1, so if you reach that (the recursion terminating condition), 
  # the current PID is the top-level parent (or highest ancestor). Otherwise, recursively keep looking.
  if [[ ${ppid} == 1 ]] ; then
    #declare -a ppidArrayRevOrder		#same as ppidArrayRef, but in reverse order

	#    #Use C-style for-loop to revserse order of all elements of array ppidArrayRef, so as to have PIDs in order of ancestry.
	#    for (( index=${#ppidArrayRef[@]}-1 ; index>=0 ; index-- )) {
	#        ppidArrayRevOrder=("${PPIDarrRevOrder[@]}" "${PPIDarr[$index]}")
    #   }
	return 	#terminate this function and return to caller	
  else
	  ppidArrayRef=("${ppidArrayRef[@]}" "$ppid")	#append ppid to END of array PPIDarr	
	  parent_pids ${ppid}	              #recurse, passing the ppid as the argument
  fi
    
  return    
 }

 ## function elementIn ()
  #   Small function to check if an array contains a value. 
  #   The search string is the first argument ($1) and the second ($2) is the array passed by reference
  #   with which to search in.
  #
  #	NOTE: array passed by reference possible in BASH 4.3+
  #
 function elementIn () {
  #DEBUG LINE: comment in/out as necesarry
  echo -e "DEBUG:  inside function elementIn"

  #local USAGE="Usage: elementIn \"searchString\" \"\${array[@]}\""
  local USAGE="Usage: $0 \"searchString\" arrayName"
  
  ##CHECK PARAMS RECEIVED AND SET DIR & REGEX VARs
  #	Return to caller if either 1st ($1) or 2nd parameter ($2) passed is zero
  # Else, set local variables
  #
  if [[ ("$#" == "0") || (-z "$2") || (-z "$1") ]]; then
	  echo "$USAGE"
    return 1
	  #exit 1  
  fi

  #DEBUG LINE: comment in/out as necesarry
  echo -e "DEBUG:  \n1st param (search string):  $1   \n2nd param (array by ref.): $2"

  local str="$1"				#search string to check for
  #local -n arr=$2				#array to search in;  -n switch required to make array reference (point to) another array
              #("${arr[@]}")
  #declare -a arr=("$2")  
  #declare -a arr         #local copy of array elements in $2: default empty
  declare -n arr=$2       #ref. to array received
  declare -i idx=0        #index (integer)  alt.: local -i idx=0  (local = declare)
  
  #populate empty local array
  #for el in $2
  #do
  #    arr[idx]="$el"
  #    idx+=1        #increment index for next iteration
  #done  

  #DEBUG: comment in as required
  echo -e "\nDEBUG: elements in local/referenced array arr[]:"
  for el in ${arr[*]}; do echo "$el"; done

  #DEPRECATED: shift each positional parameter (arguments passed to this function) by 1
  #shift 		#'shift n' will shift positional parameters to left by n (default n=1), 
  				#	eg. if 3 parameters passed to function, then 'shift 2' will make $3 the new $1, $2 the new $0, and $1 the new $3 
  
  #string comparison
  for el in "${arr[*]}" 
    #do [[ "$e" == "$str" ]] && return 0	#if match found, return success (0)
  do
    if [[ "$el" == "$str" ]]; then 
      #DEBUG: comment in as required
      echo -e "\nDEBUG:	PID $str found in array arr[]"      
      return 0    #if match found, return success (0) exit status
    else
      #DEBUG: comment in as required
      echo -e "\nDEBUG:	PID $str NOT found in array arr[]"      
      return 1    #if no match found, return fail (1) exit status
    fi
  done  
  
  #else - element not found - return fail (1)
  return 1
 }

 ## function readLinesIntoArray () 
  #   @description:   reads each line in a file to an array
  #   @parameters:    $1 = file or directory name (absolute path)
  #                   $2 = array passed by reference
  #
 function readLinesIntoArray () {
  local DEBUG=0             #flag, default 1 (true in '$(( ))' integer testing
  local EXIT_STATUS=0       #default 0 (success)
  declare -n arr=$2         #reference to array in parameter $2
  local filename="$1"       
  
  if [[ $# -ne 2 || -z "$filename" || ! -f "$filename" ]]; then 
    echo ""
    echo "Bad Usage of function readLinesArray(), or file name not supplied."
    echo "Usage:  readLinesArray <filename> <arrayname>"
    echo ""

    EXIT_STATUS=1
    return $EXIT_STATUS
  fi  

  ##DEBUG: output every line as its read
   local c=0               #counter
   if (( $DEBUG )); then 
    echo "DEBUG: file path is $2"
    while read line; do
      # reading each line
      echo "Line No. $c: $line"
      c=$((c+1))
    done < $filename
   fi
  #

  ##Read every line into the referenced array
  local index=0           #index counter
  while read line; do
    #skip lines containing comment out sign '#'
    if [[ ( $line == *"#"*  || $line == *";"* ) ]]; then 
      continue
    else 
      arr[$index]="$line"     #assign the array element
      index=$((index+1))      #increment the array index
    fi    
    #increment counter
    c=$((c+1))    
  done < $filename

  return $EXIT_STATUS
 }

 ##Function printUsage ()
  #	Prints to standard out the correct usage of this script.
  #	@param: 	--debug
  #	@returns:	exit status 0
  #
 function printUsage () {  
    echo ""
    echo "DESCRIPTION: "
    echo "  $0 is a FULL (gzip archived) backup script which syncs data - files and directories listed "
    echo "  in ./toBackup.txt - either between two locations on a local host, or between a location on"
    echo "  the local host to another on a remote host."
    echo ""
    echo "  *** It CANNOT NOT perform backups FROM A REMOTE HOST (to a local host) at this time ***"    
    echo ""
    echo "  Configuring the backup script is done via ./gzip-backup.conf."
    echo ""
    echo "REQUIREMENTS:"
    echo "  1. Configuration files:     ./toBackup.txt, ./gzip-backup.conf"
    echo "  2. Temp storage direcotry:  ./backup-info"
    echo "  3. Sufficiently large temporary archive area."
    echo "  4. SSH and SSH authentication credentials."
    echo "  5. Supporting scripts under path ./files: "
    echo "      fileExist.sh, getAddr.sh, getRsyncPID.sh, lsDirSSH.sh, duDirSSH.sh, killProc.sh, "
    echo "      getValFromFile.sh, purgeOldestFileOrDirSSH.sh, fileOrDirExists.sh"    
    echo ""
    echo "SYNTAX: "
    echo "  $0 [--debug] [--help]"
    echo ""
    echo "  where:"
    echo "      --debug     : OPTIONAL:  interactive outputs & debugging."
    echo "      --help      : OPTIONAL:  prints to stdout this text."
    echo ""
  return 0
 }

 ## function printScriptRunStatus ()
  # Function that prints the running status of the script, by checking if file in $1 exists. 
  # parm: ($1) filename  - indicate whether this file exist or not with a nice looking echo to stdout
  #
 function printScriptRunStatus () {    
    if [[ -f "$1" ]]; then 
        echo -e "\nScript running status: running."
    else 
        echo -e "\nScript running status: stopped."
    fi    

    return 0
 }

 ## function scriptIsRunning ()
  # Function echoes to stdout either '1' (caller to interpret script is running) or '0' (not running)
  # parm:   ($1) filename  - indicate whether this file exist or not with a nice looking echo to stdout
  #
 function scriptIsRunning () {
  if [[ -f "$1" ]]; then 
    echo "1"    #caller to interpretate as true
  else 
    echo "0"    #caller to interpreate as false        
  fi

  return
 }

 ## function setScriptRunFlag ()
  # parm: ($1) filename  - create this file if it doesn't exist
  #
 function setScriptRunFlag () {
  echo -e "\n...script should RUN now"
  if [[ -f "$1" ]]; then return 0; else touch "$1"; fi
  return $?
 }

 ## function stopScriptRunFlag ()
  # parm: ($1) filename  - remove this file if it exists
  #
 function stopScriptRunFlag () {
  echo -e "\n...script should STOP now"
  if [[ -f "$1" ]]; then rm -f "$1"; else return 0; fi
  return $?
 }

 ## function pressAnyKey ()
  # Interactive pause of process until any key pressed (key not stored)
  #
 function pressAnyKey () {
  echo ""
  read -p "Press [Enter] key to continue..." key
  echo ""

  return 0
 }
#

##GENERAL VARIABLES
 # -----------------
 EXIT_STATUS=0       #default 0 (success)
 DEBUG=0             #flag to flip debug interactive output (default: 0, off)
 datetime=$(date '+%Y-%m-%d@%H:%M:%S')                   #date & time now (e.g. 2018-09-09@16:54:10)
 CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"	#path of this script 
 resourceDir="$CURRENT_DIR/files"                        #helper scripts 
 backupConfig="$CURRENT_DIR/gzip-backup.conf"		#configuration file: file used to populate ALL script variables
 filesAndDirsToBackup="$CURRENT_DIR/toBackup.txt"         #file that containts the directories or files (absolute paths) to backup
 ExcludeList="$CURRENT_DIR/backup_exclude_list.txt"		#files to exclude in this backup (if any); if absent, rsync will ignore and continue.
  
 SERVER_NAME="$HOSTNAME"									#name of server running this script
 SERVER_IP="$(ip -4 addr show scope global | grep -Evi "(secondary|inet6|"127.0.0.1"|"10.1.1"|"10.8.0")" | awk '$1 == "inet" {print $2}' | sed 's/\/.*//')"
 SCRIPT_NAME="$(basename $0)"							#filename of this script (e.g. "backup_home-andre_from_host-dycom_to_3TB.sh")
														#alternatively: "$(basename ${BASH_SOURCE[0]})"
 
 #output formatting
 bold=$(tput bold)          #format font in output text to bold
 normal=$(tput sgr0)        #return to previous font

 #a file to identify if a script is running or not (if file exists, then script assumed active, if not then script assumed NOT active)
 scriptRunFlag="$CURRENT_DIR/running..."
 
 #By default the sync between souce and target dictates that the source directory HAS to exist
 #and absolutely MUST not be empty.  Change this value to 'yes' if the source is allowed to be empty.
 sourceDirMayBeEmpty="$($resourceDir/getValFromFile.sh "$backupConfig" "sourceDirMayBeEmpty")" 
 if [[ -z "$sourceDirMayBeEmpty" ]]; then sourceDirMayBeEmpty="no"; fi

 #As for the source directory, same default applies
 targetDirMayBeEmpty="$($resourceDir/getValFromFile.sh "$backupConfig" "targetDirMayBeEmpty")"
 if [[ -z "$targetDirMayBeEmpty" ]]; then targetDirMayBeEmpty="no"; fi

 #error & rsync log files 
 RSYNC_LOG="rsync-$datetime.log"							#to record all rsync output
 ERROR_LOG="error-$datetime.log"							#to record all error messges (rsync or otherwise) - this will be the file to be revied by admin

 ##default email error notification message, subject and receiver
 EMAIL_RECEIVER="root"
 EMAIL_SUBJECT="Script Error(s) From: $SERVER_NAME"
 EMAIL_MESSAGE="Script Error(s) From: $SERVER_NAME\nScript path: $CURRENT_DIR/$SCRIPT_NAME\nPlease review log-file: $backupInfoDir/$ERROR_LOG or $targetDir/$datetime/$ERROR_LOG on destination host" 

 #INCLUSION TO REVIEW
 #--------------------
 SCRIPT_PID="$BASHPID"					#this scripts process ID number
 SCRIPT_PPID="$PPID"						#this scripts direct parent process ID number
 #SCRIPT_PPIDs="$(parent_pids)"			#array containing this script's process ID, and all of its ancestor's PIDs (upto but excluding PID 1)
 declare -a SCRIPT_PPIDs					#(default unset) array containing this script's process ID, and all of its ancestor's PIDs (upto but excluding PID 1)		
 parent_pids SCRIPT_PPIDs				#passing name of array to function where it can be set
 SCRIPT_TOPLEVEL_PPID="$(top_level_parent_pid)"			#this script's top-level parent process ID number (ie. highest ancestor PID number, just before 1 (/sbin/init))
 #--------------------
#

##TRAPS (catch/trap signal handlers) 
 # --------------------------------- 
 #Trap (catch) either signals: 1 (HUP/SIGHUP), 2 (INT/SIGINT/CTRL+C), 3 (SIGQUIT), 15 (SIGTERM), or 20/terminal-stop (SIGTSTP/TSTP)
  #and then:
  #   1. remove the 'running...' file (indicating the script has stopped running)
  #   2. call exit (EXIT) signal to terminate the script if the intention is for the script NOT to continue with the rest 
  #      of the program after the trap, but return to the parent process.
  #  
  #syntax:
   #   set the trap:        trap [commands] [signals]
   #   remove the trap:     trap <-> [signals]   OR  trap [signals]
   #
   #      where:  <commands> is any (semi-colon seperated) number of commands or function-calls, and
   #              <signal> is either the signal name or signal number to be caught.
   #
   #   e.g.1
   #      trap "echo Booh!" 2 3 9
   #
   #   e.g.2
   #      function myFunc () { rm -r /path/to/dir/to/delete }
   #      function myFunc2 () { echo "All done!"; return 0 }
   #	     trap "{ myFunc; myFunc2; }" EXIT
  # 
  #signals (kill -l to see complete list):   
   #    Signal Name 	Signal Number 	Description
   #    -----------------------------------------
   #    SIGHUP 	      1 	            Hang up detected on controlling terminal or death of controlling process
   #    SIGINT        2 	            Issued if the user sends an interrupt signal (Ctrl + C)
   #    SIGQUIT 	    3 	            Issued if the user sends a quit signal (Ctrl + D)
   #    SIGFPE 	      8 	            Issued if an illegal mathematical operation is attempted
   #    SIGKILL 	    9 	            If a process gets this signal it must quit immediately and will not perform any clean-up operations
   #    SIGALRM 	    14 	            Alarm clock signal (used for timers)
   #    SIGTERM 	    15 	            Software termination signal (sent by kill by default)
  #   
 #
 trap "{ stopScriptRunFlag $scriptRunFlag; 
        (($DEBUG)) && printScriptRunStatus $scriptRunFlag; 
        exit 1; 
      }" HUP INT QUIT TERM TSTP
#

##CODE
# ------------------------------------------------------------------------------------------------------------
#
##INITIALIZE ERROR & RSYNC LOG FILEs
 # ---------------------------------- 
 echo "" > "$backupInfoDir/$RSYNC_LOG"					#to save *all* rsync output; make the log file that has timestamp in filename
 echo "" > "$backupInfoDir/$ERROR_LOG"					#to save *only* rsync errors (ie. std err output)

 ##DEBUG
  (($DEBUG)) && echo -e "\nLog Files created" && pressAnyKey
 #
#

##prevent concurrency - ie. if previous instance of this (exact) script is still active, then log it and terminate the script.
 #
 if (( $(scriptIsRunning $scriptRunFlag) )); then   
  #construct error message
  errMsg="\n${bold}ERROR:  Concurrent instances of this script not allowed!!${normal}"	
	errMsg+="\n\n   A previous instance of this script appears to be running as indicated by the"
  errMsg+="\n   presence of the 'running...' (or similar) text file in the file path of the script."
  errMsg+="\n\n   If this is not the case, then the text file may be removed manually, followed by"
  errMsg+="\n   executing the script again."
  errMsg+="\n\n   Terminating this new instance...\n"
  
  #echo error message to stdout
  echo -e "$errMsg"
  
  #send email notification
	echo -e "$errMsg" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER  

  ##DEBUG:
   if (( $DEBUG )); then
    echo ""
    read -p   "DEBUG: Press [Enter] key to continue..." key
    echo ""
   fi
  #  

  #terminate this script
  exit 1
 fi
#

##No concurrent instances running....
 # ...so set the running flag status (create ./running... file) to indicate the start of the
 #
 (( $DEBUG )) && echo -e "\nSetting flag to indicate script is RUNNING"
 setScriptRunFlag "$scriptRunFlag"
 if [[ $? -ne 0 ]]; then
  #construct error message
  errMsg="\n${bold}ERROR:  Running indicator appears not to be working...${normal}"
  errMsg+="\n   Please ensure write permission to script file path, or run script with sudo privaleges."
  errMsg+="\n"
  errMsg+="\n   Terminating script..."
  errMsg+="\n"

  #echo error message to stdout AND error log file
  echo -e "errMsg" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"

  #send email notification
	echo -e "$errMsg" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER 

  #terminate this script, after some houskeeping
  stopScriptRunFlag "$scriptRunFlag"
  (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey
  exit 1
 fi
 (( $DEBUG )) && printScriptRunStatus "$scriptRunFlag"
#

##Process optional script agruments received:
 # individually loop through every argument received ($1,$2,... $n), assigning to appropriate VARs
 #
 for i in "$@"; do                                                                   
    if [[ "$#" == "0" ]]; then break
    elif [[ $i == "--debug" ]]; then DEBUG=1    
    elif [[ $($i | grep -Ei) == "--help" ]]; then 
      printUsage
      
      #terminate this script, after some houskeeping
      stopScriptRunFlag "$scriptRunFlag"
      (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey      
      exit $EXIT_STATUS
    else 
      printUsage
      
      #terminate this script, after some houskeeping
      stopScriptRunFlag "$scriptRunFlag"
      (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey      
      exit $EXIT_STATUS
    fi
 done
#

##DEBUG: view script name, PID, PPID & Top Level PPID
 if (( $DEBUG )); then
  echo -e "\nDEBUG: SCRIPT_NAME = $(basename $0)"
  echo -e "\nDEBUG: Current PID: $BASHPID		PPID: $PPID		Top-level PPID: $(top_level_parent_pid)"
  echo ""
  read -p   "DEBUG: Press [Enter] key to continue..." key
  echo ""
 fi
#

##CONFIRM BACKUP LOG FILE DIRECTORY EXISTS
 # If not, create it, incl. the time_now.txt tracking file
 # ------------------------------------------------------------
 backupInfoDir="$CURRENT_DIR/backup-info"				#log files
 if [[ ! -d $backupInfoDir ]];
 then
  mkdir -p $backupInfoDir
  MAKE_DIR_EXIT_STATUS=$?
  
  chown -R root:root $backupInfoDir
  CHOWN_EXIT_STATUS=$?
  
  chmod 777 -R $backupInfoDir
  CHMOD_EXIT_STATUS=$?
  
  if [[ $MAKE_DIR_EXIT_STATUS -ne 0 ]] || [[ $CHOWN_EXIT_STATUS -ne 0 ]] || [[ $CHMOD_EXIT_STATUS -ne 0 ]]
  then
  	errMsg="\n${bold}ERROR:  Backup info directory ($backupInfoDir) does not exist, or has failed to be created with the required permissions.${normal}"	
	  errMsg+="\nPlease ensure you have write/execute permissions, or execute the command with sudo/admin privaleges."
	  echo -e "$errMsg" >> "$backupInfoDir/$ERROR_LOG"
	  echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER

    #terminate this script, after some houskeeping
    stopScriptRunFlag "$scriptRunFlag"
    (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey    
	  exit 1  
  fi
 fi
# 

##CONFIRM RESOURCE FILES PRESENT - typically helper programs
 # ---------------------------------------------------------
 #Array containing the required supporting script file names
 #  (NOTE: 0th entry **must** be file fileExist.sh)
 resourceFiles=("fileExist.sh" "getAddr.sh" "getRsyncPID.sh" "lsDirSSH.sh" "duDirSSH.sh" "killProc.sh" "getValFromFile.sh" "purgeOldestFileOrDirSSH.sh" "fileOrDirExists.sh")
															
 FILE_EXIST=false										#flag: default = false

 #check resource directory and resource file(s) exists - log if not, then terminate (else continue script)
 if [[ -d $resourceDir ]]; then
  
  #first check if critical program fileExist.sh exists under the resource directory - log if not, then quite this script.
  if [[ ! -r $resourceDir/${resourceFiles[0]} ]]; then
  	echo -e "\n${bold}CRITICAL ERROR:  program ${resourceFiles[0]} missing from path $resourceDir.${normal}" >> "$backupInfoDir/$ERROR_LOG"		#prev.: echo -e "\nCRITICAL ERROR:  program ${resourceFiles[0]} missing under directory $resourceDir." >> "$backupInfoDir/rsync-$datetime.log"
	  echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
  
    #terminate this script, after some houskeeping
    stopScriptRunFlag "$scriptRunFlag"
    (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey    
  	exit 1
  fi
  
  #check required resourceFiles exist in resourceDir, and read permission is granted (-r)
  for rf in ${resourceFiles[*]}
  do  	 
    FILE_EXIST="$($resourceDir/${resourceFiles[0]} $rf $resourceDir)"
	if [[ $FILE_EXIST != 'true' ]]; then 
		echo -e "\n${bold}CRITICAL ERROR:  program $rf missing from $resourceDir.${normal}" >> "$backupInfoDir/$ERROR_LOG"		#prev.: echo -e "\nCRITICAL ERROR:  program $rf missing under directory $resourceDir." >> "$backupInfoDir/rsync-$datetime.log"
		echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER

    #terminate this script, after some houskeeping
    stopScriptRunFlag "$scriptRunFlag"
    (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey    
		exit 1
	fi		
  done
  
 else
	echo -e "\n${bold}CRITICAL ERROR:  missing resource directory $resourceDir.${normal}" >> "$backupInfoDir/$ERROR_LOG"			#prev.: echo -e "\nCRITICAL ERROR:  missing resource directory $resourceDir." >> "$backupInfoDir/rsync-$datetime.log"
	echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER

  #terminate this script, after some houskeeping
  stopScriptRunFlag "$scriptRunFlag"
  (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey  
	exit 1
 fi
#

##GET/SET SOURCE HOST VARIABLES - i.e. backup source
 # --------------------------------------------------
 # populate variables from config file (gzip-backup.config)
 # 
 #absolute paths to content (files/dirs) to backup from source host - indexed array (default empty); alt. syntax: array=()
 declare -a arrOfSrcFilesAndDirs                         

 #retrieve source host address (either local or remote)
 sourceAddress="$($resourceDir/getValFromFile.sh "$backupConfig" "sourceAddress")"
 if (( $DEBUG )); then echo "DEBUG: sourceAddress set 1st time to $sourceAddress"; fi

 #sources's IP address and host/domain name respectively (to be tested for reachability)
 s_addr1="$($resourceDir/getValFromFile.sh "$backupConfig" "s_addr1")"          
 s_addr2="$($resourceDir/getValFromFile.sh "$backupConfig" "s_addr2")"

 #user credentials with which to authenticate on source (login name, ssh key, tcp port ssh listens at)
 s_userName="$($resourceDir/getValFromFile.sh "$backupConfig" "s_userName")"
 s_sshKey="$($resourceDir/getValFromFile.sh "$backupConfig" "s_sshKey")"
 s_sshPort="$($resourceDir/getValFromFile.sh "$backupConfig" "s_sshPort")"
 #xxx="$($resourceDir/getValFromFile.sh "$backupConfig" "xxx")"

 #source host cannot be both local host and remote host
 if [[ $sourceAddress == "localhost" && ( ! -z "$s_addr1" || ! -z "$s_addr2" ) && ! -z "$s_userName" && ! -z "$s_sshKey" ]]; then 
    echo ""
    echo "${bold}WARNING:  Config file appears to be pointing to both local and remote source host!${normal}" >> "$backupInfoDir/$ERROR_LOG"
    echo "Assuming local host." >> "$backupInfoDir/$ERROR_LOG"
    echo ""
    sourceAddress="localhost"
 fi

 #Call external getAddr.sh script to retrieve first of two remote host addresses that is reachable.  Else empty string.
 if [[ "$sourceAddress" != "localhost" ]]; then
    sourceAddress="$($resourceDir/getAddr.sh "$s_addr1" "$s_addr2")"
    if (( $DEBUG )); then echo "DEBUG: sourceAddress set 2nd time to $sourceAddress"; fi
 fi
# 

##GET/SET TARGET HOST VARIABLES - i.e. backup target
 # --------------------------------------------------
 # populate variables from config file (gzip-backup.config)
 #
 #location (on local or remote host) to backup to
 targetDir="$($resourceDir/getValFromFile.sh "$backupConfig" "targetDir")"
 targetAddress="$($resourceDir/getValFromFile.sh "$backupConfig" "targetAddress")"

 ##DEBUG:
  if (( $DEBUG )); then echo "DEBUG: targetAddress set 1st time to $targetAddress"; fi
 # 

 #target's IP address and host/domain name respectively (to be tested for reachability)
 t_addr1="$($resourceDir/getValFromFile.sh "$backupConfig" "t_addr1")"
 t_addr2="$($resourceDir/getValFromFile.sh "$backupConfig" "t_addr2")"

 #user credentials with which to authenticate on target (login name, ssh key, tcp port ssh listens at)
 t_userName="$($resourceDir/getValFromFile.sh "$backupConfig" "t_userName")"
 t_sshKey="$($resourceDir/getValFromFile.sh "$backupConfig" "t_sshKey")"
 t_sshPort="$($resourceDir/getValFromFile.sh "$backupConfig" "t_sshPort")"
 #xxx="$($resourceDir/getValFromFile.sh "$backupConfig" "xxx")"

 #source host cannot be both local host and remote host
 if [[ "$targetAddress" == "localhost" && ( ! -z "$t_addr1" || ! -z "$t_addr2" ) && ! -z "$t_userName" && ! -z "$t_sshKey" ]]; then 
    echo ""
    echo "${bold}WARNING:  Config file appears to be pointing to both local and remote source host!${normal}" >> "$backupInfoDir/$ERROR_LOG"
    echo "    Assuming local host." >> "$backupInfoDir/$ERROR_LOG"
    echo ""
    targetAddress="localhost"

    ##DEBUG:
     if (( $DEBUG )); then echo "DEBUG: targetAddress set 2nd time to $targetAddress"; fi
    # 
 fi

 #if target is NOT local, call external getAddr.sh script to retrieve first 
 #of two remote host addresses that is reachable.  Terminate script if remote target not found.
 if [[ "$targetAddress" != "localhost" ]]; then 
    targetAddress="$($resourceDir/getAddr.sh "$t_addr1" "$t_addr2")"
    if (( $DEBUG )); then echo "DEBUG: targetAddress set 1st time to $targetAddress"; fi
    
    #if target address does not exist (ie. empty); do some housekeeping then terminate the script.
    if [[ -z "$targetAddress" || $targetAddress == "" ]]; then
      echo ""
      echo -e "${bold}CRITICAL ERROR:  Target host ($t_addr1 or $t_addr2) could NOT be found.${normal}  \n\nTerminating script..." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
      echo ""
      echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER    

      #terminate script after some housekeeing
      stopScriptRunFlag "$scriptRunFlag"
      (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey
      exit 1
    fi
 fi
#

##PURGE OLDEST (ERROR AND RSYNC) LOG FILES BEFORE CONTINUING (when the max number logs is exceeded)
 # -------------------------------------------------------------------------------------------------
 #set max rsync and error log files with those retrieved from the config file; else use default values
 MAX_NUM_RSYNC_LOGS="$($resourceDir/getValFromFile.sh "$backupConfig" "MAX_NUM_RSYNC_LOGS")"
 if [[ -z "$MAX_NUM_RSYNC_LOGS" || $MAX_NUM_RSYNC_LOGS == "" ]]; then MAX_NUM_RSYNC_LOGS=3; fi

 MAX_NUM_ERROR_LOGS="$($resourceDir/getValFromFile.sh "$backupConfig" "MAX_NUM_ERROR_LOGS")"
 if [[ -z "$MAX_NUM_ERROR_LOGS" || $MAX_NUM_ERROR_LOGS == "" ]]; then MAX_NUM_ERROR_LOGS=3; fi

 ##DEBUG:
  if (( $DEBUG )); then 
    echo "DEBUG: MAX_NUM_RSYNC_LOGS = $MAX_NUM_RSYNC_LOGS"
    echo "DEBUG: MAX_NUM_ERROR_LOGS = $MAX_NUM_ERROR_LOGS"
    echo ""
    read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
  fi
 #

 #set rsync and error log file expressions with those retrieved from the config file; else use default values
 RSYNC_LOG_REGEXP="$($resourceDir/getValFromFile.sh "$backupConfig" "RSYNC_LOG_REGEXP")"
 if [[ -z "$RSYNC_LOG_REGEXP" || $RSYNC_LOG_REGEXP == "" ]]; then RSYNC_LOG_REGEXP="^(rsync)+.*(log)$"; fi 
 ERROR_LOG_REGEXP="$($resourceDir/getValFromFile.sh "$backupConfig" "ERROR_LOG_REGEXP")"
 if [[ -z "$ERROR_LOG_REGEXP" || $ERROR_LOG_REGEXP == "" ]]; then ERROR_LOG_REGEXP="^(rsync)+.*(log)$"; fi

 ##DEBUG:
  if (( $DEBUG )); then 
    echo "DEBUG: RSYNC_LOG_REGEXP = $RSYNC_LOG_REGEXP"
    echo "DEBUG: ERROR_LOG_REGEXP = $ERROR_LOG_REGEXP"
    echo ""
    read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
  fi
 #

 #list of all the rsync and error log files - sorted by name 
 if [[ "$targetAddress" == "localhost" ]]; then
    RSYNC_LOGS="$(ls -A "$targetDir" | grep -Ei "$RSYNC_LOG_REGEXP")"	#	ls -A   = list excl. directories . & ..    
    ERROR_LOGS="$(ls -A "$targetDir" | grep -Ei "$ERROR_LOG_REGEXP")"	#	|				= pipe output to
																	    #	grep -E '.*(rsync)+.*(log)$'	= match every line piped by presens of strings 'log' (right at end) and 'rsync' (before that)
    ##DEBUG:
     if (( $DEBUG )); then 
        echo "DEBUG: RSYNC_LOGS:"
        echo "$RSYNC_LOGS"
        echo "DEBUG: ERROR_LOGS:"
        echo "$ERROR_LOGS"        
        echo ""
        read -p "DEBUG: Press [Enter] key to continue..." key  
        echo ""
     fi
    #

 else        
    RSYNC_LOGS="$($resourceDir/lsDirSSH.sh "$targetDir" "$t_userName@$targetAddress" "$t_sshKey" "$t_sshPort" | grep -Ei "$RSYNC_LOG_REGEXP")"           #lsDirSSH.sh syntax: <REMOTE_FILE_OR_DIR> <REMOTE_HOST> <SSH_KEY> <TCP_PORT>	                
    ERROR_LOGS="$($resourceDir/lsDirSSH.sh "$targetDir" "$t_userName@$targetAddress" "$t_sshKey" "$t_sshPort" | grep -Ei "$ERROR_LOG_REGEXP")"
    
    ##DEBUG:
     if (( $DEBUG )); then 
        echo "DEBUG: RSYNC_LOGS:"
        echo "$RSYNC_LOGS"
        echo "DEBUG: ERROR_LOGS:"
        echo "$ERROR_LOGS"        
        echo ""
        read -p "DEBUG: Press [Enter] key to continue..." key  
        echo ""
     fi    
    #
 fi 

 CURRENT_NUM_RSYNC_LOGS=$(echo "$RSYNC_LOGS" | wc -l )					# number of rsync logs	( wc -l	= count the number of lines )
 CURRENT_NUM_ERROR_LOGS=$(echo "$ERROR_LOGS" | wc -l )					# number of error logs	( wc -l	= count the number of lines )


 ##DEBUG:
  if (( $DEBUG )); then 
    echo "DEBUG: CURRENT_NUM_RSYNC_LOGS: $CURRENT_NUM_RSYNC_LOGS"            
    echo "DEBUG: CURRENT_NUM_ERROR_LOGS: $CURRENT_NUM_ERROR_LOGS"
    echo ""
    read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
  fi    
 #

 ##purge oldest **rsync** log files if max allowed exceeded
 #
 if [[ $CURRENT_NUM_RSYNC_LOGS -ge $MAX_NUM_RSYNC_LOGS ]]; then

    ##DEBUG:
     if (( $DEBUG )); then 
      echo "DEBUG: CURRENT_NUM_RSYNC_LOGS ($CURRENT_NUM_RSYNC_LOGS) exceeded maximum allowed ($MAX_NUM_RSYNC_LOGS)."                  
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key  
      echo ""
     fi    
    #

    if [[ "$targetAddress" == "localhost" ]]; then        
        # syntax:  ./purgeOldestFileOrDirSSH.sh [--debug] <-d|-f> --dir=<"/dir/to/evaluate"> --regex=<"regular-expression"> [ user@host --ssh-key=<key> --port=<port> ]        
        $resourceDir/purgeOldestFileOrDirSSH.sh -f --dir="$targetDir" --regex="$RSYNC_LOG_REGEXP"
        if [[ $? != 0 ]]; then	        
          echo -e "\n${bold}ERROR: MAX RSYNC LOG FILES EXCEEDED:  Oldest log file failed to delete.${normal}\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
 	        #exit 1	
        fi
    else
        # syntax:  ./purgeOldestFileOrDirSSH.sh [--debug] <-d|-f> --dir=<"/dir/to/evaluate"> --regex=<"regular-expression"> [ user@host --ssh-key=<key> --port=<port> ]
        $resourceDir/purgeOldestFileOrDirSSH.sh -f --dir="$targetDir" --regex="$RSYNC_LOG_REGEXP" "$t_userName@$targetAddress" --ssh-key="$t_sshKey" --port="$t_sshPort"
        if [[ $? != 0 ]]; then	        
          echo -e "\n${bold}ERROR: MAX RSYNC LOG FILES EXCEEDED:  Oldest log file failed to delete.${normal}\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
 	        #exit 1	
        fi
    fi
 fi

 # purge oldest **error** log files if max allowed exceeded
 #
 if [[ $CURRENT_NUM_ERROR_LOGS -ge $MAX_NUM_ERROR_LOGS ]]; then

    ##DEBUG:
     if (( $DEBUG )); then       
      echo "DEBUG: CURRENT_NUM_ERROR_LOGS ($CURRENT_NUM_ERROR_LOGS) exceeded maximum allowed ($MAX_NUM_ERROR_LOGS)."
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key  
      echo ""
     fi    
    #

    if [[ "$targetAddress" == "localhost" ]]; then        
        # syntax:  ./purgeOldestFileOrDirSSH.sh [--debug] <-d|-f> --dir=<"/dir/to/evaluate"> --regex=<"regular-expression"> [ user@host --ssh-key=<key> --port=<port> ]        
        $resourceDir/purgeOldestFileOrDirSSH.sh -f --dir="$targetDir" --regex="$ERROR_LOG_REGEXP"
        if [[ $? != 0 ]]; then	        
          echo -e "\nERROR: MAX ERROR LOG FILES EXCEEDED:  Oldest log file failed to delete.\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
 	        #exit 1	
        fi
    else
        # syntax:  ./purgeOldestFileOrDirSSH.sh [--debug] <-d|-f> --dir=<"/dir/to/evaluate"> --regex=<"regular-expression"> [ user@host --ssh-key=<key> --port=<port> ]
        $resourceDir/purgeOldestFileOrDirSSH.sh -f --dir="$targetDir" --regex="$ERROR_LOG_REGEXP" "$t_userName@$targetAddress" --ssh-key="$t_sshKey" --port="$t_sshPort"
        if [[ $? != 0 ]]; then	        
          echo -e "\nERROR: MAX ERROR LOG FILES EXCEEDED:  Oldest log file failed to delete.\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
 	        #exit 1	
        fi
    fi
 fi
#

##PURGE PREVIOUS ARCHIVE ON TARGET - **if stipulated in config file**
 #--------------------------------
 #retrieve source host address (either local or remote)
 toPurgePreviousBackups="$($resourceDir/getValFromFile.sh "$backupConfig" "toPurgePreviousBackups")" 
 if [[ -z $toPurgePreviousBackups || $toPurgePreviousBackups == "" ]]; then toPurgePreviousBackups=no; fi
 if (( $DEBUG )); then echo "DEBUG: toPurgePreviousBackups flag set 1st time to \"$toPurgePreviousBackups\""; fi

  if [[ $toPurgePreviousBackups == "yes" ]]; then
    ##DEBUG:
     if (( $DEBUG )); then       
      echo "DEBUG: Purging previous archive(s) on target at $targetAddress."
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key  
      echo ""
     fi    
    #

    if [[ "$targetAddress" == "localhost" ]]; then        
      rm "$targetDir"/*.tar.gz      
      if [[ $? != 0 ]]; then	        
        echo -e "\n${bold}WARNING: Previous archives on $targetAddress at $targetDir failed to delete.${normal}\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	      echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER 	  
      fi
    else
      ssh "$t_userName@$targetAddress" -i "$t_sshKey" -p "$t_sshPort" "rm $targetDir/*.tar.gz"
      if [[ $? != 0 ]]; then	        
        echo -e "\n${bold}WARNING: Previous archives on $targetAddress at $targetDir failed to delete.${normal}\nManual delete required." >> "$backupInfoDir/$ERROR_LOG"
	      echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
 	    fi
    fi
  fi
#

##GET THE LIST OF FILE/DIRECTORIES TO BACKUP FROM THE ./toBackup.txt FILE AND STORE IN ARRAY
 # ------------------------------------------------------------------------------------------
 readLinesIntoArray "$filesAndDirsToBackup" arrOfSrcFilesAndDirs
 EXIT_STATUS="$?"
 if [[ $EXIT_STATUS != 0 ]]; then 
  echo ""
  echo "${bold}Bad usage or file name does not exist.${normal}"
  echo "Usage:  $0 <filename>"
  echo ""

  #terminate this script, after some houskeeping
  stopScriptRunFlag "$scriptRunFlag"
  (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey  
  exit $EXIT_STATUS
 fi

 ##DEBUG:
  if (( $DEBUG )); then
    c=0       #counter
    echo -e "\nDEBUG: content of \${arrOfSrcFilesAndDirs[@]}:\n"
    for ele in ${arrOfSrcFilesAndDirs[@]}; do
        echo "Line No. $c: $ele"
        c=$((c+1))
    done
   
    #reset counter
    c=0
    echo ""  
  fi
 #
#

##GET/SET TAR/GZIP VARIABLES
 # populate variable(s) from config file (gzip-backup.config)
 # 
 #temp archive directory location
 tmpArchDir="$($resourceDir/getValFromFile.sh "$backupConfig" "tmpArchDir")"
 
 #Tar archiver switches
 tarSwitches="$($resourceDir/getValFromFile.sh "$backupConfig" "tarSwitches")"
 if [[ -z "$tarSwitches" || $tarSwitches == "" ]]; then tarSwitches="-cvzpf"; fi
 
 #confirm local (temp) archive dir exists; terminate script if not
 if [[ ! -d "$tmpArchDir" ]]; then 
    echo ""
    echo -e "${bold}CRITICAL ERROR:  Local directory ($tmpArchDir) for temporary archive could NOT be found.${normal}  \n\nTerminating script..." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
    echo ""
    echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER    

    #terminate script after some housekeeing
    stopScriptRunFlag "$scriptRunFlag"
    (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey
    exit 1 
 fi 

 ##DEBUG:
  if (( $DEBUG )); then echo "DEBUG: tmpArchDir set 1st time to $tmpArchDir"; fi
 # 
#

##CREATE LOCAL TEMP ARCHIVE, THEN RSYNC IT TO TARGET:
 # -------------------------------------------------
 ##rsync switches:
  #       -avzhPR         -a = archive mode, equals -rlptgoD              -v = verbose    -z = compress file data during transfer
  #                       -h = human readible numbers                     -R = use relative pathnames (also creates dirs on the fly)
  #                       -P = combines --progress and --partial (preserves partially transfered files for future completion)
  #						-A = preserves ACLs (Access Control Lists; i.e. extended permissions)
  #       --chmod                 affect file and/or directory permissions
  #       --delete                delete extraneous files from destination directories 
  #       --stats                 stats that are useful to review amount of traffic sent over network (handy for sysadmins)
  #       --log-file              to log rsync output for later review
  #       --exclude-from          contains directory paths (one per line) of what not to backup
  #       --link-dest=DIR         To create hardlink (instead of copy) to files in DIR (previous backup), when files are unchanged.
  #                               This means that the --link-dest command is given the directory of the previous backup (on the target).
  #                               If we are running backups every two hours, and it’s 4:00PM at the time we ran this script, then the 
  #                               --link-dest command looks for the directory created at 2:00PM (on the target/destination path) and
  #                               only transfers the data that has changed since then (if any).
  #
  #                               To reiterate, that is why time_now.txt is copied to time_before.txt at the beginning of the script,
  #                               so the --link-dest command can reference that time (and the folder with the same name) later.
  #
  #       -e                      specify the remote shell to use (e.g. SSH) during the sync.
  #
 #
 #populate rsync switches; defaults if not set in config file
  prelimSwitches="$($resourceDir/getValFromFile.sh "$backupConfig" "prelimSwitches")"
  if [[ -z "$prelimSwitches" || $prelimSwitches == "" ]]; then prelimSwitches="-avzhHAPR"; fi

  delSwitch="$($resourceDir/getValFromFile.sh "$backupConfig" "delSwitch")"
  if [[ -z "$delSwitch" || $delSwitch == "" ]]; then delSwitch="--delete"; fi

  statsSwitch="$($resourceDir/getValFromFile.sh "$backupConfig" "statsSwitch")"
  if [[ -z "$statsSwitch" || $statsSwitch == "" ]]; then statsSwitch="--stats"; fi
 #

 ##DEBUG:
  if (( $DEBUG )); then 
    echo "DEBUG: sourceAddress = $sourceAddress"
    echo "DEBUG: s_addr1 = $s_addr1"
    echo "DEBUG: s_addr2 = $s_addr2"
    echo "DEBUG: s_userName = $s_userName"
    echo "DEBUG: s_sshKey = $s_sshKey"
    echo "DEBUG: s_sshPort = $s_sshPort"
    echo "DEBUG: sourceDirMayBeEmpty = $sourceDirMayBeEmpty"
    echo ""
    
    echo "DEBUG: targetAddress = $targetAddress"
    echo "DEBUG: t_addr1 = $t_addr1"
    echo "DEBUG: t_addr2 = $t_addr2"
    echo "DEBUG: t_userName = $t_userName"
    echo "DEBUG: t_sshKey = $t_sshKey"
    echo "DEBUG: t_sshPort = $t_sshPort"    
    echo "DEBUG: targetDirMayBeEmpty = $targetDirMayBeEmpty"
    echo ""

    echo "DEBUG: prelimSwitches = $prelimSwitches"
    echo "DEBUG: delSwitch = $delSwitch"
    echo "DEBUG: statsSwitch = $statsSwitch"
    echo ""
    read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
  fi
 #

 ##ITERATE OVER ARRAY OF SOURCE FILES/FOLDERS TO ARCHIVE LOCALLY, THEN EXECUTE RSYNC BACKUP:
  # Note:
  # - Optional rsync switch if you want to change file/directory permission on the fly:  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r
  # - Also, incl. -R switch (relative paths) to maintain directory structure where ever synced to.  eg.: -avzhAPR
  #
  counter=0                   #new counter
  for fileOrDir in ${arrOfSrcFilesAndDirs[@]}; do       #IF ERROR OCCUR: try double quoting wrap around, ie. "${arrOfarrOfSrcFilesAndDirs[@]}"
    
    RSYNC1_EXIT_STATUS=1		#default exit status is 1 (fail)

    ##Check that the target host is reachable, and that the target directory (either on remote or local host) exists.
    # Terminate under the following conditions:
    #	1. directory does not exist.
    #	2. directory exists, but is empty when the targetDirMayBeEmpty flag is set to 'no' (cannot be empty, cannot be 0 bytes in size)
    #
    TEMP_EXIT_STATUS=0   
    if [[ $targetAddress == "localhost" ]]; then      
      $resourceDir/fileOrDirExists.sh "$targetDir" "$targetAddress" "$targetDirMayBeEmpty"    #syntax: ./fileOrDirExists.sh <file-dir> <\"localhost\"> [yes|no]
      TEMP_EXIT_STATUS="$?"
    else      
      $resourceDir/fileOrDirExists.sh "$targetDir" "$targetAddress" "$t_userName" "$t_sshKey" "$t_sshPort" "$targetDirMayBeEmpty"     #syntax: ./fileOrDirExists.sh  <file-dir> <host-address> <username> <ssh-key> <ssh-port> [yes|no]
      TEMP_EXIT_STATUS="$?"
    fi

    if [[ "$TEMP_EXIT_STATUS" != "0" ]]; then                     
        echo -e "\n${bold}ERROR:  Backup to target directory ($targetDir) on host ($targetAddress) terminated.${normal}" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "One or more of the following occured:" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"        
        echo "  1. Either the target directory on the target host, or the target host itself, cannot be found, " 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"        
        echo "  2. The target directory is empty when not expected to be (see ./gzip-backup.conf), " 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "  3. The user lacks permision to succesfully perform a read or write process." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"

        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER

        #terminate this script, after some houskeeping
        stopScriptRunFlag "$scriptRunFlag"
        (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey
        exit 1        
    fi

    ##Check that the source directory (either on remote or local host) exists.
    # Terminate under the following conditions:
    #	1. directory does not exist.
    #	2. directory exists, but is empty when the sourceDirMayBeEmpty flag is set to 'no' (cannot be empty, cannot be 0 bytes in size)
    # 
    if [[ $sourceAddress == "localhost" ]]; then
      $resourceDir/fileOrDirExists.sh "$fileOrDir" "$sourceAddress" "$sourceDirMayBeEmpty"
      TEMP_EXIT_STATUS="$?"
    else
      $resourceDir/fileOrDirExists.sh "$fileOrDir" "$sourceAddress" "$s_userName" "$s_sshKey" "$s_sshPort" "$sourceDirMayBeEmpty"
      TEMP_EXIT_STATUS="$?"
    fi
    if [[ "$TEMP_EXIT_STATUS" != "0" ]]; then     

        echo -e "\n${bold}ERROR:  Backup of the source file/directory ($fileOrDir) skipped.${normal}" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "One or more of the following occured:" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "  1. Either the source host ($sourceAddress) or source file/directory ($fileOrDir) cannot be found on the the source host, " 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "  2. The source directory is empty when not expected to be, " 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        echo "  3. The user lacks permission to succesfully perform a read or write process." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
        
        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER        
        continue    #skip this iteration of parent for-loop
    fi

    ##DEBUG:
     if (( $DEBUG )); then 
        echo "DEBUG: fileOrDir = $fileOrDir"
        echo "DEBUG: sourceAddress = $sourceAddress"
        echo "DEBUG: targetAddress = $targetAddress"
        echo ""
        read -p "DEBUG: Press [Enter] key to continue..." key  
        echo ""
     fi
    #

    #refresh script run status
    setScriptRunFlag "$scriptRunFlag"
    
    ##Perform a temporary archive backup (eg. gzip) to local storage with TAR
     #
     ##DEBUG:
      if (( $DEBUG )); then  
        echo -e "\nDEBUG: Ready to start archiving $fileOrDir to $tmpArchDir ..."    
        echo ""
        read -p   "DEBUG: Press [Enter] key to continue..." key
        echo ""
      fi
     #
 
     #commence archive... confirm it worked, or terminate script.
     tar "$tarSwitches" "$tmpArchDir/backup.$datetime.tar.gz" -C / "$fileOrDir" 2>> "$backupInfoDir/$ERROR_LOG"       #send stderr to errorLogFile
     EXIT_CODE_TAR=$?

     ##DEBUG:
      if (( $DEBUG )); then  
        echo -e "\nDEBUG: TAR completed with exit code: $EXIT_CODE_TAR"    
        echo ""
        read -p   "DEBUG: Press [Enter] key to continue..." key
        echo ""
      fi
     #

     case $EXIT_CODE_TAR in
        0) (( $DEBUG )) && echo -e "\nDEBUG: Temporary (local) archive completely succesfully.\n" && pressAnyKey
           ;;
           #break;;
        1) echo -e "\n${bold}WARNING:  Temporary archive of $fileOrDir at local directory ($tmpArchDir) has completed, but with some differences from the original files/directories.${normal}" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           ;;
           #break;;           
        *) echo -e "\n${bold}FATAL ERROR:  Temporary archive of $fileOrDir at local directory ($tmpArchDir) suffered an unrecoverable error.${normal}" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           echo "One or more of the following occured:" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           echo "  1. Either the local (archive) directory cannot be found (see gzip-backup.conf), or" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           echo "  2. The local (archive) directory is insufficient in space, or" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           echo "  3. The user lacks permision to succesfully perform a read or write process." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
           echo ""
           echo "Terminating script..."
           echo ""
           echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER

           #terminate this script, after some houskeeping
           stopScriptRunFlag "$scriptRunFlag"
           (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey
           exit 1
           ;;
     esac
    # 

    ##Now that you've confirmed both source and target hosts, AND the archiving of the source file/dir completed succesfully, 
    # you may now commence the rsync backup for ONE of the following scenarios (only):
    #    
    ##*** OPTION NO.1 IS NOT ACTIVE AT THIS MOMENT ***
     ## 1. from remote source to local host (ie. data PULLed from remote source):
     #if [[ "$sourceAddress" != "localhost" ]] && [[ "$targetAddress" == "localhost" ]]; then    
     #    if (( $DEBUG )); then echo "rsync type 1"; fi
     #
     #    #source is remote host - ie. data PULLed from remote source
     #    echo -e "\nBACKUP: source = $s_userName@$sourceAddress:$fileOrDir    target = localhost:$targetDir/" >> "$backupInfoDir/$RSYNC_LOG"
     #    echo    "----------------------------------------------------------------------------------------" >> "$backupInfoDir/$RSYNC_LOG"
     #    rsync $prelimSwitches $delSwitch $statsSwitch --exclude-from=$ExcludeList --log-file="$backupInfoDir/$RSYNC_LOG" -e "ssh -i $s_sshKey -p $s_sshPort -o StrictHostKeyChecking=no" "$s_userName@$sourceAddress:$fileOrDir" "$targetDir/" 2>> "$backupInfoDir/$ERROR_LOG"
     #    RSYNC1_EXIT_STATUS=$?
    #
    # 2. from local source to local host:
    #elif [[ "$sourceAddress" == "localhost" ]] && [[ "$targetAddress" == "localhost" ]]; then    
    if [[ ( "$sourceAddress" == "localhost" && "$targetAddress" == "localhost" ) ]]; then
        if (( $DEBUG )); then echo "rsync type 2"; fi

        #both source and target host is local host - ie. data PUSHed from local host to local host    
        echo -e "\nARCHIVE BACKUP: source = localhost:$fileOrDir    target = localhost:$targetDir/" >> "$backupInfoDir/$RSYNC_LOG"
        echo    "------------------------------------------------------------------------------" >> "$backupInfoDir/$RSYNC_LOG"
        #rsync $prelimSwitches $delSwitch $statsSwitch --exclude-from=$ExcludeList --log-file="$backupInfoDir/$RSYNC_LOG" "$fileOrDir" "$targetDir/" 2>> "$backupInfoDir/$ERROR_LOG"        
        rsync $prelimSwitches $delSwitch $statsSwitch --exclude-from=$ExcludeList --log-file="$backupInfoDir/$RSYNC_LOG" "$tmpArchDir/backup.$datetime.tar.gz" "$targetDir/" 2>> "$backupInfoDir/$ERROR_LOG"
        RSYNC1_EXIT_STATUS=$?
    
    # 3. from local source to remote host (ie. data PUSHed to remote target)
    elif [[ ( "$sourceAddress" == "localhost" && "$targetAddress" != "localhost" ) ]]; then    
        #"$sourceAddress" == "localhost"  &&  "$targetAddress" != "localhost", ie. data PUSHed from local host to remote host
        if (( $DEBUG )); then echo "rsync type 3: sourceAddress = $sourceAddress, targetAddress = $targetAddress"; fi

        echo -e "\nARCHIVE BACKUP: source = localhost:$fileOrDir    target = $t_userName@$targetAddress:$targetDir/" >> "$backupInfoDir/$RSYNC_LOG"
        echo    "-----------------------------------------------------------------------------------------------" >> "$backupInfoDir/$RSYNC_LOG"       
        #rsync $prelimSwitches $delSwitch $statsSwitch --exclude-from=$ExcludeList --log-file="$backupInfoDir/$RSYNC_LOG" -e "ssh -i $t_sshKey -p $t_sshPort -o StrictHostKeyChecking=no" "$fileOrDir" "$t_userName@$targetAddress:$targetDir/" 2>> "$backupInfoDir/$ERROR_LOG"
        rsync $prelimSwitches $delSwitch $statsSwitch --exclude-from=$ExcludeList --log-file="$backupInfoDir/$RSYNC_LOG" -e "ssh -i $t_sshKey -p $t_sshPort -o StrictHostKeyChecking=no" "$tmpArchDir/backup.$datetime.tar.gz" "$t_userName@$targetAddress:$targetDir/" 2>> "$backupInfoDir/$ERROR_LOG"
        RSYNC1_EXIT_STATUS=$?

    # 4. from remote host to either local or remote host - THIS IS NOT ALLOWED! - terminate script w/ error message & log. 
    else
      echo -e "\n${bold}CRITICAL ERROR:    Backup from a remote host ($sourceAddress), aka PULLing data, is not allowed.${normal}" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
      echo "    Backup from a remote host (ie PULLing data), is not allowed." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"
      echo -e "\nTerminating script..." 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"             

      echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
  
      #terminate this script, after some houskeeping
      stopScriptRunFlag "$scriptRunFlag"
      (($DEBUG)) && printScriptRunStatus $scriptRunFlag && pressAnyKey      
      exit 1  
    fi

    ##DEBUG:
     (( $DEBUG )) && echo -e "\nDEBUG: RSYNC1_EXIT_STATUS = $RSYNC1_EXIT_STATUS" && pressAnyKey
    #

    #delete temp local archive copy if successfully synced to target host    
    if [[ ( $RSYNC1_EXIT_STATUS == 0 || $RSYNC1_EXIT_STATUS == 23 ) ]]; then
      if [[ $RSYNC1_EXIT_STATUS == 0 ]]; then echo -e "\nRSYNC of archive $fileOrDir completed 100% succesfully." 2>&1 | tee -a "$backupInfoDir/$RSYNC_LOG"; fi
      if [[ $RSYNC1_EXIT_STATUS == 23 ]]; then echo -e "\nRSYNC of archive $fileOrDir completed PARTIALLY succesfully." 2>&1 | tee -a "$backupInfoDir/$RSYNC_LOG"; fi
      
      echo "Deleting temporary (local) archive copy..." 2>&1 | tee -a "$backupInfoDir/$RSYNC_LOG"
      rm "$tmpArchDir/backup.$datetime.tar.gz"      
      if [[ $? == 0 ]]; then
        echo "Done" 2>&1 | tee -a "$backupInfoDir/$RSYNC_LOG"
      else
        #append error message to both rsyncLogFile and errorLogFile logs using 'tee' command (syntax:  tee -a <file1> <file2> ...)
        echo "${bold}Error deleting archive copy!  Manual deletion required.${normal}" | tee -a "$backupInfoDir/$RSYNC_LOG" "$backupInfoDir/$ERROR_LOG"
        echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER        
      fi
    else
      echo -e "\n${bold}Error occured during rsync:${normal}"
      echo "  The sync did either NOT complete 100% successfully, or completed PARTIALLY successfully"
      echo "  The temp archive copy NOT deleted.  Manual deletion required." | tee -a "$backupInfoDir/$RSYNC_LOG" "$backupInfoDir/$ERROR_LOG"
      echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER        
    fi

    #inc counter
    counter=$((counter+1))
  done
#

##RSYNC BACKUP LOG-FILEs TO TARGET DIRECTORY (and then delete local/temp log file)
 #--------------------------------------------------------------------------------
 #  We use either secure copy or rsync to take the rsync & error logs and place it in the proper directory (i.e. under the $targetDir)
 #
 RSYNC2_EXIT_STATUS=1    #to record exit status to the rsync command  (default exit status is 1 (fail))
 RSYNC3_EXIT_STATUS=1    #to record exit status to the rsync command  (default exit status is 1 (fail))

 #if [[ ( "$targetAddress" == "localhost" || "$targetAddress" == "$SERVER_IP" ) && ( "$RSYNC1_EXIT_STATUS" -eq 0 ) ]]; then 
 if [[ ( "$targetAddress" == "localhost" || "$targetAddress" == "$SERVER_IP" ) ]]; then     
    rsync -avzhP "$backupInfoDir/$RSYNC_LOG" "$targetDir/$RSYNC_LOG" 2>> "$backupInfoDir/$ERROR_LOG"    
    RSYNC2_EXIT_STATUS=$?

    rsync -avzhP "$backupInfoDir/$ERROR_LOG" "$targetDir/$ERROR_LOG" 2>> "$backupInfoDir/$ERROR_LOG"
    RSYNC3_EXIT_STATUS=$?
 #elif [[ "$RSYNC1_EXIT_STATUS" -eq 0 ]]; then
 else
    rsync -avzhP -e "ssh -i $t_sshKey -p $t_sshPort -o StrictHostKeyChecking=no" "$backupInfoDir/$RSYNC_LOG" "$t_userName@$targetAddress:$targetDir/$RSYNC_LOG" 2>> "$backupInfoDir/$ERROR_LOG"
    RSYNC2_EXIT_STATUS=$?

    rsync -avzhP -e "ssh -i $t_sshKey -p $t_sshPort -o StrictHostKeyChecking=no" "$backupInfoDir/$ERROR_LOG" "$t_userName@$targetAddress:$targetDir/$ERROR_LOG" 2>> "$backupInfoDir/$ERROR_LOG"
    RSYNC3_EXIT_STATUS=$?
 fi

 # check if exit status of previous rsync commands was succesful (0); wipe log-files under $backupInfoDir
 if [[ ( ! $RSYNC2_EXIT_STATUS -eq 0 || ! $RSYNC3_EXIT_STATUS -eq 0 ) ]]; then  
    echo -e "\n${bold}WARNING:  One or both rsync and error logs have not been transfered to the target host ($targetAddress) succesfully.${normal}\n" 2>&1 | tee -a "$backupInfoDir/$ERROR_LOG"  
    echo -e "$EMAIL_MESSAGE" | mail -s "$EMAIL_SUBJECT" $EMAIL_RECEIVER
    #exit 1
 else
    rm "$backupInfoDir/$RSYNC_LOG"  
    rm "$backupInfoDir/$ERROR_LOG"
 fi
#

##EXIT THE SCRIPT & PROCESS
 #-------------------------
 #Exit the process with succesful (0) exit status value after final housekeeping
 #
 echo -e "\n\nTerminating script..."
 stopScriptRunFlag "$scriptRunFlag"
 (($DEBUG)) && pressAnyKey
 exit 0
# 



