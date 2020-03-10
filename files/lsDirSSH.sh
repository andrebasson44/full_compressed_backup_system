#!/bin/bash

#DESCRIPTION:	lsDirSSH.sh checks via SSH authentication, if a directory on a remote host exists, then 'returns' to the caller
#				(ie. echo to standard out) a list of the contents of that directory.  Else, an empty line is returned.
#
# SYNTAX:	bash lsDirSSH.sh "/mnt" "andre@dycomserver.ddns.net" "/home/andre/.ssh/id_rsa_dycom" "2200"			(quotes optional)
#
# PARAMS:	$1: REMOTE_DIR=""                   #absolute path to directory on remote host	(e.g. '/mnt/storage')
#			$2: REMOTE_HOST=""                  #username + either IP or domain address 	(e.g. 'support@skynet.ddns.net')
#			$3: SSH_KEY=""                      #aboslute path to private key by which to authenticate over SSH protocol
#			$4: TCP_PORT="22"                   #default TCP port for SSH traffick is 22	(e.g. '22')
#
# VERSION:	1.0
#
# NOTE:		During SSH authentication, lsDirSSH.sh cannot assume the authenticity of the remote host, and thus
#			accepts the prompt on request for attempt to communicate.
#
# -----------------------------------------------------------------------------------------------------------
# SOME FUNCTIONS:
# ---------------
##Function printUsage ()
#	Prints to standard out the correct usage of this script.
#	@param: 	none
#	@returns:	exit status 0
#
function printUsage ()
{  
  echo -e "\n DESCRIPTION:	lsDirSSH.sh checks via SSH authentication, if a directory on a"
  echo -e   "		remote host exists, then 'returns' to the caller (ie. echo to standard out)"
  echo -e	"		a list of the contents of that directory.  Else, an empty line is returned."

  echo -e "\n SYNTAX:	bash lsDirSSH.sh REMOTE_DIR REMOTE_HOST SSH_KEY TCP_PORT"
  echo -e "\n PARAMS:	1: REMOTE_DIR		#absolute path to directory on remote host	(e.g. '/mnt/storage')"
  echo -e	"		2: REMOTE_HOST		#username + either IP or domain address 	(e.g. 'support@skynet.ddns.net')"
  echo -e	"		3: SSH_KEY		#aboslute path to private key by which to authenticate over SSH protocol"
  echo -e	"		4: TCP_PORT		#default TCP port for SSH traffick is 22	(e.g. '22')"

  echo -e	"\n VERSION:	1.0"
  
  echo -e	"\n NOTE:		During SSH authentication, lsDirSSH.sh cannot assume the authenticity"
  echo -e	"		of the remote host, and thus accepts the prompt on request for attempt to communicate."
  
  return 0
}

##Function hostExists()
#   Tests whether the host address (argument 1) received is reachable (pings succesfully) or not, 
#      i.e. if the IP address or domain name exists.
#   @param:       expects a single argument passed at command line ($1)
#   @returns:     echoes to standard out "true" if address exists, "false" otherwise
#
function hostExists ()
{
  #echo -e "\nDEBUG: check if host is reachable"
  #read -p   "DEBUG: Press any key..." key

  # check number of arguments passed (must be exactly 1, or terminate the script)
  if [ $# -ne 1 ];then
    echo "Please Enter (only) One (e.g. IP or domain) Host Destination"
    exit 1
  fi

  # save the first command argument (address) as a string
  local dst_addr="$1"
  local result=""

  # ping the address to see if it exists on LAN/WAN
  # (note: redirect both stdout & stderr to null device to discard output, but retain whether command (ping) was succesful or not. 
  #        Required to discard output so that final [echo "$result"] is the only output "seen" by the caller)
  ping -c 1 -w 5 $dst_addr > /dev/null 2>&1

  # check return status of previous command (i.e. if ping returned with '0'/true )
  if [ "$?" = "0" ]
  then
    result="true"
  else
    result="false"
  fi

  # echoes to stdout whether host address is reachable to be "true" or "false"
  echo "$result"
  return
}
# ----------------------------------------------------------------------------------------------------------

##VARs
#
REMOTE_DIR=""			#absolute path to directory on remote host
REMOTE_HOST=""			#either IP or domain address
SSH_KEY=""				#private key by which to authenticate over SSH protocol
TCP_PORT="22"			#default TCP port for SSH traffick is 22
REMOTE_DIR_CONTENT=""		#default empty

##CONSTANTS
#
ERROR=1				#if less than 3 parameters received, or any execution error occured
SUCCESS=0

##CHECK IF PARAM 1 = '--help'
# Output program description and usage
#
if [[ ! -z "$1" ]] && [[ "$1" == "--help" ]]; then 
  printUsage
  echo  ""				#empty string echo to standard out (i.e. empty string "" output 'returned' to caller)
  EXIT_STATUS=$ERROR
  exit $EXIT_STATUSxit 
fi

##CHECK PARAMS 1 TO 3 RECEIVED & SET ASSOCIATED VARs
# Return to caller if either 1st ($1), 2nd parameter ($2) or 3rd parameter passed is zero, or empty
# Else: set variables REMOTE_DIR, REMOTE_HOST & SSH_KEY
#
if [[ -z "$1" ]] || [[ -z "$2" ]] || [[ -z "$3" ]]; then
  #...SOME ERROR OUTPUT REQUIRED HERE TO DESCRIPT THE PARAMETERS (AND ORDER OF) EXPECTED...
  printUsage
  
  echo  ""			#empty string echo to standard out (i.e. no output returned to caller)
  EXIT_STATUS=$ERROR
  exit $EXIT_STATUS
else
  REMOTE_DIR="$1"
  REMOTE_HOST="$2"
  SSH_KEY="$3"
fi

##CHECK PARAMS 4 RECEIVED & SET FILE / DIR VARs
# if so: set TCP_PORT
# Else:  leave as default
#
if [[ -z "$4" ]]; then
  TCP_PORT="22"
else
  TCP_PORT="$4"
fi

##CONFIRM REMOTE HOST IS REACHABLE
#
remoteHostExists=$(hostExists $(echo $REMOTE_HOST | sed 's/.*@//'))	#sed command substitutes (s) all characters upto and incl. '@', with a blank (i.e. deletes it)
if [[ "$remoteHostExists" = "false" ]]; then
  EXIT_STATUS=$ERROR
  exit $EXIT_STATUS
fi

## TEST FOR EXISTENCE OF REMOTE_DIR ON REMOTE_HOST
#  If so, get listing of content of REMOTE_DIR on REMOTE_HOST
#
#if ssh -q $REMOTE_HOST -i $SSH_KEY -p $TCP_PORT "[[ -d $REMOTE_DIR ]]" 	# ssh -q to quit silently (no echo of errors)
if ssh $REMOTE_HOST -i $SSH_KEY -p $TCP_PORT "[[ -d $REMOTE_DIR ]]" 2> /dev/null 	# suppress all error messages
then
  #remote directory exists - get ls (list) of directory contents, and set the exit status

  #OPTION 1) simplistic - ONLY shows file names, does NOT show any file detail
  #REMOTE_DIR_CONTENT=$(ssh $REMOTE_HOST -i $SSH_KEY -p $TCP_PORT "ls -Ath $REMOTE_DIR")
  #ssh_exit_status="$?"

  #OPTION 2) complex - shows BOTH file  name and details (if file exists)
  #if following SSH command returns with error exit status, or listing contains a line matching with 'total 0', then return emptry string  
  #REMOTE_DIR_CONTENT=$(ssh -q $REMOTE_HOST -i $SSH_KEY -p $TCP_PORT "ls -Alth $REMOTE_DIR")		#ssh -q option to suppress errors to std out
  REMOTE_DIR_CONTENT=$(ssh $REMOTE_HOST -i $SSH_KEY -p $TCP_PORT "ls -Alth $REMOTE_DIR" 2> /dev/null)		#suppress all error messages
  ssh_exit_status="$?"
  if [[ $ssh_exit_status != 0 ]] || [[ "$REMOTE_DIR_CONTENT" =~ "total 0" ]] 		#if listing shows total of 0 bytes, then return emptry string
  then
    REMOTE_DIR_CONTENT=""
  fi
  EXIT_STATUS=$ssh_exit_status		#$? = exit status of previous 'ssh' command
else
  #directory doesn't exist; set the exit status to error (1)
  EXIT_STATUS=$ERROR
fi

echo "$REMOTE_DIR_CONTENT"		#echo directory listing to standard output - i.e. 'return' listing to caller
exit $EXIT_STATUS			#terminate function with current EXIT_STATUS value
