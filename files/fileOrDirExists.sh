#!/bin/bash
#
##   @Description:   checks whether a directory, either on local or remote host, exists.  Remote connection via SSH
 #   @Requires:      supporting script ./files/lsDirSSH.sh
 #   
 #   @Parameters: either of the following sets (only) - any other will return an error (non-zero) exit status to the caller
 #       localhost syntax:  ./fileOrDirExists <file-dir-to-confirm-exist> <"localhost"> [yes|no]
 #          $1  file or directory to confirm exists (absolute path)
 #          $2  "localhost", to signify the directory is on the local machine
 #          $3  OPTIONAL:  either 'yes' or 'no' string to depict whether the directory may be empty (0 byte contents) or not respectively.
 #
 #       remotehost syntax: ./fileOrDirExists <file-dir-to-confirm-exist> <username> <host-address> <ssh-key> <ssh-port> [yes|no]
 #          $1  file or directory to confirm exists (absolute path) on remote host
 #          $2  IP address, host name, or full domain address of remote host
 #          $3  user name on remote host (must have account on remote host) 
 #          $4  sshKey:  SSH authentication key
 #          $5  sshPort: TCP/UDP port on remote host by which to contact the SSH server
 #          $6  OPTIONAL:  either 'yes' or 'no' string to depict whether the directory may be empty (0 byte contents) or not respectively.
 #                   
 #	@Returns:		exit status of 0 if no errors, and file/directory exists (directory with content if applicable)
 #					exit status of NOT 0 otherwise
 #                  exit status of NOT 0 can also be returned if the user does NOT have sufficient read permissions on the target host.
 #       
# ----------
##FUNCTIONS:
# ----------
#
##Function printUsage ()
 #	Prints to standard out the correct usage of this script.
 #	@param: 	none
 #	@returns:	exit status 0
 #
function printUsage () {  
    local bold=$(tput bold)          #format font in output text to bold    
    local normal=$(tput sgr0)        #return to previous font  

    echo ""
    echo "${bold}Bad arguments!${normal}"
    echo ""
    echo "DESCRIPTION:"
    echo "  $0 checks whether a file/directory exists, either on local or remote host. "    
    echo "  Remote connections are established using SSH.  "
    echo ""
    echo "EXIT VALUES:"
    echo "	1. exit status of 0 if no errors, and file/directory exists (directory with content if applicable)."
    echo "	2. exit status of NOT 0 otherwise."
    echo "  3. exit status of NOT 0 can also be returned if the user does NOT have sufficient read permissions on the target host."
    echo ""
    echo "REQUIREMENTS:"
    echo "  1. SSH"
    echo "  2. Supporting script ./lsDirSSH.sh"
    echo ""
    echo "CURRENT STATUS:"
    echo ""
    echo ""
    echo "SYNTAX - ${bold}local host${normal}: "
    echo "  $0 <file-dir> <\"localhost\"> [yes|no]"
    echo ""
    echo "  where:"
    echo "      file-dir    : \$1, the file or directory (folder) to confirm exists."
    echo "      localhost   : \$2, to indicate file/dir to be located on local host."    
    echo "      yes|no      : \$3, OPTIONAL:  'yes' to indicate that directory may not be empty, 'no' otherwise."
    echo ""
    echo "SYNTAX - ${bold}remote host${normal}: "
    echo "  $0 <file-dir> <host-address> <username> <ssh-key> <ssh-port> [yes|no]"
    echo ""
    echo "  where:"
    echo "      file-dir    : \$1, the file or directory (folder) to confirm exists."
    echo "      host-address: \$2, address of host machine on which to locate file/dir."
    echo "      username    : \$3, the login/user name of the user on remote host."    
    echo "      ssh-key     : \$4, SSH private key for authentiation on remote host."
    echo "      ssh-port    : \$5, TCP/UDP port on remote host by which to contact the SSH server"
    echo "      yes|no      : \$6, OPTIONAL:  'yes' to indicate that directory may not be empty, 'no' otherwise."    
    echo ""
    return 0
}
# ---------------------------------------------------------------------------------------------------------------
    ##VARs
    # ----
    DEBUG_ON=0                 #debug flag (0 = false/off, 1 = true/on) - toggle this to enable/disable user interaction
    bold=$(tput bold)          #format font in output text to bold
    normal=$(tput sgr0)        #return to previous font   

    CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"	#path to the current script
    #resourceDir="$CURRENT_DIR/files"                                              #helper scripts
    resourceDir="$CURRENT_DIR"
    ERROR=1					          #if incorrect number parameters received, or any execution error occured
    SUCCESS=0
    #local REGEX=""					#regular expression by which to match files in question
    EXIT_STATUS=$SUCCESS		#function return/exit status (default: success (0))

    #for all hosts
    FILE_OR_DIR=""					#store locally absolute path to file or directory to check
    HOST=""                   #host address or name
    dirMayBeEmpty="no"       #directory may be empty ("yes"), or not ("no"):  default is "no"
    
    #for remote hosts (SSH)
    userName=""               #user name on HOST
    sshPort=""                #TCP port used by SSH
    sshKey=""                 #[en]|[de]cryption key for SSH    

    #flags  (used in numericla testing (( .. )); ie. 1=TRUE, 0=FALSE)
    DIR_EXIST=0
    FILE_EXIST=0
  
    ##DEBUG:
     if (($DEBUG_ON)); then
      echo -e "\nDEBUG: Entering script $0 ..."
      read -p "DEBUG: Press [Enter] key to continue..." key
      echo ""
     fi
    #

    ##CHECK NUM PARAMS RECEIVED GREATER THAN 0, ELSE EXIT WITH ERROR STATUS
    # ---------------------------------------------------------------------
    if [[ ! $# -gt 0 ]]; then
        printUsage       
        EXIT_STATUS=$ERROR
        exit $EXIT_STATUS
    fi

    ##DEBUG:
     if (($DEBUG_ON)); then
      echo -e "\n${bold}DEBUG: Num arguments received: $#${normal}"
      #read -p "DEBUG: Press [Enter] key to continue..." key
      #echo ""
     fi
    #

    ##CHECK NUM PARAMS RECEIVED AND SET LOCAL VARs
    # Return to caller with (non-zero) ERROR status if any of the following conditions are not met:
    # --------------------------------------------------------------------------------------------
    if [[ ( $# -ge 2 && $# -le 3 ) ]]; then      
      if [[ $# -eq 2 ]] && [[ ! -z "$1" ]] && [[ ! -z "$2" ]]; then FILE_OR_DIR="$1"; HOST="$2"; dirMayBeEmpty="no"; fi
      if [[ $# -eq 3 ]] && [[ ! -z "$1" ]] && [[ ! -z "$2" ]] && [[ ( "$3" == "yes" || "$3" == "no" ) ]]; then FILE_OR_DIR="$1"; HOST="$2"; dirMayBeEmpty="$3"; fi      
    elif [[ ( $# -ge 5 ) && ( $# -le 6 ) ]]; then
      if [[ $# -eq 5 ]] && [[ ! -z "$1" ]] && [[ ! -z "$2" ]] && [[ ! -z "$3" ]] && [[ ! -z "$4" ]] && [[ ! -z "$5" ]]; then FILE_OR_DIR="$1"; HOST="$2"; userName="$3"; sshKey="$4"; sshPort="$5"; dirMayBeEmpty="no"; fi      
      if [[ $# -eq 6 ]] && [[ ! -z "$1" ]] && [[ ! -z "$2" ]] && [[ ! -z "$3" ]] && [[ ! -z "$4" ]] && [[ ! -z "$5" ]] && [[ "$6" == "yes" || "$6" == "no" ]]; then  FILE_OR_DIR="$1"; HOST="$2"; userName="$3"; sshKey="$4"; sshPort="$5"; dirMayBeEmpty="$6"; fi
    else
        printUsage
        EXIT_STATUS=$ERROR
    	exit $EXIT_STATUS          
    fi

    ##DEBUG:
     # individually loop through every argument ($1,$2,... $n), echoing each to stdout
     if (($DEBUG_ON)); then     
      c=1;      
      for arg in "$@"; do
        echo "DEBUG: Argument received: \$$c = $arg"      
        c=$(($c+1))      
      done
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key
      echo ""
     fi
    #  

    ##DEBUG:
     # individually loop through every possible variable {s1...s6}, echoing each to stdout
     if (($DEBUG_ON)); then     
      echo "${bold}DEBUG:  Variables set:${normal}"
      echo "DEBUG:  var FILE_OR_DIR = $FILE_OR_DIR"
      echo "DEBUG:  var HOST = $HOST"      
      echo "DEBUG:  var userName = $userName"
      echo "DEBUG:  var sshKey = $sshKey"
      echo "DEBUG:  var sshPort = $sshPort"      
      echo "DEBUG:  var dirMayBeEmpty = $dirMayBeEmpty"
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key
      echo ""
     fi
    #

    ##Check that the directory (either on remote or local host) exists.
    # Terminate under the following conditions:
    #	1. file/directory does not exist.
    #	2. directory exists, but is empty when dirMayBeEmpty flag is set to 'no' (cannot be empty, cannot be 0 bytes in size)
    # -----------------------------------------------------------------------------------------------------------------------
    if [[ ( "$HOST" != "localhost" ) ]]; then
        #Confirm file/directory exists on REMOTE host - ie. authenticate via ssh, then run tests [[ -d $FILE_OR_DIR ]] and [[ -f $FILE_OR_DIR ]] on remote host. 
        # Pending test return results, set appropriate flag to indicate presense of either directory or file
        #
        #if $(ssh $userName@$HOST -i $sshKey -p $sshPort [[ -d '$FILE_OR_DIR' ]]); then $DIR_EXIST=1; else $DIR_EXIST=0; fi
        ssh $userName@$HOST -i $sshKey -p $sshPort "[[ -d '$FILE_OR_DIR' ]]"
        if [[ "$?" == "0" ]]; then DIR_EXIST=1; else DIR_EXIST=0; fi
        

        #if $(ssh $userName@$HOST -i $sshKey -p $sshPort [[ -f '$FILE_OR_DIR' ]]); then $FILE_EXIST=1; else $FILE_EXISTS=0; fi
        ssh $userName@$HOST -i $sshKey -p $sshPort "[[ -f '$FILE_OR_DIR' ]]"
        if [[ "$?" == "0" ]]; then FILE_EXIST=1; else FILE_EXIST=0; fi

        ##DEBUG:
         if (($DEBUG_ON)); then
            echo -e "\n${bold}DEBUG (HOST != localhost): Checking DIR_EXIST and FILE_EXIST: ${normal} 0/doesn't exist, 1/does."
            echo    "DEBUG: DIR_EXIST = $DIR_EXIST, FILE_EXIST = $FILE_EXIST"
            echo ""
            read -p "DEBUG: Press [Enter] key to continue..." key
            echo ""
         fi
        #

        if (( $DIR_EXIST )); then         
            #if dirMayBeEmpty flag is set NOT to allow the directory to be empty (i.e. must have **SOME** content listed), 
            #BUT the directory is in fact empty (0 bytes), then set the EXIT_STATUS with error (non-zero) value
	        #
	        if [[ $dirMayBeEmpty == "no" ]] && [[ "$($resourceDir/lsDirSSH.sh $FILE_OR_DIR "$userName@$HOST" $sshKey $sshPort)" == "" ]]; then  #lsDirSSH.sh syntax: <REMOTE_FILE_OR_DIR> <REMOTE_HOST> <SSH_KEY> <TCP_PORT>	            
                #EXIT_STATUS="$?"            
                EXIT_STATUS="$ERROR"
    	        #exit $EXIT_STATUS
            else
                EXIT_STATUS="$SUCCESS"
	        fi
        elif (( $FILE_EXIST )); then
            EXIT_STATUS="$SUCCESS"
        else
            EXIT_STATUS="$ERROR"          
            #exit $EXIT_STATUS
        fi  
    else
        #confirm file/directory is on the LOCAL host - set error exit status if either the file/directory does
        #NOT exist, or the directory exists but is empty when it shouldn't be (i.e. the dirMayBeEmpty flag is set to 'no')
        #

        #if [[ ( ! -d "$FILE_OR_DIR" ) || ( -d '$FILE_OR_DIR' && $dirMayBeEmpty == "no" && $(ls "$FILE_OR_DIR") == "" ) ]]; then DIR_EXIST=0; else DIR_EXIST=1; fi
        if [[ ! -d "$FILE_OR_DIR" ]]; then DIR_EXIST=0; else DIR_EXIST=1; fi
        if [[ ! -f "$FILE_OR_DIR" ]]; then FILE_EXIST=0; else FILE_EXIST=1; fi

        if (( $DIR_EXIST )) && [[ $dirMayBeEmpty == "no" && $(ls "$FILE_OR_DIR") == "" ]]; then 
            EXIT_STATUS="$ERROR"
        elif (( $DIR_EXIST | $FILE_EXIST )); then
            EXIT_STATUS=$SUCCESS
            #exit $EXIT_STATUS
        else         
            #EXIT_STATUS="$?"      
            EXIT_STATUS=$ERROR
            #exit $EXIT_STATUS
        fi  

        ##DEBUG:
         if (($DEBUG_ON)); then
            echo -e "\n${bold}DEBUG (HOST == localhost): Checking DIR_EXIST and FILE_EXIST: ${normal} 0/doesn't exist, 1/does."
            echo    "DEBUG: DIR_EXIST = $DIR_EXIST, FILE_EXIST = $FILE_EXIST"
            echo ""
            read -p "DEBUG: Press [Enter] key to continue..." key
            echo ""
         fi
        #        
    fi
  
    ##DEBUG:
     if (($DEBUG_ON)); then      
      echo -e "\nDEBUG: Leaving script $0  ..."      
        if [[ $EXIT_STATUS != 0 ]]; then 
            echo "${bold}DEBUG:  EXIT_STATUS = $EXIT_STATUS (file/dir DOES NOT exist, dir is empty when not expected to be.)${normal}"
        else 
            echo "${bold}DEBUG:  EXIT_STATUS = $EXIT_STATUS (file/dir DOES exist)${normal}"
        fi
      echo ""
      read -p "DEBUG: Press [Enter] key to continue..." key
      echo ""
     fi
    #

## Return to caller with EXIT STATUS
# ----------------------------------
exit $EXIT_STATUS					#either 0 (successful function completion) or not (function completed with errors)
