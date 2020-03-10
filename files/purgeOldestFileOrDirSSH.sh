#!/bin/bash

## BASH Script:     purgeOldestFileOrDirSSH.sh
 #	@Description:   Checks for the oldest file/folder in a list of files/folders (matched by regular expression) in a given directory/folder 
 #                  on either LOCAL or REMOTE host, then deletes it.
 #
 #  @Status:        v2.22: STATUS: TESTING PHASE
 #                  1. issues when receiving a --regex parameter
 #                      >   the regular expression that works in the calling script doesn't work correctly here!
 #                          The reason for this is because the regex string doesn't find any matches when either 'checking for list of FILES'
 #                          or 'checking for list of DIRECTORIES', in turn because of the way it is used with grep here.  Either
 #                          you'll have to rethink the order in which the regex is used here, or write code that automatically ammend the regex
 #                          to 'fit' the code here.
 #
 #                  v2.21:
 #                      - purging of both LOCAL and REMOTE files and directories works correctly:
 #                          > works correctly with or without the use of double quotes for --dir parameter (eg. --dir="/mnt" or --dir=/mnt)
 #                          > works correctly with or without white spaces in the --dir parameter (eg. --dir="/mnt/dir with spaces/dir2/file one" etc.) 
 #  
 #  @Requires:      1. SSH installed on both local and remote hosts.
 #                  2. The host running this script have been SSH authenticated on the remote host previously.
 #
 #  @Syntax:        ./purgeOldestFileOrDirSSH.sh [--debug] <-d|-f> --dir=<"/dir/to/evaluate"> --regex=<"regular-expression"> [ user@host --ssh-key=<key> --port=<port> ]
 #
 #	@Parameters:	Order not important, as long as 6 no. parameters received, each preceded with correct switch:
 #                      - either "-d" or "-f" switch to signal deletion of a directory or file respectively (but not both)
 #						- "--dir=" or "--dir " switch followed by directory containing the files/folders to evaluate
 #                      - "--regex=" followed by regular expression by which to match a list of files/folders respectively, out of which to delete the oldest.
 #                      - "--key=" followed by path to SSH private key with which to authenticate to SSH server
 #                      - "--port=" followed by the TCP/UDP port at which the SSH server is listening at
 #                      - "@" preceded by the user login name of the remote server, and followed by the address of the remote host (ie. either host-name, domain-name or IP address)
 #                      - "--debug" for interactive debugging output.
 #                      - "--help" to display usage.
 #                    
 #      eg.:  to purge oldest dir     ./purgeOldestFileOrDirSSH -d andre@skyqode.ddns.net --ssh-key /home/andre/.ssh/id_rsa_skyqode1 --port=22 --dir="/home/andre/DELETE_ANYTIME" --regex=".*"
 #            to purge oldest file    ./purgeOldestFileOrDirSSH -f --dir="/home/andre/DELETE_ANYTIME" --regex=".*(rsync)+.*(log)"
 #                    
 #	@Returns:       exit status of 0 if no errors, and file/forlder deleted succesfully
 #					exit status of NOT 0 otherwise
 #
#-----------------------------------------

##FUNCTIONS:
# ----------
#
##Function printUsage ()
 #	Prints to standard out the correct usage of this script.
 #	@param: 	none
 #	@returns:	exit status 0
 #
function printUsage () {  
    echo ""
    echo "Bad arguments!"
    echo ""
    echo "DESCRIPTION: "
    echo "  $0 checks for the oldest file or folder in a list of files or folders (matched" 
    echo "  by regular expression) in a given directory on either local or remote host, and then deletes it."
    echo ""
    echo "CURRENT STATUS:"
    echo "  Purging of both LOCAL and REMOTE files and directories works correctly:"
    echo "      - works correctly with or without the use of double quotes for --dir parameter (eg. --dir=\"/mnt\" or --dir=\/mnt)"
    echo "      - works correctly with or without white spaces in the --dir parameter (eg. --dir=\"/mnt/dir with spaces/dir2/file one\" etc.)"
    echo ""
    echo "SYNTAX - local host: "
    echo "  $0 <-d|-f> --dir=</path/to/evaluate> [--regex=<regular-expression>"]
    echo ""
    echo "  where:"
    echo "      -d|-f       : evaluate either directories (d) or files (f) only."    
    echo "      --dir       : absolute path to content (files or directories) to evaluate."
    echo "                  : NOTE: paths with white spaces to be enclosed in double quotes, eg. --dir=\"/home/user/a file path/\""
    echo ""
    echo "      --regex     : OPTIONAL:  regular expression by which to match content (files or directories).  Default --regex=\".*\""
    echo "      --debug     : OPTIONAL:  interactive outputs & debugging."
    echo "      --help      : OPTIONAL:  prints to stdout this text."
    echo ""
    echo "SYNTAX - remote host: "
    echo "  $0 <-d|-f> --dir=</path/to/evaluate> [--regex=<regular-expression>] <user>@<host-address> --key=<key> --port=<port>"
    echo ""
    echo "  where:"    
    echo "      -d|-f       : evaluate either directories (d) or files (f) only."    
    echo "      --dir       : path to content (files or directories) to evaluate."
    echo "                  : NOTE: paths with white spaces to be enclosed in double quotes, eg. --dir=\"/home/user/a file path/\""
    echo ""
    echo "      --regex     : OPTIONAL:  regular expression by which to match content (files or directories).  Default --regex=\".*\""
    echo "      --ssh-key   : SSH private key."
    echo "      --port      : TCP/UDP port at which SSH server listens."
    echo "      user@host   : login and host address of remote server."    
    echo "      --debug     : OPTIONAL:  interactive outputs & debugging."
    echo "      --help      : OPTIONAL:  prints to stdout this text."
    echo ""
  return 0
}

## Function hostExists()
 #   Tests whether the host address (argument 1) received is reachable (pings succesfully) or not, 
 #      i.e. if the IP address, host name or domain name exists.
 #
 #   @param:       ($1) either host name, IP address or domain name 
 #   @returns:     returns 0 (true) if address exists, 1 (false) if it doesn't or other error occured.
 #
function hostExists () {
  # check number of arguments passed (must be exactly 1, or terminate the script)
  if [ $# -ne 1 ];then
    echo "Please Enter (only) one host destination (e.g. IP, host-name or domain)"
    return 1
    #exit 1
  fi

  # save the first command argument (address) as a string
  local dst_addr="$1"  
  local EXIT_STATUS=0       #default return value: 0 (success)

  # ping the address to see if it exists on LAN/WAN
  # (note: redirect both stdout & stderr to null device to discard output, but retain whether command (ping) was succesful or not. 
  #        Required to discard output so that final [echo "EXIT_STATUS"] is the only output "seen" by the caller) >> UPDATE: deprecated
  ping -c 1 -w 5 $dst_addr > /dev/null 2>&1

  # check return status of previous command (i.e. if ping returned with '0'/true )
  if [[ $? -eq 0 ]]; then EXIT_STATUS=0; else EXIT_STATUS=1; fi

  # return 0 (host exists) or 1 (host doesn't exist or error occured)
  # echo "#EXIT_STATUS"
  return $EXIT_STATUS
}

##----------------------------------------------------------------------------------------------------------------
##DEBUG:
 #echo -e "DEBUG: \nEntering script $0 ..."
 #read -p "DEBUG: Press [Enter] key to continue..." key
# e/o debug

##VARs  
 ERROR=1						#if not exactly 1 parameter (directory name) received, or any execution error occured
 SUCCESS=0
 EXIT_STATUS=$SUCCESS		#function return/exit status (default: success (0))    
 OPT=""                      #either "-d" or "-f" option, ie. to indicate either directory or file to be deleted
 DIR=""						#absolute path to directory containing files/folders to evaluate
 REGEX=".*"				    #regular expression by which to match files/directories in question (default: ".*")
 list=""                     #list of either files or folders (but not both)
 toDelete=""                 #absolute path to either file or folder to delete
 REMOTEHOST=0                #flag to differentiate btwn local and remote host (default: 0 (not remote host))
 USER=""                     #user login on remote host
 HOST=""                     #host name, IP address or domain name of host running SSH server
 SSH_KEY=""                  #absolute path to SSH private key (for authentication)
 PORT="22"                   #TCP/UDP port at which SSH server listens (default: 22)
 DEBUG_ON=0                  #flag to flip debug output (default: 0, off)
 bold=$(tput bold)          #format font in output text to bold
 normal=$(tput sgr0)        #return to previous font
#

##DEBUG: 
 if (( $DEBUG_ON )); then echo -e "DEBUG:  $# arguments received.\n"; fi 
# e/o debug

# individually loop through every function parameter ($1,$2,... $n), assigning parameters received to VARs    
for i in "$@"; do                                                               
    if [[ ( $i == "-d" || $i == "-f" ) ]]; then OPT="$i"    
    elif [[ $i == "--debug" ]]; then DEBUG_ON=1
    elif [[ $i == *"--dir="* ]]; then 
        DIR="$(echo "$i" | cut -d "=" -f2)"                                     # cut parameter string (eg. --dir=/mnt) by delimeter "=", then return 2nd field (ie. after the delimiter) to DIR    
        #DIR="$(echo "$i" | cut -d "=" -f2 | sed 's/ /\\ /g')"                    # cut parameter string (eg. --dir=/mnt) by delimeter "=", then return 2nd field (ie. after the delimiter) to DIR    
    elif [[ $i == *"--regex="* ]]; then REGEX="$(echo "$i" | cut -d "=" -f2)"           
    elif [[ $i == *"--port="* ]]; then PORT="$(echo "$i" | cut -d "=" -f2)"    
    elif [[ $i == *"--ssh-key="* ]]; then SSH_KEY="$(echo "$i" | cut -d "=" -f2)"    
    elif [[ $i == *"@"* ]]; then USER="$(echo "$i" | cut -d "@" -f1)"; HOST="$(echo "$i" | cut -d "@" -f2)"
    elif [[ $($i | grep -Ei) == "--help" ]]; then printUsage; EXIT_STATUS=$ERROR; exit $EXIT_STATUS
    else 
        printUsage
        EXIT_STATUS=$ERROR
        exit $EXIT_STATUS
    fi
done

##DEBUG: 
 if (( $DEBUG_ON )); then
    echo ""
    echo "DEBUG:  OPT = $OPT"
    echo "DEBUG:  DIR = $DIR"
    echo "DEBUG:  REGEX = $REGEX"
    echo "DEBUG:  PORT = $PORT"
    echo "DEBUG:  SSH_KEY = $SSH_KEY"
    echo "DEBUG:  USER = $USER"
    echo "DEBUG:  HOST = $HOST"
    echo ""
    #read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
 fi
# e/o debug

##Perform some string corrections on --dir entry
# remove Trailing forward slashe
DIR="$(echo $DIR | sed 's:/$::')"                       

##DEBUG:
 if (( $DEBUG_ON )); then
    echo "DEBUG:  \$DIR = $DIR" 
    #read -p "DEBUG: Press [Enter] key to continue..." key  
    echo ""
 fi
# e/o debug

##VALIDATE NUMBER OF LOCAL OR REMOTE HOST VARs
#   - both type hosts require entries for variables: OPT, DIR, REGEX at minimum.  Fail if absent.
if [[ -z $OPT || -z $DIR || -z $REGEX ]]; then printUsage; EXIT_STATUS=$ERROR; exit $EXIT_STATUS; fi
#   - if more than 3 arguments received (ie. assume remote host), then additional entries required for variables: PORT, SSH_KEY, USER and HOST.  Fail if absent.
#if [[ ( $# -gt 3 && (( ! $DEBUG_ON )) ) || ( $# -gt 4 && (( $DEBUG_ON )) ) ]]; then
if [[ ( $# -gt 5 && (( $DEBUG_ON )) ) || ( $# -gt 4 && (( ! $DEBUG_ON )) ) || ( $# -gt 3 && (( $DEBUG_ON )) ) ]]; then
    if [[ -z "$PORT" || -z "$SSH_KEY" || -z "$USER" || -z "$HOST" ]]; then 
        printUsage
        EXIT_STATUS=$ERROR
        exit $EXIT_STATUS    
    else 
        #set the REMOTEHOST flag to '1' so that subsequent [ if (( $REMOTEHOST)); then ... ] numerical tests can branch in different directions pending host location
        REMOTEHOST=1    
        
        #confirm remote host exists                
        if (( $DEBUG_ON )); then
            echo "DEBUG:  checking remote host $HOST exists...."                         
        fi        
        if [[ $(hostExists $HOST) -ne 0 ]]; then
            echo "\nERROR: remote host not found.  Terminating script.\n"
            exit 1
        else
            if (( $DEBUG_ON )); then
                echo "DEBUG:  remote host $HOST found!!!"                         
            fi
        fi        
        
        ##DEBUG:
         #if (( $DEBUG_ON )); then
         #    echo ""
         #    echo "REMOTEHOST!!"
         #    read -p "DEBUG: Press [Enter] key to continue..." key  
         #    echo ""
         #fi
        # e/o debug

        #confirm ssh key exists - else terminate script
        if [[ ! -f $SSH_KEY ]]; then echo -e "\nERROR: SSH key not found.  Terminating script.\n"; exit 1; fi

    fi
fi

##CHECK $OPT, then create a list of either files or folders (not both)
#
if [[ $OPT == "-f" ]]; then 
    #get list of all the FILES in $DIR, sorted by date & time, then file name, in increasing alphanumeric order
    if (( $REMOTEHOST )); then         
        if (( $DEBUG_ON )); then
            echo -e "\nDEBUG: checking for list of FILES on REMOTE host..."
            #read -p "DEBUG: Press [Enter] key to continue..." key
        fi
        
        #list="$(ssh "$USER@$HOST" -i "$SSH_KEY" -p "$PORT" "ls -A --full-time '$DIR'" | grep -E "^[^d].*" | sort -k6,8 -k9,9 | grep -Ei "$REGEX" | grep -Evi "^(total)")"
        list="$(ssh "$USER@$HOST" -i "$SSH_KEY" -p "$PORT" "ls -A --full-time '$DIR'" | grep -E "^[^d].*" | sort -k6,8 -k9,9 | grep -Evi "^(total)")"
            # where:    
            #           ls -A --full-time '$DIR'    = list directory content showing long format incl. full date & time (year, month, day, time, etc.)
            #           |                           = pipe output of previous command to next command
            #           grep -E "^[^d].*"           = match input received by regular expression (case sensitive) starting NOT with 'd' (ie. not directories)
            #           sort -k6,8 -k9,9            = sort input received first by date/time in columns 6 through 8 (first by 6, then 7, then 8), then by filename in column 9
            #           grep -Ei $REGEX             = match input received by regular expression REGEX (case sensitive)
            #           grep -Evi "^(total)"        = finally match input received to exclude (-v) only those lines starting (^) with all of the letters 'total'
            #                                         (ie. this will remove the line "total ..." from the final output returned to 'list')
        EXIT_STATUS="$?"
    else
        if (( $DEBUG_ON )); then
            echo -e "\nDEBUG: checking for list of FILES on LOCAL host..."
            #read -p "DEBUG: Press [Enter] key to continue..." key
        fi

        #list="$(ls -A --full-time "$DIR" | grep -E "^[^d].*" | sort -k6,8 -k9,9 | grep -Ei "$REGEX" | grep -Evi "^(total)")"        
        list="$(ls -A --full-time "$DIR" | grep -E "^[^d].*" | sort -k6,8 -k9,9 | grep -Evi "^(total)")"        
        EXIT_STATUS="$?"
    fi    
else 
    #get list of all the FOLDERS in $DIR, sorted by date & time, then file name, in increasing alphanumeric order    
    if (( $REMOTEHOST )); then 
        if (( $DEBUG_ON )); then
            echo -e "\nDEBUG: checking for list of DIRECTORIES on REMOTE host..."
            #read -p "DEBUG: Press [Enter] key to continue..." key
        fi

        #list="$(ssh "$USER@$HOST" -i "$SSH_KEY" -p "$PORT" "ls -A --full-time '$DIR'" | grep -E "^d.*" | sort -k6,8 -k9,9 | grep -Ei "$REGEX" | grep -Evi "^(total)")"    
        list="$(ssh "$USER@$HOST" -i "$SSH_KEY" -p "$PORT" "ls -A --full-time '$DIR'" | grep -E "^d.*" | sort -k6,8 -k9,9 | grep -Evi "^(total)")"    
        # where:
        #           grep -E "^[^d].*"       = match input received by regular expression (case sensitive) starting NOT with 'd' (ie. not directories)
        EXIT_STATUS="$?"
    else
        if (( $DEBUG_ON )); then
            echo -e "\nDEBUG: checking for list of DIRECTORIES on LOCAL host..."
            #read -p "DEBUG: Press [Enter] key to continue..." key
        fi
        
        #list="$(ls -A --full-time "$DIR" | grep -E "^d.*" | sort -k6,8 -k9,9 | grep -Ei "$REGEX" | grep -Evi "^(total)")"        
        list="$(ls -A --full-time "$DIR" | grep -E "^d.*" | sort -k6,8 -k9,9 | grep -Evi "^(total)")"   
        EXIT_STATUS="$?"
    fi
fi

##DEBUG: 
 if (( $DEBUG_ON )); then
    echo -e "DEBUG: list is:"
    if [[ -z "$list" ]]; then echo -e "${bold}EMPTY! Nothing to delete.${normal}\n"; else echo -e "$list\n"; fi    
    #read -p "DEBUG: Press [Enter] key to continue..." key
 fi
# e/o debug

#toDeleteFileDir="$( echo "$list" | sed -n '1p' | sed 's/.*[0-9][0-9][0-9][0-9]\ //')"
toDeleteFileDir="$( echo "$list" | sed -n '1p' | sed 's/.*[0-9][0-9][0-9][0-9]\ //' | grep -Ei "$REGEX")"
toDelete="$DIR/$toDeleteFileDir"

##DEBUG: 
 if (( $DEBUG_ON )); then
    if [[ -z "$list" ]]; then 
        echo -e "DEBUG: ${bold}list is empty ${normal}.  Check your command parameters again."
    else
        echo -e "DEBUG: ${bold}toDelete = $toDelete${normal}"
    fi
    echo ""
    read -p "DEBUG: Press [Enter] key to continue ..." key
 fi
# e/o debug

##Delete the file/folder toDelete (but not the parent folder!); then save the exit status to be returned to caller
#
if [[ ($OPT == "-f" && "$toDelete" != "" && "$toDelete" != "$DIR/") ]]; then 
    if (( $REMOTEHOST )); then 
        ssh $USER@$HOST -i $SSH_KEY -p $PORT "rm '$toDelete'"
        EXIT_STATUS="$?"
    else
        rm "$toDelete"
        EXIT_STATUS="$?"
    fi
fi
if [[ ($OPT == "-d" && "$toDelete" != "" && "$toDelete" != "$DIR/") ]]; then 
    if (( $REMOTEHOST )); then 
        ( ssh "$USER"@"$HOST" -i "$SSH_KEY" -p "$PORT" "rm -r '$toDelete'" )
        EXIT_STATUS="$?"
    else
        rm -r "$toDelete"
        EXIT_STATUS="$?"
    fi
fi

exit $EXIT_STATUS					#either 0 (successful function completion) or not (function completed with errors)

##=====================================================================================
## SCRAPS OF CODE NOT USED - DELETE ANYTIME
#

 #Escape white spaces in $DIR with '\ ' and remove trailing forward slash
 #if [[ $DIR == *" "* ]]; then
 #    if (($DEBUG_ON)); then echo "...escaping white spaces in --dir entry"; fi
 #    #DIR="$(echo $DIR | sed 's/\ /\\ /g')"
 #    DIR="$(echo $DIR)"
 #fi

 #OPT=$1   # option
 #FILE=$2  # filename
 # test -e and -E command line args matching
 #case $OPT in
 #  -e|-E) 
 #  	echo "Editing $2 file..." 
 #        # make sure filename is passed else an error displayed   
 #  	[ -z $FILE ] && { echo "File name missing"; exit 1; } || vi $FILE	
 #  	;;
 #  -c|-C) 
 #  	echo "Displaying $2 file..." 
 #  	[ -z $FILE ] && { echo "File name missing"; exit 1; } || cat $FILE	
 #  	;;
 #  -d|-D) 
 #  	echo "Today is $(date)" 
 #  	;;
 #   *) 
 #    echo "Bad argument!" 
 #    echo "Usage: $0 -ecd filename"
 #    echo "	-e file : Edit file."
 #    echo "	-c file : Display file."
 #    echo "	-d      : Display current date and time."	
 #    ;;
 #esac

 #for i in "$@"; do
 #    #echo "DEBUG:  $i"
 #     case "-d" in
 #        $i)
 #            continue            
 #            ;;
 #        $i)
 #            continue
 #            ;;
 #        $i)
 #            continue
 #            ;;        
 #    esac
 #done

 #for ((i = 1; i <= $@; i++)); do                                   # individually loop through every function parameter ($1,$2,... $n)
 #    ##DEBUG: comment in for debugging
 #    echo -e "DEBUG:  $i"
 #
 #    case $i in                                      # eg. on first loop $i = $1
 #        # if ith argument received from caller:
 #        "-d"|"-f")
 #            OPT="$i"
 #            ;;
 #        "--dir=")
 #            DIR="$(echo "$i" | cut -d "=" -f2)"       # cut line with delimeter "=", then select 2nd field (ie. after the delimiter)
 #            ;;
 #        "--regex=")
 #            REGEX="$(echo "$i" | cut -d "=" -f2)"       # cut line with delimeter "=", then select 2nd field (ie. after the delimiter)
 #            ;;
 #        *)
 #            printUsage
 #            EXIT_STATUS=$ERROR
 #            exit $EXIT_STATUS;
 #            ;;
 #    esac  
 #done

 #get list of all the FILES in $DIR 
 # > to sort by date and time from oldest to newest modification date & time, include -tr switches 
 # > to sort by name exclude -tr switches, or include pipe to sort by column 9 (eg.: | sort -k9,9 )    
 #list="$(ls -ltrA $DIR | sort -k9,9 | grep -E "^[^d].*" | grep -Ei "$REGEX")" 
 ## where:  list -ltrA            = list directory content in long format (l), by date & time (t), 
 #                                  in reverse (r) order (ie. oldest first)
 #                                  excl. directories . & .. ((A), if any)
 #          |                     = pipe output to
 #          grep -E "^[^d].*"     = match by regular expression (case sensitive) the lines starting NOT with 'd' (ie. not directories)
 #          |                     = pipe output to
 #          grep -Ei "$REGEX"     = match by regular expression (case insensitive) in REGEX