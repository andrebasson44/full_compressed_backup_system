#!/bin/bash
#
##PROGRAM: fileExist
# ============================================================================================================
#  VERSION:		v1.0
#  PARAMS: 		
#				if no param:		Echo to standard output the program description and usage.
#				if one param:		$1	=	absolute path of file name to check if it exists
#				if two params:		$1	=	base file name to check for existence
#									$2	=	absolute path of directory to check for file
#				
#
#  RETURNS:		"true" 		echoed to std out if file exists in directory
#				"false"		echoed to std out if file does not exist in directory, directory does not exist, 
#							or another minor error occurs
#
#  EXIT STATUS:	0			if program succesfully executes to completion
#				1			if a minor error occurs
#				250			if less or more than 2 parameters passed to function
#
# ------------------------------------------------------------------------------------------------------------
#
##FUNCTIONS:
#
# fExist ()
#	Description:	Checks if a file exists, at a certain directory (absolute path)
#
#  	Params: 	$1		file name to check if exists
#				$2		directory name to check within
#
#  	Returns:	true	if file exists in directory
#				false	if files does not exist in directory, or any other outcome (e.g. error) occurs
#
function fExist ()
{ 
  ##DEBUG:
  #echo -e "DEBUG: \nFunction fExist () entered..."

  ##LOCAL VARs
  local ERROR=1							#if less than 2 parameters received, or any execution error occured
  local SUCCESS=0					
  local FILE=""							#store locally name of file to check for existence
  local DIR=""							#store locally absolute path to directory to check
  local EXIST=false						#local flag to idicate whether file exists (default: false)
  local EXIT_STATUS=$SUCCESS			#function return/exit status (default: success (0))
  
  ##CHECK PARAMS RECEIVED & SET FILE / DIR VARs
  #	Return to caller if either 1st ($1) or 2nd parameter ($2) passed is zero, or empty, or directory ($2) doesn't exist.
  # Else: set variables FILE and DIR
  #
  if [[ -z "$2" ]] || [[ ! -d "$2" ]] || [[ -z "$1" ]]; then	
  	EXIST=false
	echo $EXIST
	EXIT_STATUS=$ERROR
	return $EXIT_STATUS
  else  
  	FILE=$1
	DIR=$2
  fi

  #get list of filenames (if any) in DIR
  local CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"	#store current path  
  cd $DIR								#for next command must change to directory in question first
  shopt -s nullglob						#SET (s) nullglob option in bash; returns an array of filenames (*) in DIR
  local fileNamesListedInResourceDir=(*)		#store file names in array
  shopt -u nullglob						#UNSET (u) nullglob option in bash (i.e. return to previous shell option state)
  cd $CURRENT_DIR						#change back to directory where this script is running from
  
  #cycle over fileNamesListedInResourceDir and look for match to FILE 
  for rf in ${fileNamesListedInResourceDir[*]}
  	do
		if [[ $rf == $FILE ]]; then
			EXIST=true					#set flag to true (0)
			break						#EXIT_STATUS=$ERR_PARAMthen break out of for loop
		else
			continue					#optional: continue with next for iteration
		fi	
	done

  ##DEBUG:
  #echo -e "DEBUG: \n-FILE = $FILE	\n-DIR = $DIR	CURRENT_DIR = $CURRENT_DIR	\n-fileNamesListedInResourceDir = $fileNamesListedInResourceDir"

  echo $EXIST							#either 'true' or 'false' returned to caller
  return $EXIT_STATUS					#either 0 (successful function completion) or not (function completed with errors)
}
# -------------------------------------------------------------------------------------------------------
#
##PROGRAM VARIABLES
# -----------------
ERR_DIR=1							#if directory does not exist, file is not found in directory, or other minor error
ERR_PARAM=250						#if insufficient parameters passed to function
FILE_EXIST=false					#flag, default false
EXIT_STATUS_SUCCESS=0				#default: 0 (success)
EXIT_STATUS=$EXIT_STATUS_SUCCESS
PROG_DESCRIPTION="
	PROGRAM:	fileExist.sh
	VERSION:	v1.0
	PARAMS:		if no param:		Echo to standard output the program description and usage.
			if one param:		\$1	=	absolute path of file name to check if it exists
			if two params:		\$1	=	base file name to check for existence
						\$2	=	absolute path of directory to check for file
				
	RETURNS:	\"true\" 		echoed to std out if file exists in directory
			\"false\"		echoed to std out if file does not exist in directory, directory does not exist, 
					or another minor error occurs
	
	EXIT STATUS:	0		if program succesfully executes to completion
			1		if a minor error occurs
			250		if less or more than 2 parameters passed to function\n"

##PROGRAM CODE
# ------------
#follow different lines of processing based on numbers parameters passed;
#each occasion setting the FILE_EXIST and/or EXIT_STATUS variables before
#
case $# in
0)	
  	##DEBUG:
  	#echo -e "DEBUG: case 0 fired"
	
	#incorrent number of parameters passed (max 2 allowed)
	echo -e "$PROG_DESCRIPTION"
	FILE_EXIST=false	
	EXIT_STATUS=$ERR_PARAM
	;;
1)
  	##DEBUG:
  	#echo -e "DEBUG: case 1 fired"
	
	##1 parameter passed:  file path includes file to check for existence ($1)
	# check if file exists at the path give, and that you have read permission
	if [[ -r $1 ]]; then
		FILE_EXIST=true		
	fi
	;;
2)
  	##DEBUG:
  	#echo -e "DEBUG: case 2 fired"
	
	##2 parameters passed: file name ($1), absolute file path ($2)
	# check directory exists
	if [[ -d  $2 ]]; then			#if directory exists
  		if [[ -z $1 ]]; then		#true if 1st parameter passed is zero, or empty
			FILE_EXIST=false
			EXIT_STATUS=$ERR_PARAM
		else
			FILE_EXIST="$(fExist $1 $2)"
			EXIT_STATUS=$?					#exit status of fExist function call
		fi			
	else
		FILE_EXIST=false
		EXIT_STATUS=$ERR_DIR  			
	fi
	;;
*)	
  	##DEBUG:
  	#echo -e "DEBUG: case 3 fired"
	
	#incorrent number of parameters passed (max 2 allowed)
	echo -e "$PROG_DESCRIPTION"
	FILE_EXIST=false	
	EXIT_STATUS=$ERR_PARAM
	;;
esac

##PROGRAM EXIT
# ------------
echo "$FILE_EXIST"			#echo to std out ('returned' to caller)
exit $EXIT_STATUS			#program exit status

