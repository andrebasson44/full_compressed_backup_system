#!/bin/bash

## Find the process ID of an rsync process running in memory - if at all.
## Uses ps, grep and either sed or awk.
#
#
#  STATUS:	DEPRECATED (mostly), but does have its uses:
#				> this entire file can be replaced with a single, better functioning line, ie.:
#
#					PID="$(ps -afx -o pid,cmd | grep -vi 'color' | grep -E $regex | sed -n '1p' | awk '{ print $1 }')"
#					where:
#						'regex' is the regular expression by which to locate/match any process	eg. regex="rsync.*(/path/to/source)+.*(/path/to/target)+"
#
#  VERSION: 1.0
#  INPUT:		searchPattern ($1)	- a regular expression by which to match the process
#  OUTPUT:		process ID or empty	- echoes to stdout the PID of the process in question
#
#  INSTRUCTIONS:
#		1. MIN_COUNT
#		   Under VARIABLES, change the MIN_COUNT value for retrieving PIDs of programs other than RSYNC.
#
#  -----------------------------------------------------------------------------------------------------------------

##CONFIRM CORRECT (1) NO. INPUT PARAMETERS
#
if [[ $# != 1 ]]
then
  echo -e "\nMissing search pattern (regex) input parameter"
  echo -e   "Syntax ex.: PID=$(/bin/bash /path/to/getRsyncPID.sh "regex") \n"
  exit
fi

##VARIABLES 
##regular expression by which to match (find) the process(es) in memory
#
searchPattern="$1"		#e.g. searchPattern="rsync.*backup_all.sh"
MIN_COUNT=3			#rsync open 3 additional subprocesses (i.e. minimum 4 lines of text in 'ps' standard output)

##count the number of matches found:
# NOTE:	The count is important, because even if no actual match exists, grep itself (ALONG WITH ITS REGEX search string) 
#	will appear as part of the 'ps' output.
# 	It will then be filtered by the grep command and register as a process - i.e. a false positive
#
count=$(ps -afx -o pid,cmd | grep -cE "$searchPattern")

##Because the regex in the grep command is part of the 'ps' subprocess (between brackets), grep itself will always return at
#  least one additional match (i.e. itself), recognised by the substring "--color" , even if no actual match was found.
#  The additional match(es) found is therefore a false match.  To circumvent false positives, we calculate two process IDs:
#	- pid1 will store the process ID of the 1st process that matches regex (i.e. possibly true match)
#	- pid2 will store the process ID matching regex, but which matches the "--color" substring  (i.e. a false match)
#
pid1=$(ps -afx -o pid,cmd | grep -E "$searchPattern" | sed -n "1p" | awk '{ print $1 }')
pid2=$(ps -afx -o pid,sid,cmd | grep -E "(color)+.*$searchPattern" | sed -n "1p" | awk '{ print $1 }')

##Because RSYNC opens 3 additional subprocesses for every execution, the 'ps' output will show 4 lines of text featuring the
#   matching string ($regex), *if* a match occured.
#   Thus, we can safely assume that $pid1 is the true rsync process ID, if $count is 4 or more, and $pid1 =/= $pid2
#
if [[ $count > $MIN_COUNT ]] && [[ $pid1 != $pid2 ]]; then
  echo $pid1	#rsync process running with this PID
else
  echo ""	#no rsync process running
fi


################################################## NOTES/EXPLANATIONS ############################################################
######
###

## using grep & sed (stream editor)
#ps -afx -o pid,cmd | grep -E "$searchPattern" | sed -n "1p" | sed "s/[^0-9].*//g"
		#DESCRIPTION:
		#	ps -afx -o pid,cmd	- prints all running processes (in extended format),
		#						  incl. options (o) to indicate Process ID and Command.
		#
		#	|					- pipe output from command to standard input of following command.
		#
		#	grep "\ $searchPattern"	- match input to double-quoted regular expression consisting of:
		#							1. single whitespace (ps output is formatted to incl. whitespace)
		#							2. $searchStr (i.e. command or /path/to/file or combo, etc.)
		#
		#	|					- pipe output from command to standard input of following command.
		#
		#	sed -n "1p"			- use stream editor to output the first line only of the stream
		#						  input received. Expression placed either in single or double quotes.
		#
		#	|					- pipe output from command to standard input of following command.
		#
		#	sed "s/[^0-9].*//g"	- use stream editor substitute command (s) to match one or more (*)
		#						  non-numerical value ([^0-9].*), and replace with nothing (//g)


## using grep & awk
#ps -afx -o pid,cmd | grep -E "$searchPattern" | sed -n "1p" | awk '{print $1}'
		#DESCRIPTION:
		#						- see above for other descriptions.
		#
		#	awk '{print $1}'	- in single quoted curly braces, use awk to print to stdout
		#						  the first word.  Note: in awk, double quotes are used for
		#						  string literals.




