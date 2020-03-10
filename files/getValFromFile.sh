#!/bin/bash

## script getValFromFile
 #   @description:   reads each line in a file ($1) looking for a variable ($2), then returns the value of that variable
 #   @parameters:    $1 = file or directory name (absolute path)
 #                   $2 = variable to get value of
 #
#

##VARs
#
DEBUG=0             #flag, default 0 (false for '$(( ))' integer testing)
EXIT_STATUS=0       #default 0 (success)  
filename=""       
varName=""
val=""              #value to echo (return) to std out; default empty

##Check arguments received (must receive 2 arguments, of which first must have a value and not be empty)
if [[ $# -ne 2 || -z $1 ]]; then 
    echo ""
    echo "Bad Usage of function getValFromFile(), or file name not supplied."
    echo "Usage:  getValFromFile <filename> <variable>"
    echo ""

    EXIT_STATUS=1
    exit $EXIT_STATUS
else
    filename="$1"       
    varName="$2"
fi  

##DEBUG: output every line as its read
 c=0               #counter
 if (( $DEBUG )); then 
    echo "DEBUG: file path is $1"
    while read line; do
      # reading each line
      echo "Line No. $c: $line"
      c=$((c+1))
    done < $filename
 fi
#

##Read every line into the referenced array
index=0           #index counter
while read line; do    

    #skip lines containing comment out sign '#'
    if [[ ( $line == *"#"*  || $line == *";"* ) ]]; then continue
    elif [[ $line == "$varName="* ]]; then val="$(echo $line | cut -d "=" -f2)"; break; fi
    
    if (( $DEBUG )); then echo "DEBUG: val = $val"; fi
    
done < $filename

##Setup exit status and echo to stdout the value
if [[ $val == "" ]]; then EXIT_STATUS=1; else EXIT_STATUS=0; echo "$val"; fi

exit $EXIT_STATUS
