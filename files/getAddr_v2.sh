#!/bin/bash

# DESCRIPTION:
 #   A slight update to script getAddr.sh; getAddr_v2.ssh only takes on parameter instead of two.
 #   The single parameter - an IP address, host name or domain name - will be pinged to confirm
 #   it is either reachable (exit status 0), or not (exit status non-zero)
#   

# SOME FUNCTIONS:
# ---------------
# Function addrExists()
#   Tests whether the host address (argument 1) received is reachable (pings succesfully) or not, 
#      i.e. if the IP address or domain name exists.
#   @param:       expects a single argument passed at command line ($1)
#   @returns:     exits with 0 (true) if address exists, 1 (false) otherwise
#
function addrExists ()
{
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
}

# function getAddress()
#       Checks if either arg1 or arg2 is reachable (ping'able) address, echoes to stdOut the first one that is.
#       If neither is, exits/return with exit status '1'.
#       @uses:          references helper function addrExists()
#       @param1:        host address
#       @param2:        alternative host address
#       @returns:       echoes to stdout first of two params that is reachable, else terminates with exit status '1'.
#
function getAddress ()
{
  # check number of arguments passed (must be exactly 2, or terminate the function)
  if [ $# -ne 2 ];then
    echo "Please Enter 2 no. (e.g. IP or domain) Host Addresses"
    exit 1
  fi

  # specify local variable to store potential host address
  local dst_addr=""

  # check both arguments received, then update destination address to first one valid, or terminate function
  local exists=$(addrExists $1)
  if [[ "$exists" = "true" ]]; then
      dst_addr="$1"
  else
    exists=$(addrExists $2)
    if [[ "$exists" = "true" ]]; then
      dst_addr="$2"
    else
      #terminate the script (and all subscripts) completely
      #echo "Both Destination Hosts $1 and $2 is Unreachable"
      exit 1
    fi
  fi

  # BASH function cannot RETURN a value (e.g. return "$dst_addr") like in other programming languages;
  # have to echo the value to stdOut instead, and then the caller can assign it to a variable.
  echo "$dst_addr"
}
# e/o SOME FUNCTIONS


# SCRIPT
# ------

# check number of arguments passed (must be exactly 2, or terminate the function)
if [ $# -ne 2 ];then
  echo "Please Enter 2 no. (e.g. IP or domain) Host Addresses"
  exit 1
fi

# get the address - echo to stdout
getAddress $1 $2

exit 0

