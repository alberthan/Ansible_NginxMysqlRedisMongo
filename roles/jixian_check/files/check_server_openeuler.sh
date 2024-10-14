#!/bin/sh
[ $# -ne 1 ] && { 
 echo "Usage: sh check_server_openeuler.sh IP ";
 exit 1;
}

pathname=`pwd`


perl $pathname/check_server_openeuler.pl "${1}" 
