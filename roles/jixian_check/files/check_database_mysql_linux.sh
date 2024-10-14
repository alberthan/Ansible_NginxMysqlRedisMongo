#!/bin/sh
[ $# -ne 5 ] && { 
 echo "Usage: sh check_database_mysql_linux.sh IP  数据库密码 数据库用户名 端口号 MYSQL路径";
 exit 1;
}

pathname=`pwd`


perl $pathname/check_database_mysql_linux.pl "${1}" "${2}" "${3}" "${4}" "${5}"
