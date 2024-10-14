#!/bin/bash
#检测mysql是否启动了
A=`ss -tnlp | grep 3306| wc -l`
#如果mysql没有启动就启动nginx
if [ $A -eq 0 ];then
        #停掉keepalived服务，进行VIP转移
        echo "`date` mysql down ,keepalived will stop" >> /var/log/checknginx.log
        systemctl stop keepalived
fi

