#!/bin/bash
#检测nginx是否启动了
A=`ps -C nginx --no-header |wc -l`
#如果nginx没有启动就启动nginx
if [ $A -eq 0 ];then
      #重启nginx
      systemctl restart nginx
      sleep 1;
      if [ `ps -C nginx --no-header |wc -l` -eq 0 ];then
        #nginx重启失败，则停掉keepalived服务，进行VIP转移
        echo "`date` nginx down ,keepalived will stop" >> /var/log/checknginx.log
        systemctl stop keepalived
      fi
fi
