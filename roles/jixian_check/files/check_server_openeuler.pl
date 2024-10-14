#!env perl
#Author: autoCreated
my $para_num = "1";
my %para;
@array_pre_flag = ();
@array_appendix_flag = ();

$para{Linux_su_password} = $ARGV[1];
$para{Linux_su_user} = $ARGV[2];

$pre_cmd{6608} = "ls -l /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null
if [ -f /etc/pam.d/system-auth ]&&[ -f /etc/pam.d/password-auth ];then
for FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth
do
echo \$FILE
cat \$FILE|sed '/^\\s*#/d'|sed '/^\\s*\$/d'
venus1=\$(cat \$FILE|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|egrep \"auth\\s+required\\s+pam_faillock.so\\s+preauth\"|egrep \"deny=\\w\")
venus2=\$(cat \$FILE|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|egrep \"auth\\s+\\[default=die\\]\\s+pam_faillock.so\\s+authfail\"|egrep \"deny=\\w\")
venus3=\$(cat \$FILE|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|egrep \"account\\s+required\\s+pam_faillock.so\")
if [[ -n \$venus1 ]]&&[[ -n \$venus2 ]]&&[[ -n \$venus3 ]];then
echo \"result=\"\$(echo \$venus1|sed 's/.*\\sdeny=\\(\\w*\\)\\s.*/\\1/')
echo \"result=\"\$(echo \$venus2|sed 's/.*\\sdeny=\\(\\w*\\)\\s.*/\\1/')
else
echo \"result=false\"
fi
done
unset FILE venus1 venus2 venus3
else
echo \"result=false\"
fi
";
push(@array_pre_flag, 6608);$pre_cmd{6609} = "cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"
";
push(@array_pre_flag, 6609);$pre_cmd{6610} = "if grep -v \"^[[:space:]]*#\" /etc/ssh/sshd_config|grep -i \"PermitRootLogin no\"
then echo \"This device does not permit root to ssh login,check result:true\";
else
echo \"This device permits root to ssh login,check result:false\";
fi
if grep  -v \"^[[:space:]]*#\" /etc/ssh/sshd_config|egrep \"^protocol[[:space:]]*2|^Protocol[[:space:]]*2\"
then echo \"SSH protocol version is 2,check result:true\"
else
echo \"SSH protocol version is not 2,check result:false\"
fi
";
push(@array_pre_flag, 6610);$pre_cmd{6611} = "export LANG=en_US.UTF-8
echo \"telnet_status=\"`systemctl|grep \"telnet\\.socket\"|grep \"active\"|wc -l`
echo \"ssh_status=\"`ps -ef|grep \"sshd\"|grep -v \"grep\"|wc -l`
";
push(@array_pre_flag, 6611);$pre_cmd{6612} = "awk '{print \$1\":\"\$2}' /etc/profile|grep -v \"^[[:space:]]*#\"|grep -i umask|tail -n1
";
push(@array_pre_flag, 6612);$pre_cmd{6613} = "ls -alL /etc/passwd /etc/shadow /etc/group
echo \"passwd_total=\"`ls -alL /etc/passwd 2>/dev/null|grep -v  \"[r-][w-]-[r-]--[r-]--\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
echo \"shadow_total=\"`ls -alL /etc/shadow 2>/dev/null|grep -v  \"[r-][w-]-------\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
echo \"group_total=\"`ls -alL /etc/group 2>/dev/null|grep -v  \"[r-][w-]-[r-]--[r-]--\"|grep \"[r-][w-][x-][r-][w-][x-][r-][w-][x-]\"|wc -l`
";
push(@array_pre_flag, 6613);$pre_cmd{6614} = "cat /etc/login.defs |grep -v \"^[[:space:]]*#\"|grep -E '^\\s*PASS_MAX_DAYS|^\\s*PASS_MIN_DAYS|^\\s*PASS_WARN_AGE'
";
push(@array_pre_flag, 6614);$pre_cmd{6615} = "awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd
echo \"result=\"`awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd | grep -v \"^[[:space:]]*#\" |grep -v root|wc -l`
";
push(@array_pre_flag, 6615);$pre_cmd{6616} = "Calculate (){
echo \"DCREDIT=\"`cat \$1 |egrep -v \"[[:space:]]*#\"|tr -d ' '|awk 'BEGIN{RS=\" \"}{print \$0}'|awk -F\"=\" '/dcredit/{print\$2}'|awk '{print\$1}'|awk -F\"-\" '{print\$2}'`
echo \"LCREDIT=\"`cat \$1 |egrep -v \"[[:space:]]*#\"|tr -d ' '|awk 'BEGIN{RS=\" \"}{print \$0}'|awk -F\"=\" '/lcredit/{print\$2}'|awk '{print\$1}'|awk -F\"-\" '{print\$2}'`
echo \"UCREDIT=\"`cat \$1 |egrep -v \"[[:space:]]*#\"|tr -d ' '|awk 'BEGIN{RS=\" \"}{print \$0}'|awk -F\"=\" '/ucredit/{print\$2}'|awk '{print\$1}'|awk -F\"-\" '{print\$2}'`
echo \"OCREDIT=\"`cat \$1 |egrep -v \"[[:space:]]*#\"|tr -d ' '|awk 'BEGIN{RS=\" \"}{print \$0}'|awk -F\"=\" '/ocredit/{print\$2}'|awk '{print\$1}'|awk -F\"-\" '{print\$2}'`
echo \"MINLEN=\"`cat \$1 |egrep -v \"[[:space:]]*#\"|awk 'BEGIN{RS=\" \"}{print \$0}'|awk -F\"=\" '/minlen/{print\$2}'|awk '{print\$1}'`
}
if [ -f /etc/pam.d/system-auth ];then
pam_pwquality=\$(cat /etc/pam.d/passwd|egrep -v \"[[:space:]]*#\"|egrep \"password[[:space:]]+required[[:space:]]+pam_pwquality.so\")
if [ -n \"\$pam_pwquality\" ];then
echo \"result0=Found pam_pwquality.so module\"
cat /etc/security/pwquality.conf | egrep -v \"\\s*#|^\$\"
else
FILE=/etc/pam.d/system-auth;
Calculate \"\$FILE\";
unset FILE
fi
fi
";
push(@array_pre_flag, 6616);$pre_cmd{6617} = "echo \$PATH
echo \"result=`echo \$PATH|egrep \"^\\.\\:|^\\.\\.\\:|\\:\\.\$|\\:\\.\\.\$|\\:\\.\\:|\\:\\.\\.\\:\"|wc -l`\"
";
push(@array_pre_flag, 6617);$pre_cmd{6618} = "telnet_status=`systemctl|grep \"telnet.socket\"|wc -l`
if [ \$telnet_status -ge 1 ];then
echo \"Telnet process is open\"
echo \"pts_count=\"`cat /etc/securetty 2>/dev/null|grep -v \"^[[:space:]]*#\"|grep \"pts/*\"|wc -l`
else
echo \"Telnet process is not open\"
fi
unset telnet_status
";
push(@array_pre_flag, 6618);$pre_cmd{6619} = "cat /etc/profile|grep -v \"^[[:space:]]*#\"|grep \"ulimit[[:space:]]*-S[[:space:]]*-c[[:space:]]*0[[:space:]]*>[[:space:]]*/dev/null[[:space:]]*2>&1\"
cat /etc/security/limits.conf|grep -v \"[[:space:]]*#\"
";
push(@array_pre_flag, 6619);$pre_cmd{6620} = "if [ -f /etc/rsyslog.conf ];
then cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep -E '[[:space:]]*.+@.+';
fi
";
push(@array_pre_flag, 6620);$pre_cmd{6621} = "ssh_status=`ps -ef|grep \"sshd\"|grep -v grep`
if [ -n \"\$ssh_status\" ];then
echo \"result1=SSH is running\"
if [ -f /etc/motd ];then
content=`cat /etc/motd 2>/dev/null | wc -l`
if [ \"\$content\" -ge 1 ];then
echo \"result2=banner is not null\"
else
echo \"result2=banner is null\"
fi
else
echo \"The /etc/motd file not found\"
fi
else
echo \"result1=SSH not running\"
fi
unset ssh_status content
";
push(@array_pre_flag, 6621);$pre_cmd{6622} = "cat /etc/shadow|sed '/^\\s*#/d'|awk -F: '(\$2!~/^*/) && (\$2!~/^!!/) {print \$1\":\"}'|egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\"
egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'
echo \"result_pw=\"`cat /etc/shadow|sed '/^\\s*#/d'|awk -F: '(\$2!~/^*/) && (\$2!~/^!!/) {print \$1}'|egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\"|wc -l`
echo \"result_shell=\"`egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'|wc -l`
";
push(@array_pre_flag, 6622);$pre_cmd{6623} = "ls -lL /etc/passwd 2>/dev/null
echo \"passwd=\"`ls -lL /etc/passwd 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/group 2>/dev/null
echo \"group=\"`ls -lL /etc/group 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/services 2>/dev/null
echo \"services=\"`ls -lL /etc/services 2>/dev/null|grep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
ls -lL /etc/shadow 2>/dev/null
echo \"shadow=\"`ls -lL /etc/shadow 2>/dev/null|grep -v \"[r-][w-]-------\"|wc -l`
ls -lL /etc/xinetd.conf 2>/dev/null
echo \"xinetd=\"`ls -lL /etc/xinetd.conf 2>/dev/null|grep -v \"[r-][w-]-------\"|wc -l`
ls -lLd /etc/security 2>/dev/null
echo \"security=\"`ls -lLd /etc/security 2>/dev/null|grep -v \"[r-][w-]-------\"|wc -l`
";
push(@array_pre_flag, 6623);$pre_cmd{6624} = "if [ -f /etc/rsyslog.conf ];
then
rsyslog=`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"*.err\\;kern\\.debug\\;daemon\\.notice[[:space:]]*/var/adm/messages\"|wc -l`;
if [ \$rsyslog -ge 1 ];
then
echo \"rsyslog check result:true\";
else
echo \"rsyslog check result:false\";
fi;
fi;
unset rsyslog
";
push(@array_pre_flag, 6624);$pre_cmd{6625} = "UP_GIDMIN=`(grep -v ^# /etc/login.defs |grep \"^GID_MIN\"|awk '(\$1=\"GID_MIN\") {print \$2}')`
UP_GIDMAX=`(grep -v ^# /etc/login.defs |grep \"^GID_MAX\"|awk '(\$1=\"GID_MAX\") {print \$2}')`
egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$4>='\$UP_GIDMIN' && \$4<='\$UP_GIDMAX') {print \$1\":\"\$3\":\"\$4}'
echo \$UP_GIDMIN \$UP_GIDMAX
echo \"result=\"`egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$4>='\$UP_GIDMIN' && \$4<='\$UP_GIDMAX') {print \$1\":\"\$3\":\"\$4}'|wc -l`
unset UP_GIDMIN UP_GIDMAX
";
push(@array_pre_flag, 6625);$pre_cmd{6626} = "if [[ -n `ps -ef|grep sshd|grep -v grep` ]];then
echo \"SSH_status=running\"
if [ -e /etc/ssh/sshd_config ];then
Banner_file=`cat /etc/ssh/sshd_config|grep -v \"^#\"|grep -v \"^\$\"|grep -w Banner|awk '{print\$2}'`
if [ -n \"\$Banner_file\" ];then
cat /etc/ssh/sshd_config|grep -v \"^#\"|grep -v \"^\$\"|grep -w Banner
if [ -e \$Banner_file ];then
echo \"Banner file:\$Banner_file\"
if [ -s \$Banner_file ];then
echo \"result=yes\"
else
echo \"result=The \$Banner_file is empty\"
fi
else
echo \"result=The \$Banner_file file not found\"
fi
else
echo \"result=Banner is not configured\"
fi
else
echo \"result=The /etc/ssh/sshd_config not found\"
fi
unset Banner_file
else
echo \"SSH_status=not running\"
fi
";
push(@array_pre_flag, 6626);$pre_cmd{6627} = "echo \"ip_forward=\"`sysctl -n net.ipv4.ip_forward`
";
push(@array_pre_flag, 6627);$pre_cmd{6628} = "ps -ef |grep \"rpc\"
if [[ -n `ps -ef|grep nfsd|grep -v grep` ]];then
echo \"result=nfs is running\"
cat /etc/hosts.allow|grep -v \"^[[:space:]]*#\"|grep \"^nfs:\"
if [[ -n `cat /etc/hosts.allow|grep -v \"^[[:space:]]*#\"|grep \"^nfs:\"` ]];then
echo \"result1=true\"
else
echo \"result1=false\"
fi
cat /etc/hosts.deny|grep -v \"^[[:space:]]*#\"|egrep -i \"nfs:ALL|ALL:ALL\"
if [[ -n `cat /etc/hosts.deny|grep -v \"^[[:space:]]*#\"|egrep -i \"nfs:ALL|ALL:ALL\"` ]];then
echo \"result2=true\"
else
echo \"result2=false\"
fi
else
echo \"result=nfs not running\"
fi
";
push(@array_pre_flag, 6628);$pre_cmd{6629} = "cat /etc/inittab|grep -v \"^#\"|grep \"ctrlaltdel\"
";
push(@array_pre_flag, 6629);$pre_cmd{6630} = "cat /etc/hosts.allow |sed '/^#/d'|sed '/^\$/d'|egrep -i \"sshd|telnet|all\"
cat /etc/hosts.deny |sed '/^#/d'|sed '/^\$/d'|egrep -i \"all:all\"
echo \"allowno=\"`egrep -i \"sshd|telnet|all\" /etc/hosts.allow |sed '/^#/d'|sed '/^\$/d'|wc -l`
echo \"denyno=\"`egrep -i \"sshd|telnet|all\\s{0,10}:\\s{0,10}all\" /etc/hosts.deny |sed '/^#/d'|sed '/^\$/d'|wc -l`
";
push(@array_pre_flag, 6630);$pre_cmd{6631} = "awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow
echo \"result=\"`awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow |wc -l`
";
push(@array_pre_flag, 6631);$pre_cmd{6632} = "if [ -n \"`ps -ef|grep chrony|grep -v grep`\" ];then
echo \"Process is running\"
grep \"^server\" /etc/chrony.conf|grep -v \"127.127.1.0\"|grep -v \"127.0.0.1\";
echo \"ntpserver1=\"`grep \"^server\" /etc/chrony.conf|grep -v \"127.127.1.0\"|grep -v \"127.0.0.1\"|wc -l`;
else
echo \"Process is not running\"
crontab -l 2>/dev/null|grep -v \"^#\"|grep ntp;
echo \"ntpserver2=\"`crontab -l 2>/dev/null|grep -v \"^#\"|grep ntp|wc -l`;
fi
";
push(@array_pre_flag, 6632);$pre_cmd{6633} = "echo \"accept_redirects=\"`sysctl -n net.ipv4.conf.all.accept_redirects`
";
push(@array_pre_flag, 6633);$pre_cmd{6634} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \"\$FTPCONF\" ]
then
if [ `grep -v \"^[[:space:]]*#\" \$FTPCONF|grep -i \"ftpd_banner\"|wc -l` -ne 0 ];
then
echo \"vsftpd is running.Banner in \$FTPCONF is recommended.FTP check result:true\";
else
echo \"vsftpd is running.Banner in \$FTPCONF is not recommended.FTP check result:false\";
fi;
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
if [ `cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|wc -l` -eq 0 ]
then
echo \"pure-ftpd is running.banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|awk '{print \$2}'`\" ];
then
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
else
if [ -f /etc/pure-ftpd.conf ]
then
if [ `cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|wc -l` -eq 0 ]
then
echo \"pure-ftpd is running.banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"FortunesFile\"|awk '{print \$2}'`\" ];
then
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"pure-ftpd is running.Banner in pure-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi
fi;
fi;
if [ -f /etc/ftpaccess ];
then
if [ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|wc -l` -eq 0 ]
then
echo \"wu-ftpd is running.banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|awk '{print \$2}'`\" ];
then
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
else
if [ -f /etc/ftpd/ftpaccess ]
then
if [ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|wc -l` -eq 0 ]
then
echo \"wu-ftpd is running.banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
else
if [ -s \"`cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*banner\"|awk '{print \$2}'`\" ];
then
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is recommended.FTP check result:true.\";
else
echo \"wu-ftpd is running.Banner in wu-ftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
if [ -s \"`cat /etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed '/<Anonymous.*>/,/<\\/Anonymous>/d'|grep -i \"DisplayConnect\"|awk '{print \$2}'`\" ]
then
echo \"proftpd is running.banner in proftpd.conf is recommended.FTP check result:true.\";
else
echo \"proftpd is running.banner in proftpd.conf is not recommended.FTP check result:false.\";
fi;
else
if [ -f /etc/proftpd/proftpd.conf ];
then
if [ -s \"`cat /etc/proftpd/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed '/<Anonymous.*>/,/<\\/Anonymous>/d'|grep -i \"DisplayConnect\"|awk '{print \$2}'`\" ]
then
echo \"proftpd is running.banner in proftpd.conf is recommended.FTP check result:true.\";
else
echo \"proftpd is running.banner in proftpd.conf is not recommended.FTP check result:false.\";
fi;
else
if  [ -f /usr/local/proftpd/etc/proftpd.conf ]
then
if [ -s \"`cat /usr/local/proftpd/etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed '/<Anonymous.*>/,/<\\/Anonymous>/d'|grep -i \"DisplayConnect\"|awk '{print \$2}'`\" ]
then
echo \"proftpd is running.banner in proftpd.conf is recommended.FTP check result:true.\";
else
echo \"proftpd is running.banner in proftpd.conf is not recommended.FTP check result:false.\";
fi;
fi;
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then
echo \"FTP is not running.FTP check result:true\"
else
Check_ftp;
fi;
unset FTPSTATUS;
";
push(@array_pre_flag, 6634);$pre_cmd{6635} = "SNMPD_STATUS=`ps -ef|grep snmpd|egrep -v \"grep\"|wc -l`;
Check_SNMPD ()
{
if [ -f /etc/snmp/snmpd.conf ];
then SNMPD_CONF=/etc/snmp/snmpd.conf;
else SNMPD_CONF=/etc/snmpd.conf;
fi;
grep -v \"^#\" \$SNMPD_CONF|egrep \"community\";
if [ `grep -v \"^#\" \$SNMPD_CONF|egrep \"rocommunity|rwcommunity\"|egrep \"public|private\"|wc -l` -eq 0 ];
then echo \"SNMPD is running.SNMP check result:true\";
else echo \"SNMPD is running.SNMP check result:false\";
fi;
}
if [ \"\$SNMPD_STATUS\" -ge  1 ];
then Check_SNMPD;
else echo \"SNMPD is not running.SNMP check result:true\";
fi
unset SNMPD_STATUS SNMPD_CONF;
";
push(@array_pre_flag, 6635);$pre_cmd{6636} = "up_uidmin=`(grep -v ^# /etc/login.defs |grep \"^UID_MIN\"|awk '(\$1=\"UID_MIN\"){print \$2}')`
up_uidmax=`(grep -v ^# /etc/login.defs |grep \"^UID_MAX\"|awk '(\$1=\"UID_MAX\"){print \$2}')`
egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'
echo \"result=\"`egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'|wc -l`
unset up_uidmin up_uidmax
";
push(@array_pre_flag, 6636);$pre_cmd{6637} = "if [[ -n `ps -A | egrep -i -w \"gnome|kde|mate|cinnamon|lx|xfce|jwm\"` ]];then
echo \"result1=\"`gconftool-2 -g /apps/gnome-screensaver/idle_activation_enabled 2>/dev/null`
echo \"result2=\"`gconftool-2 -g /apps/gnome-screensaver/lock_enabled 2>/dev/null`
echo \"result3=\"`gconftool-2 -g /apps/gnome-screensaver/mode 2>/dev/null`
echo \"result4=\"`gconftool-2 -g /apps/gnome-screensaver/idle_delay 2>/dev/null`
else
echo \"result=No desktop installed\"
fi
";
push(@array_pre_flag, 6637);$pre_cmd{6638} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`;
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \"\$FTPCONF\" ]
then
echo \"vsftpd is running.\"
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"ls_recurse_enable\";
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"local_umask\";
cat \$FTPCONF|grep -v \"^[[:space:]]*#\"|grep \"anon_umask\";
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
echo \"pureftp_umask=\"`cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /etc/pure-ftpd.conf ]
then
echo \"pureftp_umask=\"`cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /etc/proftpd/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
else
if [ -f /usr/local/proftpd/etc/proftpd.conf ];
then
echo \"proftp_umask=\"`cat /usr/local/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*Umask\"`;
fi;
fi;
fi;
if [ -f /etc/ftpaccess ];
then
cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*upload\";
else
if [ -f /etc/ftpd/ftpaccess ]
then
cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"^[[:space:]]*upload\";
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then  echo \"FTP is not running.FTP check result:true.\";
else
Check_ftp;
fi
unset FTPSTATUS;
";
push(@array_pre_flag, 6638);$pre_cmd{6639} = "ls /etc/rc2.d/* /etc/rc3.d/* /etc/rc4.d/* /etc/rc5.d/* 2>/dev/null|egrep \"lp|rpc|snmpdx|keyserv|nscd|Volmgt|uucp|dmi|sendmail|autoinstall\"|grep \"^S\"
echo \"result=\"` ls /etc/rc2.d/* /etc/rc3.d/* /etc/rc4.d/* /etc/rc5.d/* 2>/dev/null|egrep \"lp|rpc|snmpdx|keyserv|nscd|Volmgt|uucp|dmi|sendmail|autoinstall\"|grep \"^S\"|wc -l`
";
push(@array_pre_flag, 6639);$pre_cmd{6640} = "cat /etc/redhat-release 2>/dev/null;uname -a
";
push(@array_pre_flag, 6640);$pre_cmd{6641} = "if [ -s /etc/rsyslog.conf ];
then
cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | egrep \"authpriv\\.\\*.*[[:space:]]*\\/|authpriv\\.info.*[[:space:]]*\\/\";
fi;
";
push(@array_pre_flag, 6641);$pre_cmd{6642} = "if [[ -n `ps -ef|egrep -w \"rsyslogd\"|grep -v grep` ]];then
echo \"result=Log service is running\"
if [ -f /etc/rsyslog.conf ];then
for Log_File in `cat /etc/rsyslog.conf | egrep -v \"^[[:space:]]*#|\\)\"|egrep  \"^[^\\\$]\"|grep \"/\"|awk '{print\$2}'|sed 's/^-//g'`
do
if [ -f \$Log_File ];then
ls -l \$Log_File
echo \"result1=\"`ls -l \$Log_File|grep -v \"[r-][w-]-[r-]-----\"|wc -l`
else
echo \"The \$Log_File file not found\"
fi
done
unset Log_File
else
echo \"The /etc/rsyslog.conf file not found\"
ls -l \$(find /var/log/ -type f)
echo \"result1=\"`ls -l \$(find /var/log/ -type f)|grep -v \"[r-][w-]-[r-]-----\"|wc -l`
fi
fi
";
push(@array_pre_flag, 6642);$pre_cmd{6643} = "if [ -f /etc/pam.d/system-auth ];
then FILE=/etc/pam.d/system-auth
cat \$FILE |sed '/^#/d'|sed '/^\$/d'|grep password
fi
";
push(@array_pre_flag, 6643);$pre_cmd{6644} = "Check_ftp2 (){
if [ -f /etc/vsftpd.conf ];then
FTPCONF=\"/etc/vsftpd.conf\";
FTPUSER=`cat \$FTPCONF|grep -v \"^#\"|grep userlist_file|cut -d= -f2`;
Check_vsftpconf;
elif [ -f /etc/vsftpd/vsftpd.conf ];then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
FTPUSER=`cat \$FTPCONF|grep -v \"^#\"|grep userlist_file|cut -d= -f2`;
Check_vsftpconf;
fi;
}
Check_vsftpconf (){
userlist_enable=`grep -v \"^#\" \$FTPCONF|grep -i \"userlist_enable=YES\"|wc -l`;
userlist_deny=`grep -v \"^#\" \$FTPCONF|grep -i \"userlist_deny=NO\"|wc -l`;
if [ \$userlist_enable = 1 -a \$userlist_deny = 1 ];then
if [ -n \"\$FTPUSER\" ];then
if [ `grep -v \"^#\" \$FTPUSER|egrep \"^root\$\"|wc -l` = 0 ];then
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" is recommended.FTP check result:true\";
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" is not recommended.FTP check result:false\";
fi;
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.FTP user config \"\$FTPUSER\" does not exist.FTP check result:false\";
fi;
else
echo \"FTP is running.FTP user config \$ftpusers_pam is not recommended.userlist_enable and userlist_deny is not recommended.FTP check result:false\";
fi;
}
Check_ftp1 (){
if [ -f /etc/pam.d/vsftpd ];then
ftpusers_pam=`grep \"file\" /etc/pam.d/vsftpd|egrep -v \"^#\"|sed 's/^.*file=//g'|awk '{print \$1}'`
if [ -n \"\$ftpusers_pam\" ];then
if [ `grep -v \"^#\" \$ftpusers_pam|egrep \"^root\$\"|wc -l` = 1 ];then
echo \"FTP is running.FTP user config \$ftpusers_pam is recommended.FTP check result:true\";
else
Check_ftp2;
fi
else
Check_ftp2;
fi
else
echo \"/etc/pam.d/vsftpd is not exist,scripts exit now\";
Check_ftp2;
fi
if [ -f /etc/proftpd.conf ];then
if [ `cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on\"|wc -l` -eq 0 ];then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
else
if [ -f /etc/proftpd/proftpd.conf ];then
if [ `cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on\"|wc -l` -eq 0 ];then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
elif [ -f /usr/local/proftpd/etc/proftpd.conf ];then
if [ `cat /usr/local/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"RootLogin[[:space:]]*on\"|wc -l` -eq 0 ];then
echo \"proftpd is running.FTP check result:true\";
else
echo \"proftpd is running.FTP check result:false\";
fi;
fi;
fi;
if [ -f /etc/ftpusers ];then
echo \"wu-ftp_users=\"`cat /etc/ftpusers|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^root\"`;
else
if [ -f /etc/ftpd/ftpusers ];then
echo \"wu-ftp_users=\"`cat /etc/ftpd/ftpusers|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^root\"`;
fi;
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"MinUID\";
else
if [ -f /etc/pure-ftpd.conf ];then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"MinUID\";
fi;
fi;
}
if [[ -z `ps -ef|grep ftpd|grep -v grep` ]];then
echo \"result=FTP is not running\";
else
echo \"result=FTP is running\";
Check_ftp1;
fi
unset FTPCONF FTPUSER ftpusers_pam
";
push(@array_pre_flag, 6644);$pre_cmd{6645} = "if [ -s /etc/rsyslog.conf ];
then
cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"authpriv\\.\\*[[:space:]]\\/*\";
fi
";
push(@array_pre_flag, 6645);$pre_cmd{6646} = "FTPSTATUS=`ps -ef|grep -v grep|grep -i ftpd|wc -l`
Check_ftp ()
{
if [ -f /etc/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd.conf\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
FTPCONF=\"/etc/vsftpd/vsftpd.conf\";
fi;
fi;
if [ -f \"\$FTPCONF\" ];
then
if ([ `grep -v \"^#\" \$FTPCONF|grep -i \"chroot_list_enable=YES\"|wc -l` -eq 1 ] && [ `grep -v \"^#\" /etc/vsftpd/vsftpd.conf|grep -i \"chroot_local_user=YES\"|wc -l` -eq 0 ]);
then
if [ -s \"`grep -v \"^#\" /etc/vsftpd/vsftpd.conf|grep -i \"chroot_list_file\"|cut -d\\= -f2`\" ]
then
echo \"FTP is running.FTP check result:true\"
else
echo \"FTP is running.FTP check result:false\"
fi
else
echo \"FTP is running.FTP check result:false\"
fi
fi
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"ChrootEveryone\";
else
if [ -f /etc/pure-ftpd.conf ];
then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"ChrootEveryone\";
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
cat /etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
else
if [ -f /etc/proftpd/proftpd.conf ];
then
cat /etc/proftpd/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
else
if [ -f /usr/local/proftpd/etc/proftpd.conf ];
then
cat /usr/local/proftpd/etc/proftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|egrep -i \"DefaultRoot\";
fi;
fi;
fi;
if [ -f /etc/ftpaccess ];
then
cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"restricted-uid\";
else
if [ -f /etc/ftpd/ftpaccess ];
then
cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"restricted-uid\";
fi;
fi;
unset FTPCONF;
}
if [ \$FTPSTATUS -eq 0 ];
then
echo \"FTP is not running.FTP check result:true\";
else
Check_ftp;
fi
unset FTPSTATUS;
";
push(@array_pre_flag, 6646);$pre_cmd{6647} = "systemctl|grep active;netstat -an|awk '{if( \$2==0 ){print\$0}}'
";
push(@array_pre_flag, 6647);$pre_cmd{6648} = "cat /etc/pam.d/su|grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"^auth\"
";
push(@array_pre_flag, 6648);$pre_cmd{6649} = "if [ `ps -ef|grep ftpd|grep -v \"grep\"|wc -l` -ge 1 ];
then
if [ -f /etc/vsftpd.conf ];
then
echo \"ftp is running\"
cat /etc/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"anonymous_enable\";
else
if [ -f /etc/vsftpd/vsftpd.conf ];
then
echo \"ftp is running\"
cat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"anonymous_enable\";
fi
fi;
if [ -f /etc/ftpaccess ];
then
if ([ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*guest\"|wc -l` -ne 0 ] || [ `cat /etc/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*anonymous\"|wc -l` -ne 0 ]);
then
echo \"wu-ftp There are anonymous logins\";
else
echo \"wu-ftp There is no anonymous logins\";
fi;
else
if [ -f /etc/ftpd/ftpaccess ];
then
if ([ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*guest\"|wc -l` -ne 0 ] || [ `cat /etc/ftpd/ftpaccess|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep \"^class\\s*[^\\s]\\{1,\\}\\s*.*anonymous\"|wc -l` -ne 0 ]);
then
echo \"wu-ftp There are anonymous logins\";
else
echo \"wu-ftp There is no anonymous logins\";
fi;
fi;
fi;
if [ -f /etc/proftpd.conf ];
then
Anonymous_1=`cat /etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|grep -i \"AnonRequirePassword[[:space:]]*on\"|wc -l`;
Anonymous_2=`cat /etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|egrep -i \"User|Group|UserAlias\"|wc -l`;
if ([ \$Anonymous_1 -ge 1 ] || [ \$Anonymous_2 -lt 3 ])
then
echo \"proftp There is no anonymous logins\";
else
echo \"proftp There are anonymous logins\";
fi;
else
if [ -f /etc/proftpd/proftpd.conf ];
then
Anonymous_1=`cat /etc/proftpd/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|grep -i \"AnonRequirePassword[[:space:]]*on\"|wc -l`;
Anonymous_2=`cat /etc/proftpd/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|egrep -i \"User|Group|UserAlias\"|wc -l`;
if ([ \$Anonymous_1 -ge 1 ] || [ \$Anonymous_2 -lt 3 ])
then
echo \"proftp There is no anonymous logins\";
else
echo \"proftp There are anonymous logins\";
fi;
else
if [ -f /usr/local/proftpd/etc/proftpd.conf ];
then
Anonymous_1=`cat /usr/local/proftpd/etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|grep -i \"AnonRequirePassword[[:space:]]*on\"|wc -l`;
Anonymous_2=`cat /usr/local/proftpd/etc/proftpd.conf|sed '/^\\s*#/d'|sed '/^\\s*\$/d'|sed -n '/<Anonymous.*/,/<\\/Anonymous>/p'|egrep -i \"User|Group|UserAlias\"|wc -l`;
if ([ \$Anonymous_1 -ge 1 ] || [ \$Anonymous_2 -lt 3 ])
then
echo \"proftp There is no anonymous logins\";
else
echo \"proftp There are anonymous logins\";
fi;
fi;
fi;
fi;
if [ -f /etc/pure-ftpd/pure-ftpd.conf ];
then
cat /etc/pure-ftpd/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"NoAnonymous\";
else
if [ -f /etc/pure-ftpd.conf ];
then
cat /etc/pure-ftpd.conf|grep -v \"^[[:space:]]*#\"|grep -v \"^[[:space:]]*\$\"|grep -i \"NoAnonymous\";
fi;
fi;
else
echo \"ftp is not running,result=true\";
fi;
";
push(@array_pre_flag, 6649);$pre_cmd{6650} = "if [[ `systemctl status telnet.socket 2>/dev/null|grep -w \"Active\"|grep -wo \"listening\"` == \"listening\" ]];then
echo \"TELNET_status=telnet is running\"
cat /etc/issue;cat /etc//issue.net
else
echo \"TELNET_status=telnet not running\"
fi
";
push(@array_pre_flag, 6650);$pre_cmd{6651} = "if [ -f /etc/rsyslog.conf ]
then
echo \"rsyslog=\"`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"cron.\\*\"`
fi
";
push(@array_pre_flag, 6651);$pre_cmd{6652} = "lsattr /var/log/messages 2>/dev/null
";
push(@array_pre_flag, 6652);$pre_cmd{6653} = "cat /proc/sys/net/ipv4/conf/*/accept_source_route
";
push(@array_pre_flag, 6653);$pre_cmd{6654} = "cat /proc/sys/net/ipv4/tcp_syncookies
";
push(@array_pre_flag, 6654);$pre_cmd{6655} = "cat /etc/host.conf|grep -v \"^[[:space:]]*#\"|egrep \"order[[:space:]]hosts,bind|multi[[:space:]]on\"
";
push(@array_pre_flag, 6655);$pre_cmd{6656} = "cat /etc/profile|grep -v \"^[[:space:]]*#\"|egrep \"HISTFILESIZE\\s{0,10}=\"|tail -n1
cat /etc/profile|grep -v \"^[[:space:]]*#\"|egrep \"HISTSIZE\\s{0,10}=\"|tail -n1
";
push(@array_pre_flag, 6656);$pre_cmd{6657} = "if [ `echo \$SHELL|egrep \"bash|sh\"|wc -l` -ge 1 ];then
if [ -f /root/.bashrc ];then
cat /root/.bashrc|grep -v \"^[[:space:]]*#\"
else
alias
fi
else
if [ -f /root/.cshrc ];then
cat /root/.cshrc|grep -v \"^[[:space:]]*#\"
else
alias
fi
fi
";
push(@array_pre_flag, 6657);$pre_cmd{6658} = "openssl version
";
push(@array_pre_flag, 6658);$pre_cmd{6659} = "env -i  X='() { (a)=>\\' bash -c '/dev/stdout echo vulnerable'  2>/dev/null
";
push(@array_pre_flag, 6659);


sub get_os_info
{
	my %os_info = (
 "initSh"=>"","hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"initSh"} = `unset LANG`;
	$os_info{"hostname"} = `uname -n`;
	$os_info{"osname"} = `uname -s`;
	$os_info{"osversion"} = `lsb_release -a;cat /etc/issue;cat /etc/redhat-release;uname -a`;
	foreach (%os_info){   chomp;}
	return %os_info;
}

sub add_item
{
	 my ($string, $flag, $value)= @_;
	 $string .= "\t\t".'<script>'."\n";
	 $string .= "\t\t\t<id>$flag</id>\n";
	 $string .= "\t\t\t<value><![CDATA[$value]]></value>\n";
	 $string .= "\t\t</script>\n";
	return $string;
}
sub generate_xml
{
	$ARGC = @ARGV;
	if($ARGC lt 1)
	{
		print qq{usag:uuid.pl IP };
		exit;
	}
	my %os_info = get_os_info();
	my $os_name = $os_info{"osname"};
	my $host_name = $os_info{"hostname"};
	my $os_version = $os_info{"osversion"};
	my $date = ` date "+%Y-%m-%d %H:%M:%S"`;
	chomp $date;
	my $coding = `echo \$LANG`;
	my $coding_value = "UTF-8";
	chomp $coding;
	if($coding =~ "GB")
	{
        $coding_value = "GBK"
    }
	my $ipaddr = $ARGV[0];
	my $xml_string = "";
	
	$xml_string .='<?xml version="1.0" encoding="'.$coding_value.'"?>'."\n";
	$xml_string .='<result>'."\n";
	$xml_string .= '<osName><![CDATA['."$os_name".']]></osName>'."\n";
	$xml_string .= '<version><![CDATA['."$os_version".']]></version>'."\n";
	$xml_string .= '<ip><![CDATA['."$ipaddr".']]></ip>'."\n";
	$xml_string .= '<type><![CDATA[/server/OpenEuler]]></type>'."\n";
	$xml_string .= '<startTime><![CDATA['."$date".']]></startTime>'."\n";
	$xml_string .= '<pId><![CDATA[287]]></pId>'."\n";

	$xml_string .=	"\t".'<scripts>'."\n";
	
	foreach $key (@array_pre_flag)
	{
	    print $key."\n";
		$value = $pre_cmd{$key};
		my $tmp_result = $value.`$value`;
		chomp $tmp_result;
		$tmp_result =~ s/>/&gt;/g;
		$tmp_result =~ s/[\x00-\x08\x0b-\x0c\x0e-\x1f]//g;
		$xml_string = &add_item( $xml_string, $key, $tmp_result );
	}
	$xml_string .= "\t</scripts>\n";
	
	my $enddate = ` date "+%Y-%m-%d %H:%M:%S"`;
	$xml_string .= '<endTime><![CDATA['."$enddate".']]></endTime>'."\n";
	
	$xml_string .= "</result>"."\n";
	$xmlfile = $ipaddr."_"."OpenEuler"."_chk.xml";
	print $xmlfile."\n";
	open XML,">$ENV{'PWD'}/".$xmlfile or die "Cannot create ip.xml:$!";
	print XML $xml_string;
    print "write  result to $ENV{'PWD'}/$xmlfile\n";
    print "execute end!\n";
 }
 generate_xml();
