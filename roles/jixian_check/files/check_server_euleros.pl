#!env perl
#Author: autoCreated
my $para_num = "1";
my %para;
@array_pre_flag = ();
@array_appendix_flag = ();

$para{Linux_su_password} = $ARGV[1];
$para{Linux_su_user} = $ARGV[2];

$pre_cmd{6609} = "cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"
";
push(@array_pre_flag, 6609);$pre_cmd{6611} = "export LANG=en_US.UTF-8
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
push(@array_pre_flag, 6616);$pre_cmd{6618} = "telnet_status=`systemctl|grep \"telnet.socket\"|wc -l`
if [ \$telnet_status -ge 1 ];then
echo \"Telnet process is open\"
echo \"pts_count=\"`cat /etc/securetty 2>/dev/null|grep -v \"^[[:space:]]*#\"|grep \"pts/*\"|wc -l`
else
echo \"Telnet process is not open\"
fi
unset telnet_status
";
push(@array_pre_flag, 6618);$pre_cmd{6620} = "if [ -f /etc/rsyslog.conf ];
then cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep -E '[[:space:]]*.+@.+';
fi
";
push(@array_pre_flag, 6620);$pre_cmd{6622} = "cat /etc/shadow|sed '/^\\s*#/d'|awk -F: '(\$2!~/^*/) && (\$2!~/^!!/) {print \$1\":\"}'|egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\"
egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'
echo \"result_pw=\"`cat /etc/shadow|sed '/^\\s*#/d'|awk -F: '(\$2!~/^*/) && (\$2!~/^!!/) {print \$1}'|egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\"|wc -l`
echo \"result_shell=\"`egrep \"^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:\" /etc/passwd|awk -F: '(\$7!~/bin\\/false/) {print \$1\":\"\$7}'|wc -l`
";
push(@array_pre_flag, 6622);$pre_cmd{6634} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`
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
push(@array_pre_flag, 6634);$pre_cmd{6636} = "up_uidmin=`(grep -v ^# /etc/login.defs |grep \"^UID_MIN\"|awk '(\$1=\"UID_MIN\"){print \$2}')`
up_uidmax=`(grep -v ^# /etc/login.defs |grep \"^UID_MAX\"|awk '(\$1=\"UID_MAX\"){print \$2}')`
egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'
echo \"result=\"`egrep -v \"oracle|sybase|postgres\" /etc/passwd|awk -F: '(\$3>='\$up_uidmin' && \$3<='\$up_uidmax') {print \$1\":\"\$3}'|wc -l`
unset up_uidmin up_uidmax
";
push(@array_pre_flag, 6636);$pre_cmd{6638} = "FTPSTATUS=`ps -ef|grep ftpd|grep -v grep|wc -l`;
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
push(@array_pre_flag, 6638);$pre_cmd{6640} = "cat /etc/redhat-release 2>/dev/null;uname -a
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
push(@array_pre_flag, 6642);$pre_cmd{6644} = "Check_ftp2 (){
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
push(@array_pre_flag, 6644);$pre_cmd{6647} = "systemctl|grep active;netstat -an|awk '{if( \$2==0 ){print\$0}}'
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
push(@array_pre_flag, 6649);$pre_cmd{6651} = "if [ -f /etc/rsyslog.conf ]
then
echo \"rsyslog=\"`cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\" | grep \"cron.\\*\"`
fi
";
push(@array_pre_flag, 6651);


sub get_os_info
{
	my %os_info = (
 "initSh"=>"","hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"initSh"} = `unset LANG`;
	$os_info{"hostname"} = `uname -n`;
	$os_info{"osname"} = `uname -s`;
	$os_info{"osversion"} = `cat /etc/os-release 2>/dev/null`;
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
	$xml_string .= '<type><![CDATA[/server/EulerOS]]></type>'."\n";
	$xml_string .= '<startTime><![CDATA['."$date".']]></startTime>'."\n";
	$xml_string .= '<pId><![CDATA[10000001]]></pId>'."\n";

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
	$xmlfile = $ipaddr."_"."EulerOS"."_chk.xml";
	print $xmlfile."\n";
	open XML,">$ENV{'PWD'}/".$xmlfile or die "Cannot create ip.xml:$!";
	print XML $xml_string;
    print "write  result to $ENV{'PWD'}/$xmlfile\n";
    print "execute end!\n";
 }
 generate_xml();
