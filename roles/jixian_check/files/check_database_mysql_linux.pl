#!env perl
#Author: autoCreated
my $para_num = "5";
my %para;

$para{password} = $ARGV[1];
$para{user} = $ARGV[2];
$para{port} = $ARGV[3];
$para{path} = $ARGV[4];
if($ARGV[3] eq "null"){
   $para{port}=3306;
}
my $cmd_pre;
my $tmp_result1;
my $float;
$flat=0;
$cmd_pre="mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select lower('LOGIN DB SUSSESS')\"";
if($ARGV[1] eq "null" && $ARGV[2] ne "null"){
	$cmd_pre=~s/-p'null'//;
	$tmp_result1= `$cmd_pre`;
	if($tmp_result1 eq "" || $tmp_result1 =~ m/login db sussess/ eq 0){
	   $cmd_pre=$para{path}."/".$cmd_pre;
	   $tmp_result1= `$cmd_pre`;
	   $flat=1;
	}
}elsif($ARGV[1] ne "null" && $ARGV[2] eq "null"){
	$cmd_pre=~s/-u"null"//;
	$tmp_result1 = `$cmd_pre`;
	if($tmp_result1 eq "" || $tmp_result1 =~ m/login db sussess/ eq 0){
	   $cmd_pre=$para{path}."/".$cmd_pre;
	   $tmp_result1= `$cmd_pre`;
	   $flat=1;
	}
}elsif($ARGV[1] eq "null" && $ARGV[2] eq "null"){
    $cmd_pre=~s/-p'null'//;
	$cmd_pre=~s/-u"null"//;
	$tmp_result1 = `$cmd_pre`;
	if($tmp_result1 eq "" || $tmp_result1 =~ m/login db sussess/ eq 0){
	   $cmd_pre=$para{path}."/".$cmd_pre;
	   $tmp_result1= `$cmd_pre`;
	   $flat=1;
	}
}else{
	$tmp_result1 = `$cmd_pre`;
	if($tmp_result1 eq "" || $tmp_result1 =~ m/login db sussess/ eq 0){
	   $cmd_pre=$para{path}."/".$cmd_pre;
	   $tmp_result1= `$cmd_pre`;
	   $flat=1;
	}
}
$pre_cmd{1304} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"show variables like 'log_error';show variables like 'log_bin';show variables like 'log';\"";
$pre_cmd{1307} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select count(*) from mysql.user where user = ''\"";
$pre_cmd{1311} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"show variables like 'max_connections'\"";
$pre_cmd{1312} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"show variables like 'version'\"";
$pre_cmd{1313} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select * from mysql.user where length(Password) = 0 or Password is null;select count(*) from mysql.user where length(Password) = 0 or Password is null;\"";
$pre_cmd{1315} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select Host,User,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,Drop_priv from mysql.user where (Select_priv = 'Y') or (Select_priv = 'Y') or (Update_priv = 'Y') or (Delete_priv = 'Y') or (Create_priv = 'Y') or (Drop_priv = 'Y');select user,host,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,Drop_priv from mysql.db where db = 'mysql' and ( (Select_priv = 'Y') or (Insert_priv = 'Y') or (Update_priv = 'Y') or (Delete_priv = 'Y') or (Create_priv = 'Y') or (Drop_priv = 'Y'));\"";
$pre_cmd{1316} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select count(*) from mysql.user where user !='root' and User !='' and Password !=''\"";
$pre_cmd{1319} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"show variables like 'skip_networking'\"";
$pre_cmd{1320} = "ps -ef|grep \"mysqld\"|grep -v \"grep\"|grep -v \"mysqld_safe\"|awk '{print \$1}'
";
push(@array_pre_flag, 1320);
$pre_cmd{1321} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select Host from mysql.user where Host not in ('localhost','localhost.localdomain','127.0.0.1') and Password !=''\"";
$pre_cmd{1323} = "mysql -u\"$para{user}\" -p'$para{password}' -h127.0.0.1 --port=$para{port} -e\"select * from mysql.user where length(authentication_string) = 0 or authentication_string is null;select count(*) from mysql.user where length(authentication_string) = 0 or authentication_string is null;\"";



sub get_os_info
{
	my %os_info = (
 "initSh"=>"","hostname"=>"","osname"=>"","osversion"=>"","appversion"=>"");
 $os_info{"initSh"} = `unset LANG`;
	$os_info{"hostname"} = `uname -n`;
	$os_info{"osname"} = `uname -s`;
	$os_info{"osversion"} = `lsb_release -a;cat /etc/issue;cat /etc/redhat-release;uname -a`;
	$os_info{"appversion"} = `\"$para{path}\"/mysql -u\"$para{user}\" -p\"$para{password}\" -h127.0.0.1 --port=\"$para{port}\" -e\"select version();\"`;
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
	if($ARGC lt 5)
	{
		print "usag:uuid.pl IP  '数据库密码' 数据库用户名 端口号 数据库可执行文件mysql.sh路径";
		exit;
	}
	my %os_info = get_os_info();
	my $os_name = $os_info{"osname"};
	my $host_name = $os_info{"hostname"};
	my $os_version = $os_info{"osversion"};
	my $app_version = $os_info{"appversion"};
	my $date = `date "+%Y-%m-%d %H:%M:%S"`;
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
	$xml_string .= '<appver><![CDATA['."$app_version".']]></appver>'."\n";
	$xml_string .= '<ip><![CDATA['."$ipaddr".']]></ip>'."\n";
	$xml_string .= '<type><![CDATA[/database/Mysql]]></type>'."\n";
	$xml_string .= '<startTime><![CDATA['."$date".']]></startTime>'."\n";
	$xml_string .= '<pId><![CDATA[7000000]]></pId>'."\n";
	
	$xml_string .=	"\t".'<scripts>'."\n";
	
	while(($key,$value) = each%pre_cmd)
	{
	    print $key."\n";
		if($ARGV[1] eq "null" && $ARGV[2] ne "null"){
			$value=~s/-p'null'//;
			if($flat eq 1){
			 if($value =~ /mysql -/){
			    $value=$para{path}."/".$value;
			 }
			}
		}elsif($ARGV[1] ne "null" && $ARGV[2] eq "null"){
			$value=~s/-u"null"//;
			if($flat eq 1){
			  if($value =~ /mysql -/){
			    $value=$para{path}."/".$value;
			 }
			}
		}elsif($ARGV[1] eq "null" && $ARGV[2] eq "null"){
			$value=~s/-p'null'//;
			$value=~s/-u"null"//;
			if($flat eq 1){
			  if($value =~ /mysql -/){
			    $value=$para{path}."/".$value;
			 }
			}
		}else{
		    if($flat eq 1){
			  if($value =~ /mysql -/){
			    $value=$para{path}."/".$value;
			 }
			}
		}
		my $tmp_result = "\n".`$value`;
		chomp $tmp_result;
		$tmp_result =~ s/>/&gt;/g;
		$tmp_result =~ s/[\x00-\x08\x0b-\x0c\x0e-\x1f]//g;
		$xml_string = &add_item( $xml_string, $key, $tmp_result );
		
	}
	
	$xml_string .= "\t</scripts>\n";
	my $enddate = ` date "+%Y-%m-%d %H:%M:%S"`;
	$xml_string .= '<endTime><![CDATA['."$enddate".']]></endTime>'."\n";
	$xml_string .= "</result>"."\n";
	$xmlfile = $ipaddr."_"."linux_mysql"."_chk.xml";
	print $xmlfile."\n";
	open XML,">$ENV{'PWD'}/".$xmlfile or die "Cannot create ip.xml:$!";
	print XML $xml_string;
    print "write  result to $ENV{'PWD'}/$xmlfile\n";
    print "execute end!\n";
}
if($tmp_result1 =~ m/login db sussess/ eq 1){
  generate_xml();
}else{
  print "LOGIN DB failed!\n";
}
