# New Server BUILD AA v2.1 (newServerBuildAASOLARIS.sh)
# GOC Security Compliance Team (UNIX) for AA Client
# Luciano Trillo Pelizzari (luciano.trillo@hp.com)

PATH=$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/lbin:/usr/local/etc:/opt/sfw/bin/.
FUNCTIONALS="nobody nscd rpc dbus avahi haldaemon oprofile sabayon"
DATE=`date '+%m-%d-%y'`

accountsUpd(){
	/bin/cp -p /etc/passwd /etc/passwd.$DATE
	/bin/cp -p /etc/shadow /etc/shadow.$DATE

	/usr/sbin/groupadd -g 99999 nossh
	/usr/sbin/userdel uefix

	for i in $FUNCTIONALS;
		do
		[ ! -d /export/home/$i ] && mkdir /export/home/$i
		/usr/bin/chown -R $i:$i /export/home/$i
		/usr/sbin/usermod -d /export/home/$i $i
	done
	
	cat /export/home/unxdbftp/.ssh/id_dsa.pub1 >> /export/home/unxdbftp/.ssh/authorized_keys
	/usr/bin/chown -R unxdbftp:9200 /export/home/unxdbftp/.ssh/authorized_keys

	for i in `egrep "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x90 -n7 -w7 $i;done
	for i in `egrep -v "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x99999 $i;done
	for i in `egrep "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do usermod -f90 $i;done
}
newServChk_AA(){
	chmod 744 /export/home/unxdbftp/private/incoming/newservchk_AA_only.sh
	sh /export/home/unxdbftp/private/incoming/newservchk_AA_only.sh act &> /dev/null
}
newServUpd_AA(){
	chmod 744 /export/home/unxdbftp/private/incoming/newservupd_AA_only.sh
	sh /export/home/unxdbftp/private/incoming/newservupd_AA_only.sh act &> /dev/null
}
offPayInstall(){
	chmod 744 /export/home/unxdbftp/private/incoming/offpayinstall.sh
	sh /export/home/unxdbftp/private/incoming/offpayinstall.sh -d &> /dev/null
}
loginCheckAA(){
	mv /export/home/unxdbftp/private/incoming/logincheck.sh /etc
	echo ""; echo "- UPDATING LOGIN CONFIGURATIONS -"; echo ""

	/bin/cp -p /etc/profile /etc/profile.$DATE

	grep "trap 2 3" /etc/profile  >> /dev/null;
	if [ "$?" -eq "0" ]; then
		echo "";echo "    - TRAP - [ LINE EXISTS ]";echo ""
	else
		perl -i -pe 'chomp,$_.="\n# HP Information Security - Midrange Access Control Administration\n" if $. ==1' /etc/profile
		perl -i -pe 'chomp,$_.="\n# The following two lines are for the support of /etc/security/login.deny\n" if $. ==2' /etc/profile
		perl -i -pe 'chomp,$_.="\ntrap 2 3\n" if $. ==3' /etc/profile
		echo "";echo "    - TRAP - [ LINE HAS BEEN ADDED ]";echo ""
	fi

	grep "/etc/logincheck" /etc/profile >> /dev/null;
	if [ "$?" -eq "0" ]; then
		echo "";echo "    - LOGINCHECK - [ LINE EXISTS ]";echo ""
	else
		if uname | grep -i Linux >> /dev/null; then
			perl -i -pe 'chomp,$_.="\nsh /etc/logincheck.sh\n\n" if $. ==4' /etc/profile
			echo "";echo "    - LOGINCHECK - [ LINE HAS BEEN ADDED ]";echo ""
		else
			if uname | grep -i SunOS >> /dev/null; then
				perl -i -pe 'chomp,$_.="\n/etc/logincheck.sh\n\n" if $. ==4' /etc/profile
				echo "";echo "    - LOGINCHECK - [ LINE HAS BEEN ADDED ]";echo ""
			else
				echo "--- ATTENTION ---"
				echo "This is not a Linux or SunOS System. Please verify."
			fi
		fi
	fi

	if uname | grep -i Linux >> /dev/null; then
		chown root:root /etc/logincheck.sh
		ls -la /etc/ | grep logincheck.sh >> /dev/null;
		else
		chown root:sys /etc/logincheck.sh
		ls -la /etc/ | grep logincheck.sh >> /dev/null;
	fi

	chmod 755 /etc/security
	chmod 644 /etc/security/login.deny
	chmod 755 /etc/logincheck.sh
	chmod 644 /etc/profile
}
fixPerlSunOSAA(){
	/usr/bin/cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.$DATE
	/usr/bin/cp -p /etc/default/passwd /etc/default/passwd.$DATE
	/usr/bin/cp -p /etc/default/login /etc/default/login.$DATE
	/usr/bin/cp -p /etc/security/policy.conf /etc/security/policy.conf.$DATE

	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MAXWEEKS=[0-9]*/MAXWEEKS=12/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MAXWEEKS=[0-9]*/MAXWEEKS=12/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINWEEKS=[0-9]*/MINWEEKS=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINWEEKS=[0-9]*/MINWEEKS=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/PASSLENGTH=[0-9]*/PASSLENGTH=7/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#PASSLENGTH=[0-9]*/PASSLENGTH=7/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/HISTORY=[0-9]*/HISTORY=4/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#HISTORY=[0-9]*/HISTORY=4/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINDIFF=[0-9]*/MINDIFF=3/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINDIFF=[0-9]*/MINDIFF=3/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINALPHA=[0-9]*/MINALPHA=2/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINALPHA=[0-9]*/MINALPHA=2/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINNONALPHA=[0-9]*/MINNONALPHA=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINNONALPHA=[0-9]*/MINNONALPHA=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MAXREPEATS=[0-9]*/MAXREPEATS=2/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MAXREPEATS=[0-9]*/MAXREPEATS=2/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINUPPER=[0-9].*/MINUPPER=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINUPPER=[0-9].*/MINUPPER=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/MINLOWER=[0-9].*/MINLOWER=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#MINLOWER=[0-9].*/MINLOWER=1/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/NAMECHECK=[a-z].*/NAMECHECK=yes/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#NAMECHECK=[a-z].*/NAMECHECK=yes/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/NAMECHECK=[A-Z].*/NAMECHECK=yes/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#NAMECHECK=[A-Z].*/NAMECHECK=yes/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/DICTIONLIST=.*/DICTIONLIST=\/usr\/share\/lib\/dict\/words/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#DICTIONLIST=.*/DICTIONLIST=\/usr\/share\/lib\/dict\/words/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/DICTIONDBDIR=.*/DICTIONDBDIR=\/var\/passwd/'
	/usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#DICTIONDBDIR=.*/DICTIONDBDIR=\/var\/passwd/'
	
	/bin/grep DICTIONMINWORDLENGTH /etc/default/passwd >> /dev/null
	if [ "$?" -eq "0" ]; then
		echo "";echo "    - DICTIONMINWORDLENGTH - [ LINE EXISTS ]";echo ""
		echo /usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/DICTIONMINWORDLENGTH=.*/DICTIONMINWORDLENGTH=3/'
		echo /usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#DICTIONMINWORDLENGTH=.*/DICTIONMINWORDLENGTH=3/'
		echo "";echo "- DICTIONARY DEFAUTLTS -";echo ""
		mkpwdict;echo ""
	else
		echo "";echo "    - DICTIONMINWORDLENGTH - [ LINE ADDED ]";echo ""
		echo DICTIONMINWORDLENGTH=3 >> /etc/default/passwd
		echo "";echo "    - DICTIONARY DEFAUTLTS -";echo ""
		mkpwdict;echo ""
	fi
	
	cp -p /usr/share/lib/dict/words /usr/share/lib/dict/words.bak
	cp -p /tmp/dictionlist.words /tmp/dictionlist.words.bak
	awk 'length >3' /usr/share/lib/dict/words > /tmp/dictionlist.words
	cp -p /tmp/dictionlist.words /usr/share/lib/dict/words

	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#CONSOLE/CONSOLE/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/TIMEOUT=[0-9]*/TIMEOUT=60/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#TIMEOUT=[0-9]*/TIMEOUT=60/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/UMASK=[0-9]*/UMASK=022/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#UMASK=[0-9]*/UMASK=022/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/DISABLETIME=[0-9]*/DISABLETIME=3600/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#DISABLETIME=[0-9]*/DISABLETIME=3600/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/RETRIES=[0-9]*/RETRIES=6/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#RETRIES=[0-9]*/RETRIES=6/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/SYSLOG_FAILED_LOGIN=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/SYSLOG_FAILED_LOGINS=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#SYSLOG_FAILED_LOGIN=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
	/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#SYSLOG_FAILED_LOGINS=[0-9]*/SYSLOG_FAILED_LOGINS=0/'

	/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/LOCK_AFTER_RETRIES=[A-Z].*/LOCK_AFTER_RETRIES=yes/'
	/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/#LOCK_AFTER_RETRIES=[A-Z].*/LOCK_AFTER_RETRIES=yes/'
	/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/LOCK_AFTER_RETRIES=[a-z].*/LOCK_AFTER_RETRIES=yes/'
	/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/#LOCK_AFTER_RETRIES=[a-z].*/LOCK_AFTER_RETRIES=yes/'
	
	/bin/grep TMOUT /etc/profile >> /dev/null;
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/TMOUT=[0-9].*/TMOUT=900/'
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#TMOUT=[0-9].*/TMOUT=900/'
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#export TMOUT.*/export TMOUT/'
		echo "";echo "    - TMOUT - [ LINES EXISTS AND HAVE BEEN UPDATED ]";echo ""
	else
		echo " " >> /etc/profile
		echo TMOUT=900 >> /etc/profile
		echo export TMOUT >> /etc/profile
		echo " " >> /etc/profile
		echo "";echo "    - TMOUT - [ LINES ADDED ]";echo ""
	fi
}				
fixPerlSshdConfigAA(){
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/LoginGraceTime [0-9].*/LoginGraceTime 60/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#LoginGraceTime [0-9]*/LoginGraceTime 60/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitRootLogin\s*[a-z].*/PermitRootLogin no/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitRootLogin\s*[a-z].*/PermitRootLogin no/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitRootLogin\s*[A-Z].*/PermitRootLogin no/'
	/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitRootLogin\s*[A-Z].*/PermitRootLogin no/'
	/bin/grep known_hosts /etc/ssh/sshd_config >> /dev/null
	
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/known_hosts.*/known_hosts/'
	fi
	
	/bin/grep RhostsRSAAuthentication /etc/ssh/sshd_config >> /dev/null
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/RhostsRSAAuthentication [a-z]*/RhostsRSAAuthentication no/'
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#RhostsRSAAuthentication [a-z]*/RhostsRSAAuthentication no/'
		echo "";echo "    - RHOSTSRSAAUTHENTICATION - [ PARAMETER & VALUE UPDATED ]";echo ""
	else
		echo " " >> /etc/ssh/sshd_config 
		echo RhostsRSAAuthentication no >> /etc/ssh/sshd_config 
		echo " " >> /etc/ssh/sshd_config 
		echo "";echo "    - RHOSTSRSAAUTHENTICATION - [ PARAMETER & VALUE ADDED ]";echo ""
	fi
	
	/bin/grep RhostsAuthentication /etc/ssh/sshd_config >> /dev/null
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/RhostsAuthentication [a-z]*/RhostsAuthentication no/'
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#RhostsAuthentication [a-z]*/RhostsAuthentication no/'
		echo "";echo "    - RHOSTSAUTHENTICATION - [ PARAMETER & VALUE UPDATED ]";echo ""
	else
		echo " " >> /etc/ssh/sshd_config 
		echo RhostsAuthentication no >> /etc/ssh/sshd_config 
		echo " " >> /etc/ssh/sshd_config 
		echo "";echo "    - RHOSTSAUTHENTICATION - [ PARAMETER & VALUE ADDED ]";echo ""
	fi
	
	/bin/grep IgnoreRhosts /etc/ssh/sshd_config >> /dev/null
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/IgnoreRhosts [a-z]*/IgnoreRhosts yes/'
		echo /usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#IgnoreRhosts [a-z]*/IgnoreRhosts yes/'
		echo "";echo "    - IGNORERHOSTS - [ PARAMETER & VALUE UPDATED ]";echo ""
	else
		echo " " >> /etc/ssh/sshd_config 
		echo IgnoreRhosts yes >> /etc/ssh/sshd_config 
		echo " " >> /etc/ssh/sshd_config 
		echo "";echo "    - IGNORERHOSTS -[ PARAMETER & VALUE ADDED ]";echo ""
	fi	
				
	/bin/grep nossh /etc/ssh/sshd_config >> /dev/null;			
	if [ "$?" -eq "0" ]; then			
		echo "";echo "    - NOSSH - [ LINES EXISTS ]";echo ""		
	else			
		echo " " >> /etc/ssh/sshd_config		
		echo "# Deny all users who are in the nossh group" >> /etc/ssh/sshd_config		
		echo DenyGroups nossh >> /etc/ssh/sshd_config		
		echo " " >> /etc/ssh/sshd_config		
		echo "";echo "    - NOSSH - [ LINES ADDED ]";echo ""		
	fi

	ps -ef | grep sshd | nawk '$3==1 {print "kill -HUP",$2}' | sh
}
showSunOSData(){
	echo ""; echo "- PASSWORD CONFIGURATION DEFINITIONS -"; echo ""
	echo "";/usr/xpg4/bin/grep -e MAXWEEKS= -e MINWEEKS= -e PASSLENGTH= -e HISTORY= -e NAMECHECK= -e MINDIFF= -e MINALPHA= -e MINNONALPHA= -e MAXREPEATS= -e DICTIONLIST= -e MINUPPER= -e MINLOWER= -e DICTIONDBDIR= -e DICTIONMINWORDLENGTH= /etc/default/passwd;echo ""
	mkpwdict;echo ""
	echo ""; echo "- LOGIN DEFINITIONS -"; echo ""
	echo "";/usr/xpg4/bin/grep -e CONSOLE= -e PASSREQ= -e UMASK= -e DISABLETIME= -e RETRIES= -e SYSLOG_FAILED_LOGINS= -e TIMEOUT= /etc/default/login;echo ""
	echo ""; echo "- POLICY DEFINITIONS -"; echo ""
	echo "";/bin/grep LOCK_AFTER_RETRIES /etc/security/policy.conf;echo ""			
	echo ""; echo "- PROFILE DEFINITIONS -"; echo ""
	echo "";/bin/grep TMOUT /etc/profile;echo ""
	echo "";/bin/grep trap /etc/profile;echo ""
	echo "";/bin/grep "/etc/logincheck" /etc/profile;echo ""
}
showSSHDConfigData(){
	if uname | grep -i Linux >> /dev/null; then
		echo ""; echo "- SSHD CONFIGURATION DEFINITIONS -"; echo ""
		echo "";grep -e LoginGraceTime -e PermitRootLogin -e RhostsAuthentication -e IgnoreRhosts -e RhostsRSAAuthentication -e PermitEmptyPasswords -e nossh /etc/ssh/sshd_config;echo ""
	else
		echo ""; echo "- SSHD CONFIGURATION DEFINITIONS -"; echo ""
		echo "";/usr/xpg4/bin/grep -e LoginGraceTime -e PermitRootLogin -e RhostsAuthentication -e IgnoreRhosts -e RhostsRSAAuthentication -e PermitEmptyPasswords -e nossh /etc/ssh/sshd_config;echo ""
	fi
}
main (){
	if uname | grep -i SunOS >> /dev/null; then
		echo ""; echo "--- UPDATING ACCOUNTS ---"; echo ""
			accountsUpd &> /dev/null;
		echo ""; echo "    [ SUCCESSFUL ]"; echo ""
		echo ""; echo "--- LAUNCHING & RUNNING NEW SERVER SCRIPTS ---"; echo ""
			newServChk_AA &> /dev/null;
			newServUpd_AA &> /dev/null;
			offPayInstall &> /dev/null;
			loginCheckAA;
		echo ""; echo "    [ SUCCESSFUL ]"; echo ""
		echo ""; echo "--- CHECKING & FIXING TECHNICAL SECURITY STANDARDS (AA) DATA ---"; echo ""
			fixPerlSunOSAA;
			fixPerlSshdConfigAA;
		echo ""; echo "    [ SUCCESSFUL ]"; echo ""
		echo ""; echo "||| CURRENT TECHNICAL SECURITY STANDARDS (AA) DATA |||"; echo ""
			showSSHDConfigData;
			showSunOSData;
		echo ""; echo "||| CURRENT TECHNICAL SECURITY STANDARDS (AA) DATA |||"; echo ""
		else
		echo "--- ATTENTION ---"
		echo "This is not a SunOS System. Please verify."
	fi
}				
# Calls "main" function
main
