# New Server BUILD AA v2.1 (newServerBuildAARHEL.sh)
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
		[ ! -d /home/$i ] && mkdir /home/$i
		chown -R $i:$i /home/$i
		/usr/sbin/usermod -d /home/$i $i
	done

	cat /home/unxdbftp/.ssh/id_dsa.pub1 >> /home/unxdbftp/.ssh/authorized_keys
	chown -R unxdbftp:9200 /home/unxdbftp/.ssh/authorized_keys
		
	for i in `egrep "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x90 -n7 -w7 -i 90 $i;done &> /dev/null;
	for i in `egrep -v "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x99999 $i;done &> /dev/null;
	for i in `egrep -v "^ed[0-9]|^aa|[0-9]^sg[0-9]" /etc/passwd|cut -d: -f1`;do chage -M-1 -m-1 -W-1 $i;done &> /dev/null;
}
newServChk_AA(){
	chmod 744 /home/unxdbftp/private/incoming/newservchk_AA_only.sh
	sh /home/unxdbftp/private/incoming/newservchk_AA_only.sh act &> /dev/null;
}
newServUpd_AA(){
	chmod 744 /home/unxdbftp/private/incoming/newservupd_AA_only.sh
	sh /home/unxdbftp/private/incoming/newservupd_AA_only.sh act &> /dev/null;
}
offPayInstall(){
	chmod 744 /home/unxdbftp/private/incoming/offpayinstall.sh
	sh /home/unxdbftp/private/incoming/offpayinstall.sh -d &> /dev/null;
}
loginCheckAA(){
	mv /home/unxdbftp/private/incoming/logincheck.sh /etc
	echo ""; echo "- UPDATING LOGIN CONFIGURATIONS -"; echo ""

	/bin/cp -p /etc/profile /etc/profile.$DATE

	grep "trap 2 3" /etc/profile  >> /dev/null;
	if [ "$?" -eq "0" ]; then
		echo "";echo "- TRAP - [ LINE EXISTS ]";echo ""
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
fixPerlLinuxAA(){

	/bin/cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.$DATE
	/bin/cp -p /etc/login.defs /etc/login.defs.$DATE
	/bin/cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.$DATE

	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MAX_DAYS\s*[0-9].*/PASS_MAX_DAYS   90/'
	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MIN_DAYS\s*[0-9].*/PASS_MIN_DAYS   1/'
	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MIN_LEN\s*[0-9].*/PASS_MIN_LEN    7/'
	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_WARN_AGE\s*[0-9].*/PASS_WARN_AGE   7/'
	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/UMASK\s*[0-9].*/UMASK           022/'
	/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/#UMASK\s*[0-9].*/UMASK           022/'

	/bin/grep UMASK /etc/login.defs >> /dev/null;
	if [ "$?" -eq "0" ]; then
		/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/UMASK.*/UMASK           022/'
		/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/#UMASK.*/UMASK           022/'
		echo "";echo "    - UMASK - [ LINES EXISTS AND HAVE BEEN UPDATED ]";echo ""
	else
		echo "# The permission mask is initialized to this value. If not specified," >> /etc/login.defs
		echo "# the permission mask will be initialized to 022." >> /etc/login.defs
		echo "UMASK            022" >> /etc/login.defs
		echo "";echo "    - UMASK - [ LINES ADDED ]";echo ""
	fi

	/bin/egrep 'readonly|TMOUT' /etc/profile >> /dev/null;
	if [ "$?" -eq "0" ]; then
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#readonly TMOUT=[0-9].*/readonly TMOUT=900/'
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/readonly TMOUT=[0-9].*/readonly TMOUT=900/'
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#export TMOUT.*/export TMOUT/'
		echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/export TMOUT.*/export TMOUT/'
		echo "";echo "    - TMOUT - [ LINES EXISTS AND HAVE BEEN UPDATED ]";echo ""
	else
		echo " " >> /etc/profile
		echo readonly TMOUT=900 >> /etc/profile
		echo export TMOUT >> /etc/profile
		echo " " >> /etc/profile
		echo "";echo "    - TMOUT - [ LINES ADDED ]";echo ""
	fi

	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/pam_pwquality.so/pam_cracklib.so/'
	
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*retry=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*lcredit=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*dcredit=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*difok=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*minlen=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*ocredit=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*ucredit=[0-9-]*//'

	/usr/bin/perl -i -pe 'chomp,$_.=" retry=3 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" lcredit=-1 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" dcredit=-1 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" difok=3 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" minlen=7 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" ocredit=-1 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" ucredit=-1 \n" if /s*pam_cracklib.so/' /etc/pam.d/system-auth

	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*remember=[0-9-]*//'
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*sha512*//'
	/usr/bin/perl -i -pe 'chomp,$_.="\n" if /password\s*sufficient\s*pam_unix.so/' /etc/pam.d/system-auth
	/usr/bin/perl -i -pe 'chomp,$_.=" remember=4 sha512\n" if /password\s*sufficient\s*pam_unix.so/' /etc/pam.d/system-auth
	
	/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/password\s*sufficient\s*pam_unix.so\s*remember=4\s*sha512\n//'
	
	/bin/grep "pam_tally.so" /etc/pam.d/system-auth
	if [ "$?" -eq "0" ]; then
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/pam_tally.so/pam_tally2.so/'
		#cat /etc/pam.d/system-auth
	fi

	/bin/grep "pam_tally2.so" /etc/pam.d/system-auth
	if [ "$?" -eq "0" ]; then
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*onerr=.*//'
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*deny=[0-9-].*//'
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*unlock_time=[0-9-].*//'
		/usr/bin/perl -i -pe 'chomp,$_.="" if /auth\s.*required\s.*pam_tally2.so\s.*/' /etc/pam.d/system-auth
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/auth\s.*required\s.*pam_tally2.so\s*/\n/'
		/usr/bin/perl -i -pe 'chomp,$_.="\n" if /run./' /etc/pam.d/system-auth
		/usr/bin/perl -i -pe 'chomp,$_.="\nauth        required      pam_tally2.so onerr=fail deny=3 unlock_time=3600\n" if /run./' /etc/pam.d/system-auth
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*per_user*//'
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*reset*//'
		/usr/bin/perl -i -pe 'chomp,$_.="\n" if /account\s.*required\s.*pam_tally2.so/' /etc/pam.d/system-auth
		/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/account\s.*required\s.*pam_tally2.so\s*//'
		/usr/bin/perl -i -pe 'chomp,$_.="\naccount     required      pam_tally2.so\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
		#cat /etc/pam.d/system-auth
	else
		/usr/bin/perl -i -pe 'chomp,$_.="\n" if /run./' /etc/pam.d/system-auth
		/usr/bin/perl -i -pe 'chomp,$_.="\nauth        required      pam_tally2.so onerr=fail deny=3 unlock_time=3600\n" if /run./' /etc/pam.d/system-auth
		/usr/bin/perl -i -pe 'chomp,$_.="\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
		/usr/bin/perl -i -pe 'chomp,$_.="\naccount     required      pam_tally2.so\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
		#cat /etc/pam.d/system-auth
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

	ps -ef | grep sshd | awk '$3==1 {print "kill -HUP",$2}' | sh
}
showLinuxData(){
	echo ""; echo "- SYSTEM AUTHORIZATIONS DEFINITIONS -"; echo ""
	echo "";cat /etc/pam.d/system-auth;echo ""
	echo ""; echo "- LOGIN DEFINITIONS -"; echo ""
	echo "";grep -e PASS -e UMASK /etc/login.defs;echo ""
	echo ""; echo "- PROFILE DEFINITIONS -"; echo ""
	echo "";grep TMOUT /etc/profile;echo ""
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
	if uname | grep -i Linux >> /dev/null; then
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
			fixPerlLinuxAA;
			fixPerlSshdConfigAA;
		echo ""; echo "    [ SUCCESSFUL ]"; echo ""
		echo ""; echo "||| CURRENT & UPDATED TECHNICAL SECURITY STANDARDS (AA) DATA |||"; echo ""
			showSSHDConfigData;
			showLinuxData;
		echo ""; echo "||| CURRENT & UPDATED TECHNICAL SECURITY STANDARDS (AA) DATA |||"; echo ""
		else
		echo "--- ATTENTION ---"
		echo "This is not a Linux System. Please verify."
	fi
}
# Calls "main" function
main
