PATH=$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/lbin:/usr/local/etc:/opt/sfw/bin/.

fecha=`date '+%m-%d-%y'`
/bin/cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.Compliance.$fecha
/bin/cp -p /etc/login.defs /etc/login.defs.Compliance.$fecha
/bin/cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.Compliance.$fecha
/bin/cp -p /etc/profile /etc/profile.Compliance.$fecha

/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MAX_DAYS\s*[0-9].*/PASS_MAX_DAYS   90/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MIN_DAYS\s*[0-9].*/PASS_MIN_DAYS   1/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_MIN_LEN\s*[0-9].*/PASS_MIN_LEN    7/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/PASS_WARN_AGE\s*[0-9].*/PASS_WARN_AGE   7/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/UMASK\s*[0-9].*/UMASK           022/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/#UMASK\s*[0-9].*/UMASK           022/'

/bin/grep UMASK /etc/login.defs
if [ "$?" -eq "0" ]; then
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/UMASK.*/UMASK           022/'
/usr/bin/find /etc/login.defs | /usr/bin/xargs perl -pi -e 's/#UMASK.*/UMASK           022/'
echo "";echo "UMASK LINES EXISTS - UPDATED";echo ""
else
echo "# The permission mask is initialized to this value. If not specified," >> /etc/login.defs
echo "# the permission mask will be initialized to 022." >> /etc/login.defs
echo "UMASK            022" >> /etc/login.defs
echo "";echo "UMASK LINES ADDED";echo ""
fi

/bin/egrep 'readonly|TMOUT' /etc/profile >> /dev/null
if [ "$?" -eq "0" ]; then
echo "";echo "LINE EXISTS";echo ""
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#readonly TMOUT=[0-9].*/readonly TMOUT=900/'
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/readonly TMOUT=[0-9].*/readonly TMOUT=900/'
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#export TMOUT.*/export TMOUT/'
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/export TMOUT.*/export TMOUT/'
else
echo " " >> /etc/profile
echo readonly TMOUT=900 >> /etc/profile
echo export TMOUT >> /etc/profile
echo " " >> /etc/profile
echo "";echo "LINE ADDED";echo ""
fi

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

/bin/grep "pam_tally.so" /etc/pam.d/system-auth
if [ "$?" -eq "0" ]; then
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/pam_tally.so/pam_tally2.so/'
cat /etc/pam.d/system-auth
fi

/bin/grep "pam_tally2.so" /etc/pam.d/system-auth
if [ "$?" -eq "0" ]; then
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*onerr=.*//'
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*deny=[0-9-].*//'
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*unlock_time=[0-9-].*//'
/usr/bin/perl -i -pe 'chomp,$_.="" if /auth\s.*required\s.*pam_tally2.so\s.*/' /etc/pam.d/system-auth
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/auth\s.*required\s.*pam_tally2.so\s*//'
/usr/bin/perl -i -pe 'chomp,$_.="\n" if /run./' /etc/pam.d/system-auth
/usr/bin/perl -i -pe 'chomp,$_.="\nauth        required      pam_tally2.so onerr=fail deny=3 unlock_time=3600\n" if /run./' /etc/pam.d/system-auth
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*per_user*//'
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/\s*reset*//'
/usr/bin/perl -i -pe 'chomp,$_.="\n" if /account\s.*required\s.*pam_tally2.so/' /etc/pam.d/system-auth
/usr/bin/find  /etc/pam.d/system-auth | /usr/bin/xargs perl -pi -e 's/account\s.*required\s.*pam_tally2.so\s*//'
/usr/bin/perl -i -pe 'chomp,$_.="\naccount     required      pam_tally2.so\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
cat /etc/pam.d/system-auth
else
/usr/bin/perl -i -pe 'chomp,$_.="\n" if /run./' /etc/pam.d/system-auth
/usr/bin/perl -i -pe 'chomp,$_.="\nauth        required      pam_tally2.so onerr=fail deny=3 unlock_time=3600\n" if /run./' /etc/pam.d/system-auth
/usr/bin/perl -i -pe 'chomp,$_.="\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
/usr/bin/perl -i -pe 'chomp,$_.="\naccount     required      pam_tally2.so\n" if /account\s.*required\s.*pam_unix.so/' /etc/pam.d/system-auth
cat /etc/pam.d/system-auth
fi

/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/LoginGraceTime [0-9].*/LoginGraceTime 60/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#LoginGraceTime [0-9]*/LoginGraceTime 60/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitEmptyPasswords [a-z]*/PermitEmptyPasswords no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitRootLogin\s*[a-z].*/PermitRootLogin no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitRootLogin\s*[a-z].*/PermitRootLogin no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/PermitRootLogin\s*[A-Z].*/PermitRootLogin no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#PermitRootLogin\s*[A-Z].*/PermitRootLogin no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/IgnoreRhosts [a-z]*/IgnoreRhosts yes/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#IgnoreRhosts [a-z]*/IgnoreRhosts yes/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/RhostsAuthentication [a-z]*/RhostsAuthentication no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#RhostsAuthentication [a-z]*/RhostsAuthentication no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/RhostsRSAAuthentication [a-z]*/RhostsRSAAuthentication no/'
/usr/bin/find /etc/ssh/sshd_config | /usr/bin/xargs perl -pi -e 's/#RhostsRSAAuthentication [a-z]*/RhostsRSAAuthentication no/'

/bin/grep nossh /etc/ssh/sshd_config
if [ "$?" -eq "0" ]; then
echo "";echo "LINE EXISTS";echo ""
else
echo " " >> /etc/ssh/sshd_config
echo "# Deny all users who are in the nossh group" >> /etc/ssh/sshd_config
echo DenyGroups nossh >> /etc/ssh/sshd_config
echo " " >> /etc/ssh/sshd_config
echo "";echo "LINE ADDED";echo ""
fi

ps -ef | grep sshd | awk '$3==1 {print "kill -HUP",$2}' | sh

echo "";grep -e LoginGraceTime -e PermitRootLogin -e RhostsAuthentication -e IgnoreRhosts -e RhostsRSAAuthentication -e PermitEmptyPasswords -e nossh /etc/ssh/sshd_config;echo ""
echo "";grep -e PASS -e UMASK /etc/login.defs;echo ""
echo "";cat /etc/pam.d/system-auth;echo ""
echo "";egrep 'readonly|TMOUT' /etc/profile;echo ""
echo "";/bin/grep trap /etc/profile;echo ""
echo "";/bin/grep "/etc/logincheck" /etc/profile;echo ""
