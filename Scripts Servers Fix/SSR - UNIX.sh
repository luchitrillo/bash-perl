PATH=$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/lbin:/usr/local/etc:/opt/sfw/bin/.

fecha=`date '+%m-%d-%y'`
/usr/bin/cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.$fecha
/usr/bin/cp -p /etc/default/passwd /etc/default/passwd.$fecha
/usr/bin/cp -p /etc/default/login /etc/default/login.$fecha
/usr/bin/cp -p /etc/security/policy.conf /etc/security/policy.conf.$fecha
/usr/bin/cp -p /etc/profile /etc/profile.$fecha

grep "trap 2 3" /etc/profile
if [ "$?" -eq "0" ]; then
echo "";echo "-TRAP- LINE EXISTS";echo ""
else
perl -i -pe 'chomp,$_.="\n# HP Information Security - Midrange Access Control Administration\n" if $. ==1' /etc/profile
perl -i -pe 'chomp,$_.="\n# The following two lines are for the support of /etc/security/login.deny\n" if $. ==2' /etc/profile
perl -i -pe 'chomp,$_.="\ntrap 2 3\n" if $. ==3' /etc/profile
echo "";echo "-TRAP- LINE HAS BEEN ADDED";echo ""
fi

grep "/etc/logincheck" /etc/profile >> /dev/null;
if [ "$?" -eq "0" ]; then
echo "";echo "-/ETC/LOGINCHECK- LINE EXISTS";echo ""
else
if uname | grep -i Linux >> /dev/null; then
perl -i -pe 'chomp,$_.="\nsh /etc/logincheck.sh\n\n" if $. ==4' /etc/profile
echo "";echo "-/ETC/LOGINCHECK- LINE HAS BEEN ADDED";echo ""
else
perl -i -pe 'chomp,$_.="\n/etc/logincheck.sh\n\n" if $. ==4' /etc/profile
echo "";echo "-/ETC/LOGINCHECK- LINE HAS BEEN ADDED";echo ""
fi
fi

if uname | grep -i Linux >> /dev/null; then
chown root:root /etc/logincheck.sh
ls -la /etc/ | grep logincheck.sh
else
chown root:sys /etc/logincheck.sh
ls -la /etc/ | grep logincheck.sh
fi

chmod 755 /etc/security
chmod 644 /etc/security/login.deny
chmod 755 /etc/logincheck.sh
chmod 644 /etc/profile

echo ""; echo "UPDATING ACCOUNTS"; echo ""
for i in `egrep "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x90 -n7 -w7 $i;done >> /dev/null;
for i in `egrep "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do usermod -f90 $i;done >> /dev/null;
for i in `egrep -v "^ed[0-9]|^aa[0-9]|^sg[0-9]" /etc/passwd|cut -d: -f1`;do passwd -x99999 $i;done >> /dev/null;

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
echo "";echo "LINE EXISTS";echo ""
echo /usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/DICTIONMINWORDLENGTH=.*/DICTIONMINWORDLENGTH=3/'
echo /usr/bin/find /etc/default/passwd | /usr/bin/xargs perl -pi -e 's/#DICTIONMINWORDLENGTH=.*/DICTIONMINWORDLENGTH=3/'
echo "";echo "DICTIONARY DEFAUTLTS";echo ""
mkpwdict;echo ""
else
echo "";echo "LINE ADDED";echo ""
echo DICTIONMINWORDLENGTH=3 >> /etc/default/passwd
echo "";echo "DICTIONARY DEFAUTLTS";echo ""
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
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/RETRIES=[0-9]*/RETRIES=3/'
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#RETRIES=[0-9]*/RETRIES=3/'
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/SYSLOG_FAILED_LOGIN=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/SYSLOG_FAILED_LOGINS=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#SYSLOG_FAILED_LOGIN=[0-9]*/SYSLOG_FAILED_LOGINS=0/'
/usr/bin/find /etc/default/login | /usr/bin/xargs perl -pi -e 's/#SYSLOG_FAILED_LOGINS=[0-9]*/SYSLOG_FAILED_LOGINS=0/'

/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/LOCK_AFTER_RETRIES=[A-Z].*/LOCK_AFTER_RETRIES=yes/'
/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/#LOCK_AFTER_RETRIES=[A-Z].*/LOCK_AFTER_RETRIES=yes/'
/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/LOCK_AFTER_RETRIES=[a-z].*/LOCK_AFTER_RETRIES=yes/'
/usr/bin/find /etc/security/policy.conf | /usr/bin/xargs perl -pi -e 's/#LOCK_AFTER_RETRIES=[a-z].*/LOCK_AFTER_RETRIES=yes/'

/bin/grep TMOUT /etc/profile >> /dev/null
if [ "$?" -eq "0" ]; then
echo "";echo "LINE EXISTS";echo ""
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/TMOUT=[0-9].*/TMOUT=900/'
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#TMOUT=[0-9].*/TMOUT=900/'
echo /usr/bin/find /etc/profile | /usr/bin/xargs perl -pi -e 's/#export TMOUT.*/export TMOUT/'
else
echo " " >> /etc/profile
echo TMOUT=900 >> /etc/profile
echo export TMOUT >> /etc/profile
echo " " >> /etc/profile
echo "";echo "LINE ADDED";echo ""
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

ps -ef | grep sshd | nawk '$3==1 {print "kill -HUP",$2}' | sh

echo "";/usr/xpg4/bin/grep -e LoginGraceTime -e PermitRootLogin -e RhostsAuthentication -e IgnoreRhosts -e RhostsRSAAuthentication -e PermitEmptyPasswords -e nossh /etc/ssh/sshd_config;echo ""
echo "";/usr/xpg4/bin/grep -e MAXWEEKS= -e MINWEEKS= -e PASSLENGTH= -e HISTORY= -e NAMECHECK= -e MINDIFF= -e MINALPHA= -e MINNONALPHA= -e MAXREPEATS= -e DICTIONLIST= -e MINUPPER= -e MINLOWER= -e DICTIONDBDIR= -e DICTIONMINWORDLENGTH= /etc/default/passwd;echo ""
echo "";/usr/xpg4/bin/grep -e CONSOLE= -e PASSREQ= -e UMASK= -e DISABLETIME= -e RETRIES= -e SYSLOG_FAILED_LOGINS= -e TIMEOUT= /etc/default/login;echo ""
echo "";/bin/grep TMOUT /etc/profile;echo ""
echo "";/bin/grep LOCK_AFTER_RETRIES /etc/security/policy.conf;echo ""
echo "";/bin/grep trap /etc/profile;echo ""
echo "";/bin/grep "/etc/logincheck" /etc/profile;echo ""
