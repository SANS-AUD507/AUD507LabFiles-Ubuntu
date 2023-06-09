#!/bin/bash
echo '******************************************************'
echo 'Admin has downloaded Tripwire and is setting up the site and local keys'
echo '******************************************************'
sudo rm -f /etc/tripwire/*.key
sudo rm -f /etc/tripwire/tw.cfg
sudo rm -f /etc/tripwire/twcfg.txt
sudo rm -f /var/lib/tripwire/ubuntu.twd
sudo twadmin --generate-keys -L /etc/tripwire/ubuntu-local.key -S /etc/tripwire/site.key  -P Aud507LocalKey -Q Aud507SiteKey
sudo cp /home/student/twpol.txt /etc/tripwire/

echo '******************************************************'
echo 'These are the current contents of the /etc/tripwire directory'
echo '******************************************************'

ls -alt /etc/tripwire

echo '******************************************************'
echo 'Admin is building a new configuration file'
echo '******************************************************'

sudo bash -c 'cat << EOF >/etc/tripwire/twcfg.txt
ROOT          =/usr/sbin
POLFILE       =/etc/tripwire/tw.pol
DBFILE        =/var/lib/tripwire/\$(HOSTNAME).twd
REPORTFILE    =/var/lib/tripwire/report/\$(HOSTNAME)-\$(DATE).twr
SITEKEYFILE   =/etc/tripwire/site.key
LOCALKEYFILE  =/etc/tripwire/\$(HOSTNAME)-local.key
EDITOR        =/usr/bin/editor
LATEPROMPTING =false
LOOSEDIRECTORYCHECKING =false
MAILNOVIOLATIONS =true
EMAILREPORTLEVEL =3
REPORTLEVEL   =3
SYSLOGREPORTING =true
MAILMETHOD    =SMTP
SMTPHOST      =localhost
SMTPPORT      =25
TEMPDIRECTORY =/tmp
RESOLVE_IDS_TO_NAMES =false
EOF'


sudo bash -c 'cat << EOF >/home/student/twconf
#!/usr/bin/expect
spawn sudo twadmin --create-cfgfile --cfgfile /home/student/tw.cfg --site-keyfile /etc/tripwire/site.key /etc/tripwire/twcfg.txt
expect "passphrase"
send "Aud507SiteKey\n"
interact
exit
EOF'

sudo chmod +x /home/student/twconf
sudo /home/student/twconf


sudo cp /home/student/tw.cfg /etc/tripwire
sudo 
echo '******************************************************'
echo 'Admin is building a Tripwire policy file'
echo '******************************************************'

sudo bash -c 'cat << EOF >/home/student/twpol
#!/usr/bin/expect
spawn sudo twadmin  -m P /etc/tripwire/twpol.txt
expect "passphrase"
send "Aud507SiteKey\n"
interact
exit
EOF'

sudo chmod +x /home/student/twpol
sudo /home/student/twpol

echo '******************************************************'
echo 'Admin is attempting to build a baseline hash database'
echo '******************************************************'

sudo bash -c 'cat << EOF >/home/student/twinit
#!/usr/bin/expect
spawn sudo tripwire  -m i 
expect "passphrase"
send "Aud507LocalKey\n"
interact
exit
EOF'

sudo chmod +x /home/student/twinit
sudo /home/student/twinit

#rm /home/student/tw*
echo '******************************************************'
echo 'Admin thinks they have finished configuring Tripwire'
echo '******************************************************'
