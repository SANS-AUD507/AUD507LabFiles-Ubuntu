#! /bin/bash

cat << EOF > /etc/issue
####################################################################
This VM hosts some of the services for the AUD507 course.
There is no need to log on at the console; access is available via
SSH from the Windows 10 student VM.
####################################################################

EOF

IP=$(ip a show ens38 | awk '/inet[^6]/ {print $2}' | grep -v "^10\.50" | sed -e "s/\/24//")

echo  >> /etc/issue
echo "####################################################################" >> /etc/issue
echo "Host only IP is $IP" >> /etc/issue
echo "EWB website is available at:" >> /etc/issue
echo "EWB website is available at http://$IP:507/workbook" >> /etc/issue
echo "####################################################################" >> /etc/issue
echo  >> /etc/issue
echo  >> /etc/issue