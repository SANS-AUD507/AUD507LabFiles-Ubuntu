#! /bin/bash

cat << EOF > /etc/issue
####################################################################
This VM hosts some of the services for the AUD507 lab environment.
DO NOT log on at this console! 
Access is available via SSH from the 507Win10 student VM.
####################################################################

EOF

IP=$(ip a show ens38 | awk '/inet[^6]/ {print $2}' | grep -v "^10\.50" | sed -e "s/\/24//")

echo  >> /etc/issue
echo "####################################################################" >> /etc/issue
echo "Electronic Lab Workbook (EWB) website is available at:" >> /etc/issue
echo "http://$IP:507/workbook" >> /etc/issue
echo "####################################################################" >> /etc/issue
echo  >> /etc/issue
echo  >> /etc/issue