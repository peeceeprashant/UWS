#!/bin/bash
SITESTORY_ARCHIVE_IP=10.147.151.224
CMS_SERVER_IP=10.80.5.209
sudo yum -y install httpd httpd-devel gcc git curl-devel apr-devel openssl-devel java
sudo mkdir ~/development
cd development
sudo git clone https://github.com/peeceeprashant/UWS.git
#sudo git clone https://github.com/mementoweb/SiteStory.git
cd UWS
sudo cp mod_sitestory.c /etc/httpd/
sudo cp mod_testsite_patten4.c /etc/httpd/mod_testsite.c
#Change Sitestory Archive IP Address
sudo sed -i "s/127.0.0.1/$SITESTORY_ARCHIVE_IP/g" /etc/httpd/mod_testsite.c
cd /etc/httpd/
sudo /usr/sbin/apxs -c -i –a /etc/httpd/mod_sitestory.c
sudo /usr/sbin/apxs -c -i –a /etc/httpd/mod_testsite.c -lcurl
sudo mv /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.original
sudo cp ~/development/UWS/httpd.conf /etc/httpd/conf/
#Change Sitestory Archive IP
sudo sed -i "s/54.161.238.59/$SITESTORY_ARCHIVE_IP/g" /etc/httpd/conf/httpd.conf
#Change Proxy Server Forward Direct IP
sudo sed -i "s/dlrl.cc.vt.edu/$CMS_SERVER_IP/g" /etc/httpd/conf/httpd.conf
sudo service httpd restart
