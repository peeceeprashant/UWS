#!/bin/bash
ARCHIVE_DIR=ephemeral
sudo yum -y install httpd httpd-devel gcc git curl-devel apr-devel openssl-devel java
sudo mkdir ~/development
cd development
sudo git clone https://github.com/peeceeprashant/UWS.git
sudo git clone https://github.com/peeceeprashant/SiteStory.git
cd UWS
sudo cp apache-tomcat-6.0.41.tar.gz ../
cd ..
sudo tar -xvf apache-tomcat-6.0.41.tar.gz
cd apache-tomcat-6.0.41/webapps/
sudo cp ~/development/SiteStory/sitestory-webapp/target/sitestory.war .
cd ..
sudo bin/startup.sh
#Change directory where archives will be stored
sudo sed -i "s/backup/$ARCHIVE_DIR/g" ~/development/apache-tomcat-6.0.41/webapps/sitestory/WEB-INF/classes/ta.properties
sudo bin/shutdown.sh
sudo bin/startup.sh
