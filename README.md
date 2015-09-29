UWS
===

Please find below the list of files and the instructions for their setup. Please contact me at peecee@vt.edu, if you have any questions or suggestions regarding the project and if you face any issues with the installation. Thank you!

Enjoy an "un-interruptible" web service!

Basic requirements
===

1) Machines: UWS framework requires that you have at least ONE machine (preferably TWO) at your disposal to install Apache HTTP server and Apache Tomcat server. We would recommend that you dedicate one machine for each for improved performance. Preferably a CentOS-based system.

2) Libraries: Please ensure the following libraries in your machine(s) using yum or other package manager.
 - httpd 
 - httpd-devel 
 - gcc 
 - git 
 - curl-devel 
 - apr-devel 
 - openssl-devel 
 - java 

Installation
===

1) Login to the machine dedicated for Apache HTTP server. 
  - Create a clone of this git repo with the command: sudo git clone https://github.com/peeceeprashant/UWS.git
  - Execute script: sudo sh ./UWS/proxyserversetup.sh
2) Login to the machine dedicated for Apache Tomcat.
  - Create a clone of this git repo with the command: sudo git clone https://github.com/peeceeprashant/UWS.git (if machine is different from the above machine)
  - Execute script: sudo sh ./UWS/sitestoryserversetup.sh
3) Edit Apache HTTP server's Proxy setting
  - Login to Apache HTTP server machine.
  - Go to folder: /etc/httpd/conf
  - Open file: httpd.conf
  - Edit Sitestory module settings as described in their documentation, http://mementoweb.github.io/SiteStory/getStarted.html, under the heading, Installation of SiteStory Apache Module.
  - Change the URI that is pointed to as a redirect in the ErrorDocument directive to a randomly generated string (the URI doesn't need to exist in the system). Do the same for all 5xx errors.
  - Go to line: ProxyPass /{Randomly Generated String} http://localhost:8080/{Randomly Generated String}. Change the URL in ProxyPass directive to the IP of the Sitestory server/machine. The value will be the same if Sitestory is in the same machine)
  - Add a line: ProxyPass / {IP Location of your website server}. For example: ProxyPass / http://10.0.0.5:80/
  - Restart Apache with the command: service httpd restart (if CentOS based system)

Testing
==

In this Git repo, you can also find a report on how we've tested this framework with preliminary results. 
If everything is setup according to the above steps, you will notice the Apache HTTP server sending responses to Sitestory (in Tomcat) for archival. If/when your website server goes down, you will notice that your website will still be serving pages. This can be confirmed by looking at the Apache HTTP server's log to see the request being made for archived version of the page.


