#!/bin/bash
echo "This is in development so be aware you might lose points and have a backup ready."
sleep 3

touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
printTime "Backups folder created on the Desktop."

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/
printTime "/etc/group and /etc/passwd files backed up."

echo Type all user account names, with a space in between
read -a users

usersLength=${#users[@]}	

for (( i=0;i<$usersLength;i++))
do
	clear
	echo ${users[${i}]}
	echo Delete ${users[${i}]}? yes or no
	read yn1
	if [ $yn1 == yes ]
	then
		userdel -r ${users[${i}]}
		printTime "${users[${i}]} has been deleted."
	else	
		echo Make ${users[${i}]} administrator? yes or no
		read yn2								
		if [ $yn2 == yes ]
		then
			gpasswd -a ${users[${i}]} sudo
			gpasswd -a ${users[${i}]} adm
			gpasswd -a ${users[${i}]} lpadmin
			gpasswd -a ${users[${i}]} sambashare
			printTime "${users[${i}]} has been made an administrator."
		else
			gpasswd -d ${users[${i}]} sudo
			gpasswd -d ${users[${i}]} adm
			gpasswd -d ${users[${i}]} lpadmin
			gpasswd -d ${users[${i}]} sambashare
			gpasswd -d ${users[${i}]} root
			printTime "${users[${i}]} has been made a standard user."
		fi
		
		echo Make custom password for ${users[${i}]}? yes or no
		read yn3								
		if [ $yn3 == yes ]
		then
			echo Password:
			read pw
			echo -e "$pw\n$pw" | passwd ${users[${i}]}
			printTime "${users[${i}]} has been given the password '$pw'."
		else
			echo -e "Cupcake21@\nCupcake21@" | passwd ${users[${i}]}
			printTime "${users[${i}]} has been given the password 'Cupcake21@'."
		fi
		passwd -x30 -n3 -w7 ${users[${i}]}
		usermod -L ${users[${i}]}
		printTime "${users[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
	fi
done
clear

apt-get -y update
apt-get -y upgrade
# File System Configuration
# Bind Mount the /var/tmp directory to /tmp
echo -e "/tmp /var/tmp                       none rw,noexec,nosuid,nodev,bind        0 0" >> /etc/fstab
#
# Set Sticky Bit on All World-Writable Directories
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
#
# Disable mounting of following filesystems
cat >> /etc/modprobe.d/filesystems-blacklist.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
#
# Disable automounting
/usr/bin/apt-get -y install gconf2
/usr/bin/gconftool-2 --type bool --set /apps/nautilus/preferences/media_automount False
/usr/bin/gconftool-2 --type bool --set /apps/nautilus/preferences/media_automount_open False
#
# Secure Boot Settings
/bin/chown root:root /boot/grub/grub.cfg
/bin/chmod 600 /boot/grub/grub.cfg
#
# Require authentication for single-user mode by setting password for root
#/usr/bin/passwd root
#
# Additional Process Hardening
echo "*                hard    core          0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
#
# Uninstall apport and whoopsie packages
apt-get -y purge apport
apt-get -y purge whoopsie
#
# Disable prelink
/usr/sbin/prelink -ua
apt-get -y purge prelink
#
# Activate AppArmor
apt-get -y install apparmor apparmor-utils
/usr/sbin/aa-enforce /etc/apparmor.d/*
#
# OS Services
# Uninstall NIS
apt-get -y purge nis
#
# Uninstall rsh client and server
apt-get -y purge rsh-server
apt-get -y purge rsh-client rsh-reload-client
#
# Uninstall talk client and server
apt-get -y purge talk
apt-get -y purge talkd
#
# Uninstall telnet server
apt-get -y purge telnetd
#
# Uninstall tftp server
apt-get -y purge tftpd
#
# Uninstall xinetd
apt-get -y purge xinetd
#
# Special Purpose Services
# Uninstall X windows
apt-get -y purge xserver-xorg-core*
#
# Uninstall avahi server
apt-get -y purge avahi-daemon
#
# Uninstall biosdevname
apt-get -y purge biosdevname
#
# Uninstall cups
apt-get -y purge cups
#
# Uninstall dhcp server
apt-get -y purge isc-dhcp-server isc-dhcp-server6
#
# Uninstall ldap
#apt-get -y purge slapd
#
# Uninstall NFS and RPC
apt-get -y purge nfs-kernel-server rpcbind
#
# Uninstall DNS
apt-get -y purge bind9
#
# Uninstall FTP
apt-get -y purge vsftpd
#
# Uninstall HTTP
apt-get -y purge apache2
#
# Uninstall HTTP proxy
apt-get -y purge squid
#
# Uninstall IMAP and POP server
apt-get -y purge dovecot
#
# Disable Rsync service
sed -i -e 's/^\(RSYNC_ENABLE=\).*/\1false/' /etc/default/rsync
#
# Uninstall Samba
apt-get -y purge samba
apt-get -y purge samba-\*
#
# Uninstall SNMP
apt-get -y purge snmp
#
# Configure NTP
apt-get -y install ntp
#echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
#echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
#
# Configure MTA
export DEBIAN_FRONTEND=noninteractive
apt-get -y install postfix
sed -i -e 's/^\(inet_interfaces\).*/\1 = localhost/' /etc/postfix/main.cf
service postfix restart
#
# Network Configuration and Firewalls
# Set Network Configuration and Firewalls
cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF
#
# Configure ipv6
cat >> /etc/sysctl.conf << EOF
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
#
# Install TCP Wrappers
apt-get -y install tcpd
if [ ! -e /etc/hosts.allow ];then
    touch /etc/hosts.allow
fi
if [ ! -e /etc/hosts.deny ];then
    touch /etc/hosts.deny
fi
/bin/chmod 644 /etc/hosts.allow
/bin/chmod 644 /etc/hosts.deny
#
# Disable Network Protocols
cat >> /etc/modprobe.d/usgcb-blacklist.conf << EOF
install dccp /bin/true
install sctp /bin/true
install tipc /bin/true
install rds /bin/true
EOF
#
# Deactivate wireless interfaces
#apt-get -y install network-manager
#/usr/bin/nmcli nm wifi off
#
# Enable host-based Firewall
#echo 'y' | /usr/sbin/ufw enable --stdin
#
# Logging and Auditing
# Ensure rsyslog is running
service rsyslog start
#
# Edit /etc/rsyslog.conf settings
cat >> /etc/rsyslog.conf << EOF
authpriv.* /var/log/secure
auth user.* /var/log/messages
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp.* /var/log/unused.log
EOF
#
# Add logrotate for unused.log
cat >> /etc/logrotate.d/unused-log << EOF
/var/log/unused.log {
    rotate 3
    maxage 5
    copytruncate
    daily
    missingok
    notifempty
    compress
    size 100M
    delaycompress
    su root root
}
EOF
#
# Set permissions
/bin/chmod 600 /var/log/boot.log*
/bin/chmod 600 /var/log/cron*
/bin/chmod 644 /var/log/dmesg
/bin/chmod 600 /var/log/maillog*
/bin/chmod 600 /var/log/messages*
/bin/chmod 750 /var/log/news/*
/bin/chmod 600 /var/log/secure*
/bin/chmod 600 /var/log/spooler*
/bin/chmod 750 /var/log/squid/*
/bin/chmod 750 /var/log/vbox/*
/bin/chmod 664 /var/log/wtmp
#/bin/chown -R root:root /var/log
/bin/chgrp utmp /var/log/wtmp
/bin/chown -R news:news /var/log/news
#
# Ensure auditd is running
apt-get -y install auditd
service auditd start
#
# Edit /etc/audit/auditd.conf
sed -i -e 's/^\(num_logs =\).*/\1 3/' /etc/audit/auditd.conf
sed -i -e 's/^\(max_log_file =\).*/\1 5/' /etc/audit/auditd.conf
sed -i -e 's/^\(space_left_action\).*/\1 = suspend/' /etc/audit/auditd.conf
sed -i -e 's/^\(action_mail_acct\).*/\1 = root/' /etc/audit/auditd.conf
sed -i -e 's/^\(admin_space_left_action\).*/\1 = suspend/' /etc/audit/auditd.conf
sed -i -e 's/^\(max_log_file_action\).*/\1 = rotate/' /etc/audit/auditd.conf
#
# Edit /etc/default/grub
sed -i -e 's/^\(GRUB_CMDLINE_LINUX\)="\(.*\)"/\1="\2 audit=1"/' /etc/default/grub
#
# Edit /etc/audit/audit.rules
cat >> /etc/audit/audit.rules << EOF
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-e 2
EOF
#
# Configure Cron
/bin/chown root:root /etc/crontab
/bin/chmod 400 /etc/crontab
/bin/chown –R root:root /var/spool/cron
/bin/chmod –R go-rwx /var/spool/cron
/bin/chown root:root /etc/cron.hourly
/bin/chmod 400 /etc/cron.hourly
/bin/chown root:root /etc/cron.daily
/bin/chmod 400 /etc/cron.daily
/bin/chown root:root /etc/cron.weekly
/bin/chmod 400 /etc/cron.weekly
/bin/chown root:root /etc/cron.monthly
/bin/chmod 400 /etc/cron.monthly
/bin/chown root:root /etc/cron.d
/bin/chmod 400 /etc/cron.d
#
# Restrict at/cron to Authorized Users
/bin/rm -f /etc/cron.deny
/bin/rm -f /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
/bin/chmod og-rwx /etc/cron.allow
/bin/chmod og-rwx /etc/at.allow
/bin/chown root:root /etc/cron.allow
/bin/chown root:root /etc/at.allow
#
# Configure PAM
echo "password required pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/common-password
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/login
echo "password sufficient pam_unix.so use_authtok remember=5" >> /etc/pam.d/common-password
#
# Configure SSH
sed -i -e 's/^#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
sed -i -e 's/^#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
sed -i -e 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
sed -i -e 's/^#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
echo "RhostsAuthentication no" >> /etc/ssh/sshd_config
sed -i -e 's/^\(RhostsRSAAuthentication\).*/\1 no/' /etc/ssh/sshd_config
sed -i -e 's/^#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i -e 's/^\(PermitRootLogin\).*/\1 without-password/' /etc/ssh/sshd_config
sed -i -e 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
#echo "Banner - \"Banner\"" >> /etc/ssh/sshd_config
/bin/chown root:sys /etc/ssh/sshd_config
/bin/chmod 600 /etc/ssh/sshd_config
#
# User Accounts and Environment
# Set default umask (we got an exception to change it to 022)
sed -i "/UMASK/s/[0-9]\{3\}/022/" /etc/login.defs
sed -i -e 's/^\(PASS_MAX_DAYS\).*/\1   90/' /etc/login.defs
sed -i -e 's/^\(PASS_MIN_DAYS\).*/\1   7/' /etc/login.defs
sed -i -e 's/^\(PASS_WARN_AGE\).*/\1   7/' /etc/login.defs
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do
    if [ $user != "root" ]; then
        /usr/sbin/usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
            /usr/sbin/usermod -s /usr/sbin/nologin $user
        fi
    fi
done
/usr/sbin/usermod -g 0 root
/usr/sbin/useradd -D -f 60
#
# Warning Banners
#
# Verify System File Permisstions
/bin/chmod 644 /etc/passwd
/bin/chown root:root /etc/passwd
/bin/chmod 400 /etc/shadow
/bin/chown root:shadow /etc/shadow
/bin/chmod 644 /etc/group
/bin/chown root:root /etc/group
#
# Review User and Group Settings
find / -name .rhosts -exec rm -f {} \;
find / -name .netrc -exec rm -f {} \;
find / -name .forward -exec rm -f {} \;
#
# Additional Configuration Settings
/usr/sbin/dpkg-statoverride --update --add root admin 4750 /bin/su
#
# Install ipset
apt-get -y install ipset
echo "some api shiz that i found on the internet."
sudo apt-get install gksu wget
wget https://www.thefanclub.co.za/sites/default/files/public/downloads/ubuntu-server-secure.tar.gz
sudo tar -zxvf ubuntu-server-secure.tar.gz
cd ubuntu-server-secure
sudo chmod +x ubuntu-server-secure.sh
gksudo sh ubuntu-server-secure.sh


