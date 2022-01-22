#!/bin/bash
# By geovpn
# My Telegram : https://t.me/geovpn
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
IZIN=$( curl https://dpvpn.me/ip.json | grep $MYIP )
if [ $MYIP = $IZIN ]; then
echo -e "${NC}${GREEN}Permission Accepted...${NC}"
else
echo -e "${NC}${RED}Permission Denied!${NC}";
echo -e "${NC}${LIGHT}Please Contact Admin!!"
echo -e "${NC}${LIGHT}Telegram : https://t.me/geovpn"
exit 0
fi
# ==================================================
# Link Hosting Kalian
1="raw.githubusercontent.com/geovpn/scvps/main/ssh"

# Link Hosting Kalian Untuk Xray
2="raw.githubusercontent.com/geovpn/scvps/main/xray"

# Link Hosting Kalian Untuk Trojan Go
3="raw.githubusercontent.com/geovpn/scvps/main/trojango"

# Link Hosting Kalian Untuk Stunnel5
#4="raw.githubusercontent.com/geovpn/scvps/main/stunnel5"

# Link Hosting Kalian Untuk menu
5="raw.githubusercontent.com/geovpn/scvps/main/menu"

# Link Hosting Kalian Untuk banner
6="raw.githubusercontent.com/geovpn/scvps/main/banner"

# Link Hosting Kalian Untuk dom
7="raw.githubusercontent.com/geovpn/scvps/main/dom"

# Link Hosting Kalian Untuk trial
8="raw.githubusercontent.com/geovpn/scvps/main/trial"

# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

#detail nama perusahaan
country=ID
state=Indonesia
locality=Indonesia
organization=www.geogabut.com
organizationalunit=www.geogabut.com
commonname=www.geogabut.com
email=paoandest@gmail.com

# simple password minimal
wget -O /etc/pam.d/common-password "https://${1}/password"
chmod +x /etc/pam.d/common-password

# go to root
cd
# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

# install wget and curl
apt -y install wget curl

#figlet
apt-get install figlet -y
apt-get install toilet -y
apt-get install ruby -y
gem install lolcat
apt -y install python
apt -y install tmux
sudo snap install lolcat
sudo apt-get install figlet

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# install
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git lsof
echo "clear" >> .profile
echo "figlet -f slant GEO GABUT | lolcat" >> .profile
echo "sleep 0.5" >> .profile
echo "clear" >> .profile
echo "running" >> .profile
echo "echo -e \" - Script Mod By Geo Gabut\" | lolcat" >> .profile
echo "echo -e \"\x1b[96m - Silahkan Ketik\x1b[m \x1b[92mMENU\x1b[m \x1b[96mUntuk Melihat daftar Perintah\x1b[m\"" >> .profile

# Install SSLH
apt -y install sslh -y

#SSLH
apt-get install sslh -y
#Forward 443 = ws-ssl-stunnel4-dropbear
wget -O /etc/default/sslh "https://${geovpn}/sslh.conf"
service sslh restart

# install webserver
apt -y install nginx php php-fpm php-cli php-mysql libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
curl https://${geovpn}/nginx.conf > /etc/nginx/nginx.conf
curl https://${geovpn}/vps.conf > /etc/nginx/conf.d/vps.conf
sed -i 's/listen = \/var\/run\/php-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/fpm/pool.d/www.conf
useradd -m vps;
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
cd /home/vps/public_html
wget -O /home/vps/public_html/index.html "https://${1}/index.html1"
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://${1}/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
apt -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 69 -p 77"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
cd
apt -y install squid3
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/Sangarya/premium/main/sshvpn/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf

# setting vnstat
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6

# install stunnel
apt install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:109

[openssh]
accept = 171
connect = 127.0.0.1:22

[ws-stunnel]
accept = 2096
connect = 127.0.0.1:443

[dropbear]
accept = 777
connect = 127.0.0.1:109

[openvpn]
accept = 990
connect = 127.0.0.1:1194

END

# certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

#OpenVPN
wget https://${1}/vpn.sh &&  chmod +x vpn.sh && ./vpn.sh

# Install BBR
wget https://${1}/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# Ganti Banner
wget -O /etc/issue.net "https://${1}/issue.net"

# install fail2ban
apt -y install fail2ban

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Tolong  Uninstall Versi Sebelumnya!"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# banner /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/Sangarya/premium/main/file/banner.conf"
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# blockir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# download script
cd /usr/bin
wget -O addhost "https://${1}/addhost.sh"
wget -O autoreboot "https://${1}/autoreboot.sh"
wget -O about "https://${1}/about.sh"
wget -O menu "https://${1}/menu.sh"
wget -O addssh "https://${1}/addssh.sh"
wget -O trialssh "https://${1}/trialssh.sh"
wget -O delssh "https://${1}/delssh.sh"
wget -O member "https://${1}/member.sh"
wget -O delexp "https://${1}/delexp.sh"
wget -O cekssh "https://${1}/cekssh.sh"
wget -O restart "https://${1}/restart.sh"
wget -O speedtest "https://${1}/speedtest_cli.py"
wget -O info "https://${1}/info.sh"
wget -O ram "https://${1}/ram.sh"
wget -O renewssh "https://${1}/renewssh.sh"
wget -O autokill "https://${1}/autokill.sh"
wget -O ceklim "https://${1}/ceklim.sh"
wget -O tendang "https://${1}/tendang.sh"
wget -O clearlog "https://${1}/clearlog.sh"
wget -O changeport "https://${1}/changeport.sh"
wget -O portovpn "https://${1}/portovpn.sh"
wget -O portwg "https://${1}/portwg.sh"
wget -O porttrojan "https://${1}/porttrojan.sh"
wget -O portsstp "https://${1}/portsstp.sh"
wget -O portsquid "https://${1}/portsquid.sh"
wget -O portv2ray "https://${1}/portv2ray.sh"
wget -O portvless "https://${1}/portvless.sh"
wget -O wbmn "https://${1}/webmin.sh"
wget -O xp "https://${1}/xp.sh"
wget -O menu-backup "https://${5}/menu-backup.sh"
wget -O menu-domain "https://${5}/menu-domain.sh"
wget -O menu-l2tp "https://${5}/menu-l2tp.sh"
wget -O menu "https://${5}/menu.sh"
wget -O menu-pptp "https://${5}/menu-pptp.sh"
wget -O menu-shadowsocks "https://${5}/menu-shadowsocks.sh"
wget -O menu-ssh "https://${5}/menu-ssh.sh"
wget -O menu-sstp "https://${5}/menu-sstp.sh"
wget -O menu-tools "https://${5}/menu-tools.sh"
wget -O menu-trial "https://${5}/menu-trial.sh"
wget -O menu-trojan "https://${5}/menu-trojan.sh"
wget -O menu-v2ray "https://${5}/menu-v2ray.sh"
wget -O menu-vpn "https://${5}/menu-vpn.sh"
wget -O menu-wireguard "https://${5}/menu-wireguard.sh"
wget -O bbr "https://${5}/bbr.sh"
wget -O status "https://${5}/status.sh"
wget -O running "https://${5}/running.sh"
wget -O swapkvm "https://${1}/swapkvm.sh"
wget -O addv2ray "https://${2}/addv2ray.sh"
wget -O trialv2ray "https://${2}/trialv2ray.sh"
wget -O addvless "https://${2}/addvless.sh"
wget -O addtrojan "https://${2}/addtrojan.sh"
wget -O delv2ray "https://${2}/delv2ray.sh"
wget -O delvless "https://${2}/delvless.sh"
wget -O deltrojan "https://${2}/deltrojan.sh"
wget -O cekv2ray "https://${2}/cekv2ray.sh"
wget -O cekvless "https://${2}/cekvless.sh"
wget -O cektrojan "https://${2}/cektrojan.sh"
wget -O renewv2ray "https://${2}/renewv2ray.sh"
wget -O renewvless "https://${2}/renewvless.sh"
wget -O renewtrojan "https://${2}/renewtrojan.sh"
wget -O certv2ray "https://${2}/certv2ray.sh"
wget -O addtrgo "https://${3}/addtrgo.sh"
wget -O deltrgo "https://${3}/deltrgo.sh"
wget -O renewtrgo "https://${3}/renewtrgo.sh"
wget -O cektrgo "https://${3}/cektrgo.sh"
wget -O bebek "https://${5}/bebek.sh"
wget -O l2tp "https://${5}/l2tp.sh"
wget -O medo "https://${5}/medo.sh"
wget -O menu "https://${5}/menu.sh"
wget -O paneli "https://${5}/paneli.sh"
wget -O ppt "https://${5}/ppt.sh"
wget -O ssh "https://${5}/ssh.sh"
wget -O ssssr "https://${5}/ssssr.sh"
wget -O sstpp "https://${5}/sstpp.sh"
wget -O status "https://${5}/status.sh"
wget -O system "https://${5}/system.sh"
wget -O trojaan "https://${5}/trojaan.sh"
wget -O v2raay "https://${5}/v2raay.sh"
wget -O wgr "https://${5}/wgr.sh"
wget -O bbr "https://${5}/bbr.sh"
wget -O bannerku "https://${5}/bannerku"
wget -O bannerDOMAIN "https://${6}/bannerDOMAIN"
wget -O bannerTRIAL "https://${6}/bannerTRIAL"
wget -O bannerL2TP "https://${6}/bannerL2TP"
wget -O bannerPPTP "https://${6}/bannerPPTP"
wget -O bannerSHADOWSOCK "https://${6}/bannerSHADOWSOCK"
wget -O bannerSSH "https://${6}/bannerSSH"
wget -O bannerSSTP "https://${6}/bannerSSTP"
wget -O bannerSYSTEM "https://${6}/bannerSYSTEM"
wget -O bannerTROJAN "https://${6}/bannerTROJAN"
wget -O bannerV2RAY "https://${6}/bannerV2RAY"
wget -O bannerVPN "https://${6}/bannerVPN"
wget -O bannerWIREGUARD "https://${6}/bannerWIREGUARD"
wget -O bannerBACKUP "https://${6}/bannerBACKUP"
wget -O addcf "https://${7}/addcf.sh"
wget -O cfd "https://${7}/cfd.sh"
wget -O cff "https://${7}/cff.sh"
wget -O cfh "https://${7}/cfh.sh"
wget -O host "https://${7}/host.sh"
wget -O pointing "https://${7}/pointing.sh"
wget -O bw "https://${7}/bw.sh"
wget -O update "https://${7}/update.sh"
wget -O host "https://${7}/host.sh"
wget -O trial-akun "https://${8}/trial-akun.sh"
wget -O triall2tp "https://${8}/triall2tp.sh"
wget -O trialpptp "https://${8}/trialpptp.sh"
wget -O trialss "https://${8}/trialss.sh"
wget -O trialssh "https://${8}/trialssh.sh"
wget -O trialssr "https://${8}/trialssr.sh"
wget -O trialsstp "https://${8}/trialsstp.sh"
wget -O trialtrojan "https://${8}/trialtrojan.sh"
wget -O trialv2ray "https://${8}/trialv2ray.sh"
wget -O trialvless "https://${8}/trialvless.sh"
wget -O trialwg "https://${8}/trialwg.sh"
wget -O /usr/bin/trialv2ray https://${8}/trialv2ray.sh && chmod +x /usr/bin/trialv2ray && cd /usr/bin && apt install -y dos2unix && dos2unix trialv2ray
chmod +x trial-akun
chmod +x trialpptp
chmod +x trialss
chmod +x trialssh
chmod +x trialssr
chmod +x trialsstp
chmod +x trialtrojan
chmod +x triall2tp
chmod +x trialv2ray
chmod +x trialvless
chmod +x trialwg
chmod +x autoreboot
chmod +x addhost
chmod +x menu
chmod +x addssh
chmod +x trialssh
chmod +x delssh
chmod +x member
chmod +x delexp
chmod +x cekssh
chmod +x restart
chmod +x speedtest
chmod +x info
chmod +x about
chmod +x autokill
chmod +x tendang
chmod +x ceklim
chmod +x ram
chmod +x renewssh
chmod +x clearlog
chmod +x changeport
chmod +x portovpn
chmod +x portwg
chmod +x porttrojan
chmod +x portsstp
chmod +x portsquid
chmod +x portv2ray
chmod +x portvless
chmod +x wbmn
chmod +x xp
chmod +x swapkvm
chmod +x addv2ray
chmod +x addvless
chmod +x addtrojan
chmod +x delv2ray
chmod +x delvless
chmod +x deltrojan
chmod +x cekv2ray
chmod +x cekvless
chmod +x cektrojan
chmod +x renewv2ray
chmod +x renewvless
chmod +x renewtrojan
chmod +x certv2ray
chmod +x addtrgo
chmod +x deltrgo
chmod +x renewtrgo
chmod +x cektrgo
chmod +x bebek
chmod +x l2tp
chmod +x medo
chmod +x menu
chmod +x paneli
chmod +x ppt
chmod +x ssh
chmod +x ssssr
chmod +x sstpp
chmod +x status
chmod +x system
chmod +x trojaan
chmod +x v2raay
chmod +x wgr
chmod +x bbr
chmod +x update
chmod +x bannerku
chmod +x bannerDOMAIN
chmod +x bannerL2TP
chmod +x bannerPPTP
chmod +x bannerSHADOWSOCK
chmod +x bannerSSH
chmod +x bannerSSTP
chmod +x bannerSYSTEM
chmod +x bannerTROJAN
chmod +x bannerV2RAY
chmod +x bannerVPN
chmod +x bannerWIREGUARD
chmod +x bannerTRIAL
chmod +x addcf
chmod +x cfd
chmod +x cff
chmod +x cfh
chmod +x host
chmod +x pointing
chmod +x bw
chmod +x menu-backup
chmod +x menu-domain
chmod +x menu-l2tp
chmod +x menu
chmod +x menu-pptp
chmod +x menu-shadowsocks
chmod +x menu-ssh
chmod +x menu-sstp
chmod +x menu-tools
chmod +x menu-trial
chmod +x menu-trojan
chmod +x menu-v2ray
chmod +x menu-vpn
chmod +x menu-wireguard
chmod +x bbr
chmod +x status
chmod +x running
chmod +x trialtrgo
chmod +x trial-akun
chmod +x trialpptp
chmod +x trialss
chmod +x trialssh
chmod +x trialssr
chmod +x trialsstp
chmod +x trialtrojan
chmod +x triall2tp
chmod +x trialv2ray
chmod +x trialvless
chmod +x trialwg
echo "0 5 * * * root clearlog && reboot" >> /etc/crontab
echo "0 0 * * * root xp" >> /etc/crontab
# remove unnecessary files
cd
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y
# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
/etc/init.d/vnstat restart
/etc/init.d/squid restart
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh

# finihsing
clear
