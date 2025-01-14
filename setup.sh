#!/bin/bash
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(wget -qO- icanhazip.com);
echo "Authentikasi pada server"
IZIN=$( curl icanhazip.com | grep $MYIP )
if [ $MYIP = $IZIN ]; then
echo -e "${green}Permintaan Diterima...${NC}"
else
echo -e "${red}Permintaan Ditolak!${NC}";
echo "Hanya untuk pengguna terdaftar"
rm -f setup.sh
exit 0
fi
mkdir /var/lib/premium-script;
mkdir /etc/v2ray;
echo "Tolong masukan domain yang sudah dipointing agar v2ray service work"
read -p "Hostname / Domain: " host
echo "IP=$host" >> /var/lib/premium-script/ipvps.conf
echo "$host" >> /etc/v2ray/domain

#install ssh ovpn
wget https://raw.githubusercontent.com/4hidessh/websocket/main/ssh.sh && chmod +x ssh.sh && screen -S ssh.sh ./ssh.sh
#wget https://adiscript.vercel.app/vpn/sstp.sh && chmod +x sstp.sh && screen -S sstp ./sstp.sh
#install ssr
#wget https://adiscript.vercel.app/vpn/ssr.sh && chmod +x ssr.sh && screen -S ssr ./ssr.sh
#wget https://adiscript.vercel.app/vpn/sodosok.sh && chmod +x sodosok.sh && screen -S ss ./sodosok.sh
#installwg
#wget https://adiscript.vercel.app/vpn/wg.sh && chmod +x wg.sh && screen -S wg ./wg.sh
#install v2ray
#wget http://adiscript.vercel.app/vpn/ins-vt.sh && chmod +x ins-vt.sh && screen -S v2ray ./ins-vt.sh
#install L2TP
#wget https://adiscript.vercel.app/vpn/ipsec.sh && chmod +x ipsec.sh && screen -S ipsec ./ipsec.sh
#wget https://adiscript.vercel.app/vpn/set-br.sh && chmod +x set-br.sh && ./set-br.sh

rm -f /root/ssh-vpn.sh
#rm -f /root/sstp.sh
#rm -f /root/wg.sh
#rm -f /root/ss.sh
#rm -f /root/ssr.sh
rm -f /root/ins-vt.sh
#rm -f /root/ipsec.sh
#rm -f /root/set-br.sh
cat <<EOF> /etc/systemd/system/autosett.service
[Unit]
Description=autosetting
Documentation=https://adiscript.vercel.app/vpn

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/set.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable autosett
wget -O /etc/set.sh "https://adiscript.vercel.app/vpn/set.sh"
chmod +x /etc/set.sh
history -c
echo "1.2" > /home/ver
clear
echo " "
echo "Installation has been completed!!"
echo " "
echo "=================================-Script Premium-===========================" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "--------------------------------------------------------------------------------" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - OpenVPN                 : TCP 1194, UDP 2200, SSL 442"  | tee -a log-install.txt
echo "   - Stunnel4                : 443, 777"  | tee -a log-install.txt
echo "   - Dropbear                : 109, 143"  | tee -a log-install.txt
echo "   - WebSocket               : 2082"  | tee -a log-install.txt
echo "   - Squid Proxy             : 3128, 8080 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Badvpn                  : 7100, 7200, 7300"  | tee -a log-install.txt
echo "   - Nginx                   : 81"  | tee -a log-install.txt
echo "   - Wireguard               : 7070"  | tee -a log-install.txt
echo "   - L2TP/IPSEC VPN          : 1701"  | tee -a log-install.txt
echo "   - PPTP VPN                : 1732"  | tee -a log-install.txt
echo "   - SSTP VPN                : 444"  | tee -a log-install.txt
echo "   - Shadowsocks-R           : 1443-1543"  | tee -a log-install.txt
echo "   - SS-OBFS TLS             : 2443-2543"  | tee -a log-install.txt
echo "   - SS-OBFS HTTP            : 3443-3543"  | tee -a log-install.txt
echo "   - V2RAY Vmess TLS         : 8443"  | tee -a log-install.txt
echo "   - V2RAY Vmess None TLS    : 80"  | tee -a log-install.txt
echo "   - V2RAY Vless TLS         : 2083"  | tee -a log-install.txt
echo "   - V2RAY Vless None TLS    : 8880"  | tee -a log-install.txt
echo "   - Trojan                  : 2087"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On 05.00 GMT +7" | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "   - White Label" | tee -a log-install.txt
echo "   - Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   - Dev/Main                : Adi Project"  | tee -a log-install.txt
echo "   - Telegram                : T.me/adisubagja"  | tee -a log-install.txt
echo "   - Instagram               : @adisubagja.id"  | tee -a log-install.txt
echo "   - Whatsapp                : Gapunya"  | tee -a log-install.txt
echo "   - Facebook                : https://www.facebook.com/adisubagja.mint" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "------------------Script Modified By Adi Subagja-----------------" | tee -a log-install.txt
echo ""
echo " Harap Reboot Manual ! "
sleep 12
rm -f adi.sh
rm -f setup.sh

