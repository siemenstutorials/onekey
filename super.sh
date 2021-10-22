#! /bin/bash
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
shell_version="1.0.4"
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"

function check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif cat /etc/issue | grep -q -E -i "debian"; then
    release="debian"
  elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  elif cat /proc/version | grep -q -E -i "debian"; then
    release="debian"
  elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  fi
  bit=$(uname -m)
  if test "$bit" != "x86_64"; then
    echo "请输入你的芯片架构，/386/armv5/armv6/armv7/armv8"
    read bit
  else
    bit="amd64"
  fi
}

function Install_base() {
  gzip_ver=$(gzip -V)
  if [[ -z ${gzip_ver} ]]; then
    if [[ ${release} == "centos" ]]; then
      yum update
      yum install -y wget
      yum install -y gzip
    else
      apt-get update
      apt-get install -y gzip
    fi
  fi
}

function check_file() {
  if test ! -d "/usr/lib/systemd/system/"; then
    mkdir /usr/lib/systemd/system
    chmod -R 777 /usr/lib/systemd/system
  fi
}

function check_nor_file() {
  rm -rf "$(pwd)"/gost
  rm -rf "$(pwd)"/gost.service
  rm -rf "$(pwd)"/config.json
  rm -rf /etc/gost
  rm -rf /usr/lib/systemd/system/gost.service
  rm -rf /usr/bin/gost
}

function Install_ct() {
  check_nor_file
  Install_base
  check_file
  check_sys
  echo -e 
  read -e -p "是否使用国内镜像加速下载？[y/n]:" addyn
  [[ -z ${addyn} ]] && addyn="n"
  if [[ ${addyn} == [Yy] ]]; then
    rm -rf gost-linux-amd64-2.11.1.gz
    wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost-linux-amd64-2.11.1.gz
    gunzip gost-linux-amd64-2.11.1.gz
    mv gost-linux-amd64-2.11.1.gz gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  else
    rm -rf gost-linux-amd64-2.11.1.gz
    wget --no-check-certificate https://github.com/ginuerzh/gost/releases/download/v2.11.1/gost-linux-amd64-2.11.1.gz
    gunzip gost-linux-amd64-2.11.1.gz
    mv gost-linux-amd64-2.11.1.gz gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://raw.githubusercontent.com/siemenstutorials/onekeygost/master/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://raw.githubusercontent.com/siemenstutorials/onekeygost/master/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  fi
  systemctl enable gost && systemctl restart gost
  echo "------------------------------"
  if test -a /usr/bin/gost -a /usr/lib/systemctl/gost.service -a /etc/gost/config.json; then
    echo -e "GOST安装成功"
    rm -rf "$(pwd)"/gost
    rm -rf "$(pwd)"/gost.service
    rm -rf "$(pwd)"/config.json
  else
    echo -e "GOST安装失败 "
    rm -rf "$(pwd)"/gost
    rm -rf "$(pwd)"/gost.service
    rm -rf "$(pwd)"/config.json
    rm -rf "$(pwd)"/install.sh
  fi
}
function Uninstall_ct() {
  rm -rf /usr/bin/gost
  rm -rf /usr/lib/systemd/system/gost.service
  rm -rf /etc/gost
  rm -rf "$(pwd)"/install.sh
  echo "GOST已删除"
}
function Start_ct() {
  systemctl start gost
  echo "GOST已启动"
}
function Stop_ct() {
  systemctl stop gost
  echo "GOST已停止"
}
function Restart_ct() {
  systemctl restart gost
  echo "GOST已重启"
}
function read_protocol() {
  echo -e "请选择转发模式: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密tcp+udp流量转发"
  echo -e "-----------------------------------"
  echo -e "[2] 加密隧道流量转发[中转机]"
  echo -e "-----------------------------------"
  echo -e "[3] 解密由gost传输而来的流量并转发[落地机]"
  echo -e "-----------------------------------"
  echo -e "[4] 一键安装ss/socks5代理"
  echo -e "-----------------------------------"
  echo -e "[5] 进阶：多落地均衡负载"
  echo -e "-----------------------------------"
  echo -e "[6] 进阶：转发CDN自选节点"
  echo -e "-----------------------------------"
  read -p "请选择: " numprotocol

  if [ "$numprotocol" == "1" ]; then
    flag_a="nonencrypt"
  elif [ "$numprotocol" == "2" ]; then
    encrypt
  elif [ "$numprotocol" == "3" ]; then
    decrypt
  elif [ "$numprotocol" == "4" ]; then
    proxy
  elif [ "$numprotocol" == "5" ]; then
    enpeer
  elif [ "$numprotocol" == "6" ]; then
    cdn
  else
    echo "type error, please try again"
    exit
  fi
}
function read_s_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "-----------------------------------"
    read -p "请输入ss密码: " flag_b
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "请输入socks密码: " flag_b
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机哪个端口接收到的流量进行转发?"
    read -p "请输入: " flag_b
  fi
}
function read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请选择设置ss加密: "
    echo -e "-----------------------------------"
    echo -e "[1] aes-256-gcm"
    echo -e "[2] aes-256-cfb"
    echo -e "[3] chacha20-ietf-poly1305"
    echo -e "[4] chacha20"
    echo -e "[5] rc4-md5"
    echo -e "[6] AEAD_CHACHA20_POLY1305"
    echo -e "-----------------------------------"
    read -p "请选择ss加密方式: " ssencrypt

    if [ "$ssencrypt" == "1" ]; then
      flag_c="aes-256-gcm"
    elif [ "$ssencrypt" == "2" ]; then
      flag_c="aes-256-cfb"
    elif [ "$ssencrypt" == "3" ]; then
      flag_c="chacha20-ietf-poly1305"
    elif [ "$ssencrypt" == "4" ]; then
      flag_c="chacha20"
    elif [ "$ssencrypt" == "5" ]; then
      flag_c="rc4-md5"
    elif [ "$ssencrypt" == "6" ]; then
      flag_c="AEAD_CHACHA20_POLY1305"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "请输入socks用户名: " flag_c
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请输入落地列表文件名"
    read -e -p "自定义配置文件，例如ips1、iplist2: " flag_c
    touch $flag_c.txt
    echo -e "------------------------------------------------------------------"
    echo -e "请依次输入你要均衡负载的落地ip与端口"
    while true; do
      echo -e "请问你要将本机从${flag_b}接收到的流量转发向的IP或域名?"
      read -p "请输入: " peer_ip
      echo -e "请问你要将本机从${flag_b}接收到的流量转发向${peer_ip}的哪个端口?"
      read -p "请输入: " peer_port
      echo -e "$peer_ip:$peer_port" >>$flag_c.txt
      read -e -p "是否继续添加落地？[Y/n]:" addyn
      [[ -z ${addyn} ]] && addyn="y"
      if [[ ${addyn} == [Nn] ]]; then
        echo -e "------------------------------------------------------------------"
        echo -e "已在root目录创建$flag_c.txt，您可以随时编辑该文件修改落地信息，重启GOST即可生效"
        echo -e "------------------------------------------------------------------"
        break
      else
        echo -e "------------------------------------------------------------------"
        echo -e "继续添加均衡负载落地配置"
      fi
    done
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "将本机从${flag_b}接收到的流量转发向的自选ip:"
    read -p "请输入: " flag_c
    if [ "$flag_a" == "cdnno" ]; then
      echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
      echo -e "[1] 80"
      echo -e "[2] 443"
      read -p "请选择端口: " cdnport
        if [ "$cdnport" == "1" ]; then
          flag_c="$flag_c:80"
        elif [ "$cdnport" == "2" ]; then
          flag_c="$flag_c:443"
        else
          echo "type error, please try again"
          exit
        fi
    elif [ "$flag_a" == "cdnws" ]; then
      echo -e "ws将默认转发至80端口"
      flag_c="$flag_c:80"
    else
      echo -e "wss将默认转发至443端口"
      flag_c="$flag_c:443"
    fi
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向哪个IP或域名?"
    echo -e "注: IP既可以是[远程机器/当前机器]的公网IP, 也可是以本机本地回环IP(即127.0.0.1)"
    read -p "请输入: " flag_c
  fi
}
function read_d_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置ss代理服务的端口?"
    read -p "请输入: " flag_d
  elif [ "$flag_a" == "socks" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置socks代理服务的端口?"
    read -p "请输入: " flag_d
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请选择设置均衡负载策略: "
    echo -e "-----------------------------------"
    echo -e "[1] round - 轮询"
    echo -e "[2] random - 随机"
    echo -e "[3] fifo - 自上而下"
    echo -e "-----------------------------------"
    read -p "请选择均衡负载类型: " numstra

    if [ "$numstra" == "1" ]; then
      flag_d="round"
    elif [ "$numstra" == "2" ]; then
      flag_d="random"
    elif [ "$numstra" == "3" ]; then
      flag_d="fifo"
    else
      echo "type error, please try again"
      exit
    fi
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    read -p "请输入host:" flag_d
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
    read -p "请输入: " flag_d
  fi
}
function writerawconf() {
  echo $flag_a"/""$flag_b""#""$flag_c""#""$flag_d" >>$raw_conf_path
}
function rawconf() {
  read_protocol
  read_s_port
  read_d_ip
  read_d_port
  writerawconf
}
function eachconf_retrieve() {
  d_server=${trans_conf#*#}
  d_port=${d_server#*#}
  d_ip=${d_server%#*}
  flag_s_port=${trans_conf%%#*}
  s_port=${flag_s_port#*/}
  is_encrypt=${flag_s_port%/*}
}
function confstart() {
  echo "{
    \"Debug\": true,
    \"Retries\": 0,
    \"ServeNodes\": [" >>$gost_conf_path
}
function multiconfstart() {
  echo "        {
            \"Retries\": 0,
            \"ServeNodes\": [" >>$gost_conf_path
}
function conflast() {
  echo "    ]
}" >>$gost_conf_path
}
function multiconflast() {
  if [ $i -eq $count_line ]; then
    echo "            ]
        }" >>$gost_conf_path
  else
    echo "            ]
        }," >>$gost_conf_path
  fi
}
function encrypt() {
  echo -e "设置隧道转发传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls隧道"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "-----------------------------------"
  read -p "请选择转发传输类型: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function enpeer() {
  echo -e "请设置均衡负载传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] tls隧道"
  echo -e "[3] ws隧道"
  echo -e "[4] wss隧道"
  echo -e "-----------------------------------"
  read -p "请选择转发传输类型: " numpeer

  if [ "$numpeer" == "1" ]; then
    flag_a="peerno"
  elif [ "$numpeer" == "2" ]; then
    flag_a="peertls"
  elif [ "$numpeer" == "3" ]; then
    flag_a="peerws"
  elif [ "$numpeer" == "4" ]; then
    flag_a="peerwss"

  else
    echo "type error, please try again"
    exit
  fi
}
function cdn() {
  echo -e "设置的CDN传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] ws隧道-80"
  echo -e "[3] wss隧道-443"
  echo -e "此功能只需在中转机设置，落地机若用隧道，流量入口必须是80/443，之后套cdn即可"
  echo -e "-----------------------------------"
  read -p "请选择CDN转发传输类型: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function decrypt() {
  echo -e "请问您要设置的解密传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "-----------------------------------"
  read -p "请选择解密传输类型: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "请问您要设置的代理类型: "
  echo -e "-----------------------------------"
  echo -e "[1] shadowsocks"
  echo -e "[2] socks5(强烈建议加隧道用于Telegram代理)"
  echo -e "-----------------------------------"
  read -p "请选择代理类型: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  else
    echo "type error, please try again"
    exit
  fi
}
function method() {
  if [ $i -eq 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "        \"tcp://:$s_port/$d_ip:$d_port\",
        \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "        \"tcp://:$s_port/$d_ip?host=$d_port\",
        \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "        \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
        \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "        \"tcp://:$s_port\",
        \"udp://:$s_port\"
    ],
    \"ChainNodes\": [
        \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "        \"tcp://:$s_port\",
		\"udp://:$s_port\"
	],
	\"ChainNodes\": [
		\"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      echo "        \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      echo "        \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  elif [ $i -gt 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "                \"tcp://:$s_port/$d_ip:$d_port\",
                \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "                \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
                \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "                \"tcp://:$s_port/$d_ip?host=$d_port\",
                \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "                \"tcp://:$s_port\",
	            \"udp://:$s_port\"
	        ],
	        \"ChainNodes\": [
	            \"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "                \"tcp://:$s_port\",
		        \"udp://:$s_port\"
		    ],
		    \"ChainNodes\": [
		        \"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "                 \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      echo "                \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        		  \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  else
    echo "config error"
    exit
  fi
}

function writeconf() {
  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    if [ $i -eq 1 ]; then
      trans_conf=$(sed -n "${i}p" $raw_conf_path)
      eachconf_retrieve
      method
    elif [ $i -gt 1 ]; then
      if [ $i -eq 2 ]; then
        echo "    ],
    \"Routes\": [" >>$gost_conf_path
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      else
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      fi
    fi
  done
}
function show_all_conf() {
  echo -e "                      GOST 配置                        "
  echo -e "--------------------------------------------------------"
  echo -e "序号|方法\t    |本地端口\t|目的地地址:目的地端口"
  echo -e "--------------------------------------------------------"

  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    trans_conf=$(sed -n "${i}p" $raw_conf_path)
    eachconf_retrieve

    if [ "$is_encrypt" == "nonencrypt" ]; then
      str="不加密中转"
    elif [ "$is_encrypt" == "encrypttls" ]; then
      str=" tls隧道 "
    elif [ "$is_encrypt" == "encryptws" ]; then
      str="  ws隧道 "
    elif [ "$is_encrypt" == "encryptwss" ]; then
      str=" wss隧道 "
    elif [ "$is_encrypt" == "peerno" ]; then
      str=" 不加密均衡负载 "
    elif [ "$is_encrypt" == "peertls" ]; then
      str=" tls隧道均衡负载 "
    elif [ "$is_encrypt" == "peerws" ]; then
      str="  ws隧道均衡负载 "
    elif [ "$is_encrypt" == "peerwss" ]; then
      str=" wss隧道均衡负载 "
    elif [ "$is_encrypt" == "decrypttls" ]; then
      str=" tls解密 "
    elif [ "$is_encrypt" == "decryptws" ]; then
      str="  ws解密 "
    elif [ "$is_encrypt" == "decryptwss" ]; then
      str=" wss解密 "
    elif [ "$is_encrypt" == "ss" ]; then
      str="   ss   "
    elif [ "$is_encrypt" == "socks" ]; then
      str=" socks5 "
    elif [ "$is_encrypt" == "cdnno" ]; then
      str="不加密转发CDN"
    elif [ "$is_encrypt" == "cdnws" ]; then
      str="ws隧道转发CDN"
    elif [ "$is_encrypt" == "cdnwss" ]; then
      str="wss隧道转发CDN"
    else
      str=""
    fi

    echo -e " $i  |$str  |$s_port\t|$d_ip:$d_port"
    echo -e "--------------------------------------------------------"
  done
}

cron_restart() {
  echo -e "------------------------------------------------------------------"
  echo -e "GOST定时重启任务: "
  echo -e "-----------------------------------"
  echo -e "[1] 配置GOST定时重启任务"
  echo -e "[2] 删除GOST定时重启任务"
  echo -e "-----------------------------------"
  read -p "请选择: " numcron
  if [ "$numcron" == "1" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "GOST定时重启任务类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 每？小时重启"
    echo -e "[2] 每日？点重启"
    echo -e "-----------------------------------"
    read -p "请选择: " numcrontype
    if [ "$numcrontype" == "1" ]; then
      echo -e "-----------------------------------"
      read -p "每？小时重启: " cronhr
      echo "0 0 */$cronhr * * ? * systemctl restart gost" >>/etc/crontab
      echo -e "定时重启设置成功！"
    elif [ "$numcrontype" == "2" ]; then
      echo -e "-----------------------------------"
      read -p "每日？点重启: " cronhr
      echo "0 0 $cronhr * * ? systemctl restart gost" >>/etc/crontab
      echo -e "定时重启设置成功！"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$numcron" == "2" ]; then
    sed -i "/gost/d" /etc/crontab
    echo -e "定时重启任务删除完成！"
  else
    echo "type error, please try again"
    exit
  fi
}

update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/siemenstutorials/onekeygost/master/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$ol_version" ]]; then
    echo -e "存在新版本，是否更新；不更新直接回车 [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/siemenstutorials/onekeygost/master/install.sh
      echo -e "更新完成"
      exit 0
      ;;
    *) ;;

    esac
  else
    echo -e "                 ${Green_font_prefix}当前版本为最新版本！${Font_color_suffix}"
  fi

}
clear
echo && echo -e "             ${Green_font_prefix}Gost一键安装配置脚本${Font_color_suffix}"${Green_font_prefix} v2.11.1 ${Font_color_suffix}"
_____________________________________________________

Website: https://siemenstutorials.com                      
Author:  SiemensTutorials                                 
Youtube: https://www.youtube.com/c/siemenstutorials  
特性: 支持Reboot转发不失效|TCP+UDP转发|隧道中转|负载均衡
_____________________________________________________
 ${Green_font_prefix}1.${Font_color_suffix} 安装 GOST
 ${Green_font_prefix}2.${Font_color_suffix} 更新 GOST
 ${Green_font_prefix}3.${Font_color_suffix} 卸载 GOST

 ${Green_font_prefix}4.${Font_color_suffix} 启动 GOST
 ${Green_font_prefix}5.${Font_color_suffix} 停止 GOST
 ${Green_font_prefix}6.${Font_color_suffix} 重启 GOST

 ${Green_font_prefix}7.${Font_color_suffix} 新增GOST转发
 ${Green_font_prefix}8.${Font_color_suffix} 查看GOST转发
 ${Green_font_prefix}9.${Font_color_suffix} 删除GOST转发

 ${Green_font_prefix}10.${Font_color_suffix} GOST定时重启
" && echo
read -e -p " 请输入数字 [1-9]:" num
case "$num" in
1)
  Install_ct
  ;;
2)
  checknew
  ;;
3)
  Uninstall_ct
  ;;
4)
  Start_ct
  ;;
5)
  Stop_ct
  ;;
6)
  Restart_ct
  ;;
7)
  rawconf
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo -e "配置已生效，当前配置如下"
  echo -e "--------------------------------------------------------"
  show_all_conf
  ;;
8)
  show_all_conf
  ;;
9)
  show_all_conf
  read -p "请输入你要删除的配置编号：" numdelete
  if echo $numdelete | grep -q '[0-9]'; then
    sed -i "${numdelete}d" $raw_conf_path
    rm -rf /etc/gost/config.json
    confstart
    writeconf
    conflast
    systemctl restart gost
    echo -e "配置已删除，服务已重启"
  else
    echo "请输入正确数字"
  fi
  ;;
10)
  cron_restart
  ;;
*)
  echo "请输入正确数字 [1-9]"
  ;;
esac
