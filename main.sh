#!/bin/bash

# 打印彩色文字
red() {
	echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
	echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
	echo -e "\033[33m\033[01m$1\033[0m"
}

# 检测 root 权限
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 系统相关
CMD=(
	"$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)"
	"$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)"
	"$(lsb_release -sd 2>/dev/null)"
	"$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)"
	"$(grep . /etc/redhat-release 2>/dev/null)"
	"$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')"
)

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 系统包管理器相关
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

for i in "${CMD[@]}"; do
	SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
	[[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统，请使用主流的操作系统" && exit 1
[[ -z $(type -P curl) ]] && ${PACKAGE_UPDATE[int]} && ${PACKAGE_INSTALL[int]} curl

# 生成随机的超时秒数以对抗 GFW 的主动探测

handshake=$(((($RANDOM*6)/32768)+4)) #4-10
connIdle=$(((($RANDOM*201)/32768)+300)) # 300-500
uplinkOnly=$(((($RANDOM*9)/32768)+2)) # 2-10
downlinkOnly=$(((($RANDOM*11)/32768)+5)) # 5-15

# 函数部分

# 配置结束后的设置
function finishSetting() {
    systemctl stop xray
    systemctl start xray
    ufw allow $port

    # udp full cone
    ufw allow 1024:65535/udp
    ufw reload
}

# 检查是否使用 acme 申请过证书
function configCert() {
    read -p " 请输入你的域名: " domain
    echo -e " 当前域名: ${YELLOW}$domain${PLAIN}"
    # acme.sh 申请的证书会放在 ~/.acme.sh/$domain 文件夹中
    if [[ -f "/root/.acme.sh/${domain}/${domain}.cer" ]] || [[ -f "/root/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo ""
        green " 检测到自有证书，即将使用自有证书部署"
        bash /root/.acme.sh/acme.sh --install-cert -d $domain  --fullchain-file /usr/local/etc/xray/cert.crt --key-file /usr/local/etc/xray/key.key --reloadcmd "systemctl restart xray; systemctl restart nginx"
    else
        echo ""
        read -p " 请输入证书路径(不要以'~'开头！): " cert
        [ -z "$cert" ] && red "请输入证书路径！" && exit 1
        if [[ ${cert:0:1} == "~" ]] || [ -z "$cert" ]; then
            red " 请输入证书路径 或 证书路径不能以 ~ 开头！" && exit 1
        fi
        echo -e " 当前证书路径: ${YELLOW}$cert${PLAIN}"
        echo ""
        read -p " 请输入密钥路径(不要以'~'开头！): " key
        [ -z "$key" ] && red "请输入密钥路径！" && exit 1
        if [[ ${key:0:1} == "~" ]] || [ -z "$key" ]; then
            red " 请输入密钥路径 或 密钥路径不能以 ~ 开头！" && exit 1
        fi
        echo -e " 当前密钥路径: ${YELLOW}$key${PLAIN}"
        ln -s $cert /usr/local/etc/xray/cert.crt
        ln -s $key /usr/local/etc/xray/key.key
        red " 警告：请勿删除源证书文件！"
    fi
}

# http 相关设置(ws/http)
function getHttp() {
    read -p " 请输入域名(不一定是自己的，默认: a.189.cn): " domain
    [[ -z "$domain" ]] && domain="a.189.cn"
    echo -e " 当前域名：${BLUE}${domain}${PLAIN}"
    echo
    read -p " 请输入路径(以"/"开头，默认随机): " path
    while true; do
        if [[ -z "${path}" ]]; then
            tmp=$(openssl rand -hex 6)
            path="/$tmp"
            break
        elif [[ "${path:0:1}" != "/" ]]; then
            red " 伪装路径必须以/开头！"
            path=""
        else
            break
        fi
    done
    echo -e " 当前路径：${BLUE}${path}${PLAIN}"
    echo              
}

# 监听端口
function getPort() {
    echo -e " 请输入 ${RED}Xray ${PLAIN}监听端口(默认 443): "
    read -p "" port
    [ -z "$port" ] && port=443
    if [[ "${port:0:1}" == "0" ]]; then
        red " 端口不能以0开头"
        port=443
    fi
    echo -e " 当前 ${RED}Xray${PLAIN} 监听端口: ${BLUE}$port${PLAIN}"
}

# REALITY 

##x25519
function getX25519() {
    echo -e " 请输入 ${BLUE}REALITY ${PLAIN}的公钥和私钥，不填将随机生成的！"
    read -p " 私钥(服务端): " answer
    if [ -z "$answer" ]; then
        red " 已随机生成密钥对！"
        # 调用 Xray 生成
        tmpKey=$(xray x25519)
        PrivateKey=$(echo "$tmpKey" | grep Private | cut -d " " -f 3)
        echo -e " 当前私钥: ${GREEN} $PrivateKey${PLAIN}"
    else
        PrivateKey=$answer
        echo
        echo -e " 当前私钥: ${GREEN} $PrivateKey${PLAIN}"
        read -p " 公钥(客户端): " PublicKey
    fi

    if [ -z "$PublicKey" ]; then
        PublicKey=$(xray x25519 -i "$PrivateKey" | grep Public | cut -d " " -f 3)
    fi
    echo 
    echo -e " 当前公钥: ${GREEN} $PublicKey${PLAIN}"
}

##shortID
function getShortID() {
    read -p " 请输入允许的 shortID（默认随机）："  shortID
    if [ -z "$shortID" ]; then
        local randomLength=$((RANDOM % 5 + 4))
        shortID=$(openssl rand -hex $randomLength)
    fi
    echo -e " 当前 shortID： ${BLUE}$shortID${PLAIN}"

    # 生成客户端连接用的 shortID
}

# share

## REALITY
function shareReality() {
    yellow " 服务器信息: "
    echo
    red " 节点一: "
    echo -e " 协议: ${GREEN}VLESS${PLAIN}"
    echo -e " 服务器地址: ${BLUE}$linkIP${PLAIN}"
    echo -e " 端口: ${BLUE}$port${PLAIN}"
    echo -e " uuid: ${GREEN}$uuid${PLAIN}"
    echo -e " 流控: ${GREEN}$flow${PLAIN}"
    echo -e " 传输方式: ${YELLOW}tcp${PLAIN}"
    echo -e " 传输层安全: ${BLUE}REALITY${PLAIN}"
    echo -e " 浏览器指纹: 任选，推荐 ${BLUE}ios${PLAIN}"
    echo -e " serverName / 服务器名称指示 / sni: ${YELLOW}$domain${PLAIN} (可以换成别的，只要能用)"
    echo -e " publicKey / 公钥: ${RED}$PublicKey${PLAIN}"
    echo -e " spiderX: 自行访问目标网站，找个靠谱的路径，不懂就填 \"/\" "
    echo -e " shortId: ${BLUE}$shortID${PLAIN}"
    echo
    green " 分享链接："
    green " vless://${uuid}@${linkIP}:${port}?encryption=none&security=reality&sni=${domain}&flow=xtls-rprx-vision&pbk=${PublicKey}&fp=ios&sid=${shortID}#REALITY"
    echo
    echo
    red " 节点二:"
    echo -e " 协议: ${GREEN}VLESS${PLAIN}"
    echo -e " 服务器地址: ${BLUE}$linkIP${PLAIN}"
    echo -e " 端口: ${BLUE}$port${PLAIN}"
    echo -e " uuid: ${GREEN}$uuid${PLAIN}"
    echo -e " 流控: ${RED}none${PLAIN}"
    echo -e " 传输方式: ${GREEN}HTTP/2${PLAIN}"
    echo -e " 路径: ${BLUE}/${PLAIN}"
    echo -e " 传输层安全: ${RED}REALITY${PLAIN}"
    echo -e " 浏览器指纹: 任选，推荐 ${BLUE}ios${PLAIN}"
    echo -e " serverName / 服务器名称指示 / sni: ${BLUE}$domain${PLAIN} (可以换成别的，只要能用)"
    echo -e " publicKey / 公钥: ${RED}$PublicKey${PLAIN}"
    echo -e " spiderX: 自行访问目标网站，找个靠谱的路径，不懂就填 \"/\" "
    echo -e " shortId: ${BLUE}$shortID${PLAIN}"
    echo
    green " 分享链接："
    green " vless://${uuid}@${linkIP}:${port}?encryption=none&security=reality&sni=${domain}&type=http&pbk=${PublicKey}&fp=ios&sid=${shortID}#REALITY-H2"
}

# 选择流控
function chooseFlow() {
    yellow " 流控: "
    echo -e " 1. ${GREEN}xtls-rprx-vision${PLAIN} (默认)"
    yellow " 2. ${YELLOW}none${PLAIN}(不使用流控)"
    echo 
    read -p " 请选择: " answer
    case $answer in
        1) flow="xtls-rprx-vision" ;;
        2) flow="" ;;
        *) red " 已自动选择 xtls-rprx-vision!" && flow="xtls-rprx-vision" ;;
    esac
    echo -e " 当前流控: ${RED} $flow${PLAIN}"
}

# 获取 uuid
function getUUID() {
    echo ""
    # from ChatGPT
    # 用正则表达式表示出 uuid，再检测是否合法
    local uuid_regex='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
    yellow " 请输入你的 uuid，如果输入内容不合法将自动映射为一个 uuid，不输入则随机生成。"
    # 使用 read -p 读取用户输入，并使用 ${var//pattern/replacement} 替换操作删除空格
    read -p "" answer
    answer=${answer// /}
    if [ -z "$answer" ]; then
        uuid=$(xray uuid)
    elif [[ "$answer" =~ $uuid_regex ]]; then
        uuid="${answer}"
    elif [ "${#answer}" -gt 30 ]; then
        red " 长度超过 30，无法映射！"
        uuid=$(xray uuid)
    else
        red " 输入的内容并非 uuid！已自动映射！"
        uuid=$(xray uuid -i "$answer")
    fi
}
# 正文 代码块

# 无 TLS 的协议
set_withoutTLS() {
    # 简单检测是否安装 Xray
    [ -z /usr/local/bin/xray ] && red " 请先安装 Xray！" && exit 1
    echo ""
    red " 警告: 会删除原有配置!"
    yellow " 请选择协议: "
    echo -e " 1. ${YELLOW} VMess${PLAIN}"
    echo -e " 2. ${GREEN} shadowsocks${PLAIN}"
    echo -e " 3. ${RED} VLESS ${PLAIN}(由于VLESS没有加密，请勿使用VLESS直接过墙!)"
    echo ""
    read -p " 请选择: " protocol
    # 选择协议
    case $protocol in
        1) protocol=vmess ;;
        2) protocol=shadowsocks ;;
        3) protocol=vless ;;
        *) red "请输入正确的选项！" ;;
    esac
    echo
    # 设置端口
    getPort
    echo
    # vmess/vless 使用 uuid
    if [ "$protocol" == "vmess" ] || [ "$protocol" == "vless" ]; then
        getUUID
        echo -e " 当前 uuid: ${BLUE}$uuid${PLAIN}"
    # shadowsocks 选择加密方式及设置密码
    elif [ "$protocol" == "shadowsocks" ]; then
        ss2022="false"
        yellow " 加密方式: "
        echo -e " 注: 带${YELLOW}\"2022\"${PLAIN}的为 ${YELLOW}shadowsocks-2022${PLAIN} 加密方式，抗封锁性、性能更强，且能开启 UDP over TCP"
        yellow " 按推荐程度排序"
        echo ""
        echo -e " ${GREEN}1${PLAIN}. ${GREEN}2022-blake3-aes-128-gcm${PLAIN}"
        echo -e " ${GREEN}2${PLAIN}. ${GREEN}2022-blake3-aes-256-gcm${PLAIN}"
        echo -e " ${GREEN}3${PLAIN}. ${GREEN}2022-blake3-chacha20-poly1305${PLAIN}"
        echo -e " ${GREEN}4${PLAIN}. ${YELLOW}aes-128-gcm${PLAIN}(推荐)"
        echo -e " ${GREEN}5${PLAIN}. ${YELLOW}aes-256-gcm${PLAIN}"
        echo -e " ${GREEN}6${PLAIN}. ${YELLOW}chacha20-ietf-poly1305${PLAIN}(默认)"
        echo -e " ${GREEN}7${PLAIN}. ${YELLOW}xchacha20-ietf-poly1305${PLAIN}"
        echo -e " ${GREEN}8${PLAIN}. ${RED}none${PLAIN}(不加密！)"
        echo ""
        read -p "请选择: " answer
        case $answer in
            1) method="2022-blake3-aes-128-gcm" && ss2022="true"  && keyLengh=16 ;;
            2) method="2022-blake3-aes-256-gcm" && ss2022="true" && keyLengh=32 ;;
            3) method="2022-blake3-chacha20-poly1305" && ss2022="true" && keyLengh=32 ;;
            4) method="aes-128-gcm" && keyLengh=8 ;;
            5) method="aes-256-gcm" keyLengh=8 ;;
            6) method="chacha20-ietf-poly1305" keyLengh=8 ;;
            7) method="xchacha20-ietf-poly1305" keyLengh=8 ;;
            8) method="none" keyLengh=8 ;;
            *) method="chacha20-ietf-poly1305" keyLengh=8 ;;
        esac
        echo -e " 当前加密方式: ${GREEN}$method${PLAIN}"

        echo ""
        read -p " 请输入 shadowsocks 密码(建议默认): " password
        if [ -z "$password" ]; then
            password=$(openssl rand -base64 ${keyLengh})
        # shadowsocks 2022 限制密码长度
        elif [ "${#password}" != "$keyLengh" ] && [ "$ss2022" == "true" ]; then
            red " 密码长度不符合规范！"
            password=$(openssl rand -base64 ${keyLengh})
        fi
        echo -e "当前密码: ${GREEN}$password${PLAIN}"
    fi
    echo ""

    # 设置传输方式
    yellow "底层传输方式: "
    echo -e " 1. ${YELLOW}TCP(默认)${PLAIN}"
    echo -e " 2. ${BLUE}websocket(ws)${PLAIN} (推荐)"
    echo -e " 3. ${RED}mKCP${PLAIN}"
    echo -e " 4. ${GREEN}HTTP/2${PLAIN}"
    echo -e " 5. ${GREEN}gRPC${PLAIN}"
    echo ""
    read -p " 请选择: " answer
    case $answer in
        1) transport="tcp" ;;
        2) transport="ws" ;;
        3) transport="kcp" ;;
        4) transport="http" ;;
        5) transport="grpc" ;;
        *) transport="tcp" ;;
    esac

    # tcp
    if [[ "$transport" == "tcp" ]]; then
        yellow " 伪装方式: "
        echo " 1. none(默认，无伪装)"
        echo -e " 2. ${YELLOW} http ${PLAIN} (可用于免流)"
        read -p " 请选择: " answer
        if [[ "$answer" == "2" ]]; then
            header="http"
            getHttp
        fi
    fi

    # ws
    if [[ "$transport" == "ws" ]] ;then
        getHttp
    fi

    # mKCP
    if [[ "$transport" == "kcp" ]] ;then
        # 设置带宽
        yellow " 下行带宽:"
        echo -e " 单位: ${BLUE} MB/s ${PLAIN}，注意是 ${RED} Byte ${PLAIN} 而非 ${RED} bit${PLAIN}"
        echo -e " 默认: ${BLUE} 100${PLAIN}"
        yellow " 事关性能，请如实填写"
        read -p " 请设置: " uplinkCapacity
        [[ -z "$uplinkCapacity" ]] && uplinkCapacity=100
        echo -e" 当前下行带宽: ${YELLOW}$uplinkCapacity${PLAIN}"
        echo ""

        yellow " 上行带宽: "
        yellow " 单位: ${BLUE} MB/s ${PLAIN}，注意是 ${RED} Byte ${PLAIN} 而非 ${RED} bit${PLAIN}"
        yellow " 默认: ${BLUE} 100${PLAIN}"
        yellow " 建议设为你的真实上行带宽到它的两倍"
        read -p " 请设置: " downlinkCapacity
        [[ -z "$downlinkCapacity" ]] && downlinkCapacity=100
        echo -e " 当前上行带宽: ${YELLOW}$downlinkCapacity${PLAIN}"
        echo ""

        read -p " 请输入你到服务器的平均延迟（默认 200，单位 ms）：" latency
        [[ -z "$latency" ]] && latency=200
        echo -e " 当前延迟：${RED}$latency${PLAIN}"
        
        # 根据用户填写的内容计算最佳 mtu 和 tti
        downloadSpeed=$(echo "$downlinkCapacity * 1000 * 1000" | bc)
        mtu=$(echo "scale=0; ($downloadSpeed / 8 * $latency * 1.5) / 1024" | bc)
        tti=$(echo "scale=0; $latency / 2" | bc)

        # 限制 mtu 和 tti 的取值范围
        if (( mtu < 576 )); then
          mtu=576
        elif (( mtu > 1460 )); then
          mtu=1460
        fi

        if (( tti < 10 )); then
          tti=10
        elif (( tti > 100 )); then
          tti=100
        fi

        # 设置伪装
        yellow " 伪装类型: "
        echo -e " 1. ${GREEN} none(默认)${PLAIN}: 不伪装"
        echo -e " 2. ${GREEN} SRTP${PLAIN}: 伪装成 SRTP 数据包，会被识别为视频通话数据（如 FaceTime）"
        echo -e " 3. ${GREEN} uTP${PLAIN}: 伪装成 uTP 数据包，会被识别为 BT 下载数据"
        echo -e " 4. ${GREEN} wechat-video${PLAIN}: 伪装成微信视频通话的数据包"
        echo -e " 5. ${GREEN} DTLS${PLAIN}: 伪装成 DTLS 1.2 数据包"
        echo -e " 6. ${GREEN} wireguard${PLAIN}: 伪装成 WireGuard 数据包。（并不是真正的 WireGuard 协议）"
        read -p " 请选择: " answer
        case $answer in
            1) camouflageType="none" ;;
            2) camouflageType="srtp" ;;
            3) camouflageType="utp" ;;
            4) camouflageType="wechat-video" ;;
            5) camouflageType="dtls" ;;
            6) camouflageType="wireguard" ;;
            *) camouflageType="none" ;;
        esac
        echo -e " 当前伪装: ${BLUE}$camouflageType${PLAIN}"
        echo ""
        # mKCP 混淆密码
        read -p " 请输入 mKCP 混淆密码(默认没有)：" seed
        echo -e " 当前混淆密码：${GREEN}${seed}${PLAIN}"
    fi

    # gRPC
    if [[ "$transport" == "grpc" ]] ;then
        read -p " 请输入 server name: "
        while true; do
            if [[ -z "${serverName}" ]]; then
                serverName=$(openssl rand -hex 6)
                break
            else
                break
            fi
        done
        echo -e " 当前server name: ${YELLOW}$serverName${PLAIN}"
    fi

    # h2(http/2)
    if [[ "$transport" == "http" ]] ;then
        getHttp
    fi

    yellow " 开始配置......"
    # 开头的花括号
    cat >/usr/local/etc/xray/config.json <<-EOF
{
EOF

    # log
    cat >>/usr/local/etc/xray/config.json <<-EOF
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
EOF
    # policy
    cat >>/usr/local/etc/xray/config.json <<-EOF
    "policy": {
            "levels": {
                "0": {
                    "handshake": $handshake,
                    "connIdle": $connIdle,
                    "uplinkOnly": $uplinkOnly,
                    "downlinkOnly": $downlinkOnly
                }
            }
    },
EOF
    # basic inbounds
    cat >>/usr/local/etc/xray/config.json <<-EOF
    "inbounds": [
        {
            "port": $port,
            "protocol": "$protocol",
            "settings": {
EOF
    # shadowsocks
    if [ "$protocol" == "shadowsocks" ]; then
    cat >>/usr/local/etc/xray/config.json <<-EOF
                "password": "$password",
                "method": "$method",
                "level": 0,
                "email": "love@xray.com",
                "network": "tcp,udp"
            },
EOF

    # vless
    elif [ "$protocol" == "vless" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none",
EOF
    elif [ "$protocol" == "vmess" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
                 "clients": [
                    {
                        "id": "$uuid",
                        "level": 1,
                        "alterId": 0
                      }
                    ]
            },
EOF
    fi

    # 传输设置/streamSetting 及 出站
    
        # tcp
    if [ "$transport" == "tcp" ]; then
        if [ "$header" != "http" ]; then
            cat >>/usr/local/etc/xray/config.json <<-EOF
            "streamSettings": {
                "network": "tcp"
            }
        }
    ],
EOF
        else
            cat >>/usr/local/etc/xray/config.json <<-EOF
            "streamSettings": {
                "network": "tcp",
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": ["$path"],
                            "headers": {
                                "Host": ["$domain"]
                            }
                        },
                       "response": {
                            "version": "1.1",
                            "status": "200",
                            "reason": "OK"
                        }
                    }
                }
              }
            }
        ],
EOF
        fi
    fi

        # ws
    if [ "$transport" == "ws" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
            "streamSettings": {
                "network":"ws",
                "wsSettings": {
                    "path": "$path",
                    "headers": {
                        "Host": "$domain"
                    }
                }
              }
            }
        ],
EOF
    fi

        # mkcp
    if [ "$transport" == "kcp" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
            "streamSettings": {
                "network": "mkcp",
                "kcpSettings": {
                    "mtu": $mtu,
                    "tti": $tti,
                    "uplinkCapacity": ${uplinkCapacity},
                    "downlinkCapacity": ${downlinkCapacity},
                    "congestion": true,
                    "header": {
                        "type": "${camouflageType}"
                    }
                }
            }
        }
    ],
EOF
    fi

        # h2 / http/2
    if [ "$transport" == "http" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none"
            }
        }
    ],
EOF
    fi

        # gRPC
    if [ "$transport" == "grpc" ]; then
        cat >>/usr/local/etc/xray/config.json <<-EOF
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "$serviceName"
                }
            }
        }
    ],
EOF
    fi
    # outbounds
    cat >>/usr/local/etc/xray/config.json <<-EOF
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ]
EOF
    # 结尾的花括号
    cat >>/usr/local/etc/xray/config.json <<-EOF
}
EOF

    # 生成节点信息
    echo ""
    ip=$(curl ip.sb)
    if echo "$ip" | grep -q ":"
    then
        ip="[$ip]"
    else
        echo ""
    fi

    echo -e "协议: ${BLUE}${protocol}${PLAIN}"
    echo -e "ip: ${BLUE}${ip}${PLAIN}"
    echo -e "端口: ${BLUE}${port}${PLAIN}"

    if [ "$protocol" == "shadowsocks" ]; then
        echo -e "加密方式: ${YELLOW}${method}${PLAIN}"
        echo -e "密码: ${GREEN} $password${PLAIN}"
    elif [ "$protocol" == "vmess" ] || [ "$protocol" == "vmess" ]; then
        echo -e " uuid: ${GREEN} $uuid${PLAIN}"
        if [ "$protocol" == "vmess" ]; then
            echo -e " 额外ID: ${RED} 0${PLAIN}"
        else
            echo -e " 加密方式: ${YELLOW}none${PLAIN}"
        fi
    fi

    echo -e " 传输方式: ${BLUE}${transport}${PLAIN}"
    if [ "$transport" == "ws" ] || [ "$transport" == "http" ] || [ "$header" == "http" ]; then
        echo -e " 路径: ${BLUD}${path}${PLAIN}"
        echo -e " 域名/host: ${BLUD}${domain}${PLAIN}"
    elif [ "$transport" == "kcp" ]; then
        echo -e "伪装类型: ${YELLOW}$camouflageType${PLAIN}"
        echo -e "上行带宽: ${BLUE}$uplinkCapacity${PLAIN}"
        echo -e "下行带宽: ${BLUE}$downlinkCapacity${PLAIN}"
        echo -e "mKCP seed(混淆密码): ${GREEN}$seed${PLAIN}"
    elif [ "$transport" == "grpc" ]; then
        echo -e "serverName: ${GREEN} $serverName${PLAIN}"
    fi

    echo ""

    # 生成分享链接
    if [ "$protocol" == "shadowsocks" ]; then
        if [ "$transport" == "tcp" ]; then
            raw="${method}:${password}@${ip}:${port}"
            if [[ "$ss2022" != "true" ]]; then
                link=$(echo -n ${raw} | base64 -w 0)
            else
                link="$raw"
            fi
            green "分享链接: "
            green "ss://$link"
        else
            echo ""
        fi
    elif [ "$protocol" == "vmess" ]; then
        if [ "$transport" == "tcp" ]; then
            if [ "$header" != "http" ]; then
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"tcp\",
  \"type\":\"none\",
  \"host\":\"\",
  \"path\":\"\",
  \"tls\":\"\"
}"
                link=$(echo -n ${raw} | base64 -w 0)
                shareLink="vmess://${link}"
                yellow " 分享链接(v2RayN): "
                green "$shareLink"
                echo ""
                newLink="${uuid}@${ip}:${port}"
                yellow " 分享链接(Xray标准): "
                green "vmess://${newLink}"
            else
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"tcp\",
  \"type\":\"http\",
  \"host\":\"${domain}\",
  \"path\":\"${path}\",
  \"tls\":\"\"
}"
                link=$(echo -n ${raw} | base64 -w 0)
                shareLink="vmess://${link}"
                yellow " 分享链接: "
                green " $shareLink"
            fi

        elif [ "$transport" == "ws" ]; then
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"ws\",
  \"host\":\"${domain}\",
  \"path\":\"${path}\",
  \"tls\":\"\"
}"
            link=$(echo -n ${raw} | base64 -w 0)
            shareLink="vmess://${link}"
            echo ""
            yellow " 分享链接: "
            green "$shareLink"
            newPath=$(echo -n $path | xxd -p | tr -d '\n' | sed 's/\(..\)/%\1/g')
            newLink="${uuid}@${ip}:${port}?type=ws&host=${domain}&path=${newPath}"
            yellow " 分享链接(Xray标准): "
            green "vmess://${newLink}"

        elif [ "$transport" == "kcp" ]; then
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"kcp\",
  \"type\":\"$camouflageType\",
  \"tls\":\"\"
}"
            link=$(echo -n ${raw} | base64 -w 0)
            shareLink="vmess://${link}"
            yellow " 分享链接: "
            green "$shareLink"
            newLink="${uuid}@${ip}:${port}?type=kcp&headerType=$camouflageType"
            yellow " 分享链接(Xray标准): "
            green "vmess://${newLink}"
        else
            echo ""
        fi
    elif [ "$protocol" == "vless" ]; then
        if [ "$transport" == "kcp" ]; then
            newSeed=$(echo -n $seed | xxd -p | tr -d '\n' | sed 's/\(..\)/%\1/g')
            newLink="${uuid}@${ip}:${port}?type=kcp&headerType=${camouflageType}&seed=${newSeed}"
            yellow "分享链接(Xray标准): "
            green "vless://${newLink}"
        fi
    fi

    finishSetting
}

set_withXTLS() {
    [ -z /usr/local/bin/xray ] && red " 请先安装 Xray！" && exit 1
    echo

    yellow " 请确保: "
    yellow " 1. 申请了自己的 TLS 证书"
    yellow " 2. 将使用系统的包管理器(重新)安装 nginx"
    red " 3. 原 nginx 和 Xray 配置将被删除！！！"

    echo 
    read -p " 输入任意内容继续，按 ctrl + c 退出" rubbish
    echo 
    # port
    getPort
    echo

    read -p " 请输入回落网站端口(默认 80): " fallbackPort
    # 判断输入的端口信息
    [[ -z "${fallbackPort}" ]] && fallbackPort=80
    if [[ "${fallbackPort:0:1}" == "0" ]]; then
        red " 端口不能以0开头"
        fallbackPort=80
    fi
    yellow " 当前端口: $fallbackPort"

    echo 
    # 随机生成 ws 端口和路径，还有后段监听的随机端口
    wsPort=$(shuf -i10000-65000 -n1)
    wsPath=$(openssl rand -hex 6)
    fallbackPort2=$(shuf -i10000-65000 -n1)

    yellow " 当前需要用到的端口占用: "
    lsof -i :$port | grep xray -v | grep nginx -v | tail -n +2
    lsof -i :$fallbackPort | grep xray -v | grep nginx -v | tail -n +2
    lsof -i :$fallbackPort | grep xray -v | grep nginx -v | tail -n +2
    lsof -i :$fallbackPort2 | grep xray -v | grep nginx -v | tail -n +2
    read -p " 有占用请 ctrl + c 推出，无占用或强制执行请回车: " rubbish
    echo 

    uuid=$(xray uuid)
    [[ -z "$uuid" ]] && red " 请先安装 Xray !" && exit 1
    getUUID
    echo -e " 当前uuid: ${GREEN} $uuid${PLAIN}"

    chooseFlow

    configCert

    echo ""
    read -p " 请输入反代网站网址(必须为 https 网站，默认: www.bing.com): " forwardWeb
    [ -z "$forwardWeb" ] && forwardWeb="www.bing.com"
    yellow " 当前反代网站: $forwardWeb"
    echo ""

# 配置详解
# http/1.1 就回落到 80 端口，h2 回落到高位端口。毕竟浏览器不会使用 h2c。
# 反代网站对新手友好。

    green " 正在安装 nginx ......"
    ${PACKAGE_UPDATE[int]}
    ${PACKAGE_INSTALL[int]} nginx
    echo ""
    green " 正在生成 nginx 配置"
    cat >/etc/nginx/nginx.conf <<-EOF
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    gzip on;

    server {
        listen 0.0.0.0:$fallbackPort default_server;
        listen [::]:$fallbackPort default_server;
        listen 0.0.0.0:$fallbackPort2 http2;
        listen [::]:$fallbackPort2 http2;
        server_name $domain;

        location / {
            proxy_pass https://${forwardWeb};
            proxy_redirect off;
            proxy_ssl_server_name on;
            sub_filter_once off;
            sub_filter "${forwardWeb}" \$server_name;
            proxy_set_header Host "${forwardWeb}";
            proxy_set_header Referer \$http_referer;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header User-Agent \$http_user_agent;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "zh-CN";
        }

        location /${wsPath} {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:${wsPort};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

    }
}
EOF

    echo ""
    green " 正在配置 Xray"
    cat >/usr/local/etc/xray/config.json <<-EOF

{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": $handshake,
                "connIdle": $connIdle,
                "uplinkOnly": $uplinkOnly,
                "downlinkOnly": $downlinkOnly
            }
        }
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "flow": "$flow"
                    }
                ],
                "fallbacks": [
                    {
                        "alpn": "h2",
                        "xver": 1,
                        "dest": $fallbackPort2
                    },
                    {
                        "alpn": "http/1.1",
                        "xver": 1,
                        "dest": $fallbackPort
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/usr/local/etc/xray/cert.crt",
                            "keyFile": "/usr/local/etc/xray/key.key"
                        }
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": $wsPort,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/${wsPath}"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF

    finishSetting

    systemctl enable nginx
    systemctl stop nginx
    systemctl start nginx
    # 重复执行一次，防止端口占用
    finishSetting

    systemctl enable nginx
    systemctl stop nginx
    systemctl start nginx

    ip=$(curl ip.sb)
    ipv6=$(curl ip.sb -6)
    if [ "$ip" == "$ipv6" ]; then
        linkIP="[$ip]"
    else
        linkIP="$ip"
    fi

    xtlsLink="vless://${uuid}@${linkIP}:${port}?sni=${domain}&security=tls&type=tcp&flow=${flow}"
    wsLink1="vmess://${uuid}@${linkIP}:${port}?sni=${domain}&security=tls&type=ws&host=${domain}&path=${wsPath}"
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"ws\",
  \"path\":\"${wsPath}\",
  \"host\":\"${domain}\",
  \"tls\":\"tls\",
  \"sni\":\"${domain}\"
}"
    tmpLink=$(echo -n ${raw} | base64 -w 0)
    wsLink2="vmess://$tmpLink"

    yellow " 节点一:"
    echo -e " 协议: ${GREEN} VLESS${PLAIN}"
    echo -e " 地址: ${BLUE} $ip ${PLAIN} 或 ${BLUE} $domain${PLAIN}"
    echo -e " 端口: ${BLUE} $port${PLAIN}"
    echo -e " 底层传输方式: ${YELLOW} TCP${PLAIN}"
    echo -e " 传输层安全: ${RED} tls${PLAIN}"
    echo -e " 流控: ${GREEN} $flow${PLAIN}"
    echo -e " UUID: ${GREEN} $uuid${PLAIN}"
    echo -e " 服务名称指示(sni): ${BLUE} $domain${PLAIN}"
    echo ""
    green " 分享链接: $xtlsLink${PLAIN}"

    echo 
    echo 
    yellow "节点二:"
    echo -e "协议: ${YELLOW} VMess${PLAIN}"
    echo -e " 地址: ${BLUE} $ip ${PLAIN} 或 ${BLUE} $domain${PLAIN}"
    echo -e "端口: ${BLUE} $port${PLAIN}"
    echo -e "底层传输方式: ${BLUE} ws${PLAIN}"
    echo -e "ws 路径: ${BLUE} /$wsPath${PLAIN}"
    echo -e "ws host: ${BLUE} $domain${PLAIN}"
    echo -e "传输层安全: ${YELLOW} tls${PLAIN}"
    echo -e "UUID: ${GREEN} $uuid${PLAIN}"
    echo -e "额外ID: ${RED} 0${PLAIN}"
    echo -e "服务名称指示(sni): ${BLUE} $domain${PLAIN}"
    echo 
    yellow " 分享链接(DuckSoft): $wsLink1"
    echo 
    green " 分享链接(v2rayN): $wsLink2"
}

set_REALITY_steal() {
    echo 
    [ -z /usr/local/bin/xray ] && red " 请先安装 Xray！" && exit 1
    red " 会覆盖现有的 Xray 设置！"
    read -p " 输入任意内容继续，按 ctrl + c 退出" rubbish
    echo
    echo -e " 请输入借用 网站/ip，默认 ${BLUE} dl.google.com${PLAIN}: "
    read -p "" forwardSite
    [ -z "$forwardSite" ] && forwardSite="dl.google.com"
    echo -e " 当前借用网站: ${GREEN} $forwardSite${PLAIN}"
    echo
    echo -e " 请输入借用网站的 ${BLUE} sni ${PLAIN} (默认与借用网站相同): "
    read -p "" domain
    [ -z "$domain" ] && domain=$forwardSite
    echo -e " 当前借用网站的 ${BLUE} sni: $domain${PLAIN}"
    echo
    echo -e " 请输入目标网站${BLUE}端口${PLAIN}(默认 443): "
    read -p "" forwardPort
    [ -z "$forwardPort" ] && forwardPort=443
    echo -e " 当前目标端口: ${BLUE}$port${PLAIN}"
    echo
    red " 开始测试: "

    # 由于不保证测试方法的可靠性，所以允许用户无视验证。

    # 指定使用 h2 和 TLS 1.3 访问目标网站并输出状态码
    testTarget1=$(curl --http2 --tlsv1.3 https://${forwardSite}:${forwardPort} -o /dev/null -w "%{http_code}" -s)
    # 000：根本无法连接（要么网站根本连不上，要么根本不支持 TLS 1.3）
    # 444：nginx 的错误码
    # 505：不支持的 http 版本（无 h2）
    if [ "$testTarget1" == "000" ] || [ "$testTarget1" == "444" ] || [ "$testTarget1" == "505" ]; then
        red " 目标网站不支持 TLS 1.3 或 h2!"
        read -p " 按 Y 仍然继续：" answer
        if [ "$answer" != "Y" ] || [ "$answer" != "y" ]; then
            exit 1
        fi
    else
        green " 目标网站支持 TLS 1.3 和 h2"
    fi
    # 棘手的问题： openssl s_client 必须输入任意内容才能继续
    red " 输入任意内容继续！(建议仅输入一个 a，不然可能会有奇奇怪怪的问题。)"
    testTarget2=$(openssl s_client -connect ${forwardSite}:${forwardPort} -curves X25519 | grep "Server Temp Key")
    if [[ $testTarget2 =~ "25519" ]]; then
        green " 目标网站支持 X25519！"
    else
        red " 目标网站不支持 X25519！"
        yellow " 提示：可能不准，如果 h2 和 TLS1.3 能用就行了"
        read -p " 按 Y 仍然继续：" answer
        if [ "$answer" != "Y" ] || [ "$answer" != "y" ]; then
            exit 1
        fi
    fi
    echo
    getPort
    # 如果 Xray 监听 443 并且目标网站的端口也是 443,则询问是否转发 80 端口，增加伪装。
    if [ "$port" == "443" ] && [ "$forwardPort" == "443" ]; then
        echo
        green " 当前 80 端口占用: "
        lsof -i:80 | grep xray -v | grep nginx -v | tail -n +2
        echo
        yellow " 是否转发 80 端口?"
        read -p " (Y/n)" answer
        if [ "$answer" == "n" ] || [ "$answer" == "N" ]; then
            DokodemoDoorPort=$(shuf -i10000-65000 -n1)
        else
            DokodemoDoorPort=80
        fi
    else
        DokodemoDoorPort=$(shuf -i10000-65000 -n1)
    fi
    echo
    h2Port=$(shuf -i10000-65000 -n1)
    red " 检测所需端口占用情况: "
    lsof -i :$port | grep xray -v | grep nginx -v | tail -n +2
    lsof -i :$h2Port | grep xray -v | grep nginx -v | tail -n +2
    yellow " 如有占用，请使用 kill [pid] 来解除占用！"
    read -p " 是否继续(Y/n)?" answer
    if [ "$answer" == "n" ];then
        exit 0
    fi
    echo
    getUUID
    echo
    echo -e " 当前 uuid: ${GREEN}$uuid${PLAIN}"
    echo
    
    getX25519

    echo
    
    chooseFlow

    getShortID

    echo
    red " 开始配置 Xray!"
    cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
        "levels": {
            "0": {
                "handshake": $handshake,
                "connIdle": $connIdle,
                "uplinkOnly": $uplinkOnly,
                "downlinkOnly": $downlinkOnly
            }
        }
    },
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": $DokodemoDoorPort,
            "protocol": "Dokodemo-Door",
            "settings": {
                "address": "$forwardSite",
                "port": 80,
                "network": "tcp"
            }
        },
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "$flow"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "xver": 1,
                        "dest": $h2Port
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${forwardSite}:${forwardPort}",
                    "xver": 0,
                    "serverNames": [
                        ""
                    ],
                    "privateKey": "$PrivateKey",
                    "shortIds": [
                        "$shortID"
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": $h2Port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "none",
                "network": "h2",
                "httpSettings": {
                    "path": "/"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        },
        {
            "protocol": "Blackhole"
        }
    ]
}
EOF

    echo
    ufw allow $port
    if [ "$DokodemoDoorPort" == "80" ]; then
        ufw allow 80
    fi
    finishSetting
    echo
    ip=$(curl ip.sb)
    ipv6=$(curl ip.sb -6)
    if [ "$ip" == "$ipv6" ]; then
        linkIP="[$ip]"
    else
        linkIP="$ip"
    fi
    shareReality
}

set_REALITY_own() {
    [ -z /usr/local/bin/xray ] && red " 请先安装 Xray！" && exit 1
    echo
    yellow " 警告：会覆盖原有的 Xray、nginx 配置！"
    yellow " 默认的伪装网站为 404 页面，如有需求请自行替换！"
    echo
    getPort
    # 80 端口开放，更真实
    if [ "$port" == "443" ]; then
        read -p " 是否监听 80 端口？（Y/n）" answer
        if [ "$answer" == "n" ] || [ "$answer" == "N" ]; then
            httpPort=$(shuf -i10000-65000 -n1)
            httpListen="127.0.0.1"
        else
            httpPort=80
            httpListen="0.0.0.0"
        fi
    fi
    echo
    getUUID
    echo
    getX25519
    echo
    getShortID
    echo
    configCert
    echo
    nginxPort=$(shuf -i10000-65000 -n1)
    h2Port=$(shuf -i10000-65000 -n1)
    yellow " 端口占用情况："
    lsof -i:$port | grep xray -v | grep nginx -v | tail -n +2
    lsof -i:$httpPort | grep xray -v | grep nginx -v | tail -n +2
    lsof -i:$nginxPort | grep xray -v | grep nginx -v | tail -n +2
    lsof -i:$h2Port | grep xray -v | grep nginx -v | tail -n +2
    read -p " 有占用请 ctrl + c 推出，无占用或强制执行请回车: " rubbish
    echo
    ${PACKAGE_UPDATE[int]}
    ${PACKAGE_INSTALL[int]} nginx
    echo
    yellow " 开始配置 nginx......"
    cat >/etc/nginx/nginx.conf <<-EOF
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    gzip on;

    server {
        listen 127.0.0.1:$nginxPort ssl http2;
        listen ${httpListen}:$httpPort;
        server_name $domain;

        ssl_certificate       /usr/local/etc/xray/cert.crt;
        ssl_certificate_key   /usr/local/etc/xray/key.key;

        ssl_protocols    TLSv1.3 TLSv1.2;
        ssl_prefer_server_ciphers off;


        location ^~ /.well-known/acme-challenge/ {
            default_type "text/plain";
            root /var/www/acme-challenge;
        }

        location / {
            return 404;
        }

    }
}
EOF
    echo
    yellow " 正在配置 Xray......"
    cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
        "levels": {
            "0": {
                "handshake": $handshake,
                "connIdle": $connIdle,
                "uplinkOnly": $uplinkOnly,
                "downlinkOnly": $downlinkOnly
            }
        }
    },
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "${flow}"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "xver": 1,
                        "dest": $h2Port
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "127.0.0.1:${nginxPort}",
                    "xver": 0,
                    "serverNames": [
                        ""
                    ],
                    "privateKey": "$PrivateKey",
                    "shortIds": [
                        "$shortID"
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": $h2Port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "none",
                "network": "h2",
                "httpSettings": {
                    "path": "/"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        },
        {
            "protocol": "Blackhole"
        }
    ]
}
EOF

    echo
    ufw allow $port
    if [ "$httpListen" == "0.0.0.0" ]; then
        ufw allow $httpPort
    fi
    finishSetting
    systemctl stop nginx
    systemctl start nginx
    systemctl reload nginx
    finishSetting
    systemctl stop nginx
    systemctl start nginx
    systemctl reload nginx
    echo
    ip=$(curl ip.sb)
    ipv6=$(curl ip.sb -6)
    if [ "$ip" == "$ipv6" ]; then
        linkIP="[$ip]"
    else
        linkIP="$ip"
    fi
    echo
    shareReality
}

install_build() {
    echo
    yellow " 请确保: "
    yellow " 1. 安装了最新版本的 golang(可使用本脚本102选项) 和 git"
    yellow "2 . 自愿承担使用最新版本的风险(包括各种各样的bug、协议不适配等问题)"
    echo ""
    read -p " 输入任意内容继续，按 ctrl + c 退出" rubbish
    echo ""
    red " 3秒冷静期"
    sleep 3
    # 克隆储存库
    git clone https://github.com/XTLS/Xray-core.git
    yellow " 即将开始编译，可能耗时较久，请耐心等待"
    cd Xray-core && go mod download
    # 正式编译
    CGO_ENABLED=0 go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main
	chmod +x xray || {
		red "Xray安装失败"
        cd ..
        rm -rf Xray-core
		exit 1
	}
    systemctl stop xray
    cp xray /usr/local/bin/
    # clean
    cd ..
    rm -rf Xray-core/
    mkdir /usr/local/etc/xray 
    mkdir /usr/local/share/xray
    cd /usr/local/share/xray
    # 下载 geo 资源文件
    # 使用官方资源，防止奇奇怪怪的问题出现
    curl -L -k -O https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
    mv dlc.dat geosite.dat
    curl -L -k -O https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
    # 设置守护进程
	cat >/etc/systemd/system/xray.service <<-EOF
		[Unit]
		Description=Xray Service
		Documentation=https://github.com/XTLS/Xray-core
		After=network.target nss-lookup.target
		
		[Service]
		User=root
		#User=nobody
		#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		NoNewPrivileges=true
		ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
		Restart=on-failure
		RestartPreventExitStatus=23
		
		[Install]
		WantedBy=multi-user.target
	EOF

    # 创建日志文件
    mkdir -p /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    systemctl daemon-reload
    systemctl enable xray.service

    echo 
    yellow " 装完了(确信)"
}

install_official() {
# 调用官方脚本安装，懒得造轮子
    update_system
    echo ""
    read -p " 是否手动指定 Xray 版本?不指定将安装最新稳定版(y/N): " ownVersion
    if [[ "$ownVersion" == "y" ]]; then
        # 也许根本不需要判断是否输入版本号？毕竟不给版本号，官方脚本也会报错
        read -p " 请输入安装版本(不要以"v"开头): " xrayVersion
        [[ -z "$xrayVersion" ]] && red "请输入有效版本号！" && exit 1
        bash -c "$(curl -L -k https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version ${xrayVersion} -u root
    else
        bash -c "$(curl -L -k https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
    fi
}

update_system() {
    ${PACKAGE_UPDATE[int]}
    ${PACKAGE_INSTALL[int]} curl wget tar openssl lsof
}

get_cert() {
    # https://github.com/tdjnodj/simple-acme
    bash <(curl -L -k https://github.com/tdjnodj/simple-acme/releases/latest/download/simple-acme.sh)
}

install_go() {
    ${PACKAGE_INSTALL[int]} git curl
    # CPU
    bit=`uname -m`
    if [[ $bit = x86_64 ]]; then
        cpu=amd64
    elif [[ $bit = amd64 ]]; then
        cpu=amd64
    elif [[ $bit = aarch64 ]]; then
        cpu=arm64
    elif [[ $bit = armv8 ]]; then
        cpu=arm64
    elif [[ $bit = armv7 ]]; then
        cpu=arm64
    elif [[ $bit = s390x ]]; then
        cpu=s390x
    else 
        cpu=$bit
        red " 可能不支持该型号( $cpu )的CPU!"
    fi
    # 获取 go 语言版本
    go_version=$(curl https://go.dev/VERSION?m=text)
    red " 当前最新版本golang: $go_version"
    curl -O -k -L https://go.dev/dl/${go_version}.linux-${cpu}.tar.gz
    yellow " 正在解压......"
    tar -xf go*.linux-${cpu}.tar.gz -C /usr/local/
    sleep 3
    export PATH=\$PATH:/usr/local/go/bin
    rm go*.tar.gz
    echo 'export PATH=\$PATH:/usr/local/go/bin' >> /root/.bash_profile
    source /root/.bash_profile
    yellow " 检查当前golang版本: "
    go version
    yellow " 为确保正常安装，请手动输入: "
    echo "echo 'export PATH=\$PATH:/usr/local/go/bin' >> /root/.bash_profile"
    red "source /root/.bash_profile"
    echo ""
    echo " 如果错误，常见错误原因: 未删除旧的go"
}

# 调用官方脚本
unintstall_xray() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
}

updateGEO() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata
}

showLog() {
    echo ""
    echo -e " 查看 ${BLUE}访问${PLAIN} 情况： cat /var/log/xray/access.log"
    echo -e " 查看 ${RED}Xray${PLAIN} 报错： /var/log/xray/error.log"
}

myHelp() {
    echo ""
    echo -e " bash ${BLUE}${0}${PLAIN} <选项>"
    echo ""
    yellow " 选项:"
    echo ""
    echo -e " ${YELLOW}menu${PLAIN}         打开菜单"
    echo -e " ${YELLOW}help${PLAIN}         查看本帮助"
    echo -e " ${YELLOW}install${PLAIN}      使用官方脚本 安装/更新 xray"
    echo -e " ${YELLOW}build${PLAIN}        编译安装 xray"
    echo -e " ${YELLOW}cert${PLAIN}         获取 tls 证书"
}

menu() {
    # 为了防止 GFW 根据 ssh 传输数据长度识别你在使用什么脚本
    # 本脚本会生成一个随机的、包含 50-300 个字符的字符串，来对 ssh 数据长度进行混淆
    random_string=$(tr -dc '[:alnum:]' </dev/urandom | head -c $((RANDOM % 251 + 50)))
    echo $random_string
    clear
    echo -e " ${BLUE}Let's Xray!${PLAIN}"
    echo -e " ${RED}Xray${PLAIN} 一键安装/配置脚本"
    echo -e " 项目地址：${YELLOW}https://github.com/tdjnodj/LetsXray/${PLAIN}"
    echo ""
    echo -e " 1. 通过${BLUE}官方脚本${PLAIN} ${YELLOW}安装/更新${YELLOW} ${RED}Xray${PLAIN}"
    echo -e " 2. ${YELLOW}编译${YELLOW}安装 ${RED}Xray${PLAIN}"
    echo ""
    echo " ------------------------------------"
    echo ""
    echo -e " 3. 配置 ${RED}Xray${PLAIN}: 无 ${YELLOW}TLS${PLAIN} 的协议"
    echo -e " 4. 配置 ${RED}Xray${PLAIN}: VLESS + ${GREEN}xtls-rprx-vision${PLAIN} + tls + web"
    echo -e " 5. ${GREEN}(推荐)${PLAIN}配置 ${RED}Xray${PLAIN}: 用 ${BLUE}REALITY${PLAIN} \"借用\" 别人的证书: ${GREEN}REALITY + xtls-rprx-vision / h2${PLAIN} 共存！"
    echo -e " 6. ${YELLOW}(推荐)${PLAIN}配置 ${RED}Xray${PLAIN}: 用 ${BLUE}REALITY${PLAIN} 以及自己的证书: ${GREEN}REALITY + xtls-rprx-vision / h2${PLAIN} 共存！"
    echo ""
    echo " ------------------------------------"
    echo -e " 11. 启动 ${RED}Xray${PLAIN}"
    echo -e " 12. 停止 ${RED}Xray${PLAIN}"
    echo -e " 13. 设置 ${RED}Xray${PLAIN} 开机自启动"
    echo -e " 14. 取消 ${RED}Xray${PLAIN} 开机自启动"
    echo -e " 15. 查看 ${RED}Xray${PLAIN} 运行状态"
    echo -e " 16. 卸载 ${RED}Xray${PLAIN}"
    echo -e " 17. 更新 ${BLUE}geo${PLAIN} 资源文件"
    echo -e " 18. 查看 ${RED}Xray${PLAIN} 日志"
    echo " ------------------------------------"
    echo ""
    yellow " 100. 更新系统和安装依赖"
    yellow " 101. 申请 TLS 证书(http 申请/自签)"
    yellow " 102. 安装最新版本的 golang 及 编译 ${RED}Xray${PLAIN} 的其他组件"
    echo ""
    echo " ------------------------------------"
    echo ""
    yellow " 0. 退出脚本"
    read -p " 请选择: " answer
    case $answer in
        0) exit 0 ;;
        1) install_official ;;
        2) install_build ;;
        3) set_withoutTLS ;;
        4) set_withXTLS ;;
        5) set_REALITY_steal ;;
        6) set_REALITY_own ;;
        11) systemctl start xray ;;
        12) systemctl stop xray ;;
        13) systemctl enable xray ;;
        14) systemctl disable xray ;;
        15) systemctl status xray ;;
        16) unintstall_xray ;;
        17) updateGEO ;;
        18) showLog ;;
        100) update_system ;;
        101) get_cert ;;
        102) install_go ;;
        *) red "不存在本选项！" && exit 1 ;;
    esac
}

action=$1
[[ -z $1 ]] && action=menu

case "$action" in
    menu) menu ;;
    help) myHelp;;
    install) install_official ;;
    build) install_build ;;
    cert) get_cert ;;
    *) red "不存在的选项！" && myHelp ;;
esac
