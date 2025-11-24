#!/bin/bash
clear

echo "==============================================="
echo "       Instalador Xray (XHTTP + TLS + 443)"
echo "==============================================="

# ------------------------------
# 1. Ler domínio
# ------------------------------
echo
read -rp "Digite o domínio (host): " DOMAIN

if [ -z "$DOMAIN" ]; then
    echo "[ERRO] Você precisa informar um domínio."
    exit 1
fi

SNI="www.tim.com.br"
XRAY_DIR="/usr/local/etc/xray"
SSL_DIR="/opt/sshorizon/ssl"

# ------------------------------
# 2. Gerar ou receber UUID
# ------------------------------
echo
read -rp "Gerar UUID automático? (S/n): " UUID_CHOICE

if [[ "$UUID_CHOICE" =~ ^(n|N)$ ]]; then
    read -rp "Digite o UUID desejado: " USER_UUID
else
    USER_UUID=$(xray uuid)
fi

if [ -z "$USER_UUID" ]; then
    echo "[ERRO] UUID inválido."
    exit 1
fi

# ------------------------------
# 3. Instalar dependências
# ------------------------------
apt update -y
apt install -y curl socat cron unzip

# ------------------------------
# 4. Instalar acme.sh
# ------------------------------
if [ ! -d "~/.acme.sh" ]; then
    curl https://get.acme.sh | sh
fi

# Carregar acme.sh
source ~/.bashrc
source ~/.acme.sh/acme.sh.env

# ------------------------------
# 5. Gerar certificado
# ------------------------------
echo
echo "Gerando certificado SSL via ACME..."
mkdir -p "$SSL_DIR"

~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --force

if [ $? -ne 0 ]; then
    echo "[ERRO] Falha ao gerar certificado. Verifique DNS e porta 80."
    exit 1
fi

~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$SSL_DIR/privkey.pem" \
    --fullchain-file "$SSL_DIR/fullchain.pem" \
    --reloadcmd "systemctl restart xray"

chmod 600 "$SSL_DIR"/*.pem

# ------------------------------
# 6. Instalar Xray
# ------------------------------
echo
echo "Instalando Xray..."

bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)

mkdir -p "$XRAY_DIR"

# ------------------------------
# 7. Criar config.json
# ------------------------------
cat > $XRAY_DIR/config.json <<EOF
{
  "api": {
    "services": ["HandlerService", "LoggerService", "StatsService"],
    "tag": "api"
  },
  "dns": {
    "servers": ["94.140.14.14", "94.140.15.15"],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "api",
      "port": 1080,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "listen": "127.0.0.1"
    },
    {
      "tag": "inbound-sshorizon",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "client@$DOMAIN",
            "id": "$USER_UUID",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": []
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$SSL_DIR/fullchain.pem",
              "keyFile": "$SSL_DIR/privkey.pem"
            }
          ],
          "alpn": ["http/1.1"]
        },
        "xhttpSettings": {
          "headers": null,
          "host": "",
          "mode": "",
          "noSSEHeader": false,
          "path": "/",
          "scMaxBufferedPosts": 30,
          "scMaxEachPostBytes": "1000000",
          "scStreamUpServerSecs": "20-80",
          "xPaddingBytes": "100-1000"
        }
      }
    }
  ],
  "log": {
    "access": "/var/log/v2ray/access.log",
    "dnsLog": false,
    "error": "",
    "loglevel": "info",
    "maskAddress": ""
  },
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserOnline": true,
        "statsUserUplink": true
      }
    }
  },
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "inboundTag": ["api"], "outboundTag": "api", "type": "field" },
      { "ip": ["geoip:private"], "outboundTag": "blocked", "type": "field" },
      { "protocol": ["bittorrent"], "outboundTag": "blocked", "type": "field" }
    ]
  },
  "stats": {}
}
EOF

# ------------------------------
# 8. Criar diretórios de log
# ------------------------------
mkdir -p /var/log/v2ray
touch /var/log/v2ray/access.log
chmod -R 755 /var/log/v2ray

# ------------------------------
# 9. Reiniciar serviço
# ------------------------------
systemctl enable xray
systemctl restart xray

sleep 1

# ------------------------------
# 10. Testar funcionamento
# ------------------------------
if ! ss -tulpn | grep -q ":443"; then
    echo
    echo "[ERRO] Xray não abriu a porta 443!"
    echo "Verifique firewall."
    exit 1
fi

# ------------------------------
# 11. Gerar link VLESS
# ------------------------------
VLESS="vless://$USER_UUID@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=$DOMAIN&path=%2F&sni=$SNI&allowInsecure=1#Tim-BR"

echo
echo "==============================================="
echo "              INSTALAÇÃO CONCLUÍDA"
echo "==============================================="
echo
echo "Seu link VLESS:"
echo
echo "$VLESS"
echo
echo "==============================================="
echo "Xray está rodando na porta 443 com XHTTP + TLS"
echo "==============================================="
