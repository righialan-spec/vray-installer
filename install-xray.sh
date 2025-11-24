#!/bin/bash
# Xray Installer - Configuração XHTTP + TLS + Porta 443 + UUID dinâmico
# Compatível com Linode + Azion

clear
echo "==============================================="
echo "     Instalador Xray (XHTTP + TLS + 443)"
echo "==============================================="
echo

# ------------------------------
# 1. Perguntar domínio
# ------------------------------
read -rp "Digite o domínio (host/SNI) que deseja usar (ex: righi.azion.app): " DOMAIN

if [[ -z "$DOMAIN" ]]; then
    echo "[ERRO] Você deve informar um domínio válido."
    exit 1
fi

# ------------------------------
# 2. Verificar certificado
# ------------------------------
CERT_DIR="/opt/sshorizon/ssl"

if [[ ! -f "$CERT_DIR/fullchain.pem" || ! -f "$CERT_DIR/privkey.pem" ]]; then
    echo "[ERRO] Certificados não encontrados em:"
    echo "$CERT_DIR/fullchain.pem"
    echo "$CERT_DIR/privkey.pem"
    echo
    echo "Crie ou copie os arquivos antes de rodar o script."
    exit 1
fi

chmod 755 /opt/sshorizon
chmod 755 /opt/sshorizon/ssl
chmod 644 /opt/sshorizon/ssl/fullchain.pem
chmod 600 /opt/sshorizon/ssl/privkey.pem

# ------------------------------
# 3. Instalar Xray
# ------------------------------
echo "[+] Instalando Xray..."
bash <(curl -s https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)

# ------------------------------
# 4. Gerar UUID
# ------------------------------
UUID=$(xray uuid)
echo "[+] UUID gerado: $UUID"

# ------------------------------
# 5. Criar config.json
# ------------------------------
CONFIG_PATH="/usr/local/etc/xray/config.json"

cat > $CONFIG_PATH <<EOF
{
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "dns": {
    "servers": [
      "94.140.14.14",
      "94.140.15.15"
    ],
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
      "tag": "inbound-alan",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "user@installer.local",
            "id": "$UUID",
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
              "certificateFile": "$CERT_DIR/fullchain.pem",
              "keyFile": "$CERT_DIR/privkey.pem"
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
    "loglevel": "info"
  },
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "policy": {
    "levels": {
      "0": { "statsUserDownlink": true, "statsUserOnline": true, "statsUserUplink": true }
    },
    "system": {
      "statsInboundDownlink": true,
      "statsInboundUplink": true
    }
  },
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "protocol": ["bittorrent"],
        "outboundTag": "blocked",
        "type": "field"
      }
    ]
  }
}
EOF

# ------------------------------
# 6. Criar service file corrigido
# ------------------------------
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
Group=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------
# 7. Ativar serviço
# ------------------------------
systemctl daemon-reload
systemctl enable xray
systemctl restart xray

echo
echo "==============================================="
echo "        INSTALAÇÃO FINALIZADA!"
echo "==============================================="
echo
echo "[+] UUID: $UUID"
echo "[+] Domínio configurado: $DOMAIN"
echo
echo "=== Seu link VLESS ==="
echo
echo "vless://$UUID@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=$DOMAIN&path=%2F&sni=www.tim.com.br&allowInsecure=1#Tim-BR"
echo
echo "==============================================="
