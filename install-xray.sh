#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Instalador universal Xray (TLS + XHTTP + autoassinado)
# - Pergunta apenas o SUBDOMÍNIO (ex: meuserver)
# - Monta domínio completo: meuserver.azion.app
# - Instala Xray
# - Gera UUID apenas após Xray estar instalado
# - Gera certificado autoassinado
# - Cria config.json no formato fornecido pelo usuário
# - Cria systemd service
# - Gera VLESS no final

SSL_DIR="/opt/sshorizon/ssl"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="${XRAY_CONFIG_DIR}/config.json"
SNI_FIXED="www.tim.com.br"

info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*" ; }
ok(){ printf "\e[32m[OK]\e[0m %s\n" "$*" ; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*" ; exit 1 ; }

require_root(){
  if [[ "$EUID" -ne 0 ]]; then
    err "Execute como root: sudo ./install-xray.sh"
  fi
}

detect_pkgmgr(){
  if command -v apt-get >/dev/null 2>&1; then
    PKG_INST="apt-get install -y"
    UPDATE_CMD="apt-get update -y"
  elif command -v yum >/dev/null 2>&1; then
    PKG_INST="yum install -y"
    UPDATE_CMD="yum makecache"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_INST="dnf install -y"
    UPDATE_CMD="dnf makecache"
  else
    err "Gerenciador de pacotes não suportado."
  fi
}

install_dependencies(){
  info "Instalando dependências..."
  ${UPDATE_CMD}
  ${PKG_INST} curl wget unzip openssl ca-certificates
  ok "Dependências instaladas."
}

# --- Xray installation (3 fallbacks) ---

install_xray_official(){
  info "Tentando Xray via instalador oficial..."
  if curl -fsSL -o /tmp/xray.sh https://github.com/XTLS/Xray-install/raw/main/install-release.sh; then
    bash /tmp/xray.sh || return 1
    return 0
  fi
  return 1
}

install_xray_jsdelivr(){
  info "Tentando Xray via jsDelivr..."
  if curl -fsSL -o /tmp/xray.sh https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh; then
    bash /tmp/xray.sh || return 1
    return 0
  fi
  return 1
}

install_xray_release(){
  info "Baixando release do Xray (fallback)..."
  local ZIP="/tmp/xray.zip"
  if curl -fsSL -o "$ZIP" https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip; then
    mkdir -p /tmp/xray_unzip
    unzip -o "$ZIP" -d /tmp/xray_unzip >/dev/null 2>&1
    if [[ -f /tmp/xray_unzip/xray ]]; then
      install -m 755 /tmp/xray_unzip/xray /usr/local/bin/xray
      ok "Xray instalado via fallback."
      return 0
    fi
  fi
  return 1
}

install_xray_universal(){
  detect_pkgmgr
  install_dependencies

  if command -v xray >/dev/null 2>&1; then
    ok "Xray já instalado."
    return
  fi

  install_xray_official && return
  install_xray_jsdelivr && return
  install_xray_release && return

  err "Falha ao instalar Xray por todos os métodos."
}

# --- SSL self-signed ---

generate_self_signed_cert(){
  local domain="$1"
  mkdir -p "$SSL_DIR"
  info "Gerando certificado autoassinado ($domain)..."

  openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -subj "/CN=$domain" \
    -keyout "$SSL_DIR/privkey.pem" \
    -out "$SSL_DIR/fullchain.pem" >/dev/null 2>&1

  chmod 600 "$SSL_DIR/privkey.pem"
  chmod 644 "$SSL_DIR/fullchain.pem"
  ok "Certificado autoassinado pronto."
}

# --- Logs ---

prepare_logs(){
  mkdir -p /var/log/v2ray
  touch /var/log/v2ray/access.log
  chmod 755 /var/log/v2ray
}

# --- Systemd ---

create_systemd_service(){
  info "Criando serviço systemd..."

  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
Group=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable xray
}

# --- Config.json ---

create_xray_config(){
  local uuid="$1"
  local domain="$2"

  mkdir -p "$XRAY_CONFIG_DIR"

  cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "burstObservatory": null,
  "dns": {
    "servers": [
      "94.140.14.14",
      "94.140.15.15"
    ],
    "queryStrategy": "UseIPv4"
  },
  "fakedns": null,
  "inbounds": [
    {
      "tag": "api",
      "port": 1080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "listen": "127.0.0.1"
    },
    {
      "tag": "inbound-sshorizon",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "admin@${domain}",
            "id": "${uuid}",
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
              "certificateFile": "${SSL_DIR}/fullchain.pem",
              "keyFile": "${SSL_DIR}/privkey.pem"
            }
          ],
          "alpn": [
            "http/1.1"
          ]
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
  "observatory": null,
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserOnline": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundDownlink": true,
      "statsInboundUplink": true,
      "statsOutboundDownlink": false,
      "statsOutboundUplink": false
    }
  },
  "reverse": null,
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked",
        "type": "field"
      },
      {
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ],
        "type": "field"
      }
    ]
  },
  "stats": {},
  "transport": null
}
EOF

  ok "Configuração criada em $XRAY_CONFIG_PATH"
}

# --- Main ---

main(){
  require_root

  echo "==============================================="
  echo "  Instalador Xray (TLS + XHTTP + 443)"
  echo "==============================================="

  read -rp "Digite o subdomínio (ex: meuserver): " SUB
  [[ -z "$SUB" ]] && err "Subdomínio obrigatório."

  DOMAIN="${SUB}.azion.app"
  info "Domínio final: $DOMAIN"

  install_xray_universal

  # UUID AFTER Xray installation
  UUID=$(xray uuid 2>/dev/null || uuidgen || cat /proc/sys/kernel/random/uuid)
  [[ -z "$UUID" ]] && err "Falha ao gerar UUID."

  ok "UUID gerado: $UUID"

  generate_self_signed_cert "$DOMAIN"
  prepare_logs
  create_systemd_service
  create_xray_config "$UUID" "$DOMAIN"

  systemctl restart xray
  sleep 1

  VLESS="vless://${UUID}@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=${DOMAIN}&path=%2F&sni=${SNI_FIXED}&allowInsecure=1#Tim-BR"

  echo
  echo "==============================================="
  echo " INSTALAÇÃO CONCLUÍDA"
  echo "==============================================="
  echo "Domínio: $DOMAIN"
  echo "UUID: $UUID"
  echo
  echo "VLESS:"
  echo "$VLESS"
  echo
  echo "Logs: journalctl -u xray -n 200 --no-pager"
  echo "==============================================="
}

main "$@"
