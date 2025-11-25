#!/usr/bin/env bash
set -euo pipefail

BREED="vray-installer-local"
SNI_FIXED="www.tim.com.br"
SSL_DIR="/opt/sshorizon/ssl"
XRAY_BIN_PATH="/usr/local/bin/xray"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="${XRAY_CONFIG_DIR}/config.json"

# Helper
info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
ok(){ printf "\e[32m[OK]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

require_root(){
  if [ "$EUID" -ne 0 ]; then
    err "Execute como root: sudo ./install-xray.sh"
  fi
}

detect_pkgmgr(){
  if command -v apt-get >/dev/null 2>&1; then
    PKG_INST="apt-get install -y"
    UPDATE_CMD="apt-get update -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_INST="dnf install -y"
    UPDATE_CMD="dnf makecache"
  elif command -v yum >/dev/null 2>&1; then
    PKG_INST="yum install -y"
    UPDATE_CMD="yum makecache"
  else
    err "Nenhum gerenciador de pacotes compatível encontrado (apt/yum/dnf)."
  fi
}

install_deps(){
  info "Atualizando repositórios e instalando dependências (curl, wget, unzip, openssl)..."
  ${UPDATE_CMD}
  $PKG_INST curl wget unzip ca-certificates openssl socat iptables || true
  ok "Dependências instaladas (ou já presentes)."
}

# Xray installers (three fallbacks)
install_xray_official(){
  info "Tentando instalar Xray via instalador oficial..."
  tmp="/tmp/xray_install_official.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmp" "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"; then
    chmod +x "$tmp" || true
    bash "$tmp" || return 1
    return 0
  fi
  return 1
}

install_xray_jsdelivr(){
  info "Tentando instalar Xray via jsDelivr..."
  tmp="/tmp/xray_install_jsdelivr.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmp" "https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh"; then
    chmod +x "$tmp" || true
    bash "$tmp" || return 1
    return 0
  fi
  return 1
}

install_xray_release(){
  info "Tentando instalar Xray baixando release (fallback)..."
  tmpzip="/tmp/xray_core.zip"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmpzip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"; then
    mkdir -p /tmp/xray_unpack
    unzip -o "$tmpzip" -d /tmp/xray_unpack >/dev/null 2>&1 || true
    # find binary
    if [ -f /tmp/xray_unpack/xray ]; then
      install -m 755 /tmp/xray_unpack/xray /usr/local/bin/xray
      ok "Xray instalado em /usr/local/bin/xray"
      return 0
    elif [ -f /tmp/xray_unpack/Xray ]; then
      install -m 755 /tmp/xray_unpack/Xray /usr/local/bin/xray
      ok "Xray instalado em /usr/local/bin/xray"
      return 0
    fi
  fi
  return 1
}

install_xray_universal(){
  detect_pkgmgr
  install_deps
  if command -v xray >/dev/null 2>&1; then
    ok "xray já instalado"
    return 0
  fi
  if install_xray_official; then ok "Xray instalado (oficial)"; return 0; fi
  warn "Instalador oficial falhou, tentando jsDelivr..."
  if install_xray_jsdelivr; then ok "Xray instalado (jsDelivr)"; return 0; fi
  warn "jsDelivr falhou, tentando baixar release..."
  if install_xray_release; then ok "Xray instalado (release)"; return 0; fi
  err "Falha ao instalar Xray por todos os métodos."
}

# Create self-signed cert
generate_self_signed_cert(){
  local domain="$1"
  mkdir -p "$SSL_DIR"
  chmod 755 "$(dirname "$SSL_DIR")" || true
  chmod 755 "$SSL_DIR" || true
  key="$SSL_DIR/privkey.pem"
  crt="$SSL_DIR/fullchain.pem"
  info "Gerando certificado autoassinado para $domain (válido 10 anos)..."
  openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -keyout "$key" -out "$crt" -subj "/CN=${domain}" >/dev/null 2>&1 || err "Falha ao gerar certificado."
  chmod 600 "$key" || true
  chmod 644 "$crt" || true
  ok "Certificado autoassinado criado em $SSL_DIR"
}

create_systemd_service(){
  info "Criando systemd service para xray..."
  cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS
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
  systemctl daemon-reload || true
  systemctl enable xray >/dev/null 2>&1 || true
  ok "Service systemd criado."
}

create_logs(){
  mkdir -p /var/log/v2ray
  touch /var/log/v2ray/access.log
  chmod -R 755 /var/log/v2ray || true
  ok "Diretórios de log ok."
}

open_local_firewall(){
  info "Tentando liberar portas 80 e 443 no firewall local (ufw/firewalld/iptables)..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw reload || true
    ok "UFW atualizado."
    return
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=80/tcp || true
    firewall-cmd --permanent --add-port=443/tcp || true
    firewall-cmd --reload || true
    ok "firewalld atualizado."
    return
  fi
  # fallback iptables
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT || true
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT || true
  ok "Regras iptables adicionadas (temporárias)."
}

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
            "email": "righialan@${domain}",
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
      }
    ]
  },
  "stats": {},
  "transport": null
}
EOF
  ok "Arquivo de configuração $XRAY_CONFIG_PATH criado."
}

check_xray_running(){
  sleep 1
  if ss -tulpn | grep -q ":443"; then
    ok "Xray está escutando em 443."
    return 0
  else
    warn "Nenhum processo escutando em 443."
    return 1
  fi
}

# ---------- main ----------
main(){
  require_root

  echo "==============================================="
  echo "       Instalador Xray (XHTTP + TLS + 443)"
  echo "==============================================="
  echo

  read -rp "Digite o subdomínio (ex: meuserver): " SUB
  if [ -z "$SUB" ]; then err "Subdomínio obrigatório."; fi
  DOMAIN="${SUB}.azion.app"
  info "Dominio a ser usado: $DOMAIN"

  detect_pkgmgr

  # install xray first (universal)
  install_xray_universal

  # now generate UUID (xray binary should exist now)
  if command -v xray >/dev/null 2>&1; then
    UUID="$(xray uuid 2>/dev/null || true)"
  fi
  # fallback
  if [ -z "${UUID:-}" ]; then
    if command -v uuidgen >/dev/null 2>&1; then
      UUID="$(uuidgen)"
    else
      UUID="$(cat /proc/sys/kernel/random/uuid)"
    fi
  fi
  if [ -z "${UUID:-}" ]; then err "Falha ao gerar UUID."; fi
  ok "UUID gerado: $UUID"

  # generate self-signed certificate
  generate_self_signed_cert "$DOMAIN"

  # create logs, service, config
  create_logs
  create_systemd_service
  create_xray_config "$UUID" "$DOMAIN"
  open_local_firewall

  # restart xray
  info "Reiniciando xray..."
  systemctl restart xray || true
  sleep 2

  check_xray_running || warn "Verifique 'journalctl -u xray -n 200' para detalhes."

  # final VLESS
  VLESS="vless://${UUID}@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=${DOMAIN}&path=%2F&sni=${SNI_FIXED}&allowInsecure=1#Tim-BR"

  echo
  echo "==============================================="
  echo " INSTALAÇÃO FINALIZADA"
  echo "==============================================="
  echo "UUID: $UUID"
  echo "Domínio completo: $DOMAIN"
  echo
  echo "Link VLESS pronto:"
  echo
  echo "$VLESS"
  echo
  echo "Logs: journalctl -u xray -n 200 --no-pager"
  echo "==============================================="
}

main "$@"
