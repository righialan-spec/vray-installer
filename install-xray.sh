#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# install-xray-letsencrypt.sh
# Universal installer: Xray (XHTTP + TLS) with Let's Encrypt (certbot)
# - internal inbound: 1080 (dokodemo)
# - external: 443 (vless + xhttp + tls)
# - SNI fixed: www.tim.com.br
# - UUID generated at the END
# - Certificates: /etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}

info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
ok(){ printf "\e[32m[ OK ]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

require_root(){
  if [ "$EUID" -ne 0 ]; then
    err "Execute como root: sudo ./install-xray-letsencrypt.sh"
  fi
}

detect_pkgmgr(){
  if command -v apt-get >/dev/null 2>&1; then
    PKG_INSTALL="apt-get install -y --no-install-recommends"
    UPDATE_CMD="apt-get update -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_INSTALL="dnf install -y"
    UPDATE_CMD="dnf makecache"
  elif command -v yum >/dev/null 2>&1; then
    PKG_INSTALL="yum install -y"
    UPDATE_CMD="yum makecache"
  else
    err "Nenhum gerenciador de pacotes compatível encontrado (apt/dnf/yum)."
  fi
}

install_basic_deps(){
  info "Instalando dependências básicas..."
  ${UPDATE_CMD}
  $PKG_INSTALL curl wget unzip ca-certificates socat openssl lsb-release || true
  ok "Dependências básicas instaladas (ou já estavam presentes)."
}

# Xray install fallbacks (official -> jsdelivr -> release)
install_xray_official(){
  info "Tentando instalar Xray via script oficial..."
  tmpf="/tmp/xray_install_official.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmpf" "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"; then
    chmod +x "$tmpf"
    bash "$tmpf" && return 0 || return 1
  fi
  return 1
}

install_xray_jsdelivr(){
  info "Tentando instalar Xray via jsDelivr..."
  tmpf="/tmp/xray_install_jsdelivr.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmpf" "https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh"; then
    chmod +x "$tmpf"
    bash "$tmpf" && return 0 || return 1
  fi
  return 1
}

install_xray_release(){
  info "Tentando baixar release oficial do Xray (fallback)..."
  tmpzip="/tmp/xray_core.zip"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmpzip" "$url"; then
    unzip -o "$tmpzip" -d /tmp/xray_core_unpack >/dev/null 2>&1 || true
    if [ -f /tmp/xray_core_unpack/xray ]; then
      install -m 755 /tmp/xray_core_unpack/xray /usr/local/bin/xray
      ok "Xray instalado em /usr/local/bin/xray"
      return 0
    fi
    if [ -f /tmp/xray_core_unpack/Xray ]; then
      install -m 755 /tmp/xray_core_unpack/Xray /usr/local/bin/xray
      ok "Xray instalado em /usr/local/bin/xray"
      return 0
    fi
  fi
  return 1
}

install_xray_universal(){
  detect_pkgmgr
  install_basic_deps
  if install_xray_official; then ok "Xray instalado (oficial)"; return 0; fi
  warn "Instalador oficial falhou. Tentando jsDelivr..."
  if install_xray_jsdelivr; then ok "Xray instalado (jsDelivr)"; return 0; fi
  warn "jsDelivr falhou. Tentando baixar release..."
  if install_xray_release; then ok "Xray instalado (release)"; return 0; fi
  err "Falha ao instalar Xray por todos os métodos."
}

# Try to install certbot (apt or snap)
install_certbot(){
  info "Tentando instalar certbot..."
  if command -v certbot >/dev/null 2>&1; then
    ok "certbot já instalado"
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    ${UPDATE_CMD}
    # prefer snap on modern systems, but try apt first
    if apt-get install -y certbot >/dev/null 2>&1; then
      ok "certbot instalado via apt"
      return 0
    fi
    # try snap if available
    if command -v snap >/dev/null 2>&1; then
      info "Tentando instalar certbot via snap..."
      snap install core >/dev/null 2>&1 || true
      snap refresh core >/dev/null 2>&1 || true
      snap install --classic certbot >/dev/null 2>&1 || true
      ln -sf /snap/bin/certbot /usr/bin/certbot || true
      if command -v certbot >/dev/null 2>&1; then
        ok "certbot instalado via snap"
        return 0
      fi
    fi
  fi

  # fallback: try pip installer? (rare)
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install certbot >/dev/null 2>&1 || true
    if command -v certbot >/dev/null 2>&1; then
      ok "certbot instalado via pip"
      return 0
    fi
  fi

  warn "Não foi possível instalar certbot automaticamente. Você pode instalar manualmente e rodar o script novamente."
  return 1
}

# Stop common web servers on port 80 to allow standalone challenge, then restore if needed
stop_web_services_if_any(){
  # collect services to restart later
  RESTORE_SERVICES=()
  for svc in nginx apache2 httpd; do
    if systemctl is-active --quiet "$svc" >/dev/null 2>&1; then
      warn "Parando temporariamente o serviço $svc (para ACME standalone)..."
      systemctl stop "$svc" || true
      RESTORE_SERVICES+=("$svc")
    fi
  done
}

restore_web_services(){
  for svc in "${RESTORE_SERVICES[@]:-}"; do
    warn "Reiniciando $svc..."
    systemctl start "$svc" || true
  done
}

issue_cert_certbot_standalone(){
  local domain="$1"
  info "Emitindo certificado Let's Encrypt para: $domain (standalone)"
  # ensure port 80 free: stop services
  stop_web_services_if_any

  # try certbot standalone
  if ! certbot certonly --non-interactive --agree-tos --standalone -m "admin@${domain}" -d "${domain}"; then
    restore_web_services
    err "certbot falhou ao emitir certificado. Verifique DNS apontando para esta VPS e se a porta 80 está acessível."
  fi

  # certificate paths
  SSL_DIR="/etc/letsencrypt/live/${domain}"
  if [ ! -f "${SSL_DIR}/fullchain.pem" ] || [ ! -f "${SSL_DIR}/privkey.pem" ]; then
    restore_web_services
    err "Certificados não encontrados após emissão em ${SSL_DIR}"
  fi

  # set perms
  chmod 644 "${SSL_DIR}/fullchain.pem" || true
  chmod 600 "${SSL_DIR}/privkey.pem" || true

  ok "Certificado instalado em ${SSL_DIR}"
  restore_web_services
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
  systemctl daemon-reload
  systemctl enable xray >/dev/null 2>&1 || true
  ok "Systemd service criado."
}

create_logs(){
  mkdir -p /var/log/v2ray
  touch /var/log/v2ray/access.log
  chmod -R 755 /var/log/v2ray || true
  ok "Diretórios de log prontos."
}

open_firewall(){
  info "Tentando abrir portas 80 e 443 no firewall local (ufw/firewalld/iptables)..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ok "UFW atualizado."
    return
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
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
  SSL_DIR="/etc/letsencrypt/live/${domain}"
  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/config.json <<EOF
{
  "api": { "services": ["HandlerService","LoggerService","StatsService"], "tag": "api" },
  "dns": { "servers": ["94.140.14.14","94.140.15.15"], "queryStrategy": "UseIPv4" },
  "inbounds": [
    {
      "tag": "api",
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "tag": "inbound-sshorizon",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          { "email": "client@${domain}", "id": "${uuid}", "level": 0 }
        ],
        "decryption": "none",
        "fallbacks": []
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": "${SSL_DIR}/fullchain.pem", "keyFile": "${SSL_DIR}/privkey.pem" }
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
    "levels": { "0": { "statsUserDownlink": true, "statsUserOnline": true, "statsUserUplink": true } },
    "system": { "statsInboundDownlink": true, "statsInboundUplink": true }
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
  ok "Arquivo de configuração criado."
}

check_listen_443(){
  sleep 1
  if ss -tulpn | grep -q ":443"; then
    ok "Processo escutando em 443."
    return 0
  else
    warn "Nenhum processo escutando em 443."
    return 1
  fi
}

main(){
  require_root

  echo
  echo "==============================================="
  echo "       Instalador Xray (XHTTP + TLS + 443)"
  echo "==============================================="
  echo

  read -rp "Digite o domínio (host) que será usado no VLESS (ex: righi.azion.app): " DOMAIN
  DOMAIN="${DOMAIN:-}"
  if [ -z "$DOMAIN" ]; then err "Domínio obrigatório."; fi

  PKG_OK=0
  detect_pkgmgr
  install_basic_deps

  # open firewall ports so ACME can use 80
  open_firewall

  # install xray
  install_xray_universal

  # create logs & service skeleton (config will be created after cert + uuid)
  create_logs
  create_systemd_service

  # install certbot and request cert
  if install_certbot; then
    issue_cert_certbot_standalone "$DOMAIN"
  else
    err "Não foi possível instalar certbot automaticamente. Instale certbot manualmente e execute novamente."
  fi

  # generate UUID now that Xray binary should exist
  if command -v xray >/dev/null 2>&1; then
    UUID="$(xray uuid 2>/dev/null || true)"
  fi
  if [ -z "${UUID:-}" ]; then
    if command -v uuidgen >/dev/null 2>&1; then
      UUID="$(uuidgen)"
    else
      UUID="$(cat /proc/sys/kernel/random/uuid)"
    fi
  fi
  ok "UUID gerado: $UUID"

  # create config with generated uuid and cert paths
  create_xray_config "$UUID" "$DOMAIN"

  # start/restart service
  systemctl restart xray || true
  sleep 1

  if ! check_listen_443; then
    warn "Xray pode não estar escutando em 443 — verifique logs (journalctl -u xray -n 200)"
  fi

  # final VLESS link
  SNI="www.tim.com.br"
  VLESS="vless://${UUID}@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=${DOMAIN}&path=%2F&sni=${SNI}&allowInsecure=1#Tim-BR"

  echo
  echo "==============================================="
  echo " INSTALAÇÃO CONCLUÍDA"
  echo "==============================================="
  echo "UUID: $UUID"
  echo "Domínio: $DOMAIN"
  echo
  echo "Link VLESS pronto:"
  echo
  echo "$VLESS"
  echo
  echo "Se algo falhar, veja logs:"
  echo "  journalctl -u xray -n 200 --no-pager"
  echo
}

main
