#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# install-xray.sh — Instalador Universal (ACME standalone) Xray XHTTP+TLS
# - Inbound internal: 1080 (dokodemo)
# - External: 443 (vless xhttp tls)
# - SNI fixed: www.tim.com.br
# - UUID: auto (or manual)
# Notes: requires domain DNS pointed to this VPS and port 80 reachable.

# ---------- Helpers ----------
info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
ok(){ echo -e "\e[32m[OK]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERR]\e[0m $*"; exit 1; }

require_cmd(){
  command -v "$1" >/dev/null 2>&1 || err "Comando '$1' não encontrado. Instale-o e rode de novo."
}

# ---------- Detect distro ----------
detect_pkgmgr(){
  if command -v apt-get >/dev/null 2>&1; then
    PKG_INSTALL="apt-get install -y"
    UPDATE_CMD="apt-get update -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_INSTALL="dnf install -y"
    UPDATE_CMD="dnf makecache"
  elif command -v yum >/dev/null 2>&1; then
    PKG_INSTALL="yum install -y"
    UPDATE_CMD="yum makecache"
  else
    err "Nenhum gerenciador de pacotes compatível encontrado (apt/yum/dnf)."
  fi
}

# ---------- Basic deps ----------
install_basic_deps(){
  info "Instalando dependências básicas (curl, socat, unzip, jq se precisar)..."
  ${UPDATE_CMD}
  $PKG_INSTALL curl socat unzip wget ca-certificates openssl
  # jq optional (not required unless future features)
  command -v jq >/dev/null 2>&1 || $PKG_INSTALL jq || true
  ok "Dependências instaladas."
}

# ---------- Xray install (3 fallbacks) ----------
install_xray_official(){
  info "Tentando instalar Xray (script oficial)..."
  # prefer download to file and execute to avoid process substitution issues
  local tmp="/tmp/xray_install_official.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmp" "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"; then
    chmod +x "$tmp"
    bash "$tmp" || return 1
    return 0
  fi
  return 1
}

install_xray_jsdelivr(){
  info "Tentando instalar Xray via jsDelivr..."
  local tmp="/tmp/xray_install_jsdelivr.sh"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmp" "https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh"; then
    chmod +x "$tmp"
    bash "$tmp" || return 1
    return 0
  fi
  return 1
}

install_xray_release(){
  info "Tentando instalar Xray baixando release (fallback)..."
  ARCH="linux-64"
  # try known asset name: Xray-linux-64.zip (works for many releases)
  local tmpzip="/tmp/xray_core.zip"
  local url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
  if curl -A "Mozilla/5.0" -fsSL -o "$tmpzip" "$url"; then
    unzip -o "$tmpzip" -d /tmp/xray_core_unpack
    # expected binaries inside: xray or Xray; find it
    if [ -f /tmp/xray_core_unpack/xray ] || [ -f /tmp/xray_core_unpack/Xray ]; then
      local bin=""
      if [ -f /tmp/xray_core_unpack/xray ]; then bin="/tmp/xray_core_unpack/xray"; fi
      if [ -f /tmp/xray_core_unpack/Xray ]; then bin="/tmp/xray_core_unpack/Xray"; fi
      install -m 755 "$bin" /usr/local/bin/xray
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
  warn "Instalador oficial falhou, tentando jsDelivr..."
  if install_xray_jsdelivr; then ok "Xray instalado (jsDelivr)"; return 0; fi
  warn "jsDelivr falhou, tentando baixar release..."
  if install_xray_release; then ok "Xray instalado (release)"; return 0; fi
  err "Falha ao instalar Xray por todos os métodos."
}

# ---------- ACME.sh install and issue (standalone) ----------
install_acme_sh(){
  info "Instalando acme.sh..."
  # use official installer
  if curl -fsSL "https://get.acme.sh" -o /tmp/acme_install.sh; then
    bash /tmp/acme_install.sh --auto-upgrade >/dev/null 2>&1 || true
  else
    err "Falha ao baixar acme.sh"
  fi
  # source acme
  if [ -f "$HOME/.acme.sh/acme.sh.env" ]; then
    # shellcheck disable=SC1090
    source "$HOME/.acme.sh/acme.sh.env"
  fi
  ok "acme.sh instalado."
}

issue_cert_standalone(){
  local domain="$1"
  info "Emitindo certificado ACME (standalone) para: $domain"
  mkdir -p "$SSL_DIR"
  # stop any service listening on 80 temporarily? we warn user instead
  # issue
  if ! "$HOME/.acme.sh"/acme.sh --issue -d "$domain" --standalone --force; then
    err "Falha ao emitir certificado ACME. Verifique DNS e se a porta 80 está apontando para esta VPS."
  fi
  "$HOME/.acme.sh"/acme.sh --install-cert -d "$domain" \
    --key-file "$SSL_DIR/privkey.pem" \
    --fullchain-file "$SSL_DIR/fullchain.pem" \
    --reloadcmd "systemctl restart xray" >/dev/null 2>&1 || true
  chmod 600 "$SSL_DIR/privkey.pem" || true
  chmod 644 "$SSL_DIR/fullchain.pem" || true
  ok "Certificado instalado em $SSL_DIR"
}

# ---------- create systemd service ----------
create_systemd_service(){
  info "Criando service systemd para xray..."
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
  ok "Service criado."
}

# ---------- create xray config ----------
create_xray_config(){
  local uuid="$1"
  local domain="$2"

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
  ok "Config /usr/local/etc/xray/config.json criado."
}

# ---------- logs dir ----------
create_logs(){
  mkdir -p /var/log/v2ray
  touch /var/log/v2ray/access.log
  chmod -R 755 /var/log/v2ray
  ok "Diretórios de log configurados."
}

# ---------- firewall open ----------
open_firewall_ports(){
  info "Tentando abrir portas 80 e 443 no firewall local (ufw/firewalld/iptables)..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
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

# ---------- check listen ----------
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

# ---------- main ----------
main(){
  if [ "$EUID" -ne 0 ]; then
    err "Execute como root: sudo ./install-xray.sh"
  fi

  # interactive prompts
  echo
  read -rp "Digite o domínio (host) que será usado no VLESS (ex: righi.azion.app): " DOMAIN
  DOMAIN="${DOMAIN:-}"
  if [ -z "$DOMAIN" ]; then err "Domínio obrigatório."; fi

  read -rp "Gerar UUID automático? (S/n): " USE_AUTO
  USE_AUTO="${USE_AUTO:-s}"

  # prepare dirs
  SSL_DIR="/opt/sshorizon/ssl"
  mkdir -p "$SSL_DIR"
  chmod 755 /opt/sshorizon || true
  chmod 755 "$SSL_DIR" || true

  # install xray (universal)
  install_xray_universal

  # now we have xray binary (hopefully). Generate UUID via xray or fallback uuidgen
  if command -v xray >/dev/null 2>&1; then
    if [[ "$USE_AUTO" =~ ^(s|S|y|Y|)$ ]]; then
      UUID="$(xray uuid 2>/dev/null || true)"
    else
      read -rp "Digite o UUID desejado: " UUID
    fi
  else
    warn "xray não encontrado para gerar uuid; usando uuidgen se disponível."
    if [[ "$USE_AUTO" =~ ^(s|S|y|Y|)$ ]]; then
      if command -v uuidgen >/dev/null 2>&1; then
        UUID="$(uuidgen)"
      else
        # fallback to random
        UUID="$(cat /proc/sys/kernel/random/uuid)"
      fi
    else
      read -rp "Digite o UUID desejado: " UUID
    fi
  fi

  if [[ -z "$UUID" ]]; then err "UUID inválido."; fi
  ok "UUID: $UUID"

  create_logs
  create_systemd_service

  # install acme.sh and issue cert
  install_acme_sh

  # open firewall ports for ACME challenge
  open_firewall_ports

  issue_cert_standalone "$DOMAIN"

  # ensure permissions
  chown root:root "$SSL_DIR"/* || true
  chmod 644 "$SSL_DIR"/fullchain.pem || true
  chmod 600 "$SSL_DIR"/privkey.pem || true

  # create config and start service
  create_xray_config "$UUID" "$DOMAIN"

  systemctl restart xray || true
  sleep 1

  if ! check_listen_443; then
    warn "Xray não está escutando em 443. Verifique logs: journalctl -u xray -n 50"
  fi

  # final VLESS link
  SNI="www.tim.com.br"
  VLESS="vless://${UUID}@m.ofertas.tim.com.br:443?type=xhttp&security=tls&encryption=none&host=${DOMAIN}&path=%2F&sni=${SNI}&allowInsecure=1#Tim-BR"

  echo
  echo "==============================================="
  echo " INSTALAÇÃO FINALIZADA"
  echo "==============================================="
  echo "UUID: $UUID"
  echo "Domínio (host): $DOMAIN"
  echo
  echo "Link VLESS gerado:"
  echo
  echo "$VLESS"
  echo
  echo "Se algo falhar, veja logs com: journalctl -u xray -n 200"
  echo "==============================================="
}

# run
main
