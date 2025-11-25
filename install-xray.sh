#!/usr/bin/env bash
set -euo pipefail

# install.sh
# Instalador Xray para Azion/Cloudflare (Modo HTTP Porta 80)
# - Corrige erro de permissão de logs
# - Sem bloqueios (Torrent liberado)
# - Configura VLESS via XHTTP (Splithttp)

BREED="vray-installer-http-v2"
SNI_FIXED="www.tim.com.br"
XRAY_BIN_PATH="/usr/local/bin/xray"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="${XRAY_CONFIG_DIR}/config.json"

# Helper functions
info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
ok(){ printf "\e[32m[OK]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

require_root(){
  if [ "$EUID" -ne 0 ]; then
    err "Execute como root: sudo ./install.sh"
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
    err "Nenhum gerenciador de pacotes compatível."
  fi
}

install_deps(){
  info "Instalando dependências..."
  ${UPDATE_CMD}
  $PKG_INST curl wget unzip ca-certificates openssl iptables || true
  # Tenta instalar iptables-persistent se for debian/ubuntu para salvar regras
  if command -v apt-get >/dev/null 2>&1; then
     DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent || true
  fi
}

install_xray_universal(){
  info "Instalando Xray (versão oficial)..."
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || \
  bash -c "$(curl -L https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh)" @ install
  
  if [ -f "$XRAY_BIN_PATH" ]; then
    ok "Xray instalado com sucesso."
  else
    err "Falha na instalação do Xray."
  fi
}

fix_log_permissions(){
  info "Ajustando permissões de log..."
  mkdir -p /var/log/xray
  touch /var/log/xray/access.log
  touch /var/log/xray/error.log
  # Libera permissão total para evitar erro de 'permission denied' independente do usuário do serviço
  chmod -R 777 /var/log/xray
  ok "Permissões de log corrigidas."
}

create_xray_config(){
  local uuid="$1"
  local domain="$2"
  mkdir -p "$XRAY_CONFIG_DIR"
  
  # Configuração SEM bloqueios de routing e na porta 80
  cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "api": {
    "services": [ "HandlerService", "LoggerService", "StatsService" ],
    "tag": "api"
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
      "port": 80,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "user@${domain}",
            "id": "${uuid}",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": []
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
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
    "access": "/var/log/xray/access.log",
    "dnsLog": false,
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
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
      { "inboundTag": [ "api" ], "outboundTag": "api", "type": "field" }
    ]
  }
}
EOF
  ok "Configuração criada (Porta 80 / HTTP)."
}

open_firewall(){
  info "Liberando porta 80 no firewall..."
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
  fi
  ok "Firewall atualizado."
}

main(){
  require_root
  echo "==============================================="
  echo "    Instalador Xray - Modo Azion (Porta 80)"
  echo "==============================================="
  
  read -rp "Digite o subdomínio Azion (ex: meuserver): " SUB
  if [ -z "$SUB" ]; then err "Subdomínio obrigatório."; fi
  DOMAIN="${SUB}.azion.app"

  detect_pkgmgr
  install_deps
  install_xray_universal

  # Gera UUID
  UUID="$(xray uuid)"
  
  # Cria config e corrige permissões
  create_xray_config "$UUID" "$DOMAIN"
  fix_log_permissions
  open_firewall

  info "Reiniciando serviço..."
  systemctl restart xray
  sleep 2
  
  if systemctl is-active --quiet xray; then
    ok "Xray rodando!"
  else
    err "Xray falhou ao iniciar. Logs abaixo:\n$(journalctl -u xray -n 20 --no-pager)"
  fi

  # Link final
  # Nota: Na URL cliente usamos 443 e TLS, pois a Azion faz o SSL na frente.
  VLESS="vless://${UUID}@${DOMAIN}:443?type=xhttp&security=tls&encryption=none&host=${DOMAIN}&path=%2F&sni=${SNI_FIXED}&allowInsecure=1#Azion-VLESS"

  echo
  echo "==============================================="
  echo " INSTALAÇÃO CONCLUÍDA"
  echo "==============================================="
  echo "UUID: $UUID"
  echo "Domínio: $DOMAIN"
  echo "Porta Servidor: 80 (HTTP)"
  echo "Porta Cliente: 443 (HTTPS via Azion)"
  echo
  echo "Link de Importação:"
  echo "$VLESS"
  echo "==============================================="
}

main "$@"
