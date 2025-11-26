#!/usr/bin/env bash
# ================================================
# Xray VLESS + xHttp + TLS + Proxy TIM/Azion 2025
# ================================================

# --- CONFIGURAÇÃO DE SEGURANÇA DESATIVADA PARA EVITAR CRASH NO MENU ---
# set -euo pipefail

BREED="vray-installer-local"
SNI_FIXED="www.tim.com.br"
PROXY_HOST="m.ofertas.tim.com.br"
SSL_DIR="/opt/sshorizon/ssl"
XRAY_BIN_PATH="/usr/local/bin/xray"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="${XRAY_CONFIG_DIR}/config.json"
USER_DB="${XRAY_CONFIG_DIR}/users.json"

# Cores
INFO="\e[34m[INFO]\e[0m"
OK="\e[32m[OK]\e[0m"
WARN="\e[33m[WARN]\e[0m"
ERR="\e[31m[ERR]\e[0m"
RESET="\e[0m"

info() { echo -e "${INFO} $*" ; }
ok()   { echo -e "${OK} $*" ; }
warn() { echo -e "${WARN} $*" ; }
err()  { echo -e "${ERR} $*"; exit 1; }

require_root() {
  [[ "$EUID" -eq 0 ]] || err "Execute como root: sudo bash $0"
}

# ====================== FUNÇÕES AUXILIARES ======================

install_deps() {
  echo -e "${INFO} Instalando dependências...${RESET}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y curl wget unzip ca-certificates openssl socat iptables jq
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl wget unzip ca-certificates openssl socat iptables jq
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget unzip ca-certificates openssl socat iptables jq
  fi
  ok "Dependências verificadas"
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    ok "Xray já instalado"
    return
  fi

  info "Instalando Xray..."
  bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 || \
  bash <(curl -Ls https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh) >/dev/null 2>&1
  
  if command -v xray >/dev/null 2>&1; then
      ok "Xray instalado"
  else
      curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
      unzip -o /tmp/xray.zip xray -d /tmp
      install -m 755 /tmp/xray /usr/local/bin/xray
      rm -f /tmp/xray.zip /tmp/xray
      ok "Xray instalado manualmente"
  fi
}

generate_self_signed_cert() {
  local domain="$1"
  info "Gerando certificado para $domain..."
  mkdir -p "$SSL_DIR"
  openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -keyout "$SSL_DIR/privkey.pem" \
    -out "$SSL_DIR/fullchain.pem" \
    -subj "/CN=${domain}" 2>/dev/null
  chmod 600 "$SSL_DIR/privkey.pem"
  ok "Certificado gerado"
}

create_systemd_service() {
  info "Criando serviço systemd..."
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=$XRAY_BIN_PATH run -config $XRAY_CONFIG_PATH
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray --now &>/dev/null || true
  ok "Serviço criado e ativado"
}

open_ports() {
  info "Abrindo portas 80/443..."
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
  ok "Portas liberadas"
}

create_menu_shortcut() {
  info "Criando atalho global 'menu'..."
  
  # Verificação se o script está rodando de um arquivo físico
  if [[ ! -f "$0" ]]; then
      echo -e "\e[31m[ERRO] Não foi possível criar o comando 'menu' automaticamente.\e[0m"
      echo -e "\e[33mMOTIVO: O script foi executado diretamente da memória (pipe ou copy-paste).\e[0m"
      echo -e "SOLUÇÃO: Salve este script em um arquivo (ex: install.sh) e execute: sudo bash install.sh"
      return
  fi

  local script_path
  script_path=$(readlink -f "$0")
  cp "$script_path" /usr/local/bin/menu
  chmod +x /usr/local/bin/menu
  
  # Limpa duplicatas no bashrc antes de adicionar
  sed -i '/gerenciador do Xray/d' /root/.bashrc
  sed -i '/Digite menu para/d' /root/.bashrc
  sed -i '/=====/d' /root/.bashrc

  cat >> /root/.bashrc <<EOF

echo -e "\e[34m========================================================\e[0m"
echo -e "\e[32m  >>> Digite \e[1mmenu\e[0m \e[32mpara acessar o gerenciador do Xray <<<\e[0m"
echo -e "\e[34m========================================================\e[0m"
EOF
  ok "Comando 'menu' configurado!"
}

# ====================== GERENCIAMENTO DE USUÁRIOS ======================
init_user_db() {
  mkdir -p "$XRAY_CONFIG_DIR"
  [[ -f "$USER_DB" ]] || echo '{"users": []}' > "$USER_DB"
  chmod 600 "$USER_DB"
}

add_user() {
  local name="$1"
  local days="${2:-30}"
  local uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)"
  if [[ ${#uuid} -ne 36 ]]; then uuid=$(uuidgen 2>/dev/null); fi
  
  local email="${name}@$(hostname)"
  local expiry=$(( $(date +%s) + days*86400 ))

  init_user_db

  tmp=$(mktemp)
  jq --arg email "$email" 'del(.users[] | select(.email == $email))' "$USER_DB" > "$tmp" && mv "$tmp" "$USER_DB"

  tmp=$(mktemp)
  jq --arg uuid "$uuid" --arg email "$email" --arg name "$name" --argjson expiry "$expiry" \
     '.users += [{uuid: $uuid, email: $email, name: $name, expiry: $expiry, enabled: true}]' \
     "$USER_DB" > "$tmp" && mv "$tmp" "$USER_DB"
  
  ok "Usuário '$name' criado. Expira em $days dias."
  update_xray_clients
  reload_xray
}

list_users() {
  init_user_db
  echo -e "\n${OK} Usuários cadastrados:${RESET}"
  echo "──────────────────────────────────────────────────────────────"
  printf "%-15s %-12s %-13s %s\n" "NOME" "UUID" "EXPIRA" "STATUS"
  echo "──────────────────────────────────────────────────────────────"
  if jq -e '.users | length > 0' "$USER_DB" >/dev/null 2>&1; then
    jq -r '.users[] | [.name // "N/A", (.uuid[0:8] + "..."), (if .expiry then (.expiry | strftime("%d/%m/%Y")) else "Nunca" end), (if .enabled then "ATIVO" else "INATIVO" end)] | @tsv' "$USER_DB" |
      while IFS=$'\t' read -r name shortuuid expiry status; do
        color=$([[ "$status" == "ATIVO" ]] && echo "\e[32m" || echo "\e[31m")
        printf "%-15s ${color}%-12s %-13s %-8s${RESET}\n" "$name" "$shortuuid" "$expiry" "$status"
      done
  else
    echo "Nenhum usuário cadastrado."
  fi
  echo "──────────────────────────────────────────────────────────────"
}

remove_user() {
  local search="$1"
  init_user_db
  local count=$(jq --arg name "$search" '[.users[] | select(.name == $name or .email | test($name)) ] | length' "$USER_DB" 2>/dev/null || echo 0)
  if [[ $count -eq 0 ]]; then
      warn "Usuário '$search' não encontrado"
      return
  fi
  tmp=$(mktemp)
  jq --arg name "$search" 'del(.users[] | select(.name == $name or .email | test($name)))' "$USER_DB" > "$tmp" && mv "$tmp" "$USER_DB"
  ok "Usuário removido"
  update_xray_clients
  reload_xray
}

update_xray_clients() {
  [[ ! -f "$XRAY_CONFIG_PATH" ]] && return
  init_user_db
  local now=$(date +%s)
  
  local active_users=$(jq -c --argjson now "$now" '[.users[] | select(.enabled and (.expiry == null or .expiry > $now)) | {id: .uuid, email: .email, level: 0}]' "$USER_DB" 2>/dev/null)
  [[ -z "$active_users" ]] && active_users="[]"

  tmp=$(mktemp)
  jq --argjson clients "$active_users" '
    .inbounds |= map(
      if .tag == "inbound-sshorizon" then
        .settings.clients = $clients
      else . end
    )
  ' "$XRAY_CONFIG_PATH" > "$tmp" && mv "$tmp" "$XRAY_CONFIG_PATH"
  
  ok "Config atualizada com usuários"
}

reload_xray() {
  info "Recarregando Xray..."
  systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null || true
  sleep 1
}

generate_vless_link() {
  local uuid="$1"
  local domain="$2"
  echo "vless://$uuid@$PROXY_HOST:443?type=xhttp&security=tls&encryption=none&host=$domain&path=%2F&sni=$SNI_FIXED&allowInsecure=1#Tim-BR-$domain"
}

create_base_config() {
  local domain="$1"
  info "Criando config base..."
  mkdir -p "$XRAY_CONFIG_DIR"
  cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "api": { "services": [ "HandlerService", "LoggerService", "StatsService" ], "tag": "api" },
  "dns": { "servers": [ "1.1.1.1", "8.8.8.8" ] },
  "inbounds": [
    {
      "tag": "api", "port": 1080, "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }, "listen": "127.0.0.1"
    },
    {
      "tag": "inbound-sshorizon", "port": 443, "listen": "0.0.0.0", "protocol": "vless",
      "settings": { "clients": [], "decryption": "none", "fallbacks": [] },
      "streamSettings": {
        "network": "xhttp", "security": "tls",
        "tlsSettings": {
          "certificates": [ { "certificateFile": "${SSL_DIR}/fullchain.pem", "keyFile": "${SSL_DIR}/privkey.pem" } ],
          "alpn": [ "http/1.1" ]
        },
        "xhttpSettings": { "path": "/", "scMaxBufferedPosts": 30 }
      }
    }
  ],
  "log": { "loglevel": "warning", "access": "/var/log/v2ray/access.log", "error": "/var/log/v2ray/error.log" },
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "blocked" } ],
  "policy": { "levels": { "0": { "statsUserDownlink": true, "statsUserUplink": true } }, "system": { "statsInboundDownlink": true, "statsInboundUplink": true } },
  "routing": { "domainStrategy": "AsIs", "rules": [ { "inboundTag": [ "api" ], "outboundTag": "api", "type": "field" } ] }
}
EOF
  mkdir -p /var/log/v2ray
  ok "Config base criada"
}

# ====================== MENU PRINCIPAL ======================
show_menu() {
  while true; do
    clear
    echo -e "\e[34m══════════════════════════════════════════════════\e[0m"
    echo -e "     GERENCIADOR XRAY + XHTTP + TIM PROXY AZION    "
    echo -e "\e[34m══════════════════════════════════════════════════\e[0m"
    echo
    echo "1) Adicionar usuário"
    echo "2) Listar usuários"
    echo "3) Remover usuário"
    echo "4) Gerar link de um usuário"
    echo "5) Atualizar configuração (reload)"
    echo "6) Reinstalar/Criar atalho menu"
    echo
    echo "0) Sair"
    echo
    read -p "Escolha uma opção: " opt
    case $opt in
      1) echo -e "${INFO} Adicionando usuário...${RESET}"
         read -p "Nome do usuário: " nome
         if [[ -n "$nome" ]]; then
             read -p "Dias de validade (padrão 30): " dias
             add_user "$nome" "${dias:-30}"
         else
             warn "Nome inválido"
         fi
         read -p "Enter para continuar..." ;;
      2) list_users
         read -p "Enter para continuar..." ;;
      3) echo -e "${INFO} Removendo usuário...${RESET}"
         read -p "Nome ou parte do nome/email: " nome
         [[ -n "$nome" ]] && remove_user "$nome"
         read -p "Enter para continuar..." ;;
      4) echo -e "${INFO} Gerando link...${RESET}"
         read -p "Nome do usuário: " nome
         if [[ -z "$nome" ]]; then warn "Nome obrigatório"; read -p "Enter..."; continue; fi
         
         uuid=$(jq -r --arg n "$nome" '.users[] | select(.name==$n) | .uuid' "$USER_DB" 2>/dev/null | head -n1 || echo "")
         
         if [[ -n "$uuid" ]]; then
           domain=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -subject 2>/dev/null | sed -n 's/^.*CN=\([^/]*\).*$/\1/p' || echo "")
           [[ -z "$domain" ]] && domain="seu.dominio.azion.app"
           
           link=$(generate_vless_link "$uuid" "$domain")
           echo -e "\n${OK}Link VLESS pronto:${RESET}\n"
           echo "$link"
           echo
         else
           warn "Usuário '$nome' não encontrado (verifique maiúsculas/minúsculas)"
         fi
         read -p "Enter para continuar..." ;;
      5) update_xray_clients; reload_xray
         read -p "Enter para continuar..." ;;
      6) create_menu_shortcut
         read -p "Enter para continuar..." ;;
      0) echo "Saindo..."; exit 0 ;;
      *) warn "Opção inválida" ; sleep 1 ;;
    esac
  done
}

# ====================== MAIN ======================
if [[ "$(basename "$0")" == "menu" || "${1:-}" == "manage" || ( -z "${1:-}" && -f "$XRAY_CONFIG_PATH" ) ]]; then
  init_user_db
  show_menu
else
  install_full() {
    require_root
    clear
    echo -e "\e[34mInstalação Xray + xhttp + proxy TIM\e[0m\n"

    read -p "Digite seu subdomínio (ex: meu): " sub
    [[ -z "$sub" ]] && err "Subdomínio obrigatório"
    DOMAIN="${sub}.azion.app"
    info "Usando domínio: $DOMAIN"

    install_deps
    install_xray
    generate_self_signed_cert "$DOMAIN"
    create_base_config "$DOMAIN"
    create_systemd_service
    open_ports
    init_user_db
    create_menu_shortcut

    read -p "Nome do primeiro usuário: " firstuser
    [[ -z "$firstuser" ]] && firstuser="usuario1"
    add_user "$firstuser" "30"

    echo -e "\n${OK}INSTALAÇÃO CONCLUÍDA!${RESET}\n"
    uuid=$(jq -r '.users[0].uuid' "$USER_DB" | head -n1)
    link=$(generate_vless_link "$uuid" "$DOMAIN")
    echo "Link VLESS:"
    echo "$link"
    echo -e "\nDigite 'menu' para gerenciar."
    exit 0
  }
  install_full
fi
