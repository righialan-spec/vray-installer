#!/usr/bin/env bash
# ================================================
# Xray VLESS + xHttp + TLS + Proxy TIM/Azion 2025
# ================================================

# Configurações de Pastas
BREED="vray-installer-local"
SNI_FIXED="www.tim.com.br"
PROXY_HOST="m.ofertas.tim.com.br"
SSL_DIR="/opt/sshorizon/ssl"
MANAGER_PATH="/opt/sshorizon/manager.sh"
# URL oficial do seu script (necessário para instalação via curl)
SCRIPT_URL="https://raw.githubusercontent.com/righialan-spec/vray-installer/main/install.sh"

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

# ====================== FUNÇÕES DE INSTALAÇÃO ======================

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
  
  if ! command -v xray >/dev/null 2>&1; then
      curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
      unzip -o /tmp/xray.zip xray -d /tmp
      install -m 755 /tmp/xray /usr/local/bin/xray
      rm -f /tmp/xray.zip /tmp/xray
  fi
  ok "Xray instalado"
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
}

open_ports() {
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
}

# ====================== SISTEMA DE MENU ROBUSTO ======================
create_menu_shortcut() {
  info "Configurando comando 'menu'..."
  mkdir -p /opt/sshorizon
  
  # Lógica principal de detecção e download
  if [[ -f "${BASH_SOURCE[0]}" ]]; then
      # Se for executado de um arquivo local, copia ele
      cp "${BASH_SOURCE[0]}" "$MANAGER_PATH"
  else
      # Se for executado via pipe (curl | bash), baixa do GitHub
      info "Instalação via rede detectada. Baixando gerenciador..."
      curl -sL "$SCRIPT_URL" -o "$MANAGER_PATH"
  fi
  
  # Verifica se o arquivo foi criado corretamente
  if [[ ! -s "$MANAGER_PATH" ]]; then
      warn "Falha ao criar $MANAGER_PATH. Tentando método alternativo..."
      wget -qO "$MANAGER_PATH" "$SCRIPT_URL"
  fi

  if [[ -s "$MANAGER_PATH" ]]; then
      chmod +x "$MANAGER_PATH"
      
      # Cria o atalho
      cat > /usr/bin/menu <<EOF
#!/bin/bash
bash $MANAGER_PATH manage
EOF
      chmod +x /usr/bin/menu
      
      # Aviso no login
      if ! grep -q "Para acessar o gerenciador" /root/.bashrc; then
        cat >> /root/.bashrc <<EOF

echo -e "\e[34m========================================================\e[0m"
echo -e "\e[32m  >>> Digite \e[1mmenu\e[0m \e[32mpara acessar o gerenciador do Xray <<<\e[0m"
echo -e "\e[34m========================================================\e[0m"
EOF
      fi
      ok "Comando 'menu' instalado com sucesso!"
  else
      err "Não foi possível baixar o script do gerenciador. Verifique sua conexão ou a URL do script."
  fi
}

# ====================== GERENCIAMENTO DE DADOS ======================
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
  
  ok "Usuário '$name' criado."
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
  if [[ $count -eq 0 ]]; then warn "Usuário '$search' não encontrado"; return; fi
  
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
    .inbounds |= map(if .tag == "inbound-sshorizon" then .settings.clients = $clients else . end)
  ' "$XRAY_CONFIG_PATH" > "$tmp" && mv "$tmp" "$XRAY_CONFIG_PATH"
  ok "Config atualizada"
}

reload_xray() {
  systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null || true
}

generate_vless_link() {
  local uuid="$1"
  local domain="$2"
  echo "vless://$uuid@$PROXY_HOST:443?type=xhttp&security=tls&encryption=none&host=$domain&path=%2F&sni=$SNI_FIXED&allowInsecure=1#Tim-BR-$domain"
}

create_base_config() {
  local domain="$1"
  mkdir -p "$XRAY_CONFIG_DIR"
  cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "api": { "services": [ "HandlerService", "LoggerService", "StatsService" ], "tag": "api" },
  "dns": { "servers": [ "1.1.1.1", "8.8.8.8" ] },
  "inbounds": [
    {
      "tag": "api", "port": 1080, "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1" }, "listen": "127.0.0.1"
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
}

# ====================== MENU ======================
show_menu() {
  while true; do
    clear
    echo -e "\e[34m══════════════════════════════════════════════════\e[0m"
    echo -e "     GERENCIADOR XRAY + XHTTP + TIM PROXY AZION    "
    echo -e "\e[34m══════════════════════════════════════════════════\e[0m"
    echo "1) Adicionar usuário"
    echo "2) Listar usuários"
    echo "3) Remover usuário"
    echo "4) Gerar link VLESS"
    echo "5) Atualizar (Reload)"
    echo "6) Recriar atalho 'menu'"
    echo "0) Sair"
    echo
    read -p "Opção: " opt
    case $opt in
      1) read -p "Nome: " nome; [[ -n "$nome" ]] && read -p "Dias (30): " d && add_user "$nome" "${d:-30}"; read -p "Enter..." ;;
      2) list_users; read -p "Enter..." ;;
      3) read -p "Nome: " n; [[ -n "$n" ]] && remove_user "$n"; read -p "Enter..." ;;
      4) read -p "Nome: " n
         [[ -z "$n" ]] && { echo "Nome vazio"; read -p "Enter..."; continue; }
         uuid=$(jq -r --arg n "$n" '.users[] | select(.name==$n) | .uuid' "$USER_DB" 2>/dev/null | head -n1 || echo "")
         if [[ -n "$uuid" ]]; then
           domain=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -subject 2>/dev/null | sed -n 's/^.*CN=\([^/]*\).*$/\1/p' || echo "")
           [[ -z "$domain" ]] && domain="seu.dominio.azion.app"
           echo -e "\n${OK} Link:\n"
           generate_vless_link "$uuid" "$domain"
           echo
         else
           warn "Não encontrado"
         fi
         read -p "Enter..." ;;
      5) update_xray_clients; reload_xray; read -p "Enter..." ;;
      6) create_menu_shortcut; read -p "Enter..." ;;
      0) exit 0 ;;
      *) echo "Inválido"; sleep 1 ;;
    esac
  done
}

# ====================== EXECUÇÃO ======================
if [[ "$1" == "manage" ]]; then
  init_user_db
  show_menu
else
  # Instalação
  require_root
  clear
  echo -e "\e[34m>>> INSTALANDO... \e[0m"
  
  read -p "Subdomínio Azion (ex: meuapp): " sub
  [[ -z "$sub" ]] && err "Necessário subdomínio"
  DOMAIN="${sub}.azion.app"
  
  install_deps
  install_xray
  generate_self_signed_cert "$DOMAIN"
  create_base_config "$DOMAIN"
  create_systemd_service
  open_ports
  init_user_db
  
  # Cria o comando menu de forma segura
  create_menu_shortcut
  
  # Usuário padrão
  add_user "admin" "30"
  
  echo -e "\n${OK} Instalação finalizada!"
  echo -e "Digite: \e[1;32mmenu\e[0m para gerenciar."
fi
