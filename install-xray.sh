#!/usr/bin/env bash
set -euo pipefail

BREED="vray-installer-local"
SNI_FIXED="www.tim.com.br"
PROXY_HOST="m.ofertas.tim.com.br"   # Seu proxy fixo que fala com Azion
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

# ====================== INSTALAÇÃO XRAY ======================
install_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y curl wget unzip ca-certificates openssl socat iptables
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl wget unzip ca-certificates openssl socat iptables
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget unzip ca-certificates openssl socat iptables
  fi
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    ok "Xray já instalado ($(xray -version | head -n1))"
    return
  fi

  info "Instalando Xray..."
  bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1 || \
  bash <(curl -Ls https://cdn.jsdelivr.net/gh/XTLS/Xray-install/install-release.sh) >/dev/null 2>&1 || \
  { curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip -o /tmp/xray.zip xray -d /tmp && install -m 755 /tmp/xray /usr/local/bin/xray; }

  [[ -f "$XRAY_BIN_PATH" ]] && ok "Xray instalado com sucesso" || err "Falha ao instalar Xray"
}

generate_self_signed_cert() {
  local domain="$1"
  mkdir -p "$SSL_DIR"
  openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -keyout "$SSL_DIR/privkey.pem" \
    -out "$SSL_DIR/fullchain.pem" \
    -subj "/CN=${domain}" >/dev/null 2>&1
  chmod 600 "$SSL_DIR/privkey.pem"
  ok "Certificado autoassinado gerado para $domain"
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
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80,443/tcp &>/dev/null || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --add-port=80/tcp --add-port=443/tcp --permanent &>/dev/null || true
    firewall-cmd --reload &>/dev/null || true
  fi
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
}

# ====================== GERENCIAMENTO DE USUÁRIOS ======================
init_user_db() {
  mkdir -p "$XRAY_CONFIG_DIR"
  [[ -f "$USER_DB" ]] || cat > "$USER_DB" <<EOF
{"users": []}
EOF
  chmod 600 "$USER_DB"
}

add_user() {
  local name="$1"
  local days="${2:-30}"
  local uuid="$(xray uuid)"
  local email="${name}@$(hostname)"
  local expiry=$(( $(date +%s) + days*86400 ))

  init_user_db

  # Remove se já existir
  jq --arg email "$email" 'del(.users[] | select(.email == $email))' "$USER_DB" > "$USER_DB.tmp"
  mv "$USER_DB.tmp" "$USER_DB"

  # Adiciona novo
  jq --arg uuid "$uuid" --arg email "$email" --arg name "$name" --argjson expiry "$expiry" \
     '.users += [{uuid: $uuid, email: $email, name: $name, expiry: $expiry, enabled: true}]' \
     "$USER_DB" > "$USER_DB.tmp"
  mv "$USER_DB.tmp" "$USER_DB"

  ok "Usuário '$name' criado! Expira em $days dias"
  update_clients_in_config
  reload_xray
}

list_users() {
  init_user_db
  echo -e "\n${OK} Usuários cadastrados:${RESET}"
  echo "──────────────────────────────────────────────────────────────"
  printf "%-15s %-12s %-13s %s\n" "NOME" "UUID" "EXPIRA" "STATUS"
  echo "──────────────────────────────────────────────────────────────"
  jq -r '.users[] | [.name // "-", (.uuid[0:8] + "..."), (if .expiry then (.expiry | strftime("%d/%m/%Y")) else "Nunca" end), (if .enabled then "ATIVO" else "INATIVO" end)] | @tsv' "$USER_DB" |
    while IFS=$'\t' read -r name shortuuid expiry status; do
      color=$([[ "$status" == "ATIVO" ]] && echo "\e[32m" || echo "\e[31m")
      printf "%-15s ${color}%-12s %-13s %-8s${RESET}\n" "$name" "$shortuuid" "$expiry" "$status"
    done
  echo "──────────────────────────────────────────────────────────────"
}

remove_user() {
  local search="$1"
  init_user_db
  local count=$(jq --arg s "$search" '[.users[] | select(.name==$s or .email|test($s;"i"))] | length' "$USER_DB")
  [[ $count -eq 0 ]] && err "Usuário '$search' não encontrado"
  jq --arg s "$search" 'del(.users[] | select(.name==$s or .email|test($s;"i")))' "$USER_DB" > "$USER_DB.tmp"
  mv "$USER_DB.tmp" "$USER_DB"
  ok "Usuário '$search' removido"
  update_clients_in_config
  reload_xray
}

generate_vless_link() {
  local uuid="$1"
  local domain="$2"
  echo "vless://$uuid@$PROXY_HOST:443?type=xhttp&security=tls&encryption=none&host=$domain&path=%2F&sni=$SNI_FIXED&allowInsecure=1#Tim-BR-$domain"
}

update_clients_in_config() {
  init_user_db
  local now=$(date +%s)
  local active_users=$(jq -c --argjson now "$now" '.users[] | select(.enabled and (.expiry == null or .expiry > $now)) | {id: .uuid, email: .email, level: 0}' "$USER_DB")

  if [[ -z "$active_users" || "$active_users" == "null" ]]; then
    active_users="[]"
  else
    active_users=$(jq -s '.' <<<"$active_users")
  fi

  jq --argjson clients "$active_users" '
    .inbounds |= map(
      if .tag == "inbound-sshorizon" then
        .settings.clients = $clients
      else . end
    )
  ' "$XRAY_CONFIG_PATH" > "$XRAY_CONFIG_PATH.tmp"
  mv "$XRAY_CONFIG_PATH.tmp" "$XRAY_CONFIG_PATH"
}

reload_xray() {
  info "Recarregando Xray..."
  systemctl reload xray 2>/dev/null || systemctl restart xray
  sleep 2
  ss -tulnp | grep -q ":443" && ok "Xray rodando na porta 443" || warn "Xray não está escutando na 443"
}

create_base_config() {
  local domain="$1"
  mkdir -p "$XRAY_CONFIG_DIR"
  cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "inbound-sshorizon",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
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
          "path": "/",
          "scMaxEachPostBytes": "1000000",
          "scMaxBufferedPosts": 30,
          "xPaddingBytes": "100-1000"
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
  ok "Configuração base criada"
}

# ====================== MENU PRINCIPAL ======================
show_menu() {
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
  echo
  echo "0) Sair"
  echo
  read -p "Escolha uma opção: " opt
  case $opt in
    1) read -p "Nome do usuário: " nome
       read -p "Dias de validade (padrão 30): " dias
       add_user "$nome" "${dias:-30}"
       read -p "Enter para continuar..." ;;
    2) list_users
       read -p "Enter para continuar..." ;;
    3) read -p "Nome ou parte do nome/email: " nome
       remove_user "$nome"
       read -p "Enter para continuar..." ;;
    4) read -p "Nome do usuário: " nome
       uuid=$(jq -r --arg n "$nome" '.users[] | select(.name==$n or .email|test($n;"i")) | .uuid' "$USER_DB" | head -n1)
       if [[ -n "$uuid" ]]; then
         domain=$(grep -oP '"CN=\K[^"]+' "$SSL_DIR/fullchain.pem" || echo "seu.dominio")
         link=$(generate_vless_link "$uuid" "$domain")
         echo -e "\n${OK}Link VLESS pronto:${RESET}\n"
         echo "$link"
         echo
       else
         warn "Usuário não encontrado"
       fi
       read -p "Enter para continuar..." ;;
    5) update_clients_in_config && reload_xray
       read -p "Enter para continuar..." ;;
    0) echo "Saindo..."; exit 0 ;;
    *) warn "Opção inválida" ; sleep 1 ;;
  esac
  show_menu
}

# ====================== INSTALAÇÃO COMPLETA ======================
install_full() {
  require_root
  clear
  echo -e "\e[34mInstalação Xray + xhttp + proxy TIM\e[0m\n"

  read -p "Digite seu subdomínio (ex: meu): " sub
  [[ -z "$sub" ]] && err "Subdomínio obrigatório"
  DOMAIN="${sub}.azion.app"

  install_deps
  install_xray
  generate_self_signed_cert "$DOMAIN"
  create_base_config "$DOMAIN"
  create_systemd_service
  open_ports
  mkdir -p /var/log/v2ray

  # Cria usuário inicial
  read -p "Nome do primeiro usuário: " firstuser
  read -p "Dias de validade (30): " days
  add_user "$firstuser" "${days:-30}"

  echo -e "\n${OK}INSTALAÇÃO CONCLUÍDA!${RESET}\n"
  uuid=$(jq -r '.users[0].uuid' "$USER_DB")
  link=$(generate_vless_link "$uuid" "$DOMAIN")
  echo "Link VLESS:"
  echo "$link"
  echo -e "\nPara gerenciar usuários: sudo bash $0"
  exit 0
}

# ====================== MAIN ======================
if [[ "${1:-}" == "manage" || -z "${1:-}" && -f "$XRAY_CONFIG_PATH" ]]; then
  show_menu
else
  install_full
fi