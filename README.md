# 🚀 Xray Installer - VLESS XHTTP (CDN Optimized)

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![Xray](https://img.shields.io/badge/Core-Xray-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

Script automatizado para instalação e configuração do **Xray Core** em servidores Linux (Ubuntu/Debian/CentOS). 

Este instalador foi **especificamente otimizado para CDNs como Azion e Cloudflare**, resolvendo problemas comuns de *Handshake SSL (Erro 502)* ao utilizar comunicação HTTP pura entre a CDN e a VPS, enquanto mantém a segurança HTTPS entre o cliente e a CDN.

---

## 📋 Funcionalidades

- ✅ **Instalação Automática:** Detecta o sistema operacional e instala dependências.
- ✅ **Correção de Erro 502:** Configura o servidor na porta **80 (HTTP)** para evitar conflitos de certificado com a CDN.
- ✅ **Firewall:** Libera portas automaticamente (iptables/netfilter-persistent).
- ✅ **Protocolo Recente:** Configurado com **VLESS + XHTTP (SplitHTTP)** para alta performance.
- ✅ **UUID Automático:** Gera e configura credenciais seguras.
- ✅ **Serviço Systemd:** Configura o Xray para iniciar automaticamente com o sistema.

---

## 🛠️ Pré-requisitos

1. Um servidor VPS (Oracle Cloud, AWS, DigitalOcean, etc) com **Ubuntu 20+, Debian 10+ ou CentOS 8+**.
2. Um domínio configurado em uma CDN (Azion ou Cloudflare).
3. Acesso Root ao servidor.

---

## 🚀 Instalação Rápida

Acesse seu terminal como **root** e execute o comando abaixo:

```bash
bash <(curl -sL [https://raw.githubusercontent.com/righialan-spec/vray-installer/main/install.sh](https://raw.githubusercontent.com/righialan-spec/vray-installer/main/install.sh))
