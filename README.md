# Xray Installer (VLESS + TLS + XHTTP + Azion)

Este script instala automaticamente um servidor Xray com:

- VLESS (TCP Reality / XHTTP)
- TLS ativo (usando certificado já existente)
- Porta interna 1080
- Porta externa 443 (requer proxy como Azion, Cloudflare ou Nginx)
- UUID gerado automaticamente
- Host e SNI personalizados durante a instalação
- Geração automática do link VLESS final

---

## 📌 Como funciona

O instalador realiza:

1. Instalação do Xray
2. Criação do diretório `/opt/sshorizon/ssl/`
3. Instalação dos certificados `fullchain.pem` e `privkey.pem`
4. Criação da configuração `/usr/local/etc/xray/config.json`
5. Geração automática do UUID
6. Pergunta pelo domínio que será utilizado no link final
7. Inicia o serviço Xray via systemd
8. Exibe o link VLESS pronto no final

---

## 🔧 Instalação (comando único)

Na sua VPS:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/righialan-spec/vray-installer/main/install-xray.sh)
