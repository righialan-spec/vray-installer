<h1 align="center">Xray Universal Installer (XHTTP + TLS + 443)</h1>

<p align="center">
Instalador universal para Xray (XHTTP + TLS), compatível com qualquer VPS, incluindo Oracle Cloud.
</p>

---

## 📌 Sobre este instalador

Este script instala automaticamente:

- Xray-core (com 3 métodos de fallback: instalador oficial, jsDelivr e release direto).
- ACME.sh (método standalone) para gerar certificado SSL automaticamente.
- Certificados armazenados em:  
  `/opt/sshorizon/ssl/privkey.pem`  
  `/opt/sshorizon/ssl/fullchain.pem`
- Configuração completa do Xray com:
  - **Inbound interno 1080** (dokodemo)
  - **VLESS externo 443** com XHTTP + TLS
  - SNI fixo: **www.tim.com.br**
- Criação de service systemd (`xray.service`)
- Abertura automática das portas 80 e 443
- Geração do link VLESS no final da instalação

O script funciona em qualquer VPS, inclusive Oracle, mesmo quando `curl | bash` não funciona.

---

## ⚠️ Requisitos antes de instalar

1. Seu domínio **deve apontar para o IP da VPS** (A record).
2. A porta **80 deve estar aberta** temporariamente (ACME precisa dela).
3. Executar como **root**.

---

## 🚀 Instalação

### 🔥 Use o comando abaixo (via jsDelivr):

```bash
sudo su
curl -fsSL https://cdn.jsdelivr.net/gh/righialan-spec/vray-installer/install-xray.sh -o install-xray.sh
chmod +x install-xray.sh
./install-xray.sh
