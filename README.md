# 🚀 Xray Installer (XHTTP + TLS + 443)

Instalador automático do **Xray-core** configurado com:

- 🟦 **XHTTP**  
- 🔐 **TLS (porta 443 externa)**  
- 🔌 **Inbound interno na porta 1080**  
- 🎯 **UUID automático ou manual**  
- 🌐 **Domínio configurado durante a instalação**  
- 📡 **SNI fixo: `www.tim.com.br`**  
- 🔗 **Geração automática do link VLESS ao final**

Ideal para uso com plataformas como **Azion** ou CDNs que trabalham com proxying em 443.

---

## ✔️ Recursos do Instalador

- Instala Xray-core via repositório oficial  
- Solicita automaticamente certificado SSL válido com **ACME**  
- Aplica configuração completa (vless + xhttp)  
- Configura logs e permissões  
- Gera e exibe o link **VLESS** pronto para uso  
- 100% automatizado — não precisa editar nada manualmente

---

## 📥 Como instalar (comando único)

Execute:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/righialan-spec/vray-installer/main/install-xray.sh)
