<h1 align="center">🚀 Instalador Xray (TLS + XHTTP + 443)</h1>

<p align="center">
  Script universal para instalar Xray com suporte a TLS + XHTTP usando
  certificado autoassinado, ideal para uso com <strong>Azion</strong>, 
  SNI fixo e porta externa 443.
</p>

<hr>

<h2>📌 Características</h2>

<ul>
  <li>Pergunta apenas o <strong>subdomínio</strong> (ex: meuserver)</li>
  <li>Monta automaticamente: <code>meuserver.azion.app</code></li>
  <li>Instala o Xray (com vários fallbacks automáticos)</li>
  <li>Gera certificado <strong>autoassinado</strong> válido por 10 anos</li>
  <li>Gera UUID apenas após Xray estar instalado</li>
  <li>Porta interna <strong>1080</strong> (dokodemo-door)</li>
  <li>Porta externa <strong>443</strong> (VLESS + TLS + XHTTP)</li>
  <li>SNI fixo: <strong>www.tim.com.br</strong></li>
  <li>Gera o link VLESS no final</li>
  <li>Compatível com qualquer VPS Linux</li>
</ul>

<hr>

<h2>⚙️ Como instalar (via jsDelivr)</h2>

<p>Execute os comandos abaixo como <strong>root</strong>:</p>

<pre><code>rm -f install-xray.sh
curl -fsSL https://cdn.jsdelivr.net/gh/righialan-spec/vray-installer/install-xray.sh -o install-xray.sh
chmod +x install-xray.sh
sudo ./install-xray.sh
</code></pre>

<hr>

<h2>🔧 Processo de instalação</h2>

<p>O script irá:</p>

<ol>
  <li>Perguntar o subdomínio (ex: <code>meuserver</code>)</li>
  <li>Gerar: <code>meuserver.azion.app</code></li>
  <li>Instalar o Xray automaticamente</li>
  <li>Gerar certificado autoassinado</li>
  <li>Gerar UUID automaticamente</li>
  <li>Criar <code>/usr/local/etc/xray/config.json</code> com sua configuração</li>
  <li>Ativar e iniciar o serviço via systemd</li>
  <li>Exibir o link VLESS final para importação</li>
</ol>

<hr>

<h2>🔑 Exemplo de VLESS gerado</h2>

<pre><code>vless://UUID@m.ofertas.tim.com.br:443?
type=xhttp&security=tls&encryption=none
&host=subdominio.azion.app
&path=%2F
&sni=www.tim.com.br
&allowInsecure=1#Tim-BR
</code></pre>

<hr>

<h2>📄 Logs</h2>

<p>Para visualizar logs do Xray:</p>

<pre><code>journalctl -u xray -n 200 --no-pager
</code></pre>

<hr>

<h2>📬 Contato</h2>

<p>Projeto mantido por <strong>righialan-spec</strong>.  
Contribuições, sugestões e issues são bem-vindas.</p>

<hr>

<h3 align="center">✨ Feito com foco em simplicidade e compatibilidade total.</h3>
