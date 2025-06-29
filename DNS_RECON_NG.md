#!/bin/bash
## DNS RECON FURTIVO - Técnicas Proxy Avançada ###
# ------------------------------
# Ferramenta de Recon DNS Avançado com Evasão
# Autor: One CyberSec Mode
# Descrição: Consulta IPs em fontes passivas para extrair domínios associados.
# Recursos adicionais: suporte a proxy e delays randômicos para evasão
# ------------------------------

# ==============================
# Conceitos importantes
# ==============================

# 1. O que é rate-limit?
# APIs públicas como a da VirusTotal e SecurityTrails normalmente limitam o número de requisições
# que você pode fazer por minuto, hora ou mês, especialmente em contas gratuitas.
# Exemplo:
# - VirusTotal Free: 4 requisições por minuto
# - SecurityTrails Free: 50 requisições por mês
# Se você exceder esse limite, a API pode:
# - Devolver erro 429 Too Many Requests
# - Bloquear temporariamente seu IP
# - Revogar sua chave de API

# 2. Mecanismo 1: Uso de Proxy
# No script, o uso de proxy é controlado por estas variáveis:
USE_PROXY=true
PROXY="http://127.0.0.1:9050"
# Se USE_PROXY=true, o curl se conecta à internet por meio desse proxy.
# A porta 9050 é padrão do Tor, que pode ser usada com Privoxy para fornecer proxy HTTP.
# Isso faz com que as requisições pareçam vir de outro IP, driblando o limite por IP das APIs.

# Como ativar na prática:
# a) Instale Tor e Privoxy:
#    sudo apt install tor privoxy
# b) Edite /etc/privoxy/config:
#    sudo nano /etc/privoxy/config
#    Adicione ou descomente a linha:
#    forward-socks5t / 127.0.0.1:9050 .
# c) Reinicie o serviço:
#    sudo systemctl restart privoxy
# d) Configure no script:
#    PROXY="http://127.0.0.1:8118"  (porta padrão do Privoxy)

# 3. Mecanismo 2: Delay aleatório entre requisições
# Para evitar excesso de requisições em sequência:
random_delay() {
  DELAY=$(( (RANDOM % 5) + 1 ))  # entre 2 e 5 segundos
  sleep $DELAY
}
# Você pode aumentar esse intervalo para reduzir riscos:
# DELAY=$(( (RANDOM % 10) + 5 ))  # entre 5 e 15 segundos

# 4. Estratégias avançadas:
# a) Rotação de proxies:
#    PROXIES=("http://proxy1:port" "http://proxy2:port")
#    PROXY=${PROXIES[$RANDOM % ${#PROXIES[@]}]}
# b) Várias chaves de API:
#    VT_KEYS=("key1" "key2" "key3")
#    VT_API=${VT_KEYS[$RANDOM % ${#VT_KEYS[@]}]}
# c) Uso de proxychains:
#    sudo apt install proxychains
#    proxychains ./dns_reverse_lookup_tool.sh
#    Configure os proxies em /etc/proxychains.conf

# 5. O que você deve usar:
# Recurso                      | Complexidade | Ideal para...
# ----------------------------|--------------|-----------------------------
# random_delay                | Baixa        | Todos os usos
# proxy via Tor/Privoxy       | Média        | Contornar IP rate-limit
# proxychains                 | Média/Alta   | Ambientes com múltiplos proxies
# rotação de chaves           | Média        | Múltiplas contas gratuitas
# rotação de IPs com VPN      | Alta         | Automatização em larga escala

# ==============================
# IPs alvo (adicione mais conforme necessidade)
# ==============================
IPS=(
  "8.8.8.8"         # Google Public DNS
  "1.1.1.1"         # Cloudflare DNS
  "208.67.222.222"  # OpenDNS
  "13.107.21.200"   # Microsoft Azure
  "104.244.42.1"    # Twitter CDN
  "151.101.1.69"    # GitHub Pages
  "185.199.108.153" # GitHub raw
  "23.216.10.70"    # Akamai CDN
  "216.58.222.46"   # Google
  "34.194.216.183"  # AWS EC2
)

# Suas chaves de API
SECURITYTRAILS_API="SUA_CHAVE_SECURITYTRAILS"
VT_API="SUA_CHAVE_VIRUSTOTAL"

# Verifica dependências
check_dependencies() {
  for bin in curl jq; do
    if ! command -v $bin >/dev/null 2>&1; then
      echo "[!] Dependência ausente: $bin"
      echo "[+] Instalando $bin..."
      sudo apt install -y $bin || sudo yum install -y $bin
    fi
  done
}

# Função de curl com ou sem proxy
c_request() {
  local url="$1"
  local headers="$2"
  if [ "$USE_PROXY" = true ]; then
    curl -s --proxy "$PROXY" $headers "$url"
  else
    curl -s $headers "$url"
  fi
}

# Hackertarget
consulta_hackertarget() {
  echo "[Hackertarget] Subdomínios para $1"
  c_request "https://api.hackertarget.com/reverseiplookup/?q=$1" ""
  echo
  random_delay
}

# SecurityTrails
consulta_securitytrails() {
  echo "[SecurityTrails] Domínios históricos para $1"
  local data="{\"filter\":{\"ipv4\":\"$1\"}}"
  c_request "https://api.securitytrails.com/v1/search/list" \
    "-H \"apikey: $SECURITYTRAILS_API\" -H \"Content-Type: application/json\" -d '$data'" | \
    jq -r '.records[].hostname' || echo "Nenhum resultado."
  echo
  random_delay
}

# VirusTotal
consulta_virustotal() {
  echo "[VirusTotal] Domínios e certs SSL para $1"
  c_request "https://www.virustotal.com/api/v3/ip_addresses/$1" \
    "-H \"x-apikey: $VT_API\"" | \
    jq -r '.data.attributes.last_https_certificate.extensions.subject_alternative_name[]?' || echo "Nenhum resultado."
  echo
  random_delay
}

# Execução principal
main() {
  check_dependencies
  for ip in "${IPS[@]}"; do
    echo "=============================="
    echo "Analisando IP: $ip"
    consulta_hackertarget "$ip"
    consulta_securitytrails "$ip"
    consulta_virustotal "$ip"
    echo "=============================="
  done
}

main
