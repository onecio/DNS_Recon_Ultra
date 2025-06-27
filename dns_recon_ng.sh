#!/bin/bash

# ------------------------------
# Ferramenta de Recon DNS Avançado com Evasão
# Autor: ChatGPT CyberSec Mode
# Descrição: Consulta IPs em fontes passivas para extrair domínios associados com suporte a proxy e rotina evasiva
# Requisitos: curl, jq
# ------------------------------

# IPs alvo (adicione mais conforme necessidade)
IPS=(
  "8.8.8.8"         # Google Public DNS - PTR e domínio configurados
  "1.1.1.1"         # Cloudflare DNS - PTR e domínio configurados
  "208.67.222.222"  # OpenDNS (Cisco) - DNS recursivo aberto
  "13.107.21.200"   # Microsoft Azure (outlook.office365.com) - Hostname e SSL ativos
  "104.244.42.1"    # Twitter CDN (via Fastly) - Serviços e DNS ativos
  "151.101.1.69"    # GitHub Pages (Fastly CDN) - PTR e domínios disponíveis
  "185.199.108.153" # GitHub (raw.githubusercontent.com) - Certificados SSL e DNS
  "23.216.10.70"    # Akamai CDN - Alta rotatividade, ótimo para testes
  "216.58.222.46"   # Google (www.google.com) - DNS, TLS e subdomínios
  "34.194.216.183"  # AWS EC2 (Amazon) - DNS reverso comum
)

# Coloque suas chaves de API
SECURITYTRAILS_API="SUA_CHAVE_SECURITYTRAILS"
VT_API="SUA_CHAVE_VIRUSTOTAL"

# Configuração de proxy (opcional)
USE_PROXY=true
PROXY="http://127.0.0.1:9050"  # Exemplo com Tor (proxy SOCKS5 via Privoxy ou HTTP proxy local)

# Função para aplicar delay randômico entre requisições
random_delay() {
  DELAY=$(( (RANDOM % 4) + 2 ))  # Entre 2 e 5 segundos
  sleep $DELAY
}

# Função genérica de requisição com ou sem proxy
c_request() {
  local url="$1"
  local extra_args="$2"
  if [ "$USE_PROXY" = true ]; then
    curl --proxy "$PROXY" -s $extra_args "$url"
  else
    curl -s $extra_args "$url"
  fi
}

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

# Função para consultar hackertarget.com
consulta_hackertarget() {
  echo "[Hackertarget] Subdomínios para $1"
  c_request "https://api.hackertarget.com/reverseiplookup/?q=$1" ""
  echo
  random_delay
}

# Função para consultar SecurityTrails
consulta_securitytrails() {
  echo "[SecurityTrails] Domínios históricos para $1"
  local data="{\"filter\":{\"ipv4\":\"$1\"}}"
  c_request "https://api.securitytrails.com/v1/search/list" \
    "-X POST -H \"apikey: $SECURITYTRAILS_API\" -H \"Content-Type: application/json\" -d '$data'" \
    | jq -r '.records[].hostname' || echo "Nenhum resultado."
  echo
  random_delay
}

# Função para consultar VirusTotal
consulta_virustotal() {
  echo "[VirusTotal] Domínios e certs SSL para $1"
  c_request "https://www.virustotal.com/api/v3/ip_addresses/$1" \
    "-H \"x-apikey: $VT_API\"" \
    | jq -r '.data.attributes.last_https_certificate.extensions.subject_alternative_name[]?' || echo "Nenhum resultado."
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
