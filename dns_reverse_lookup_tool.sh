#!/bin/bash

# ------------------------------
# Ferramenta de Recon DNS Avançado
# Autor: One Mod CyberSec
# Descricao: Consulta de IPs em fontes passivas e extrai domínios associados.
# Requisitos: curl, jq
# ------------------------------

# IPs alvo (adicione os IPs aqui para a consulta)
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

# Chaves VT e STRAILS API
SECURITYTRAILS_API="******************0ncYklIcXs"
VT_API="******************c85ec2bf335e2b84585b5b"

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
  curl -s "https://api.hackertarget.com/reverseiplookup/?q=$1"
  echo
}

# Função para consultar SecurityTrails
consulta_securitytrails() {
  echo "[SecurityTrails] Domínios históricos para $1"
  curl -s -X POST \
    -H "apikey: $SECURITYTRAILS_API" \
    -H "Content-Type: application/json" \
    -d "{\"filter\":{\"ipv4\":\"$1\"}}" \
    https://api.securitytrails.com/v1/search/list \
    | jq -r '.records[].hostname' || echo "Nenhum resultado."
  echo
}

# Função para consultar VirusTotal
consulta_virustotal() {
  echo "[VirusTotal] Domínios e certs SSL para $1"
  curl -s -H "x-apikey: $VT_API" \
    "https://www.virustotal.com/api/v3/ip_addresses/$1" \
    | jq -r '.data.attributes.last_https_certificate.extensions.subject_alternative_name[]?' || echo "Nenhum resultado."
  echo
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
