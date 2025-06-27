# DNS Recon Ultra - Consulta Passiva de IPs Públicos

Script shell para realizar reconhecimento passivo de domínios e subdomínios associados a endereços IPv4 públicos, utilizando APIs do VirusTotal, SecurityTrails e Hackertarget.

---

## Objetivo

Obter informações sobre domínios, subdomínios e certificados SSL vinculados a um ou mais endereços IP públicos por meio de consultas a fontes abertas (OSINT), de forma automatizada, segura e ética.

---

## Requisitos

- bash (Linux)
- curl
- jq

### Instalação das dependências

Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y curl jq
```

RHEL/CentOS/Fedora:
```bash
sudo yum install -y curl jq
```

---

## Obter o script

Clone o repositório oficial:
```bash
git clone https://github.com/onecio/DNS_Recon_Ultra.git
cd DNS_Recon_Ultra
```

Ou baixe diretamente via navegador:
- Link: https://github.com/onecio/DNS_Recon_Ultra

---

## Configuração

1. Edite o script `dns_reverse_lookup_tool.sh`
2. Substitua os valores das chaves de API:
```bash
SECURITYTRAILS_API="sua_api_key_aqui"
VT_API="sua_api_key_aqui"
```

3. Defina os IPs que deseja consultar:
```bash
IPS=(
  "8.8.8.8"         # Google Public DNS
  "1.1.1.1"         # Cloudflare DNS
  "208.67.222.222"  # OpenDNS
)
```

4. Dê permissão de execução:
```bash
chmod +x dns_reverse_lookup_tool.sh
```

---

## Execução

Para rodar o script:
```bash
./dns_reverse_lookup_tool.sh
```

Saída esperada:
- Domínios encontrados via Hackertarget
- Domínios históricos via SecurityTrails
- Subdomínios e SANs de certificados via VirusTotal

Para salvar a saída:
```bash
./dns_reverse_lookup_tool.sh | tee resultados.txt
```

---

## Obter as chaves de API

### SecurityTrails
1. Crie conta em: https://securitytrails.com/
2. Acesse: Account Settings > API Key

### VirusTotal
1. Crie conta em: https://www.virustotal.com/
2. Acesse: https://www.virustotal.com/gui/user/apikey

---

## Observações

- O script é ético, seguro e realiza apenas consultas passivas (sem varredura ativa)
- As contas gratuitas têm limites de uso (50 consultas/mês para SecurityTrails)
- Pode ser usado em testes forenses, treinamentos de OSINT ou cibersegurança ofensiva/defensiva

---

## Licença

Distribuído sob a licença MIT. Consulte o arquivo LICENSE para mais informações.

---

## Autor

[onecio](https://github.com/onecio)
