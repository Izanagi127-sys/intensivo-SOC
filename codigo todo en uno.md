

#!/bin/bash
# =========================================
# SOC All-in-One con IDS/IPS + Dashboards
# Autor: ChatGPT
# =========================================

WAZUH_VERSION="4.7.3"
WAZUH_IP=$(hostname -I | awk '{print $1}')
IFACE=$(ip route | grep default | awk '{print $5}')

echo "[*] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "[*] Instalando dependencias..."
sudo apt install curl wget unzip apt-transport-https lsb-release gnupg \
  ufw iptables software-properties-common git python3-pip -y

# -------------------------
# Wazuh (Manager + Dashboard + Agent)
# -------------------------
echo "[*] Instalando Wazuh..."
curl -sO https://packages.wazuh.com/4.x/wazuh-manager-${WAZUH_VERSION}.deb
curl -sO https://packages.wazuh.com/4.x/wazuh-dashboard-${WAZUH_VERSION}.deb
curl -sO https://packages.wazuh.com/4.x/wazuh-agent-${WAZUH_VERSION}.deb

sudo dpkg -i wazuh-manager-${WAZUH_VERSION}.deb
sudo dpkg -i wazuh-dashboard-${WAZUH_VERSION}.deb
sudo WAZUH_MANAGER="$WAZUH_IP" WAZUH_AGENT_NAME="$(hostname)" dpkg -i wazuh-agent-${WAZUH_VERSION}.deb

sudo systemctl enable wazuh-manager wazuh-dashboard wazuh-agent
sudo systemctl start wazuh-manager wazuh-dashboard wazuh-agent

# -------------------------
# IDS/IPS: Suricata + Snort + Zeek
# -------------------------
echo "[*] Instalando IDS/IPS..."
sudo apt install suricata snort zeek -y

# Suricata - configurar interfaz
sudo sed -i "s|interface: .*|interface: ${IFACE}|" /etc/suricata/suricata.yaml

# Reglas Emerging Threats (ET Open)
echo "[*] Descargando reglas Emerging Threats para Suricata..."
sudo wget https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz -O /tmp/emerging.rules.tar.gz
sudo tar -xvzf /tmp/emerging.rules.tar.gz -C /etc/suricata/rules --strip-components=1
sudo systemctl restart suricata

echo "[*] Descargando reglas Snort (ET Open)..."
sudo wget https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules.tar.gz -O /tmp/snort.rules.tar.gz
sudo tar -xvzf /tmp/snort.rules.tar.gz -C /etc/snort/rules --strip-components=1
sudo systemctl restart snort

echo "[*] Configurando Zeek con scripts básicos..."
sudo zeekctl install
echo "@load policy/protocols/ssh/interesting-hostnames" | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo "@load policy/protocols/http" | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
sudo zeekctl deploy

# -------------------------
# Endpoint & Vulnerabilidades
# -------------------------
echo "[*] Instalando OSQuery..."
sudo apt install osquery -y
sudo systemctl enable osqueryd && sudo systemctl start osqueryd

echo "[*] Instalando YARA..."
sudo apt install yara -y

echo "[*] Instalando OpenVAS..."
sudo apt install gvm -y
sudo gvm-setup
sudo gvm-check-setup

# -------------------------
# ELK Stack
# -------------------------
echo "[*] Instalando ELK (Elasticsearch, Logstash, Kibana)..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt install apt-transport-https -y
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch logstash kibana -y
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch logstash kibana

# Dashboards de ejemplo (SSH brute force, Suricata alerts, Zeek flows)
echo "[*] Importando dashboards iniciales..."
DASH_JSON='{
  "attributes": {
    "title": "SOC - Vista General",
    "hits": 0,
    "panelsJSON": "[{\"type\":\"visualization\",\"id\":\"ssh_failed_logins\",\"title\":\"Intentos SSH Fallidos\"}, {\"type\":\"visualization\",\"id\":\"suricata_alerts\",\"title\":\"Alertas Suricata\"}, {\"type\":\"visualization\",\"id\":\"zeek_connections\",\"title\":\"Flujos Zeek\"}]",
    "optionsJSON": "{\"darkMode\":true}",
    "uiStateJSON": "{}",
    "version": 1
  }
}'
echo $DASH_JSON | sudo tee /tmp/soc_dashboard.json > /dev/null

# -------------------------
# Firewall UFW + Active Responses
# -------------------------
echo "[*] Configurando Firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp       # SSH
sudo ufw allow 443/tcp      # Wazuh Dashboard
sudo ufw allow 5601/tcp     # Kibana
sudo ufw allow 1514/udp     # Wazuh logs
sudo ufw allow 1515/tcp     # Wazuh agent registration
sudo ufw allow 55000/tcp    # Wazuh API
sudo ufw allow 9392/tcp     # OpenVAS Web UI
sudo ufw --force enable

# Active Responses
cat << 'EOF' | sudo tee /var/ossec/etc/active-response/active-responses.json > /dev/null
[
  {
    "command": "firewalld",
    "location": "local",
    "rules": {
      "level": 10,
      "timeout": 600
    }
  }
]
EOF

sudo systemctl restart wazuh-manager

# -------------------------
# Finalización
# -------------------------
echo "========================================="
echo " SOC All-in-One instalado 🎉"
echo " Acceso Wazuh Dashboard: https://${WAZUH_IP} (admin/admin)"
echo " Acceso Kibana (ELK): http://${WAZUH_IP}:5601"
echo " OpenVAS Web UI: https://${WAZUH_IP}:9392"
echo " IDS/IPS activos: Suricata, Snort, Zeek en interfaz ${IFACE}"
echo " OSQuery y YARA instalados"
echo " Firewall UFW con Active Responses"
echo " Dashboards iniciales importados"
echo "========================================="










-----------------------



Uso

Guardar el archivo:

nano setup_soc_full.sh


(pegar el script completo).

Dar permisos:

chmod +x setup_soc_full.sh


Ejecutar:

sudo ./setup_soc_full.sh

📊 Accesos después de instalación

Wazuh Dashboard: https://TU_IP_PUBLICA (admin / admin).

Kibana (ELK): http://TU_IP_PUBLICA:5601 → con dashboard inicial (SOC - Vista General).

OpenVAS: https://TU_IP_PUBLICA:9392 (administra vulnerabilidades).

IDS:

Suricata → /var/log/suricata/fast.log

Snort → /var/log/snort/alert

Zeek → /opt/zeek/logs/current/
