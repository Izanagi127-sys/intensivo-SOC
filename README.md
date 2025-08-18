# 🛡️ intensivo-SOC

---

## ⚡ Script de despliegue rápido (Blue Team – Wazuh)

```bash
#!/bin/bash
# =========================================
# Script Blue Team - Defensa con Wazuh
# Instala: Wazuh Agent + Suricata + UFW
# Configura: Active Responses + Firewall
# Autor: Equipo Blue CTF
# =========================================

# --- CONFIGURAR ANTES DE EJECUTAR ---
WAZUH_MANAGER_IP="IP_DEL_MANAGER"   # Cambia por la IP de tu Wazuh Manager
INTERFAZ_RED="eth0"                 # Cambia por la interfaz de red (ip a)

echo "[*] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "[*] Instalando dependencias..."
sudo apt install curl wget unzip ufw -y

# -------------------------
# Instalar Wazuh Agent
# -------------------------
echo "[*] Descargando e instalando Wazuh Agent..."
curl -sO https://packages.wazuh.com/4.x/wazuh-agent-4.7.3.deb
sudo WAZUH_MANAGER="$WAZUH_MANAGER_IP" dpkg -i ./wazuh-agent-4.7.3.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# -------------------------
# Instalar Suricata
# -------------------------
echo "[*] Instalando Suricata IDS..."
sudo apt install suricata -y
sudo systemctl enable suricata
sudo systemctl start suricata

echo "[*] Configurando Suricata en interfaz $INTERFAZ_RED..."
sudo suricata -c /etc/suricata/suricata.yaml -i $INTERFAZ_RED &

# -------------------------
# Configurar UFW (Firewall)
# -------------------------
echo "[*] Configurando UFW..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw logging on
sudo ufw enable

# -------------------------
# Configurar Active Responses en Wazuh
# -------------------------
echo "[*] Configurando Active Responses..."
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOL

  <active-response>
    <command>firewalld</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <command>host-deny</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <command>disable-account</command>
    <location>local</location>
    <level>10</level>
  </active-response>

EOL

sudo systemctl restart wazuh-agent

# -------------------------
# Estado final
# -------------------------
echo "[✔] Instalación completada."
echo "Wazuh Agent conectado a: $WAZUH_MANAGER_IP"
echo "Suricata corriendo en interfaz: $INTERFAZ_RED"
echo "UFW activo con logging"
echo "Active Responses habilitado"
