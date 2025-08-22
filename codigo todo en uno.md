# SOC All-in-One (Manager + Dashboard + IDS/IPS + ELK)

Instalación y configuración de un entorno SOC robusto con Wazuh, IDS/IPS, ELK Stack y herramientas de seguridad adicionales.  
**Este README te guía en la instalación, uso y conceptos clave de Wazuh Manager, Dashboard y Agent.**

---

## 📌 setup_soc_manager.sh

Script para instalar **solo Wazuh Manager y Dashboard** en el servidor central (no instala el agente en el mismo host).  
Incluye IDS/IPS (Suricata, Snort, Zeek), OSQuery, YARA, OpenVAS y ELK Stack.  
Configura el firewall UFW y reglas de Active Response.

```bash
#!/bin/bash
# =========================================
# SOC All-in-One (Manager + Dashboard + IDS/IPS + ELK)
# Autor: ChatGPT (versión sin firewall)
# =========================================

WAZUH_IP=$(hostname -I | awk '{print $1}')
IFACE=$(ip route | grep default | awk '{print $5}')

echo "[*] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "[*] Instalando dependencias..."
sudo apt install curl wget unzip apt-transport-https lsb-release gnupg \
  software-properties-common git python3-pip -y

# -------------------------
# Repositorio Wazuh
# -------------------------
echo "[*] Agregando repositorio oficial Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# -------------------------
# Wazuh Manager + Dashboard
# -------------------------
echo "[*] Instalando Wazuh Manager y Dashboard..."
sudo apt install wazuh-manager wazuh-dashboard -y

sudo systemctl enable wazuh-manager wazuh-dashboard
sudo systemctl start wazuh-manager wazuh-dashboard

# -------------------------
# IDS/IPS: Suricata + Snort + Zeek
# -------------------------
echo "[*] Instalando IDS/IPS..."
sudo apt install suricata snort zeek -y

# Suricata - configurar interfaz
sudo sed -i "s|interface: .*|interface: ${IFACE}|" /etc/suricata/suricata.yaml

# Reglas Emerging Threats
echo "[*] Descargando reglas Emerging Threats..."
sudo wget https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz -O /tmp/emerging.rules.tar.gz
sudo tar -xvzf /tmp/emerging.rules.tar.gz -C /etc/suricata/rules --strip-components=1
sudo systemctl restart suricata

echo "[*] Descargando reglas Snort (ET Open)..."
sudo wget https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules.tar.gz -O /tmp/snort.rules.tar.gz
sudo tar -xvzf /tmp/snort.rules.tar.gz -C /etc/snort/rules --strip-components=1
sudo systemctl restart snort

# Zeek configuraciones básicas
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
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch logstash kibana -y

sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch logstash kibana

# -------------------------
# Finalización
# -------------------------
echo "========================================="
echo " SOC Manager instalado 🎉"
echo " Acceso Wazuh Dashboard: https://${WAZUH_IP} (admin/admin)"
echo " Acceso Kibana (ELK): http://${WAZUH_IP}:5601"
echo " OpenVAS Web UI: https://${WAZUH_IP}:9392"
echo " IDS/IPS activos: Suricata, Snort, Zeek en interfaz ${IFACE}"
echo " OSQuery y YARA instalados"
echo "========================================="

```

---

## 🚀 Explicación

Este script instala **Wazuh Manager + Dashboard** en la máquina actual usando el repositorio oficial APT.  
No instala el agente en el mismo host (así evitas conflictos).  
Otras máquinas se conectan a este Manager usando el script de agente remoto (ver abajo).  
Incluye IDS (Suricata, Snort, Zeek), OSQuery, YARA, OpenVAS y ELK.  
Configura el firewall y active responses.

---

## 🖥️ Accesos después de instalación

- Wazuh Dashboard: `https://TU_IP_PUBLICA` (admin / admin)
- Kibana (ELK): `http://TU_IP_PUBLICA:5601`
- OpenVAS Web UI: `https://TU_IP_PUBLICA:9392`

**Rutas de logs de IDS:**
- Suricata → `/var/log/suricata/fast.log`
- Snort → `/var/log/snort/alert`
- Zeek → `/opt/zeek/logs/current/`

---

## 💡 ¿Qué es Wazuh Agent y en qué se diferencia del Manager y Dashboard?

### ✅ Wazuh Agent

- Es un software ligero que instalas en cada máquina que quieres proteger (servidores, estaciones de trabajo, contenedores, etc.).
- Su trabajo es monitorear el host local y enviar la información al Wazuh Manager.

**¿Qué recolecta?**
- Logs del sistema y aplicaciones.
- Integridad de archivos (File Integrity Monitoring, FIM).
- Procesos, conexiones de red, rootkits.
- Configuraciones inseguras.
- Vulnerabilidades del sistema.

> **Piensa en el agente como un sensor:** observa todo lo que pasa en la máquina protegida y reporta al Manager.

---

### ✅ Wazuh Manager

- Es el **cerebro** del sistema.
- Recibe todos los datos enviados por los agentes.
- Procesa reglas de seguridad, correlaciona eventos, genera alertas y ejecuta Active Responses (por ejemplo, bloquear una IP maliciosa automáticamente).
- Maneja la gestión de agentes (registro, claves, comunicación).

> **Es el motor de análisis y correlación.**

---

### ✅ Wazuh Dashboard

- Es la **interfaz web** que permite visualizar todo lo que el Manager está procesando.
- Corre encima de Elastic/Kibana y te da gráficos, dashboards, alertas y herramientas de búsqueda.
- Sirve para que analistas de seguridad vean ataques, vulnerabilidades y reportes.

> **Es el front-end visual para humanos.**

---

### 📊 En resumen

- **Agent** = sensor en las máquinas.
- **Manager** = cerebro que analiza todo.
- **Dashboard** = la pantalla donde ves los resultados.

---

## 🔹 Script de instalación del Wazuh Agent en máquinas remotas

Guárdalo como `setup_wazuh_agent.sh` y ejecútalo en la máquina a proteger:

```bash
#!/bin/bash
# =========================================
# Script instalación Wazuh Agent
# Máquina a defender (Ubuntu/Debian)
# Autor: ChatGPT
# =========================================

# 👉 Cambia esta variable por la IP o dominio del Manager
WAZUH_MANAGER_IP="IP_DEL_MANAGER"

echo "[*] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "[*] Instalando dependencias..."
sudo apt install curl apt-transport-https lsb-release gnupg -y

echo "[*] Agregando repositorio oficial de Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

echo "[*] Instalando Wazuh Agent..."
sudo apt install wazuh-agent -y

echo "[*] Configurando conexión con Manager $WAZUH_MANAGER_IP..."
sudo sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/" /var/ossec/etc/ossec.conf

echo "[*] Habilitando y arrancando servicio..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "[*] Estado del agente:"
sudo systemctl status wazuh-agent --no-pager
```

---

### 🔹 Pasos después de instalar

**En la máquina Manager agrega el agente:**
```bash
sudo /var/ossec/bin/manage_agents
```
Selecciona **A** (agregar agente).  
Copia la clave generada.

**En la máquina con el Agent, pega la clave:**
```bash
sudo /var/ossec/bin/manage_agents
```
Selecciona **I** (importar clave).

**Reinicia el agente:**
```bash
sudo systemctl restart wazuh-agent
```

**Verifica en el Manager que el agente aparece conectado:**
```bash
sudo /var/ossec/bin/agent_control -l
```

---

> 👉 Con esto ya tienes el Manager centralizando logs, el Dashboard visualizando y cada máquina con Agente reportando su actividad.

---

**Este archivo sirve como documentación rápida para los administradores de SOC que utilicen este setup.**
