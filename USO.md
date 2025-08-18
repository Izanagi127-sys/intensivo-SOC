# intensivo-SOC

---

### ⚡ Script de despliegue rápido (Blue Team – Wazuh)

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
```

---

## 🚀 Uso

Copia el script en tu servidor (ej: `setup_defensa.sh`).

Dale permisos de ejecución:

```bash
chmod +x setup_defensa.sh
```

Ejecútalo como root:

```bash
sudo ./setup_defensa.sh
```

Cambia las variables:

- `WAZUH_MANAGER_IP` → IP de tu Wazuh Manager.
- `INTERFAZ_RED` → interfaz de red (usa `ip a` para verla).

---

## JSON del Dashboard

Guarda este contenido como `dashboard_ctf.json` y luego lo importas en Kibana (Stack Management → Saved Objects → Import).

```json
{
  "attributes": {
    "title": "CTF Defensa - Blue Team",
    "hits": 0,
    "description": "Dashboard de defensa con Wazuh + Suricata + Firewall",
    "panelsJSON": "[{\"type\":\"visualization\",\"id\":\"ssh_failed_logins\",\"panelIndex\":\"1\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":10},\"title\":\"Intentos SSH fallidos\"}]",
    "optionsJSON": "{\"useMargins\":true,\"hidePanelTitles\":false}",
    "version": 1
  },
  "references": [
    {"name":"ssh_failed_logins","type":"visualization","id":"ssh_failed_logins"},
    {"name":"blocked_ips","type":"visualization","id":"blocked_ips"},
    {"name":"suricata_alerts","type":"visualization","id":"suricata_alerts"},
    {"name":"suspicious_processes","type":"visualization","id":"suspicious_processes"}
  ],
  "migrationVersion": {
    "dashboard": "7.9.3"
  },
  "type": "dashboard"
}
```

---

## 📘 Mini-Playbook de Respuesta Rápida (CTF Defensa)

### 1️⃣ Ataques de Fuerza Bruta SSH

**Detección en Dashboard:** Panel "Intentos SSH fallidos" con muchas entradas desde la misma IP.

**Acción inmediata:**
- Verificar si Wazuh ya bloqueó la IP (Active Response).
- Si no:

```bash
sudo ufw deny from 10.10.X.X
```

- Revisar si el atacante logró acceso (`/var/log/auth.log`).
- Si encuentras un usuario comprometido:

```bash
sudo passwd -l usuario
sudo kill -9 $(pgrep -u usuario)
```

---

### 2️⃣ Escaneos de Red / Reconocimiento

**Detección en Dashboard:** Panel "Alertas Suricata" mostrando Nmap scan, Port scan, etc.

**Acción inmediata:**
- Bloquear IP atacante:

```bash
sudo ufw deny from 10.10.X.X
```

- Marcarla como atacante en el dashboard (para tu equipo).

---

### 3️⃣ Exploits de Red / DoS

**Detección en Dashboard:** Suricata reporta Exploit Attempt o DoS. Carga inusual en CPU o RAM (`htop`).

**Acción inmediata:**
- Bloquear IP atacante.
- Si el servicio afectado no es vital → detenerlo temporalmente:

```bash
sudo systemctl stop servicio_afectado
```

- Si es vital → reiniciar solo ese servicio (ej. Apache/Nginx).

---

### 4️⃣ Procesos Sospechosos / Reverse Shell

**Detección en Dashboard:** Panel "Procesos sospechosos" muestra nc, bash -i, python -c "import socket", etc.

**Acción inmediata:**
- Matar proceso sospechoso:

```bash
sudo kill -9 PID
```

- Identificar usuario que lo lanzó:

```bash
ps -o pid,user,cmd -p PID
```

- Deshabilitar cuenta si está comprometida:

```bash
sudo passwd -l usuario
```

---

### 5️⃣ Escalada de Privilegios

**Detección en Wazuh:** Alertas de sudo inesperados. Archivos críticos modificados (`/etc/passwd`, `/etc/shadow`).

**Acción inmediata:**
- Revisar qué usuario intentó sudo:

```bash
grep "sudo:" /var/log/auth.log
```

- Si ves root comprometido → restringir acceso total (cerrar SSH y trabajar solo desde consola del cloud).

---

## 🚨 Reglas de oro en un CTF defensa

- Detecta → Bloquea → Reporta (en el chat de tu equipo).
- No caigas en pánico: bloquea IPs primero, luego investigas.
- Divide roles:
  - Uno mirando dashboard.
  - Uno aplicando bloqueos.
  - Uno revisando procesos/servicios.
- Documenta ataques: anota IPs, tiempos y técnicas (te servirá para ganar puntos).
- Mantén viva la máquina: si un servicio no es crítico → mejor detenerlo que dejar que lo exploten.

---

## Esquema de la defensa SOC

### ✅ Checklist de Configuración con Wazuh (CTF Defensa)

**1️⃣ Preparar el servidor**  
Actualizar el sistema:

```bash
sudo apt update && sudo apt upgrade -y
```

Instalar dependencias básicas:

```bash
sudo apt install curl wget git unzip -y
```

**2️⃣ Instalar Wazuh**  
Instalar Wazuh Manager (si eres tú quien centraliza la defensa, en otra máquina o en la misma).

Instalar Wazuh Agent en el servidor a defender:

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-agent-4.7.3.deb
sudo WAZUH_MANAGER="IP_DEL_MANAGER" dpkg -i ./wazuh-agent-4.7.3.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

🔹 Logs cubiertos automáticamente: auth.log, syslog, sudo, procesos, rootkits.

**3️⃣ Conectar a un stack de análisis**  
Instalar Elasticsearch + Kibana (o OpenSearch) junto a Wazuh.

Revisar que puedas entrar al dashboard en: `http://IP_DEL_MANAGER:5601`

Importar dashboards listos de Wazuh.

**4️⃣ Añadir seguridad de red**  
Instalar Suricata (IDS/IPS):

```bash
sudo apt install suricata -y
```

Configurar en modo IDS escuchando la interfaz de red:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

Integrar los logs de Suricata con Wazuh:  
En `/var/ossec/etc/ossec.conf` → añadir entrada de log Suricata.

Activar iptables/UFW con logging:

```bash
sudo ufw enable
sudo ufw logging on
sudo ufw allow ssh
```

**5️⃣ Configurar Active Responses en Wazuh**  
Editar `/var/ossec/etc/ossec.conf` → activar:

- firewalld → bloquear IP atacante.
- host-deny → añadir IP a `/etc/hosts.deny`.
- disable-account → deshabilitar usuario sospechoso.

Ejemplo de respuesta automática:

```xml
<active-response>
  <command>firewalld</command>
  <location>local</location>
  <level>6</level>
  <timeout>600</timeout>
</active-response>
```

**6️⃣ Integrar Threat Intelligence**  
Conectar con AlienVault OTX (gratis).

Activar reglas de Wazuh con IOCs públicos.

(Opcional) Configurar consulta a VirusTotal API para hashes.

**7️⃣ Monitoreo en tiempo real**  
Dashboard de Kibana/OpenSearch:

- Panel de intentos SSH fallidos.
- Alertas de Suricata (exploit, scan, DoS).
- Actividad de rootkits.
- IPs bloqueadas por Active Responses.
- Opcional: configurar alertas por correo/Slack/Telegram.
