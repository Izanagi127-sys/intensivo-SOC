# Registro manual de Agentes Wazuh: ¿Por qué es necesario y cómo se hace?

El script de instalación (`setup.sh`) automatiza casi todo el proceso para montar un entorno de seguridad con Wazuh en una máquina (Manager + Dashboard + Agent + herramientas de seguridad).  
**Sin embargo, el registro del agente en el Manager debe hacerse manualmente** por razones de seguridad.

---

## ⚙️ ¿Qué hace el script?

- Instala **Wazuh Manager** (centraliza y analiza la información).
- Instala **Wazuh Dashboard** (interfaz web para visualizar alertas y eventos).
- Instala **Wazuh Agent** en la misma máquina (para que también se monitorice a sí misma).
- Activa **IDS/IPS** (Suricata, Snort, Zeek).
- Instala herramientas de endpoint (**OSQuery, YARA, OpenVAS**).
- Configura **firewall UFW** y respuestas activas (Active Response con iptables).

---

## ❌ ¿Qué NO hace automáticamente el script?

**No registra el agente en el Manager de forma automática.**

- El proceso de registro de agentes requiere un paso _manual_ de intercambio de claves.
- Esto es por seguridad: _cada agente debe autenticarse con una clave única generada por el Manager_ para evitar que cualquier máquina pueda conectarse como agente.

---

## ✅ ¿Cómo registrar el agente en el Manager? (Pasos manuales)

**Si instalaste Manager + Dashboard + Agent en la misma máquina (por ejemplo, una EC2):**

1. **Genera la clave en el Manager:**
   ```bash
   sudo /var/ossec/bin/manage_agents
   ```
   - Selecciona `A` (Agregar agente).
   - Ingresa un nombre, por ejemplo: `self-agent`
   - Ingresa la IP: `127.0.0.1`
   - Copia la clave que se genera.

2. **Importa la clave en el Agent:**
   ```bash
   sudo /var/ossec/bin/manage_agents
   ```
   - Selecciona `I` (Importar clave).
   - Pega la clave que copiaste del Manager.

3. **Reinicia el servicio Agent:**
   ```bash
   sudo systemctl restart wazuh-agent
   ```

4. **Verifica que el agente está activo:**
   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```
   - Debes ver el agente con estado `Active`.

---

## 📈 ¿Qué ocurre después?

- El **Agent** se conecta correctamente al **Manager**.
- En el **Dashboard** comenzarás a ver información y alertas generadas por esa máquina (logs, integridad, ataques, etc.).

---

> **Este proceso de registro manual garantiza la seguridad y autenticidad de cada agente conectado al Manager Wazuh.**

---
