# ¿Qué es Wazuh y cómo funciona en un SOC?

Wazuh es el “cerebro” de un SOC open-source, capaz de recopilar información de múltiples fuentes, analizarla en tiempo real y responder ante incidentes.  
Se utiliza tanto en entornos empresariales como en laboratorios de ciberseguridad y CTFs para entrenar habilidades defensivas.

---

## 🔎 ¿Qué hace Wazuh?

### 1. Recolecta logs y eventos

- Desde sistemas Linux, Windows y macOS mediante el **Wazuh Agent**.
- También puede recibir información de firewalls, IDS (Suricata, Zeek), antivirus y aplicaciones de terceros.

### 2. Correlaciona y analiza

- El **Wazuh Manager** aplica reglas predefinidas y personalizadas para identificar anomalías, ataques o comportamientos sospechosos.
- Se apoya en bases de datos de amenazas (IOCs) como AlienVault OTX.

### 3. Visualiza y reporta

- A través del **Wazuh Dashboard** (basado en Kibana/OpenSearch) puedes ver paneles con intentos de intrusión, procesos maliciosos, actividad de usuarios y mucho más.

### 4. Responde automáticamente

Con **Active Responses**, Wazuh puede:
- Bloquear direcciones IP en el firewall.
- Matar procesos sospechosos.
- Deshabilitar cuentas comprometidas.

> Esto permite reaccionar en segundos ante un ataque.

---

## ⚙️ ¿Cómo se utiliza en la práctica?

En un **SOC (Centro de Operaciones de Seguridad)**:

1. Los agentes instalados en los servidores/víctimas envían información al **Wazuh Manager**.
2. El equipo de seguridad monitorea el dashboard para detectar ataques en tiempo real.
3. Se crean reglas personalizadas según el entorno (ejemplo: alertar si un usuario usa `sudo` fuera de horario laboral).
4. Se integran herramientas adicionales (Suricata, Zeek, ClamAV, OTX) para tener visibilidad total.

---
