
Wazuh es el “cerebro” de un SOC open-source, capaz de recopilar información de múltiples fuentes, analizarla en tiempo real y responder ante incidentes. Se utiliza tanto en entornos empresariales como en laboratorios de ciberseguridad y CTFs para entrenar habilidades defensivas.


¿Qué hace Wazuh?

Recolecta logs y eventos

Desde sistemas Linux, Windows y macOS mediante el Wazuh Agent.

También puede recibir información de firewalls, IDS (Suricata, Zeek), antivirus y aplicaciones de terceros.

Correlaciona y analiza

El Wazuh Manager aplica reglas predefinidas y personalizadas para identificar anomalías, ataques o comportamientos sospechosos.

Se apoya en bases de datos de amenazas (IOCs) como AlienVault OTX.

Visualiza y reporta

A través del Wazuh Dashboard (basado en Kibana/OpenSearch) se pueden ver paneles con intentos de intrusión, procesos maliciosos, actividad de usuarios y mucho más.

Responde automáticamente

Con Active Responses, Wazuh puede:

Bloquear direcciones IP en el firewall.

Matar procesos sospechosos.

Deshabilitar cuentas comprometidas.

Esto permite reaccionar en segundos ante un ataque.

⚙️ ¿Cómo se utiliza en la práctica?

En un SOC (Centro de Operaciones de Seguridad):

Los agentes instalados en los servidores/víctimas envían información al Wazuh Manager.

El equipo de seguridad monitorea el dashboard para detectar ataques en tiempo real.

Se crean reglas personalizadas según el entorno (ejemplo: alertar si un usuario usa sudo fuera de horario laboral).

Se integran herramientas adicionales (Suricata, Zeek, ClamAV, OTX) para tener visibilidad total.
