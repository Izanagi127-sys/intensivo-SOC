# 🛡️ intensivo-SOC

## Explicación de Conceptos Clave en Ciberseguridad

### ¿Qué es un CTF de Defensa? 🛡️
Un CTF (Capture The Flag) de defensa es una competencia de ciberseguridad donde los equipos asumen el rol de Blue Team (equipo azul). Su principal objetivo no es atacar, sino defender una infraestructura ante intentos reales de intrusión.

La meta es mantener los servicios y sistemas en funcionamiento, identificar y mitigar vulnerabilidades, y responder a incidentes en tiempo real. Ganar no se trata de obtener "banderas" (claves secretas), sino de demostrar habilidades de protección y respuesta.

**Objetivos principales:**
- Detectar ataques a tiempo.
- Bloquear a los atacantes.
- Restaurar los sistemas comprometidos.
- Documentar cada acción para ganar puntos.

---

### SOC (Security Operations Center) 🏢
El SOC es un centro de operaciones de seguridad. Es el equipo y las instalaciones dentro de una organización dedicadas a monitorear, detectar, analizar y responder a las ciberamenazas. Piensa en el SOC como el centro de mando de la defensa digital.

**Responsabilidades del SOC:**
- Vigilar el tráfico de la red y los sistemas.
- Utilizar herramientas como SIEM y Wazuh para detectar incidentes.
- Analizar las alertas y determinar si son amenazas reales.
- Coordinar la respuesta ante un incidente.

---

### SIEM (Security Information and Event Management) 📈
SIEM es una categoría de software que combina las funciones de SIM (Security Information Management) y SEM (Security Event Management). Su propósito es centralizar, analizar y correlacionar datos de eventos de seguridad para facilitar la detección de amenazas complejas.

**Funciones principales de un SIEM:**
- **Recopilación de Datos:** Agrega logs de toda la infraestructura.
- **Normalización:** Formatea los datos para que sean analizables.
- **Correlación de Eventos:** Busca patrones y relaciones entre eventos para identificar amenazas complejas que un solo log no revelaría.
- **Generación de Alertas:** Notifica a los analistas de seguridad sobre posibles incidentes.

---

### Wazuh y sus Componentes 🧠
Wazuh es una plataforma de seguridad de código abierto que integra funciones de SIEM y HIDS (Host-based Intrusion Detection System). Es fundamental para el monitoreo de seguridad, la gestión de vulnerabilidades y la respuesta ante incidentes.

**Componentes clave:**
- **Wazuh Manager:** Es el cerebro del sistema. Recibe, procesa y analiza los datos de los agentes. Aplica reglas de detección, correlaciona eventos y genera alertas. También gestiona la configuración y administración centralizada.
- **Wazuh Agent:** Software ligero instalado en los sistemas a proteger (servidores, endpoints, etc.).
  - Recopila logs: Monitoriza logs del sistema, aplicaciones y servicios.
  - Monitoreo de integridad de archivos (FIM): Detecta cambios no autorizados en archivos críticos.
  - Detección de rootkits: Escanea el sistema en busca de programas maliciosos ocultos.
  - Evaluación de vulnerabilidades: Identifica software vulnerable.
- **Active Response:** Capacidad clave de Wazuh que permite tomar medidas automáticas ante amenazas detectadas, ejecutando comandos predefinidos para mitigar riesgos.

---

### Otros Componentes Necesarios en el SOC

- **Suricata:** IDS/IPS (Intrusion Detection/Prevention System) de red. Analiza el tráfico en tiempo real para detectar amenazas, escaneos de puertos y exploits, usando reglas personalizables.
- **UFW (Uncomplicated Firewall):** Interfaz simplificada para iptables, el firewall de Linux. Permite gestionar reglas para controlar el tráfico entrante y saliente de manera sencilla.
- **ELK Stack (Elasticsearch, Logstash, Kibana):** Conjunto de herramientas para la gestión y visualización de logs.
  - **Elasticsearch:** Motor de búsqueda y análisis distribuido.
  - **Logstash:** Pipeline para procesar datos de múltiples fuentes.
  - **Kibana:** Dashboard para explorar y visualizar datos en Elasticsearch. Wazuh se integra perfectamente con ELK para proporcionar dashboards de seguridad.
- **Threat Intelligence (TI):** Datos sobre amenazas que ayudan a anticipar o detectar ataques. Fuentes como AlienVault OTX proporcionan IOCs (Indicators of Compromise) para mejorar la detección.

---

## Tácticas y Estrategias del Atacante (Red Team) 😈

Un atacante sigue un ciclo de vida para comprometer un sistema. Tu objetivo es romper este ciclo en cada fase:

### 1. Reconocimiento
- **Ataque:** Escanean la red en busca de servicios y vulnerabilidades (nmap), recopilan información de dominios (WHOIS), y buscan usuarios y correos en fuentes públicas.
- **Defensa:** Suricata detecta escaneos y puedes bloquear automáticamente las IPs con Active Responses.

### 2. Explotación Inicial
- **Ataque:** Utilizan vulnerabilidades en servicios o ataques de fuerza bruta para obtener acceso.
- **Defensa:** Wazuh Agents detectan intentos de fuerza bruta en tiempo real. Suricata identifica intentos de explotación. Wazuh alerta sobre cambios sospechosos.

### 3. Persistencia
- **Ataque:** Buscan asegurar acceso futuro, creando usuarios ocultos o modificando archivos de inicio.
- **Defensa:** Wazuh FIM alerta sobre modificaciones en archivos clave y usuarios, así como cambios en tareas programadas.

### 4. Escalada de Privilegios
- **Ataque:** Intentan obtener privilegios de administrador/root para control total.
- **Defensa:** Wazuh detecta intentos de sudo inesperados o comandos sospechosos.

### 5. Movimiento Lateral
- **Ataque:** Saltan de un servidor comprometido a otros de la red.
- **Defensa:** Monitorea tráfico saliente anómalo. Suricata y UFW ayudan a restringir y detectar movimientos laterales.

### 6. Borrado de Huellas
- **Ataque:** Borran logs tras lograr su objetivo.
- **Defensa:** Wazuh reenvía logs en tiempo real al Manager, asegurando que la información esté a salvo aunque se borren en el sistema.

---

## Consejos Adicionales para un CTF de Defensa

- **No confíes en la configuración por defecto:** Cambia puertos de servicios críticos, revisa y refuerza configuraciones.
- **Divide el trabajo:** Asigna roles; uno en el dashboard de Kibana y otro en la terminal para aplicar bloqueos y remediar incidentes.
- **Cuida los recursos:** Bloquea IPs, pero gestiona los recursos del sistema; el timeout de las respuestas automáticas es fundamental para evitar sobrecarga.

---
