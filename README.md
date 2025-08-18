# 🛡️ intensivo-SOC

Explicación de Conceptos Clave en Ciberseguridad
¿Qué es un CTF de Defensa? 🛡️
Un CTF (Capture The Flag) de defensa es un tipo de competencia de ciberseguridad donde los equipos asumen el rol de Blue Team (equipo azul). Su principal objetivo no es atacar, sino defender una infraestructura de red de los ataques de otros equipos (el Red Team).

La meta es mantener los servicios y sistemas en funcionamiento, identificar y mitigar vulnerabilidades, y responder a incidentes en tiempo real. Ganar no se trata de obtener "banderas" (claves secretas), sino de la capacidad del equipo para:

Detectar ataques a tiempo.

Bloquear a los atacantes.

Restaurar los sistemas comprometidos.

Documentar cada acción para ganar puntos.

SOC (Security Operations Center) 🏢
El SOC es un centro de operaciones de seguridad. Es el equipo y las instalaciones dentro de una organización dedicadas a monitorear, detectar, analizar y responder a las ciberamenazas. Piensa en el SOC como el "centro de control" de la seguridad cibernética de una empresa.

Sus responsabilidades incluyen:

Vigilar el tráfico de la red y los sistemas.

Utilizar herramientas como SIEM y Wazuh para detectar incidentes.

Analizar las alertas y determinar si son amenazas reales.

Coordinar la respuesta ante un incidente.

SIEM (Security Information and Event Management) 📈
SIEM es una categoría de software que combina las funciones de SIM (Security Information Management) y SEM (Security Event Management). Su propósito es centralizar, analizar y correlacionar datos de seguridad provenientes de múltiples fuentes, como logs de sistemas, firewalls, y aplicaciones.

Las funciones principales de un SIEM son:

Recopilación de Datos: Agrega logs de toda la infraestructura.

Normalización: Formatea los datos para que sean analizables.

Correlación de Eventos: Busca patrones y relaciones entre eventos para identificar amenazas complejas que un solo log no revelaría.

Generación de Alertas: Notifica a los analistas de seguridad sobre posibles incidentes.

Wazuh y sus Componentes 🧠
Wazuh es una plataforma de seguridad de código abierto que integra funciones de SIEM y HIDS (Host-based Intrusion Detection System). Es una herramienta fundamental para el monitoreo de seguridad, la detección de intrusiones y la respuesta a incidentes.

Se compone de varios elementos:

Wazuh Manager: Es el cerebro del sistema. Recibe, procesa y analiza los datos de los agentes. Aplica reglas de detección, correlaciona eventos y genera alertas. También gestiona la configuración y las políticas de los agentes.

Wazuh Agent: Es un software ligero que se instala en los sistemas a proteger (servidores, endpoints, etc.). El agente se encarga de:

Recopilar logs: Monitoriza logs del sistema, aplicaciones y servicios.

Monitoreo de integridad de archivos (FIM): Detecta cambios no autorizados en archivos críticos.

Detección de rootkits: Escanea el sistema en busca de programas maliciosos ocultos.

Evaluación de vulnerabilidades: Identifica software vulnerable.

Active Response: Es una capacidad clave de Wazuh que permite al agente tomar medidas automáticas para mitigar una amenaza. Cuando se activa una regla de alerta, Wazuh puede ejecutar un comando predefinido en el host afectado, como bloquear una IP en el firewall, matar un proceso malicioso o deshabilitar una cuenta de usuario.

Otros Componentes Necesarios en el SOC
Suricata: Es un IDS/IPS (Intrusion Detection/Prevention System) de red. Analiza el tráfico de red en tiempo real para detectar amenazas, escaneos de puertos y exploits, basándose en un conjunto de reglas (firmas). Puede funcionar en modo de detección (IDS) para solo alertar, o en modo de prevención (IPS) para bloquear el tráfico malicioso automáticamente.

UFW (Uncomplicated Firewall): Es una interfaz simplificada para iptables, el firewall de Linux. Permite gestionar reglas para controlar el tráfico entrante y saliente del servidor de manera sencilla. Es una herramienta esencial para el control de acceso a la red.

ELK Stack (Elasticsearch, Logstash, Kibana): Es un conjunto de herramientas para la gestión de logs y la visualización de datos.

Elasticsearch: Un motor de búsqueda y análisis distribuido.

Logstash: Un pipeline de procesamiento de datos que ingiere datos de múltiples fuentes.

Kibana: Una herramienta de visualización y dashboard que te permite explorar los datos en Elasticsearch y crear gráficos, mapas y cuadros de mando. Wazuh se integra perfectamente con ELK para proporcionar la visualización de las alertas y eventos.

Threat Intelligence (TI): Se refiere a los datos sobre amenazas que pueden ayudar a un equipo de seguridad a anticipar o detectar ataques. Las fuentes de TI, como AlienVault OTX, proporcionan IOCs (Indicadores de Compromiso) como IPs maliciosas, hashes de archivos o dominios. Al integrar TI en el SIEM (como Wazuh), puedes detectar automáticamente si algún host en tu red se comunica con una dirección IP conocida por ser maliciosa.







Tácticas y Estrategias del Atacante (Red Team) 😈
Un atacante no se limita a un solo tipo de ataque. Suelen seguir un ciclo de vida para comprometer un sistema, y tu objetivo es romper este ciclo en cada fase.

Reconocimiento:

¿Qué hace el atacante? Escanean tu red en busca de servicios abiertos y vulnerables (nmap), recopilan información de dominios (WHOIS), y buscan usuarios y correos en fuentes públicas.

Tu defensa: Suricata detecta los escaneos (nmap scan, port scan), y puedes bloquear automáticamente las IPs que intentan estos reconocimientos con Active Responses.

Explotación Inicial:

¿Qué hace el atacante? Utilizan vulnerabilidades en servicios (como una versión antigua de Apache o un fallo en SSH) o ataques de fuerza bruta para obtener un punto de entrada.

Tu defensa: Los Wazuh Agents detectan los intentos de fuerza bruta en tiempo real. Suricata identifica los exploit attempts. Si un atacante logra entrar, Wazuh también te alertará sobre cambios en archivos críticos (/etc/passwd).

Persistencia:

¿Qué hace el atacante? Una vez dentro, intentan asegurarse de que puedan regresar más tarde, incluso si la máquina se reinicia. Crean usuarios ocultos, modifican archivos de inicio del sistema o programan tareas maliciosas.

Tu defensa: El Wazuh FIM (File Integrity Monitoring) es tu mejor amigo aquí. Te alertará si se modifican archivos clave del sistema, si se añaden nuevos usuarios o si se alteran las tareas programadas (crontab).

Escalada de Privilegios:

¿Qué hace el atacante? Tras obtener un acceso inicial como un usuario normal, su siguiente objetivo es convertirse en root o un usuario con privilegios administrativos para tener control total. Buscan archivos con permisos incorrectos (SUID), exploits de kernel o contraseñas reutilizadas.

Tu defensa: Wazuh tiene reglas predefinidas para detectar intentos de sudo inesperados o el uso de comandos poco comunes por usuarios normales.

Movimiento Lateral:

¿Qué hace el atacante? Si hay más de un servidor en el CTF, el atacante intentará saltar de tu servidor comprometido a otros en la misma red.

Tu defensa: Monitorea el tráfico saliente desde tu servidor que no sea el esperado. Suricata te ayudará a detectar esto, y las reglas de tu firewall (UFW) pueden restringir la comunicación saliente a lo estrictamente necesario.

Borrado de Huellas:

¿Qué hace el atacante? Una vez que han logrado su objetivo (por ejemplo, obtener la "bandera"), intentarán borrar los logs para que no los detectes.

Tu defensa: Wazuh reenvía los logs en tiempo real al Wazuh Manager. Esto significa que aunque el atacante borre los logs en tu servidor, la información ya estará a salvo y lista para ser analizada en tu dashboard.

Consejos Adicionales para un CTF de Defensa
No confíes en la configuración por defecto: Aunque el script te da una buena base, un atacante experimentado buscará los servicios por defecto. Cambia los puertos de los servicios críticos (como SSH), deshabilita los que no uses y revisa los usuarios predeterminados.

Divide el trabajo: Como mencionamos en el playbook, tener a una persona enfocada en el dashboard de Kibana y otra en la línea de comandos para aplicar bloqueos y remediar, es clave para una respuesta rápida y coordinada.

No te quedes sin recursos: Bloquear IPs en el firewall es vital, pero asegúrate de que tus Active Responses no consuman todos los recursos del sistema. El timeout de la respuesta es importante para que los bloqueos se limpien después de un tiempo y no saturen la memoria.
