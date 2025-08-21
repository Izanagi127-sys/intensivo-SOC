Para usar wazuh por lo general usaremos 2 maquinas 
Topología recomendada

Máquina 1 → Wazuh Manager

Ubuntu Server 22.04 (recomendado)

Instalas Wazuh Manager + Kibana (dashboard).

Esta máquina será tu “SOC” para visualizar y gestionar alertas.

Máquina 2 → Agente (Victima o Servidor a monitorear)

Puede ser Ubuntu o Windows.

Instalas el Wazuh Agent y lo apuntas a la IP del Manager.



en la maquina 1 manager
usaremos los siguientes comandos 
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Descargar script oficial
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh  este link puede variar segun la maquina que uses ubuntu etc

# Dar permisos
chmod +x wazuh-install.sh

# Instalar (Manager + Dashboard)
sudo ./wazuh-install.sh -a
usuario y contraseña aparecen al final de la instalacion guardalos bien 



una ves termine  usaremos esto 
https://IP_PUBLICA_MAQUINA1



. Instalar Wazuh Agent (Máquina 2)
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Descargar agente
curl -sO https://packages.wazuh.com/4.x/wazuh-agent-4.7.3.deb    este link puede variar segun la maquina que uses ubuntu etc

# Instalar
sudo dpkg -i wazuh-agent-4.7.3.deb


Editar archivo de configuración para apuntar al manager:
sudo nano /var/ossec/etc/ossec.conf
Busca la sección <address> y coloca la IP pública o privada del Manager:
<server>
  <address>IP_DEL_MANAGER</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent


