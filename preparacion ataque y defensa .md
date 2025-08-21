# Preparación en Defensa (Blue Team) y Ataque (Red Team)

## 🛡️ Blue Team: Mantener tu servidor vivo bajo ataque

### 1. Conéctate rápido

- Ten lista tu llave SSH y accede en segundos apenas comience la competencia.
- Ejemplo:
  ```bash
  ssh -i clave.pem usuario@IP
  ```

### 2. Enumera servicios expuestos

- Descubre qué servicios están activos:
  ```bash
  ss -tulnp
  sudo netstat -tulnp
  ```
- Deshabilita servicios innecesarios:
  ```bash
  sudo systemctl stop servicio
  sudo systemctl disable servicio
  ```

### 3. Aplica hardening rápido

- Cambia contraseñas de usuarios:
  ```bash
  passwd
  ```
- Revisa usuarios existentes:
  ```bash
  cat /etc/passwd
  ```
- Apaga servicios innecesarios y cierra puertos:
  ```bash
  sudo ufw default deny incoming
  sudo ufw allow ssh
  sudo ufw enable
  ```

### 4. Monitorea procesos maliciosos

- Ver procesos activos:
  ```bash
  ps aux --sort=-%cpu | head
  top
  ```
- Elimina procesos sospechosos:
  ```bash
  sudo kill -9 PID
  ```

### 5. Monitorea logs

- Revisa archivos clave:
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/nginx/error.log` (si tienes web)
- Busca accesos raros:
  ```bash
  tail -f /var/log/auth.log
  ```

### 6. Automatiza defensa

- Script básico para ejecutar al inicio:
  ```bash
  #!/bin/bash
  sudo apt update -y
  sudo apt upgrade -y
  sudo ufw allow ssh
  sudo ufw default deny incoming
  sudo ufw enable
  ```
- Instala fail2ban para bloquear IPs con muchos intentos fallidos:
  ```bash
  sudo apt install fail2ban -y
  ```

---

## ⚔️ Red Team: Explotar máquinas rivales y robar flags

### 1. Reconocimiento

- Escaneo con nmap:
  ```bash
  nmap -sV -p- IP_VICTIMA
  ```
- Identifica versiones de servicios para buscar exploits.

### 2. Explotación rápida

- Si hay web server: prueba SQLi, LFI, RCE.
- Para servicios antiguos (FTP, SMB): busca exploits en searchsploit o ExploitDB.
- Usa Metasploit:
  ```bash
  msfconsole
  search servicio version
  ```

### 3. Captura de Flags

- Busca archivos tipo flag:
  ```bash
  find / -name "flag*" 2>/dev/null
  ```
- Copia y sube el contenido al scoreboard.

### 4. Automatización

- Crea scripts para repetir ataques, útil porque las flags cambian.
- Ejemplo: script en bash o python que explote, obtenga la flag y la suba automáticamente.

---

## 🧠 Estrategia Mental y de Equipo

- Divide roles: algunos en defensa, otros en ataque.
- Checklists rápidas:
  - **Defender:** cerrar puertos, cambiar credenciales, monitorear logs.
  - **Atacar:** escanear, explotar, capturar flags.
- **Velocidad > perfección:** lo más importante es cerrar los agujeros evidentes y mantener tu servicio vivo.

---
