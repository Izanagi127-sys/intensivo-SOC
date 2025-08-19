# Cómo ver puertos abiertos y monitorear seguridad en tu sistema

Uno de los puntos importantes en seguridad defensiva son los puertos abiertos de nuestra máquina, por los cuales los atacantes pueden vulnerar e ingresar a nuestro sistema.

## Cómo ver puertos abiertos en Linux

### 🛡️ Cheatsheet Blue Team – SOC/CTF

#### 🐧 Linux

##### 🔍 Puertos abiertos
- `ss -tuln`  
  Ver puertos TCP/UDP en escucha
- `sudo lsof -i -P -n | grep LISTEN`  
  Ver qué proceso usa cada puerto
- `sudo netstat -tulnp`  
  (si está instalado)

##### 👀 Procesos sospechosos
- `ps aux --sort=-%mem | head -10`  
  Top procesos por memoria
- `ps aux --sort=-%cpu | head -10`  
  Top procesos por CPU
- `sudo pstree -p`  
  Ver árbol de procesos

##### 🧑 Usuarios activos
- `who`  
  Ver usuarios conectados
- `w`  
  Ver usuarios + procesos
- `last -n 10`  
  Últimos 10 logins

##### 📂 Archivos y directorios raros
- `find /tmp -type f -size +0c -ls`  
  Archivos en /tmp (muy usado en exploits)
- `ls -al /root/.ssh`  
  Revisar claves SSH no autorizadas

##### 📜 Logs críticos
- `sudo tail -f /var/log/auth.log`  
  Intentos de login
- `sudo tail -f /var/log/syslog`  
  Eventos del sistema
- `sudo tail -f /var/log/suricata/fast.log`  
  Alertas de Suricata

##### 🧱 Firewall
- `sudo ufw status verbose`  
  Reglas activas
- `sudo ufw deny from IP`  
  Bloquear IP atacante

---

#### 🪟 Windows

##### 🔍 Puertos abiertos
- `netstat -ano`  
  Ver conexiones y PID
- `Get-NetTCPConnection | ?{$_.State -eq "Listen"}`  
  PowerShell moderno

##### 👀 Procesos sospechosos
- `tasklist | findstr "PID"`  
  Lista procesos con PID
- `Get-Process | Sort CPU -Descending | Select -First 10`

##### 🧑 Usuarios activos
- `query user`  
  Ver usuarios conectados
- `net user`  
  Ver cuentas locales

##### 📂 Archivos y directorios
- `dir C:\Users\*\AppData\Roaming`  
  Revisar persistencia en AppData

##### 📜 Logs críticos
- `Get-EventLog Security -Newest 20`  
  Últimos eventos de seguridad
- `wevtutil qe Security /c:20 /f:text /rd:true`

##### 🧱 Firewall
- `netsh advfirewall show allprofiles`
- `netsh advfirewall firewall add rule name="Block Attacker" dir=in action=block remoteip=IP`

---
