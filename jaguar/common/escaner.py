# -*- coding: utf-8 -*-
"""Escaneo de red/puertos con sockets (nmap opcional). Multiplataforma.

Acepta como objetivo: una IP, un nombre de host, una subred CIDR
(`192.168.1.0/24`) o un rango (`192.168.1.10-50` y
`192.168.1.10-192.168.1.50`).

Guardarraíl: una `/16` son 65 534 hosts; con puertos por defecto eso no
termina nunca. `MAX_HOSTS` recorta y avisa por el callback de progreso.
"""
import ipaddress
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ES_WIN = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000

# Tope de hosts por escaneo (protege de /16 y de rangos absurdos).
MAX_HOSTS = 4096

# Timeouts (segundos). Cortos: es un barrido, no un fingerprint fino.
T_CONEXION = 0.6
T_BANNER = 0.4


def _sc():
    return {"creationflags": CREATE_NO_WINDOW} if ES_WIN else {}


PUERTOS_COMUNES = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123,
                   135, 137, 138, 139, 143, 161, 389, 443, 445, 464, 500, 512,
                   513, 514, 587, 636, 873, 990, 993, 995, 1025, 1080, 1099,
                   1433, 1434, 1521, 1701, 1723, 1900, 2049, 2082, 2083, 2181,
                   2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4444, 4848,
                   5000, 5432, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
                   7001, 7002, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888,
                   9000, 9042, 9090, 9092, 9200, 9300, 9418, 10000, 11211,
                   15672, 27017, 27018, 50000, 50070, 61616]

_SERVICIOS = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
              53: "dns", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
              135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
              143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
              464: "kpasswd", 587: "smtp-sub", 636: "ldaps", 873: "rsync",
              993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
              1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
              2376: "docker-tls", 3000: "node/gitea", 3306: "mysql", 3389: "rdp",
              3690: "svn", 4444: "msf-handler", 5000: "upnp/flask", 5432: "postgres",
              5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
              5985: "winrm", 5986: "winrm-tls", 6379: "redis", 7001: "weblogic",
              8080: "http-alt", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
              9000: "php-fpm", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
              9418: "git", 11211: "memcached", 15672: "rabbitmq-mgmt",
              27017: "mongodb", 27018: "mongodb", 50070: "hdfs", 61616: "activemq"}


# ===========================================================================
#  Utilidades de red
# ===========================================================================
def ip_local():
    """IP de la interfaz de salida. No abre tráfico real (UDP connect)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def detectar_subred():
    """Subred /24 del equipo. Fallback razonable si no hay ruta."""
    try:
        return str(ipaddress.ip_network(ip_local() + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def resolver(objetivo):
    """Nombre -> IP. Si ya es IP, la devuelve igual."""
    try:
        return socket.gethostbyname(objetivo)
    except Exception:
        return objetivo


def expandir_objetivo(objetivo, limite=MAX_HOSTS):
    """Convierte el objetivo en una lista de IPs.

    Acepta '192.168.1.0/24', '192.168.1.10-50', '192.168.1.10-192.168.1.50'
    y un host suelto. Nunca lanza: en caso raro devuelve [objetivo].
    """
    objetivo = (objetivo or "").strip()
    if not objetivo:
        return [ip_local()]

    if "/" in objetivo:
        try:
            red = ipaddress.ip_network(objetivo, strict=False)
        except Exception:
            return [objetivo]
        hosts = [str(h) for h in red.hosts()]
        # Una /32 no tiene .hosts() útil para nosotros.
        if not hosts:
            hosts = [str(red.network_address)]
        return hosts[:limite]

    if "-" in objetivo and "." in objetivo:
        ini, _, fin = objetivo.partition("-")
        ini, fin = ini.strip(), fin.strip()
        base = ini.rsplit(".", 1)[0]
        try:
            a = int(ini.rsplit(".", 1)[1])
            b = int(fin.rsplit(".", 1)[1]) if "." in fin else int(fin)
            if b >= a:
                return [f"{base}.{i}" for i in range(a, min(b, a + limite - 1) + 1)]
        except Exception:
            pass

    return [objetivo]


# Alias privado por compatibilidad con código antiguo.
_expandir_objetivo = expandir_objetivo


def expandir_puertos(puertos):
    """'22,80,443' / '1-1024' -> [int]. Vacío -> PUERTOS_COMUNES."""
    puertos = (puertos or "").strip()
    if not puertos:
        return list(PUERTOS_COMUNES)
    salida = []
    for parte in puertos.split(","):
        parte = parte.strip()
        if "-" in parte:
            try:
                a, b = parte.split("-", 1)
                salida += list(range(int(a), int(b) + 1))
            except Exception:
                pass
        elif parte.isdigit():
            p = int(parte)
            if 0 < p < 65536:
                salida.append(p)
    return salida or list(PUERTOS_COMUNES)


_expandir_puertos = expandir_puertos


# ===========================================================================
#  Sondas
# ===========================================================================
def _banner(s, puerto):
    """Lee un banner si el servicio lo entrega sin preguntar. Corto y seguro."""
    try:
        s.settimeout(T_BANNER)
        datos = s.recv(256)
        if not datos:
            return ""
        return datos.decode("utf-8", "replace").strip()[:200]
    except Exception:
        return ""


def _probar(ip, puerto):
    """True/None -> dict con el puerto abierto."""
    s = socket.socket()
    s.settimeout(T_CONEXION)
    try:
        if s.connect_ex((ip, puerto)) != 0:
            return None
        return {"puerto": puerto,
                "servicio": _SERVICIOS.get(puerto, "?"),
                "banner": _banner(s, puerto)}
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _ping(ip):
    """Ping multiplataforma. Si no hay binario, se asume vivo."""
    cmd = (["ping", "-n", "1", "-w", "700", ip] if ES_WIN
           else ["ping", "-c", "1", "-W", "1", ip])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, **_sc())
        return r.returncode == 0
    except Exception:
        return True


def _reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ===========================================================================
#  Escaneo
# ===========================================================================
def escanear(objetivo, puertos="", progreso=None, usar_nmap=True):
    """Escanea hosts y puertos. Devuelve list[dict] con ip/host/puertos.

    dict de host: {"ip": str, "host": str, "puertos": [{"puerto","servicio",
    "banner"}, ...]}. Solo se incluyen hosts con al menos un puerto abierto.

    `progreso` es un callable(0-100) opcional; se invoca desde el mismo hilo.
    """
    objetivo = (objetivo or "").strip() or detectar_subred()
    hosts = expandir_objetivo(objetivo)
    lista_puertos = expandir_puertos(puertos)

    if usar_nmap and shutil.which("nmap"):
        try:
            res = _escanear_nmap(objetivo, lista_puertos, progreso)
            if res:
                return res
        except Exception:
            # Si nmap se atraganta, seguimos con sockets.
            pass

    return _escanear_socket(hosts, lista_puertos, progreso)


def _escanear_socket(hosts, lista_puertos, progreso):
    resultado = []
    total = max(1, len(hosts))
    for i, ip in enumerate(hosts):
        abiertos = []
        try:
            with ThreadPoolExecutor(max_workers=min(128, max(1, len(lista_puertos)))) as ex:
                for r in ex.map(lambda p, _ip=ip: _probar(_ip, p), lista_puertos):
                    if r:
                        abiertos.append(r)
        except Exception:
            pass
        if abiertos:
            abiertos.sort(key=lambda p: p["puerto"])
            resultado.append({"ip": ip, "host": _reverse(ip), "puertos": abiertos})
        if progreso:
            try:
                progreso(int((i + 1) / total * 100))
            except Exception:
                pass
    return resultado


def _escanear_nmap(objetivo, puertos, progreso):
    rango = ",".join(str(p) for p in puertos)
    cmd = ["nmap", "-sV", "-Pn", "-T4", "--open", "--host-timeout", "90s",
           "-p", rango, objetivo]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, **_sc())
    resultado = []
    for linea in (r.stdout or "").splitlines():
        if linea.startswith("Nmap scan report for "):
            resto = linea.replace("Nmap scan report for ", "").strip()
            if "(" in resto:
                host, ip = resto.split("(", 1)
                ip = ip.rstrip(")").strip()
                host = host.strip()
            else:
                ip, host = resto, ""
            resultado.append({"ip": ip, "host": host, "puertos": []})
        elif "/tcp" in linea and "open" in linea and resultado:
            campos = linea.split()
            try:
                puerto = int(campos[0].split("/")[0])
            except Exception:
                continue
            resultado[-1]["puertos"].append(
                {"puerto": puerto,
                 "servicio": campos[2] if len(campos) > 2 else "?",
                 "banner": " ".join(campos[3:])})
    if progreso:
        try:
            progreso(100)
        except Exception:
            pass
    return [h for h in resultado if h["puertos"]]