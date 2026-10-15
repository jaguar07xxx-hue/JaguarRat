# Jaguar — Documentación

RAT/administrador remoto con controlador PyQt6 y agente autocontenido.
Protocolo TCP propio cifrado (HMAC-SHA256 + keystream + PBKDF2). No depende de Metasploit.

## Arquitectura
- `jaguar/ui/` — interfaz (ventana, tema, logo).
- `jaguar/server/` — servidor TCP y sesiones.
- `jaguar/common/` — cripto, protocolo, escáner, exploits nativos, geo, config.
- `jaguar/builder/` — compila el agente y genera droppers.
- `agente/agente.py` — payload que se ejecuta en la víctima.

## Cómo se conecta
1. El agente arranca y prueba, en paralelo, HOST → FALLBACK (LAN) → 127.0.0.1.
2. Handshake `hola` con la info del sistema.
3. El controlador muestra el cliente y permite comandos.

## Requisitos
- Python 3.10+ (recomendado 3.11/3.12).
- Windows para compilar el .exe (Nuitka/PyInstaller no cross-compilan).
- Opcional: nmap, UPX, PyArmor, signtool.

## Instalación paso a paso (VS Code)
1. Instala VS Code y la extensión "Python".
2. Clona el repo y ábrelo en VS Code.
3. `python -m venv .venv`
4. Activa: Windows `.venv\Scripts\activate` | Linux `source .venv/bin/activate`
5. `pip install -r requirements.txt`
6. Ejecuta: `python run.py`

## Generar y desplegar el payload
1. Pestaña **Builder**: pon tu host (IP LAN, IP pública o DDNS) y el puerto.
2. Pulsa **`.exe`** (o **Generar TODO**).
3. Pulsa **`🌐 Servir dist`** y déjalo activo.
4. Copia un dropper (`RuntimeBroker.exe`, `.bat`, `.vbs`, `.lnk`, `.hta`) a la víctima y ejecútalo.

## Importante sobre cada formato
- `.exe` — ejecuta directo, sin consola. El mejor.
- `.bat` — ejecuta (breve consola). Único archivo, autónomo.
- `.vbs` — sin consola. Ejecuta con wscript.
- `.lnk` — doble clic normal.
- `.hta` — doble clic normal.
- `.ps1` — doble clic abre el editor; ejecuta con botón derecho → "Ejecutar con PowerShell".
- `.pdf` — doble clic abre el lector. Para que EJECUTE usa el archivo `.pdf.cmd`.
- `.png` — doble clic abre la foto. Para que EJECUTE usa el archivo `.png.cmd`.
- `.py` — necesita Python en la víctima; ejecútalo con `pythonw` (sin consola).
- `.bas` — impórtalo en Excel (Editor VBA) y ejecuta `Auto_Open`.

## Redes
- **LAN**: usa tu IP local (ej. 192.168.1.50) y abre el puerto en el firewall.
- **WAN/NAT**: abre el puerto del agente (y el 8080 de droppers) en el router,
  apunta a tu IP local, y usa IP pública o DDNS como host.

## subir.php (opcional)
Solo sirve para el stealer: sube un `subir.php` a un hosting y pon su URL en la pestaña Stealer.

## Seguridad
- Cifrado propio por sesión. Cambia `_K_OBF` en `constants.py` para que sea único.