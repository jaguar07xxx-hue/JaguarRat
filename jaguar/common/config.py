# -*- coding: utf-8 -*-
"""Config persistente de Jaguar (host/puerto). Se guarda en ~/.jaguar/config.json."""
import json
import os

from jaguar.common.constants import HOST_DEFECTO, PUERTO_DEFECTO

_RUTA = os.path.join(os.path.expanduser("~"), ".jaguar", "config.json")
_DEFECTO = {"host": HOST_DEFECTO, "puerto": PUERTO_DEFECTO}


def cargar():
    """Devuelve la config guardada, con el DDNS por defecto si no existe."""
    try:
        with open(_RUTA, encoding="utf-8") as f:
            datos = json.load(f)
        return {**_DEFECTO, **datos}
    except Exception:
        return dict(_DEFECTO)


def guardar(host, puerto):
    try:
        os.makedirs(os.path.dirname(_RUTA), exist_ok=True)
        with open(_RUTA, "w", encoding="utf-8") as f:
            json.dump({"host": (host or "").strip(), "puerto": str(puerto).strip()}, f, indent=2)
    except Exception:
        pass