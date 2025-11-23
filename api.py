
from fastapi import FastAPI, Form, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import hashlib
import json

app = FastAPI(
    title="API de Licencias RemotPress",
    description="API oficial para generación y validación de licencias RemotPress Taller con autenticación por API Key",
    version="1.1.0"
)

# CORS: permite llamadas desde frontends externos si hace falta
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CARGA DE USUARIOS DESDE users.json ==========
with open("users.json", "r", encoding="utf-8") as f:
    RAW_USERS = json.load(f)

USUARIOS = {}
API_KEYS = {}  # api_key -> nombre_usuario

for user, data in RAW_USERS.items():
    info = {
        "clave": data.get("clave"),
        "admin": data.get("admin", False),
        "api_key": data.get("api_key")
    }
    limites_raw = data.get("limites", {})
    if limites_raw:
        info["limites"] = {int(k): v for k, v in limites_raw.items()}
    USUARIOS[user] = info

    # Mapear api_key a usuario
    if info["api_key"]:
        API_KEYS[info["api_key"]] = user

# Duraciones en días
MESES_A_DIAS = {
    1: 30,
    3: 90,
    12: 365
}

# Contadores de uso por distribuidor en memoria
CONTADORES = {
    user: {m: 0 for m in info.get("limites", {}).keys()}
    for user, info in USUARIOS.items()
    if not info.get("admin", False) and "limites" in info
}


# ========== FUNCIONES AUXILIARES ==========
def generar_licencia(machine_hash: str, fecha_expira: str) -> str:
    """Genera la licencia con la lógica original de RemotPress."""
    fecha_compacta = fecha_expira.replace("-", "")
    secret = "REMOTPRESS2024"
    raw = machine_hash + secret + fecha_compacta
    key_hash = hashlib.sha256(raw.encode()).hexdigest().upper()
    return f"REMOT-{fecha_compacta}-{key_hash}"


def autenticar_api_key(api_key: str | None):
    """Devuelve (usuario, info_usuario) si la API key es válida, si no lanza JSONResponse."""
    if not api_key or api_key not in API_KEYS:
        raise JSONResponse(
            {"status": "error", "detail": "API key inválida o ausente"},
            status_code=401
        )
    usuario = API_KEYS[api_key]
    info_usuario = USUARIOS.get(usuario)
    if not info_usuario:
        raise JSONResponse(
            {"status": "error", "detail": "Usuario asociado a la API key no encontrado"},
            status_code=401
        )
    return usuario, info_usuario


# ========== ENDPOINTS ==========

@app.get("/api/ping")
def ping():
    """Comprobar que la API está en línea."""
    return {
        "status": "online",
        "api": "RemotPress Licencias",
        "version": "1.1.0",
    }


@app.post("/api/generar")
async def generar(
    machine_hash: str = Form(...),
    meses: int = Form(...),
    api_key: str = Header(default=None, alias="X-API-Key")
):
    """Genera una licencia nueva usando autenticación por API Key."""

    # 1) Autenticar por API Key
    try:
        usuario, info_usuario = autenticar_api_key(api_key)
    except JSONResponse as e:
        return e

    admin = info_usuario.get("admin", False)

    # 2) Validar parámetros
    if meses not in MESES_A_DIAS:
        return JSONResponse(
            {"status": "error", "detail": "Solo se permiten licencias de 1, 3 o 12 meses."},
            status_code=400
        )

    if not machine_hash.strip():
        return JSONResponse(
            {"status": "error", "detail": "El campo machine_hash está vacío."},
            status_code=400
        )

    dias = MESES_A_DIAS[meses]
    fecha_expira = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")

    # 3) ADMIN: licencias ilimitadas
    if admin:
        licencia = generar_licencia(machine_hash.strip().upper(), fecha_expira)
        return {
            "status": "ok",
            "usuario": usuario,
            "licencia": licencia,
            "expira": fecha_expira,
            "tipo": "admin-ilimitado"
        }

    # 4) Usuario limitado: comprobar límites
    limites = info_usuario.get("limites", {})
    if meses not in limites:
        return JSONResponse(
            {"status": "error", "detail": "Este usuario no tiene permitido este plan de meses."},
            status_code=403
        )

    usados = CONTADORES.get(usuario, {m: 0 for m in limites.keys()})
    if usados[meses] >= limites[meses]:
        return JSONResponse(
            {
                "status": "error",
                "detail": f"Límite alcanzado para {meses} mes(es). "
                          f"Permitidas: {limites[meses]}, usadas: {usados[meses]}"
            },
            status_code=403
        )

    # 5) Generar licencia y actualizar contador
    licencia = generar_licencia(machine_hash.strip().upper(), fecha_expira)
    usados[meses] += 1
    CONTADORES[usuario] = usados

    return {
        "status": "ok",
        "usuario": usuario,
        "licencia": licencia,
        "expira": fecha_expira,
        "usadas": usados,
        "limites": limites
    }


@app.post("/api/validar")
async def validar(
    codigo: str = Form(...),
    machine_hash: str = Form(...),
    api_key: str = Header(default=None, alias="X-API-Key")
):
    """Valida una licencia. Autenticación por API Key opcional (aquí está activada)."""

    # Si quieres que solo clientes autorizados validen, autenticamos también aquí
    try:
        _, _ = autenticar_api_key(api_key)
    except JSONResponse as e:
        return e

    # Extraer fecha del código: REMOT-YYYYMMDD-HASH
    try:
        partes = codigo.split("-")
        if len(partes) < 3 or not partes[1].isdigit() or len(partes[1]) != 8:
            raise ValueError("Formato incorrecto")
        fecha_compacta = partes[1]
        fecha_expira = f"{fecha_compacta[0:4]}-{fecha_compacta[4:6]}-{fecha_compacta[6:8]}"
        fecha_dt = datetime.strptime(fecha_expira, "%Y-%m-%d")
    except Exception:
        return JSONResponse(
            {"status": "invalid", "detail": "Formato de licencia inválido."},
            status_code=400
        )

    if fecha_dt < datetime.now():
        return {
            "status": "expired",
            "expira": fecha_expira
        }

    # (Opcional) Validación estricta con machine_hash:
    # licencia_recalc = generar_licencia(machine_hash.strip().upper(), fecha_expira)
    # if licencia_recalc != codigo:
    #     return {
    #         "status": "invalid",
    #         "detail": "El código no corresponde al machine_hash provisto."
    #     }

    return {
        "status": "valid",
        "expira": fecha_expira
    }
