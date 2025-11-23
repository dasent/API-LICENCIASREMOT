from fastapi import FastAPI, Form, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import hashlib
import json
import secrets  # <- para generar API Keys aleatorias

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

    # Limites: claves a int
    limites_raw = data.get("limites", {})
    limites_int = {}
    for k, v in limites_raw.items():
        try:
            limites_int[int(k)] = int(v)
        except Exception:
            continue

    # Usados: también a int y alineado con limites
    usados_raw = data.get("usados", {})
    usados_int = {}
    for mk in limites_int.keys():
        val = usados_raw.get(str(mk), usados_raw.get(mk, 0))
        try:
            usados_int[mk] = int(val)
        except Exception:
            usados_int[mk] = 0

    if limites_int:
        info["limites"] = limites_int
    if usados_int:
        info["usados"] = usados_int
    else:
        if limites_int:
            info["usados"] = {m: 0 for m in limites_int.keys()}

    USUARIOS[user] = info

    # Mapear api_key a usuario
    if info["api_key"]:
        API_KEYS[info["api_key"]] = user


def guardar_usuarios_en_archivo():
    """
    Vuelca USUARIOS -> users.json con limites/usados como strings.
    Así los contadores quedan persistentes.
    """
    data_out = {}
    for user, info in USUARIOS.items():
        item = {
            "clave": info.get("clave"),
            "admin": info.get("admin", False),
            "api_key": info.get("api_key")
        }
        limites = info.get("limites", {})
        usados = info.get("usados", {})

        if limites:
            item["limites"] = {str(k): int(v) for k, v in limites.items()}
        if usados:
            item["usados"] = {str(k): int(v) for k, v in usados.items()}

        data_out[user] = item

    with open("users.json", "w", encoding="utf-8") as f:
        json.dump(data_out, f, ensure_ascii=False, indent=4)


# Duraciones en días
MESES_A_DIAS = {
    1: 30,
    3: 90,
    12: 365
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

    # 4) Usuario limitado: comprobar límites PERSISTENTES
    limites = info_usuario.get("limites", {})
    if meses not in limites:
        return JSONResponse(
            {"status": "error", "detail": "Este usuario no tiene permitido este plan de meses."},
            status_code=403
        )

    # Asegurar bloque 'usados'
    usados = info_usuario.get("usados")
    if usados is None:
        usados = {m: 0 for m in limites.keys()}
        info_usuario["usados"] = usados

    if usados.get(meses, 0) >= limites[meses]:
        return JSONResponse(
            {
                "status": "error",
                "detail": f"Límite alcanzado para {meses} mes(es). "
                          f"Permitidas: {limites[meses]}, usadas: {usados.get(meses, 0)}"
            },
            status_code=403
        )

    # 5) Generar licencia y actualizar contador (memoria + archivo)
    licencia = generar_licencia(machine_hash.strip().upper(), fecha_expira)
    usados[meses] = usados.get(meses, 0) + 1
    info_usuario["usados"] = usados
    USUARIOS[usuario] = info_usuario
    guardar_usuarios_en_archivo()

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
    """Valida una licencia. Autenticación por API Key activada."""

    # Autenticar también aquí si quieres control
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


@app.post("/api/admin/crear_distribuidor")
async def crear_distribuidor(
    nombre: str = Form(..., description="Nombre de usuario del distribuidor (ej: tcnomatic2)"),
    clave: str = Form(..., description="Clave interna para este usuario"),
    api_key_nueva: str | None = Form(
        None,
        description="API Key para el distribuidor. Si se deja vacío, se genera automáticamente."
    ),
    limite_1: int = Form(0, description="Cantidad máxima de licencias de 1 mes"),
    limite_3: int = Form(0, description="Cantidad máxima de licencias de 3 meses"),
    limite_12: int = Form(0, description="Cantidad máxima de licencias de 12 meses"),
    admin_api_key: str = Header(default=None, alias="X-API-Key")
):
    """
    Crea un nuevo distribuidor en users.json.
    Solo puede ser llamado con una API Key de ADMIN (por ejemplo, dasent).
    Si 'api_key_nueva' viene vacío, se genera automáticamente.
    """

    # 1) Verificar que quien llama es admin
    try:
        usuario_admin, info_admin = autenticar_api_key(admin_api_key)
    except JSONResponse as e:
        return e

    if not info_admin.get("admin", False):
        return JSONResponse(
            {"status": "error", "detail": "Solo un usuario ADMIN puede crear distribuidores."},
            status_code=403
        )

    # 2) Validar que no exista el usuario
    if nombre in USUARIOS:
        return JSONResponse(
            {"status": "error", "detail": f"Ya existe un usuario con el nombre '{nombre}'."},
            status_code=400
        )

    # 3) Si no se envió api_key_nueva, generarla automáticamente
    if not api_key_nueva or not api_key_nueva.strip():
        # Genera algo como: RMT-API-NOMBRE-XXXXXXXXXXXXXXX
        base_nombre = nombre.upper().replace(" ", "")
        while True:
            random_suffix = secrets.token_hex(8).upper()  # 16 chars hex
            candidate = f"RMT-API-{base_nombre}-{random_suffix}"
            if candidate not in API_KEYS:
                api_key_nueva = candidate
                break
    else:
        # Verificar que la API Key no esté repetida si la mandan manualmente
        if api_key_nueva in API_KEYS:
            return JSONResponse(
                {"status": "error", "detail": "Esa API Key ya está en uso por otro usuario."},
                status_code=400
            )

    # 4) Construir limites
    limites = {}
    if limite_1 > 0:
        limites[1] = limite_1
    if limite_3 > 0:
        limites[3] = limite_3
    if limite_12 > 0:
        limites[12] = limite_12

    # 5) Crear entrada en memoria (USUARIOS, API_KEYS, RAW_USERS)
    info_nuevo = {
        "clave": clave,
        "admin": False,
        "api_key": api_key_nueva
    }
    if limites:
        info_nuevo["limites"] = limites
        info_nuevo["usados"] = {m: 0 for m in limites.keys()}

    USUARIOS[nombre] = info_nuevo
    API_KEYS[api_key_nueva] = nombre

    # Actualizar RAW_USERS y guardar en users.json
    RAW_USERS[nombre] = {
        "clave": clave,
        "admin": False,
        "api_key": api_key_nueva,
        "limites": {str(k): v for k, v in limites.items()},
        "usados": {str(k): 0 for k in limites.keys()}
    }

    with open("users.json", "w", encoding="utf-8") as f:
        json.dump(RAW_USERS, f, ensure_ascii=False, indent=4)

    return {
        "status": "ok",
        "detail": "Distribuidor creado correctamente.",
        "usuario": nombre,
        "api_key": api_key_nueva,
        "limites": limites
    }
