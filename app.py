import streamlit as st
import json
import hashlib
from datetime import datetime, timedelta

# =========================
# CARGA DE USUARIOS DESDE users.json
# =========================
with open("users.json", "r", encoding="utf-8") as f:
    RAW_USERS = json.load(f)

USUARIOS = {}
for user, data in RAW_USERS.items():
    info = {
        "clave": data["clave"],
        "admin": data.get("admin", False)
    }
    # límites: "1","3","12" -> 1,3,12
    limites_raw = data.get("limites", {})
    if limites_raw:
        info["limites"] = {int(k): v for k, v in limites_raw.items()}
    USUARIOS[user] = info

# Duraciones en días para cada plan
MESES_A_DIAS = {
    1: 30,
    3: 90,
    12: 365
}

# =========================
# INICIALIZAR SESSION STATE
# =========================
if "autenticado" not in st.session_state:
    st.session_state["autenticado"] = False
    st.session_state["usuario"] = None

if "contadores_usuarios" not in st.session_state:
    st.session_state["contadores_usuarios"] = {}
    for usuario, info in USUARIOS.items():
        if not info.get("admin", False) and "limites" in info:
            st.session_state["contadores_usuarios"][usuario] = {
                meses: 0 for meses in info["limites"].keys()
            }

# =========================
# FUNCIONES AUXILIARES
# =========================
def generar_licencia(machine_hash: str, fecha_expira: str) -> str:
    """
    Genera la licencia con la misma lógica de tu generador:
    machine_hash + 'REMOTPRESS2024' + fecha -> SHA256
    Formato final: REMOT-YYYYMMDD-HASH
    """
    fecha_compacta = fecha_expira.replace("-", "")
    secret = "REMOTPRESS2024"
    raw = machine_hash + secret + fecha_compacta
    key_hash = hashlib.sha256(raw.encode()).hexdigest().upper()
    return f"REMOT-{fecha_compacta}-{key_hash}"

def show_login():
    st.title("🔑 Panel / Generador de Licencias REMOTPRESS")
    st.write("**Acceso restringido. Solo usuarios autorizados.**")

    usuario = st.text_input("Usuario:", key="usuario_login")
    clave = st.text_input("Contraseña:", type="password", key="clave_login")

    if st.button("Iniciar sesión", key="btn_login"):
        if usuario in USUARIOS and clave == USUARIOS[usuario]["clave"]:
            st.session_state["autenticado"] = True
            st.session_state["usuario"] = usuario
            st.success(f"Bienvenido, {usuario}.")
        else:
            st.error("Usuario o contraseña incorrectos.")
            st.session_state["autenticado"] = False
            st.session_state["usuario"] = None

def main_app():
    usuario = st.session_state["usuario"]
    info_usuario = USUARIOS[usuario]
    admin = info_usuario.get("admin", False)

    st.title("🔑 Panel Admin RemotPress 3.2")
    st.success(f"Sesión iniciada como **{usuario}** "
               f"({'ADMIN' if admin else 'Usuario limitado'})")

    st.write("Gestión de usuarios, límites y **generación de licencias**.")

    # =========================
    # SECCIÓN ADMIN: VER USUARIOS Y LÍMITES
    # =========================
    if admin:
        st.subheader("👥 Usuarios registrados (desde users.json)")
        st.json(RAW_USERS)

        st.markdown("### Estado de licencias de usuarios limitados")
        for user, data in USUARIOS.items():
            if not data.get("admin", False) and "limites" in data:
                limites = data["limites"]
                usados = st.session_state["contadores_usuarios"].get(
                    user, {m: 0 for m in limites.keys()}
                )
                st.write(f"**Usuario:** {user}")
                for meses, limite in limites.items():
                    usados_m = usados.get(meses, 0)
                    st.write(
                        f"- {meses} mes(es): {usados_m}/{limite} usados "
                        f"| Quedan: {limite - usados_m}"
                    )
                st.write("---")

    # =========================
    # SECCIÓN: GENERACIÓN DE LICENCIAS
    # =========================
    st.subheader("🛠 Generar licencia")

    machine_hash = st.text_input("Código de instalación (machine_hash):")

    meses_seleccionados = st.selectbox(
        "Duración de la licencia:",
        options=[1, 3, 12],
        format_func=lambda m: f"{m} mes" if m == 1 else f"{m} meses"
    )

    if st.button("Generar Licencia", key="btn_generar"):
        if not machine_hash.strip():
            st.warning("Debes ingresar el código de instalación (machine_hash).")
        else:
            dias = MESES_A_DIAS[meses_seleccionados]
            fecha_expira = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")

            if admin:
                # Admin: licencias ilimitadas
                key = generar_licencia(machine_hash.strip().upper(), fecha_expira)
                st.success(
                    f"=== LICENCIA GENERADA (ADMIN) ===\n\n"
                    f"KEY:    {key}\n"
                    f"Expira: {fecha_expira}"
                )
                st.code(key, language="none")
                st.info("La clave se muestra arriba. Puedes copiarla y compartirla.")
            else:
                # Usuario limitado: respetar límites de users.json
                limites = info_usuario.get("limites", {})
                contadores = st.session_state["contadores_usuarios"].get(
                    usuario, {m: 0 for m in limites.keys()}
                )

                if meses_seleccionados not in limites:
                    st.error("Solo puedes generar licencias de 1, 3 o 12 meses.")
                elif contadores[meses_seleccionados] >= limites[meses_seleccionados]:
                    st.error(
                        f"Ya alcanzaste el límite de {limites[meses_seleccionados]} "
                        f"licencias de {meses_seleccionados} mes(es)."
                    )
                else:
                    key = generar_licencia(
                        machine_hash.strip().upper(), fecha_expira
                    )
                    st.success(
                        f"=== LICENCIA GENERADA ===\n\n"
                        f"KEY:    {key}\n"
                        f"Expira: {fecha_expira}"
                    )
                    st.code(key, language="none")
                    st.info("La clave se muestra arriba. Puedes copiarla y compartirla.")

                    # Actualizar contador
                    contadores[meses_seleccionados] += 1
                    st.session_state["contadores_usuarios"][usuario] = contadores

                    st.info(
                        "Uso actual:\n" + "\n".join(
                            [
                                f"- {m} mes(es): "
                                f"{contadores.get(m, 0)}/{limites.get(m, 0)}"
                                for m in sorted(limites.keys())
                            ]
                        )
                    )

    # =========================
    # BOTÓN LOGOUT
    # =========================
    if st.button("Cerrar sesión"):
        st.session_state["autenticado"] = False
        st.session_state["usuario"] = None
        st.experimental_rerun()

# =========================
# FLUJO PRINCIPAL
# =========================
if not st.session_state["autenticado"]:
    show_login()
else:
    main_app()
