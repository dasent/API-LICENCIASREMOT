from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import hashlib, json

app = FastAPI(title="API Licencias RemotPress")

USUARIOS = json.load(open("users.json"))

CONTADORES = {u:{ "1":0,"3":0,"12":0} for u,d in USUARIOS.items() if not d.get("admin",False)}

def gen(machine_hash, fecha):
    f = fecha.replace("-","")
    raw = machine_hash + "REMOTPRESS2024" + f
    h = hashlib.sha256(raw.encode()).hexdigest().upper()
    return f"REMOT-{f}-{h}"

@app.get("/api/ping")
def ping():
    return {"status":"online"}

@app.post("/api/generar")
def generar(usuario: str = Form(...), clave: str = Form(...),
            machine_hash: str = Form(...), meses: int = Form(...)):

    if usuario not in USUARIOS or USUARIOS[usuario]["clave"]!=clave:
        return JSONResponse({"status":"error","detail":"Credenciales inválidas"},401)

    admin = USUARIOS[usuario].get("admin",False)

    dur = {"1":30,"3":90,"12":365}
    if str(meses) not in dur:
        return {"status":"error","detail":"Solo 1,3,12 meses"}

    dias = dur[str(meses)]
    fecha = (datetime.now()+timedelta(days=dias)).strftime("%Y-%m-%d")

    if admin:
        return {"status":"ok","licencia":gen(machine_hash.upper(),fecha),"expira":fecha}

    lim = USUARIOS[usuario]["limites"]
    if CONTADORES[usuario][str(meses)]>=lim[str(meses)]:
        return {"status":"error","detail":"Límite alcanzado"}

    CONTADORES[usuario][str(meses)] += 1
    return {"status":"ok","licencia":gen(machine_hash.upper(),fecha),"expira":fecha}

@app.post("/api/validar")
def validar(codigo:str=Form(...),machine_hash:str=Form(...)):
    try:
        f = codigo.split("-")[1]
        fecha=f"{f[:4]}-{f[4:6]}-{f[6:8]}"
    except:
        return {"status":"invalid"}

    if datetime.strptime(fecha,"%Y-%m-%d")<datetime.now():
        return {"status":"expired","expira":fecha}
    return {"status":"valid","expira":fecha}
