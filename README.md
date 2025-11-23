
# API de Licencias RemotPress (Autenticación por API Key)

Backend FastAPI para generación y validación de licencias RemotPress Taller.
Usa autenticación por API Key, ideal para distribuidores.

## Archivos

- api.py         -> Código de la API (FastAPI)
- users.json     -> Lista de usuarios/distribuidores con su api_key y límites
- requirements.txt
- Procfile       -> Para despliegue en Render / Railway / Heroku-Like

## Endpoints

### GET /api/ping
Verifica el estado de la API.

### POST /api/generar
Genera una licencia nueva.

Headers:
- X-API-Key: clave de API del distribuidor

Body (x-www-form-urlencoded o form-data):
- machine_hash (str)  -> código de instalación
- meses (int: 1, 3 o 12)

### POST /api/validar
Valida una licencia existente.

Headers:
- X-API-Key: clave de API del distribuidor

Body:
- codigo (str)        -> licencia completa REMOT-YYYYMMDD-...
- machine_hash (str)  -> código de instalación (opcional para validación estricta)

## Ejecución local

```bash
pip install -r requirements.txt
uvicorn api:app --reload
```

La API quedará en: http://127.0.0.1:8000
