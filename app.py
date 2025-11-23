import streamlit as st
import json, requests

st.title("Panel Admin RemotPress 3.2")

st.write("Gestión de usuarios, límites y API.")

users = json.load(open("users.json"))

st.subheader("Usuarios registrados")
st.json(users)

st.subheader("Probar API /ping")
try:
    r=requests.get(st.secrets.get("api_url","http://localhost:8000")+"/api/ping")
    st.json(r.json())
except:
    st.error("No se pudo conectar a la API")
