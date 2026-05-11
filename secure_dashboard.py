"""
SecureAccess Monitor — Dashboard con Autenticación y Roles
===========================================================
Sistema de autenticación JWT con control de acceso
basado en roles (RBAC).

Roles:
- admin   → acceso total, ve IPs, puede exportar
- analista → solo lectura, IPs enmascaradas
"""

from analysis.alert_severity import construir_alerta_completa, formatear_para_email

import asyncio
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt
from jose import JWTError, jwt
import uvicorn

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from dotenv import load_dotenv
import os

load_dotenv()  # Carga las variables del archivo .env

app = FastAPI()


# ─────────────────────────────────────────────
# CONFIGURACIÓN DE SEGURIDAD
# ─────────────────────────────────────────────

# Clave secreta para firmar los tokens JWT
# En producción esto iría en una variable de entorno, nunca en el código
SECRET_KEY    = os.getenv("SECRET_KEY")
ALGORITHM     = os.getenv("ALGORITHM", "HS256")
TOKEN_EXPIRY  = int(os.getenv("TOKEN_EXPIRY", 60))
MAILTRAP_HOST = os.getenv("MAILTRAP_HOST")
MAILTRAP_PORT = int(os.getenv("MAILTRAP_PORT", 2525))
MAILTRAP_USER = os.getenv("MAILTRAP_USER")
MAILTRAP_PASS = os.getenv("MAILTRAP_PASS")
EMAIL_FROM    = os.getenv("EMAIL_FROM")
EMAIL_ADMIN   = os.getenv("EMAIL_ADMIN")

# Contexto de hashing — usamos bcrypt, el estándar de la industria
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ─────────────────────────────────────────────
# BASE DE USUARIOS
# ─────────────────────────────────────────────
# En producción esto estaría en una base de datos
# Los hashes se generaron con bcrypt para no guardar contraseñas en texto plano

USUARIOS = {
    "admin": {
        "nombre"        : "Administrador del Sistema",
        "password_hash" : bcrypt.hashpw(b"admin123", bcrypt.gensalt()),
        "rol"           : "admin"
    },
    "analista": {
        "nombre"        : "Analista SOC",
        "password_hash" : bcrypt.hashpw(b"analista123", bcrypt.gensalt()),
        "rol"           : "analista"
    }
}


# ─────────────────────────────────────────────
# FUNCIONES DE AUTENTICACIÓN
# ─────────────────────────────────────────────

def verificar_password(password_plano, password_hash):
    return bcrypt.checkpw(password_plano.encode(), password_hash)


def autenticar_usuario(username, password):
    """
    Verifica que el usuario existe y la contraseña es correcta.
    Devuelve el usuario o False si algo falla.
    """
    if username not in USUARIOS:
        return False
    usuario = USUARIOS[username]
    if not verificar_password(password, usuario["password_hash"]):
        return False
    return {**usuario, "username": username}


def crear_token(data: dict):
    """
    Genera un token JWT firmado con la clave secreta.
    El token incluye:
    - Los datos del usuario (username, rol)
    - La fecha de expiración
    """
    datos = data.copy()
    expira = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY)
    datos.update({"exp": expira})
    return jwt.encode(datos, SECRET_KEY, algorithm=ALGORITHM)


def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    """
    Middleware que se ejecuta antes de cada endpoint protegido.
    Verifica que el token es válido y no expiró.
    Si algo falla, devuelve 401 Unauthorized.
    """
    credenciales_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credenciales_exception
    except JWTError:
        raise credenciales_exception

    if username not in USUARIOS:
        raise credenciales_exception

    return {**USUARIOS[username], "username": username}


def requiere_admin(usuario=Depends(obtener_usuario_actual)):
    """
    Dependencia que solo permite acceso a administradores.
    Si el rol no es admin, devuelve 403 Forbidden.
    """
    if usuario["rol"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido a administradores"
        )
    return usuario


# ─────────────────────────────────────────────
# CONFIGURACIÓN DE DETECCIÓN
# ─────────────────────────────────────────────

PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]
UMBRAL_FALLOS      = 5
UMBRAL_VENTANA_SEG = 120
DELAY_NORMAL       = 0.05
DELAY_ALERTA       = 0.5

# ─────────────────────────────────────────────
# CONFIGURACIÓN DE EMAIL
# ─────────────────────────────────────────────

MAILTRAP_HOST     = "sandbox.smtp.mailtrap.io"
MAILTRAP_PORT     = 2525
MAILTRAP_USER     = "c375c8d2bf2d46"
MAILTRAP_PASS     = "ed1a1c49337dc6"
EMAIL_FROM        = "secureaccess@monitor.com"
EMAIL_ADMIN       = "admin@secureaccess.com"

# Set para no mandar el mismo tipo de alerta dos veces seguidas
emails_enviados = set()

estado_usuarios = {}
total_eventos   = 0
total_alertas   = 0
alertas_log     = []

def enviar_alerta_email(user_id, tipo_alerta, detalle, pais, recurso, score, timestamp):
    """
    Envía un email al admin con severidad y recomendaciones incluidas.
    """
    clave_email = f"{user_id}_{tipo_alerta}"
    if clave_email in emails_enviados:
        return
    emails_enviados.add(clave_email)

    # Construimos la alerta completa con severidad y recomendaciones
    alerta = construir_alerta_completa(
        tipo_alerta = tipo_alerta,
        user_id     = user_id,
        pais        = pais,
        recurso     = recurso,
        score       = score,
        timestamp   = timestamp,
        detalle     = detalle
    )

    asunto     = f"{alerta['emoji']} [{alerta['severidad']}] {tipo_alerta} — {user_id} — SecureAccess Monitor"
    cuerpo_html = formatear_para_email(alerta)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = asunto
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_ADMIN

        msg.attach(MIMEText(cuerpo_html, "html"))

        with smtplib.SMTP(MAILTRAP_HOST, MAILTRAP_PORT) as server:
            server.starttls()
            server.login(MAILTRAP_USER, MAILTRAP_PASS)
            server.sendmail(EMAIL_FROM, EMAIL_ADMIN, msg.as_string())

        print(f"  📧 [{alerta['severidad']}] Email enviado: {tipo_alerta} — {user_id}")

    except Exception as e:
        print(f"  ❌ Error enviando email: {e}")

def inicializar_usuario(user_id):
    estado_usuarios[user_id] = {
        "paises_vistos"     : set(),
        "fallos_recientes"  : [],
        "recursos_accedidos": set(),
        "recursos_recientes": set(),
        "total_eventos"     : 0,
        "alertas_disparadas": set()
    }


def actualizar_estado(user_id, evento):
    if user_id not in estado_usuarios:
        inicializar_usuario(user_id)
    estado = estado_usuarios[user_id]
    timestamp = pd.to_datetime(evento["timestamp"])
    estado["total_eventos"] += 1
    estado["paises_vistos"].add(evento["country"])
    if estado["total_eventos"] <= 50:
        estado["recursos_accedidos"].add(evento["resource"])
    else:
        estado["recursos_recientes"].add(evento["resource"])
    if evento["status"] == "failed":
        estado["fallos_recientes"].append(timestamp)
    ventana_inicio = timestamp - timedelta(seconds=UMBRAL_VENTANA_SEG)
    estado["fallos_recientes"] = [
        t for t in estado["fallos_recientes"] if t >= ventana_inicio
    ]


def calcular_riesgo(evento, estado):
    score = 0
    timestamp = pd.to_datetime(evento["timestamp"])
    if evento["country"] in PAISES_SOSPECHOSOS:
        score += 30
    if evento["resource"] in RECURSOS_SENSIBLES:
        score += 25
    if evento["status"] == "failed":
        score += 20
    if timestamp.hour < 6 or timestamp.hour >= 22:
        score += 15
    if len(estado["fallos_recientes"]) > UMBRAL_FALLOS:
        score += 10
    return min(score, 100)


def evaluar_reglas(user_id, evento, score):
    estado    = estado_usuarios[user_id]
    alertas   = []
    timestamp = pd.to_datetime(evento["timestamp"])

    clave_fb = f"fb_{timestamp.strftime('%Y%m%d%H%M')}"
    if (len(estado["fallos_recientes"]) > UMBRAL_FALLOS and
            clave_fb not in estado["alertas_disparadas"]):
        alertas.append({"tipo": "FUERZA_BRUTA",
                        "detalle": f"{len(estado['fallos_recientes'])} fallos en 2 minutos"})
        estado["alertas_disparadas"].add(clave_fb)

    clave_ps = f"ps_{evento['country']}"
    if (evento["country"] in PAISES_SOSPECHOSOS and
            evento["resource"] in RECURSOS_SENSIBLES and
            clave_ps not in estado["alertas_disparadas"]):
        alertas.append({"tipo": "PAIS_SOSPECHOSO",
                        "detalle": f"Acceso a {evento['resource']} desde {evento['country']}"})
        estado["alertas_disparadas"].add(clave_ps)

    clave_hi = f"hi_{timestamp.strftime('%Y%m%d')}"
    if (timestamp.hour < 6 and
            evento["resource"] in RECURSOS_SENSIBLES and
            clave_hi not in estado["alertas_disparadas"]):
        alertas.append({"tipo": "HORARIO_INUSUAL",
                        "detalle": f"Acceso a {evento['resource']} a las {timestamp.hour:02d}:00"})
        estado["alertas_disparadas"].add(clave_hi)

    clave_cc = f"cc_{evento['resource']}"
    recursos_nuevos = estado["recursos_recientes"] - estado["recursos_accedidos"]
    if (evento["resource"] in RECURSOS_SENSIBLES and
            evento["resource"] in recursos_nuevos and
            estado["total_eventos"] > 50 and
            clave_cc not in estado["alertas_disparadas"]):
        alertas.append({"tipo": "CUENTA_COMPROMETIDA",
                        "detalle": f"Primer acceso a {evento['resource']} tras {estado['total_eventos']} eventos"})
        estado["alertas_disparadas"].add(clave_cc)

    return alertas


def enmascarar_ip(ip):
    """
    Oculta los últimos dos octetos de la IP.
    Los analistas ven: 192.168.xxx.xxx
    Los admins ven:    192.168.1.45
    """
    partes = ip.split(".")
    return f"{partes[0]}.{partes[1]}.xxx.xxx"


# ─────────────────────────────────────────────
# HTML DEL DASHBOARD
# ─────────────────────────────────────────────

from fastapi.responses import HTMLResponse, FileResponse

@app.get("/")
async def login_page():
    return FileResponse("templates/login.html")

@app.get("/dashboard")
async def dashboard_page():
    return FileResponse("templates/dashboard.html")

# ─────────────────────────────────────────────
# RUTAS DEL SERVIDOR
# ─────────────────────────────────────────────

@app.get("/")
async def login_page():
    return HTMLResponse(LOGIN_HTML)


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint de login. Recibe usuario y contraseña,
    verifica las credenciales y devuelve un token JWT.
    """
    usuario = autenticar_usuario(form_data.username, form_data.password)
    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos"
        )
    token = crear_token({"sub": usuario["username"], "rol": usuario["rol"]})
    return {
        "access_token": token,
        "token_type"  : "bearer",
        "rol"         : usuario["rol"],
        "nombre"      : usuario["nombre"]
    }


@app.get("/dashboard")
async def dashboard_page():
    """
    Sirve el HTML del dashboard.
    La autenticación real ocurre en el WebSocket.
    """
    return HTMLResponse(DASHBOARD_HTML)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    """
    WebSocket protegido por JWT.
    Verifica el token antes de aceptar la conexión.
    Envía datos distintos según el rol del usuario.
    """
    global total_eventos, total_alertas

    # Verificamos el token antes de aceptar la conexión
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        rol      = payload.get("rol")
        if not username or not rol:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Resetear estado para cada nueva conexión
    global total_eventos, total_alertas
    total_eventos = 0
    total_alertas = 0
    estado_usuarios.clear()

    df = pd.read_csv("data/access_logs.csv")
    df = df.sort_values("timestamp").reset_index(drop=True)

    try:
        for _, evento in df.iterrows():
            user_id = evento["user_id"]
            actualizar_estado(user_id, evento)
            estado  = estado_usuarios[user_id]
            score   = calcular_riesgo(evento, estado)
            alertas = evaluar_reglas(user_id, evento, score)

            total_eventos += 1
            total_alertas += len(alertas)
            tasa = f"{(total_alertas/total_eventos*100):.2f}" if total_eventos > 0 else "0.00"
            
            # Enriquecer alertas con severidad y recomendaciones
            alertas_enriquecidas = []
            for alerta in alertas:
                try:
                    alerta_completa = construir_alerta_completa(
                        tipo_alerta = alerta["tipo"],
                        user_id     = user_id,
                        pais        = evento["country"],
                        recurso     = evento["resource"],
                        score       = score,
                        timestamp   = evento["timestamp"],
                        detalle     = alerta["detalle"]
                    )
                    alertas_enriquecidas.append(alerta_completa)
            
                    if score >= 70:
                        enviar_alerta_email(
                            user_id     = user_id,
                            tipo_alerta = alerta["tipo"],
                            detalle     = alerta["detalle"],
                            pais        = evento["country"],
                            recurso     = evento["resource"],
                            score       = score,
                            timestamp   = str(evento["timestamp"])
                        )
                except Exception as e:
                    print(f"  ❌ Error procesando alerta: {e}")
                    alertas_enriquecidas.append(alerta)
                        
                # Enviar email para alertas de alto riesgo
                if score >= 70:
                    enviar_alerta_email(
                        user_id     = user_id,
                        tipo_alerta = alerta["tipo"],
                        detalle     = alerta["detalle"],
                        pais        = evento["country"],
                        recurso     = evento["resource"],
                        score       = score,
                        timestamp   = str(evento["timestamp"])
                    )
            
            ip_mostrar = None
            if alertas_enriquecidas:
                ip_mostrar = (evento["ip_address"] if rol == "admin"
                             else enmascarar_ip(evento["ip_address"]))
            
            await websocket.send_json({
                "total_eventos" : total_eventos,
                "total_alertas" : total_alertas,
                "tasa"          : tasa,
                "user_id"       : user_id,
                "pais"          : evento["country"],
                "recurso"       : evento["resource"],
                "status"        : evento["status"],
                "timestamp"     : str(evento["timestamp"]),
                "score"         : score,
                "ip"            : ip_mostrar,
                "alertas"       : alertas_enriquecidas
            })
            
            if alertas_enriquecidas:
                await asyncio.sleep(0.6)   # Alertas → más lento para que se vean
            elif score > 0:
                await asyncio.sleep(0.15)  # Sospechoso → velocidad media
            else:
                await asyncio.sleep(0.08)  # Normal → rápido pero procesable

    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)