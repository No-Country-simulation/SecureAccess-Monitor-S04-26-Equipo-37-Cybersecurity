"""
SecureAccess Monitor — Generador de Dataset
===========================================
Este script genera un dataset simulado de eventos de acceso
a una infraestructura cloud ficticia.
"""

import pandas as pd
import random
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# CONFIGURACIÓN GENERAL
# ─────────────────────────────────────────────

random.seed(42)

PAISES_NORMALES = ["Argentina", "Brasil", "Mexico", "España", "Colombia"]
PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]

RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]
RECURSOS_NORMALES = ["login", "dashboard", "api", "file_storage"]

FECHA_INICIO = datetime(2024, 1, 1)
FECHA_FIN    = datetime(2024, 6, 30)


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def generar_ip(pais):
    if pais in PAISES_SOSPECHOSOS:
        return f"{random.randint(1, 50)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(150, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def fecha_aleatoria_laboral():
    delta = FECHA_FIN - FECHA_INICIO
    while True:
        fecha = FECHA_INICIO + timedelta(
            days=random.randint(0, delta.days),
            hours=random.randint(8, 19),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        if fecha.weekday() < 5:
            return fecha


def fecha_aleatoria_madrugada():
    delta = FECHA_FIN - FECHA_INICIO
    return FECHA_INICIO + timedelta(
        days=random.randint(0, delta.days),
        hours=random.randint(0, 4),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )


def calcular_riesgo(status, pais, recurso, hora, intentos_fallidos=0):
    score = 0
    if pais in PAISES_SOSPECHOSOS:
        score += 30
    if recurso in RECURSOS_SENSIBLES:
        score += 25
    if status == "failed":
        score += 20
    if hora < 6 or hora >= 22:
        score += 15
    if intentos_fallidos > 5:
        score += 10
    return min(score, 100)


# ─────────────────────────────────────────────
# PERFILES DE USUARIO
# ─────────────────────────────────────────────

def generar_eventos_normales(user_id, cantidad):
    eventos = []
    pais = random.choice(PAISES_NORMALES)
    ip = generar_ip(pais)

    for _ in range(cantidad):
        fecha = fecha_aleatoria_laboral()
        recurso = random.choice(RECURSOS_NORMALES)
        status = "failed" if random.random() < 0.05 else "success"

        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip,
            "country": pais,
            "action": "access",
            "status": status,
            "resource": recurso,
            "risk_score": calcular_riesgo(status, pais, recurso, fecha.hour),
            "scenario": "normal"
        })
    return eventos


def generar_fuerza_bruta(user_id, fecha_ataque):
    eventos = []
    pais = random.choice(PAISES_SOSPECHOSOS)
    ip = generar_ip(pais)
    cantidad_intentos = random.randint(15, 40)

    for i in range(cantidad_intentos):
        fecha = fecha_ataque + timedelta(seconds=i * random.randint(3, 15))
        recurso = random.choice(RECURSOS_SENSIBLES)
        if i == cantidad_intentos - 1 and random.random() < 0.3:
            status = "success"
        else:
            status = "failed"

        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip,
            "country": pais,
            "action": "login_attempt",
            "status": status,
            "resource": recurso,
            "risk_score": calcular_riesgo(status, pais, recurso, fecha.hour, intentos_fallidos=i),
            "scenario": "brute_force"
        })
    return eventos


def generar_acceso_pais_inusual(user_id, cantidad_normal, fecha_anomalia):
    eventos = []
    pais_habitual = random.choice(PAISES_NORMALES)
    ip_habitual = generar_ip(pais_habitual)

    for _ in range(cantidad_normal):
        fecha = fecha_aleatoria_laboral()
        recurso = random.choice(RECURSOS_NORMALES)
        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip_habitual,
            "country": pais_habitual,
            "action": "access",
            "status": "success",
            "resource": recurso,
            "risk_score": calcular_riesgo("success", pais_habitual, recurso, fecha.hour),
            "scenario": "normal"
        })

    pais_sospechoso = random.choice(PAISES_SOSPECHOSOS)
    ip_sospechosa = generar_ip(pais_sospechoso)

    for i in range(random.randint(3, 8)):
        fecha = fecha_anomalia + timedelta(minutes=i * 5)
        recurso = random.choice(RECURSOS_SENSIBLES)
        status = "success" if random.random() > 0.3 else "failed"
        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip_sospechosa,
            "country": pais_sospechoso,
            "action": "access",
            "status": status,
            "resource": recurso,
            "risk_score": calcular_riesgo(status, pais_sospechoso, recurso, fecha.hour),
            "scenario": "unusual_country"
        })
    return eventos


def generar_usuario_comprometido(user_id, cantidad_normal):
    eventos = []
    pais = random.choice(PAISES_NORMALES)
    ip = generar_ip(pais)

    for _ in range(cantidad_normal):
        fecha = fecha_aleatoria_laboral()
        recurso = random.choice(RECURSOS_NORMALES)
        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip,
            "country": pais,
            "action": "access",
            "status": "success",
            "resource": recurso,
            "risk_score": calcular_riesgo("success", pais, recurso, fecha.hour),
            "scenario": "normal"
        })

    for _ in range(random.randint(5, 12)):
        fecha = fecha_aleatoria_madrugada()
        recurso = random.choice(RECURSOS_SENSIBLES)
        eventos.append({
            "timestamp": fecha,
            "user_id": user_id,
            "ip_address": ip,
            "country": pais,
            "action": "access",
            "status": "success",
            "resource": recurso,
            "risk_score": calcular_riesgo("success", pais, recurso, fecha.hour),
            "scenario": "compromised_account"
        })
    return eventos


# ─────────────────────────────────────────────
# GENERACIÓN PRINCIPAL
# ─────────────────────────────────────────────

def generar_dataset():
    todos_los_eventos = []

    print("Generando dataset...")

    for i in range(1, 19):
        user_id = f"user_{i:03d}"
        cantidad = random.randint(80, 130)
        todos_los_eventos.extend(generar_eventos_normales(user_id, cantidad))
        print(f"  ✓ {user_id} — normal ({cantidad} eventos)")

    for i in range(19, 24):
        user_id = f"user_{i:03d}"
        fecha_ataque = FECHA_INICIO + timedelta(days=random.randint(0, 180))
        todos_los_eventos.extend(generar_fuerza_bruta(user_id, fecha_ataque))
        print(f"  ✓ {user_id} — fuerza bruta")

    for i in range(24, 28):
        user_id = f"user_{i:03d}"
        fecha_anomalia = FECHA_INICIO + timedelta(days=random.randint(60, 150))
        todos_los_eventos.extend(generar_acceso_pais_inusual(user_id, 60, fecha_anomalia))
        print(f"  ✓ {user_id} — país inusual")

    for i in range(28, 31):
        user_id = f"user_{i:03d}"
        todos_los_eventos.extend(generar_usuario_comprometido(user_id, 70))
        print(f"  ✓ {user_id} — cuenta comprometida")

    df = pd.DataFrame(todos_los_eventos)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    df.to_csv("access_logs.csv", index=False)

    print(f"\n✅ Dataset generado: {len(df)} eventos totales")
    print(f"\nDistribución de escenarios:")
    print(df["scenario"].value_counts().to_string())
    print(f"\nRisk Score promedio por escenario:")
    print(df.groupby("scenario")["risk_score"].mean().round(1).to_string())

    return df


if __name__ == "__main__":
    df = generar_dataset()