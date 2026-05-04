"""
SecureAccess Monitor — Detector en Tiempo Real
===============================================
Simula un stream de eventos de seguridad procesados
uno por uno, evaluando reglas de detección al instante.

Esto replica el comportamiento de sistemas SIEM reales
como Splunk o Microsoft Sentinel.
"""

import pandas as pd
import time
from datetime import datetime, timedelta
from colorama import init, Fore, Back, Style

init(autoreset=True)  # Inicializa colorama para Windows


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

PAISES_SOSPECHOSOS  = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
RECURSOS_SENSIBLES  = ["admin_panel", "database", "billing"]
RECURSOS_NORMALES   = ["login", "dashboard", "api", "file_storage"]

UMBRAL_FALLOS       = 5      # Fallos en ventana → alerta fuerza bruta
UMBRAL_VENTANA_SEG  = 120    # Ventana de tiempo en segundos
UMBRAL_RIESGO_ALTO  = 70     # Score mínimo para alerta

# Velocidad de simulación
# 0.05 = muy rápido, 0.3 = cómodo para leer, 1.0 = lento
DELAY_NORMAL        = 0.05
DELAY_SOSPECHOSO    = 0.4    # Pausa más larga en eventos sospechosos


# ─────────────────────────────────────────────
# ESTADO GLOBAL DEL SISTEMA
# ─────────────────────────────────────────────

# Este diccionario es la memoria del sistema
# Se actualiza con cada evento que llega
# Es el equivalente a una base de datos en memoria
estado_usuarios = {}

# Contadores globales para el resumen final
total_eventos    = 0
total_alertas    = 0
alertas_por_tipo = {
    "FUERZA_BRUTA"       : 0,
    "PAIS_SOSPECHOSO"    : 0,
    "HORARIO_INUSUAL"    : 0,
    "CUENTA_COMPROMETIDA": 0
}


# ─────────────────────────────────────────────
# FUNCIONES DE ESTADO
# ─────────────────────────────────────────────

def inicializar_usuario(user_id):
    """
    Crea el perfil de estado inicial para un usuario nuevo.
    Se llama la primera vez que vemos a ese usuario.
    """
    estado_usuarios[user_id] = {
        "paises_vistos"       : set(),      # Conjunto de países únicos
        "fallos_recientes"    : [],          # Lista de timestamps de fallos
        "recursos_accedidos"  : set(),      # Recursos que usó en primera mitad
        "recursos_recientes"  : set(),      # Recursos que usó recientemente
        "horas_vistas"        : [],          # Horas de acceso históricas
        "total_eventos"       : 0,
        "primer_evento"       : None,
        "ultimo_evento"       : None,
        "alertas_disparadas"  : set()       # Para no repetir la misma alerta
    }


def actualizar_estado(user_id, evento):
    """
    Actualiza el estado del usuario con la información del evento nuevo.
    Esto es lo que hace el sistema antes de evaluar las reglas.
    """
    if user_id not in estado_usuarios:
        inicializar_usuario(user_id)

    estado = estado_usuarios[user_id]
    timestamp = pd.to_datetime(evento["timestamp"])

    # Actualizar campos básicos
    estado["total_eventos"] += 1
    estado["paises_vistos"].add(evento["country"])
    estado["horas_vistas"].append(timestamp.hour)

    if estado["primer_evento"] is None:
        estado["primer_evento"] = timestamp
    estado["ultimo_evento"] = timestamp

    # Separamos recursos en dos grupos según cuándo los usó
    # Primera mitad del historial = comportamiento base
    # Segunda mitad = comportamiento reciente
    if estado["total_eventos"] <= 50:
        estado["recursos_accedidos"].add(evento["resource"])
    else:
        estado["recursos_recientes"].add(evento["resource"])

    # Registrar fallos y limpiar los que ya expiraron (fuera de la ventana)
    if evento["status"] == "failed":
        estado["fallos_recientes"].append(timestamp)

    # Limpiamos fallos que ocurrieron hace más de 2 minutos
    # Esto implementa la ventana deslizante de tiempo
    ventana_inicio = timestamp - timedelta(seconds=UMBRAL_VENTANA_SEG)
    estado["fallos_recientes"] = [
        t for t in estado["fallos_recientes"]
        if t >= ventana_inicio
    ]


# ─────────────────────────────────────────────
# FUNCIONES DE DETECCIÓN
# ─────────────────────────────────────────────

def calcular_riesgo(evento, estado):
    """
    Calcula el risk score del evento considerando
    tanto el evento actual como el estado acumulado del usuario.
    """
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
    """
    Evalúa las 4 reglas contra el estado actual del usuario.
    Devuelve una lista de alertas disparadas.
    """
    estado   = estado_usuarios[user_id]
    alertas  = []
    timestamp = pd.to_datetime(evento["timestamp"])

    # REGLA 1 — Fuerza bruta
    clave_fb = f"fb_{timestamp.strftime('%Y%m%d%H%M')}"
    if (len(estado["fallos_recientes"]) > UMBRAL_FALLOS and
            clave_fb not in estado["alertas_disparadas"]):
        alertas.append({
            "tipo"   : "FUERZA_BRUTA",
            "detalle": f"{len(estado['fallos_recientes'])} fallos en ventana de 2 minutos"
        })
        estado["alertas_disparadas"].add(clave_fb)

    # REGLA 2 — País sospechoso
    clave_ps = f"ps_{evento['country']}"
    if (evento["country"] in PAISES_SOSPECHOSOS and
            evento["resource"] in RECURSOS_SENSIBLES and
            clave_ps not in estado["alertas_disparadas"]):
        alertas.append({
            "tipo"   : "PAIS_SOSPECHOSO",
            "detalle": f"Acceso a {evento['resource']} desde {evento['country']}"
        })
        estado["alertas_disparadas"].add(clave_ps)

    # REGLA 3 — Horario inusual
    clave_hi = f"hi_{timestamp.strftime('%Y%m%d')}"
    if (timestamp.hour < 6 and
            evento["resource"] in RECURSOS_SENSIBLES and
            clave_hi not in estado["alertas_disparadas"]):
        alertas.append({
            "tipo"   : "HORARIO_INUSUAL",
            "detalle": f"Acceso a {evento['resource']} a las {timestamp.hour:02d}:00"
        })
        estado["alertas_disparadas"].add(clave_hi)

    # REGLA 4 — Cuenta comprometida
    clave_cc = f"cc_{evento['resource']}"
    recursos_nuevos = estado["recursos_recientes"] - estado["recursos_accedidos"]
    if (evento["resource"] in RECURSOS_SENSIBLES and
            evento["resource"] in recursos_nuevos and
            estado["total_eventos"] > 50 and
            clave_cc not in estado["alertas_disparadas"]):
        alertas.append({
            "tipo"   : "CUENTA_COMPROMETIDA",
            "detalle": f"Primer acceso a {evento['resource']} después de {estado['total_eventos']} eventos normales"
        })
        estado["alertas_disparadas"].add(clave_cc)

    return alertas


# ─────────────────────────────────────────────
# FUNCIONES DE OUTPUT
# ─────────────────────────────────────────────

def imprimir_evento(evento, score, alertas):
    """
    Imprime el evento en la terminal con colores según su nivel de riesgo.
    Verde = normal, amarillo = sospechoso, rojo = alerta crítica.
    """
    timestamp = pd.to_datetime(evento["timestamp"])
    hora      = timestamp.strftime("%m/%d %H:%M:%S")
    user      = evento["user_id"]
    pais      = evento["country"][:10].ljust(10)
    recurso   = evento["resource"][:12].ljust(12)
    status    = evento["status"]

    if alertas:
        # Evento con alertas — rojo y llamativo
        color_linea = Fore.RED + Style.BRIGHT
        icono = "🚨"
        delay = DELAY_SOSPECHOSO
    elif score > 0:
        # Evento sospechoso sin alerta aún — amarillo
        color_linea = Fore.YELLOW
        icono = "⚠ "
        delay = DELAY_SOSPECHOSO
    else:
        # Evento normal — verde tenue
        color_linea = Fore.GREEN
        icono = "✓ "
        delay = DELAY_NORMAL

    # Línea del evento
    linea = (f"[{hora}] {user}  {pais}  {recurso}  "
            f"{status:<8}  score:{score:>3}  {icono}")
    print(color_linea + linea)

    # Imprimimos cada alerta disparada
    for alerta in alertas:
        print(Fore.RED + Back.BLACK + Style.BRIGHT +
              f"         └─ ALERTA {alerta['tipo']}: {alerta['detalle']}")

    time.sleep(delay)


def imprimir_header():
    """Imprime el encabezado del sistema al inicio."""
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.CYAN + Style.BRIGHT +
          "   🔐 SECUREACCESS MONITOR — DETECCIÓN EN TIEMPO REAL")
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.WHITE +
          f"   {'TIMESTAMP':<18} {'USUARIO':<10} {'PAÍS':<12} "
          f"{'RECURSO':<14} {'STATUS':<10} {'SCORE':<8} {'ESTADO'}")
    print(Fore.CYAN + "-" * 70)


def imprimir_resumen():
    """Imprime el resumen estadístico al finalizar el stream."""
    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 70)
    print(Fore.CYAN + Style.BRIGHT + "   RESUMEN FINAL DEL SISTEMA")
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)

    print(Fore.WHITE + f"\n  Total eventos procesados : {total_eventos}")
    print(Fore.RED   + f"  Total alertas generadas  : {total_alertas}")
    print(Fore.WHITE + f"  Tasa de detección        : {total_alertas/total_eventos*100:.2f}%")

    print(Fore.YELLOW + "\n  Alertas por tipo:")
    for tipo, cantidad in alertas_por_tipo.items():
        if cantidad > 0:
            print(Fore.YELLOW + f"    {tipo:<25} : {cantidad}")

    print(Fore.RED + Style.BRIGHT + "\n  Usuarios más comprometidos:")
    ranking = sorted(
        estado_usuarios.items(),
        key=lambda x: len(x[1]["alertas_disparadas"]),
        reverse=True
    )
    for user_id, estado in ranking[:5]:
        n_alertas = len(estado["alertas_disparadas"])
        if n_alertas > 0:
            print(Fore.RED + f"    {user_id} → {n_alertas} alertas disparadas")

    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "  ✅ Stream completado")
    print(Fore.CYAN + Style.BRIGHT + "=" * 70 + "\n")


# ─────────────────────────────────────────────
# PROCESAMIENTO PRINCIPAL
# ─────────────────────────────────────────────

def procesar_stream():
    """
    Función principal: carga el dataset y procesa
    cada evento como si llegara en tiempo real.
    """
    global total_eventos, total_alertas

    df = pd.read_csv("data/access_logs.csv")
    df = df.sort_values("timestamp").reset_index(drop=True)

    imprimir_header()

    for _, evento in df.iterrows():
        user_id = evento["user_id"]

        # 1. Actualizamos el estado del usuario
        actualizar_estado(user_id, evento)

        # 2. Calculamos el riesgo del evento
        estado = estado_usuarios[user_id]
        score  = calcular_riesgo(evento, estado)

        # 3. Evaluamos las reglas
        alertas = evaluar_reglas(user_id, evento, score)

        # 4. Actualizamos contadores globales
        total_eventos += 1
        total_alertas += len(alertas)
        for alerta in alertas:
            alertas_por_tipo[alerta["tipo"]] += 1

        # 5. Imprimimos el evento en tiempo real
        imprimir_evento(evento, score, alertas)

    imprimir_resumen()


if __name__ == "__main__":
    procesar_stream()