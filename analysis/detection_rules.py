"""
SecureAccess Monitor — Reglas de Detección
==========================================
Este script aplica reglas de seguridad sobre el dataset
para identificar comportamientos anómalos y generar alertas.

Cada regla está documentada con su lógica y justificación.
"""

import pandas as pd

# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]

# Umbrales de detección — valores que definen cuándo algo es sospechoso
UMBRAL_INTENTOS_FALLIDOS  = 10    # Más de 10 fallos = posible fuerza bruta
UMBRAL_VENTANA_SEGUNDOS   = 120   # Ventana de 2 minutos para analizar fallos
UMBRAL_HORA_INICIO        = 0     # Inicio del horario sospechoso
UMBRAL_HORA_FIN           = 6     # Fin del horario sospechoso
UMBRAL_RISK_SCORE         = 70    # Score mínimo para considerar alto riesgo


# ─────────────────────────────────────────────
# CARGA DEL DATASET
# ─────────────────────────────────────────────

df = pd.read_csv("../data/access_logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hora"] = df["timestamp"].dt.hour
df = df.sort_values("timestamp").reset_index(drop=True)

alertas = []  # Lista donde vamos a acumular todas las alertas generadas


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def registrar_alerta(tipo, user_id, detalle, df_eventos):
    """
    Registra una alerta en la lista global de alertas.
    Centralizar el registro nos permite exportar todas las alertas
    al final en un solo CSV, independientemente de qué regla las generó.
    """
    alerta = {
        "tipo_alerta"    : tipo,
        "user_id"        : user_id,
        "detalle"        : detalle,
        "primer_evento"  : df_eventos["timestamp"].min(),
        "ultimo_evento"  : df_eventos["timestamp"].max(),
        "pais"           : df_eventos["country"].iloc[0],
        "resource"       : df_eventos["resource"].iloc[0],
        "risk_score_max" : df_eventos["risk_score"].max(),
        "total_eventos"  : len(df_eventos)
    }
    alertas.append(alerta)
    return alerta


def imprimir_alerta(alerta):
    """Imprime una alerta de forma legible en la terminal."""
    print(f"""
  ┌─ ALERTA DETECTADA ──────────────────────────────────
  │ Tipo          : {alerta['tipo_alerta']}
  │ Usuario       : {alerta['user_id']}
  │ Detalle       : {alerta['detalle']}
  │ Primer evento : {alerta['primer_evento']}
  │ Último evento : {alerta['ultimo_evento']}
  │ País          : {alerta['pais']}
  │ Risk score    : {alerta['risk_score_max']}
  │ Eventos       : {alerta['total_eventos']}
  └─────────────────────────────────────────────────────""")


# ─────────────────────────────────────────────
# REGLA 1 — FUERZA BRUTA
# ─────────────────────────────────────────────
# Lógica: si un usuario tiene más de N intentos fallidos
# dentro de una ventana de 2 minutos, es un ataque automatizado.
# Los humanos no pueden escribir credenciales tan rápido.

print("=" * 55)
print("REGLA 1 — DETECCIÓN DE FUERZA BRUTA")
print("=" * 55)

# Filtramos solo los eventos fallidos
fallidos = df[df["status"] == "failed"].copy()

# Agrupamos por usuario para analizar cada uno por separado
alertas_fuerza_bruta = 0

for user_id, grupo in fallidos.groupby("user_id"):
    # Ordenamos los eventos de este usuario por tiempo
    grupo = grupo.sort_values("timestamp").reset_index(drop=True)

    # Calculamos la diferencia de tiempo entre eventos consecutivos
    # diff() calcula la diferencia entre cada fila y la anterior
    grupo["segundos_desde_anterior"] = grupo["timestamp"].diff().dt.total_seconds()

    # Usamos una ventana deslizante: analizamos bloques de eventos
    # donde el tiempo entre el primero y el último sea menor a 2 minutos
    i = 0
    while i < len(grupo):
        # Tomamos este evento como punto de inicio
        inicio = grupo["timestamp"].iloc[i]
        fin_ventana = inicio + pd.Timedelta(seconds=UMBRAL_VENTANA_SEGUNDOS)

        # Encontramos todos los eventos dentro de la ventana de 2 minutos
        ventana = grupo[(grupo["timestamp"] >= inicio) &
                       (grupo["timestamp"] <= fin_ventana)]

        # Si hay más de N fallos en esa ventana → es fuerza bruta
        if len(ventana) > UMBRAL_INTENTOS_FALLIDOS:
            duracion = (ventana["timestamp"].max() -
                       ventana["timestamp"].min()).total_seconds()

            detalle = (f"{len(ventana)} intentos fallidos "
                      f"en {duracion:.0f} segundos")

            alerta = registrar_alerta("FUERZA_BRUTA", user_id, detalle, ventana)
            imprimir_alerta(alerta)
            alertas_fuerza_bruta += 1

            # Saltamos al siguiente evento después de la ventana
            # para no contar el mismo ataque dos veces
            i = ventana.index[-1] + 1
        else:
            i += 1

if alertas_fuerza_bruta == 0:
    print("\n  Sin alertas de fuerza bruta detectadas.")
else:
    print(f"\n  Total alertas fuerza bruta: {alertas_fuerza_bruta}")


# ─────────────────────────────────────────────
# REGLA 2 — ACCESO DESDE PAÍS SOSPECHOSO
# ─────────────────────────────────────────────
# Lógica: cualquier acceso desde un país de alto riesgo
# hacia un recurso sensible merece revisión inmediata.
# No importa si fue exitoso o fallido.

print("\n" + "=" * 55)
print("REGLA 2 — ACCESO DESDE PAÍS SOSPECHOSO")
print("=" * 55)

sospechosos = df[
    (df["country"].isin(PAISES_SOSPECHOSOS)) &
    (df["resource"].isin(RECURSOS_SENSIBLES))
]

alertas_pais = 0

# Agrupamos por usuario y país para no generar una alerta por cada evento
for (user_id, pais), grupo in sospechosos.groupby(["user_id", "country"]):
    detalle = (f"Acceso a recursos sensibles desde {pais} "
              f"({len(grupo)} eventos, "
              f"recursos: {', '.join(grupo['resource'].unique())})")

    alerta = registrar_alerta("PAIS_SOSPECHOSO", user_id, detalle, grupo)
    imprimir_alerta(alerta)
    alertas_pais += 1

if alertas_pais == 0:
    print("\n  Sin alertas de país sospechoso detectadas.")
else:
    print(f"\n  Total alertas país sospechoso: {alertas_pais}")


# ─────────────────────────────────────────────
# REGLA 3 — HORARIO INUSUAL
# ─────────────────────────────────────────────
# Lógica: accesos a recursos sensibles en madrugada
# son una señal fuerte de actividad no autorizada.
# Los administradores legítimos rara vez trabajan a las 3am.

print("\n" + "=" * 55)
print("REGLA 3 — ACCESO EN HORARIO INUSUAL")
print("=" * 55)

horario_inusual = df[
    (df["hora"] >= UMBRAL_HORA_INICIO) &
    (df["hora"] < UMBRAL_HORA_FIN) &
    (df["resource"].isin(RECURSOS_SENSIBLES))
]

alertas_horario = 0

for user_id, grupo in horario_inusual.groupby("user_id"):
    horas = sorted(grupo["hora"].unique())
    detalle = (f"Acceso a recursos sensibles en madrugada "
              f"({len(grupo)} eventos entre las "
              f"{min(horas):02d}:00 y {max(horas):02d}:59)")

    alerta = registrar_alerta("HORARIO_INUSUAL", user_id, detalle, grupo)
    imprimir_alerta(alerta)
    alertas_horario += 1

if alertas_horario == 0:
    print("\n  Sin alertas de horario inusual detectadas.")
else:
    print(f"\n  Total alertas horario inusual: {alertas_horario}")


# ─────────────────────────────────────────────
# REGLA 4 — CUENTA COMPROMETIDA
# ─────────────────────────────────────────────
# Lógica: detectamos usuarios que tienen un historial
# de accesos normales pero en algún punto empiezan a
# acceder a recursos sensibles que nunca habían tocado.
# Es el escenario más difícil de detectar porque
# la IP y el país son los mismos de siempre.

print("\n" + "=" * 55)
print("REGLA 4 — POSIBLE CUENTA COMPROMETIDA")
print("=" * 55)

alertas_comprometido = 0

for user_id, grupo in df.groupby("user_id"):
    grupo = grupo.sort_values("timestamp")

    # Calculamos el punto medio de la actividad del usuario
    # Dividimos su historial en primera mitad y segunda mitad
    punto_medio = len(grupo) // 2
    primera_mitad = grupo.iloc[:punto_medio]
    segunda_mitad = grupo.iloc[punto_medio:]

    # Recursos que usó en la primera mitad (comportamiento base)
    recursos_normales = set(primera_mitad["resource"].unique())

    # Recursos que usó en la segunda mitad
    recursos_recientes = set(segunda_mitad["resource"].unique())

    # Recursos nuevos que aparecen en la segunda mitad
    # y son sensibles y nunca los había usado antes
    recursos_nuevos_sensibles = (
        recursos_recientes - recursos_normales
    ) & set(RECURSOS_SENSIBLES)

    if recursos_nuevos_sensibles:
        # Filtramos los eventos donde accedió a esos recursos nuevos
        eventos_sospechosos = segunda_mitad[
            segunda_mitad["resource"].isin(recursos_nuevos_sensibles)
        ]

        # Solo alertamos si hay más de 2 accesos (evitamos falsos positivos)
        if len(eventos_sospechosos) > 2:
            detalle = (f"Acceso a recursos nunca utilizados: "
                      f"{', '.join(recursos_nuevos_sensibles)} "
                      f"({len(eventos_sospechosos)} eventos en segunda mitad del período)")

            alerta = registrar_alerta("CUENTA_COMPROMETIDA", user_id, detalle, eventos_sospechosos)
            imprimir_alerta(alerta)
            alertas_comprometido += 1

if alertas_comprometido == 0:
    print("\n  Sin alertas de cuenta comprometida detectadas.")
else:
    print(f"\n  Total alertas cuenta comprometida: {alertas_comprometido}")


# ─────────────────────────────────────────────
# RESUMEN FINAL Y EXPORTACIÓN
# ─────────────────────────────────────────────

print("\n" + "=" * 55)
print("RESUMEN DE ALERTAS GENERADAS")
print("=" * 55)

if alertas:
    df_alertas = pd.DataFrame(alertas)

    # Resumen por tipo de alerta
    print(f"\nTotal de alertas generadas: {len(df_alertas)}")
    print(f"\nAlertas por tipo:")
    for tipo, cantidad in df_alertas["tipo_alerta"].value_counts().items():
        print(f"  {tipo:<25} : {cantidad} alertas")

    print(f"\nUsuarios involucrados en alertas:")
    print(df_alertas["user_id"].value_counts().to_string())

    print(f"\nRisk score máximo por tipo de alerta:")
    print(df_alertas.groupby("tipo_alerta")["risk_score_max"].max().to_string())

    # Exportamos las alertas a CSV para usarlas en la visualización
    df_alertas.to_csv("../data/alertas.csv", index=False)
    print(f"\n✅ Alertas exportadas a: data/alertas.csv")
else:
    print("\n  No se generaron alertas.")

print("\n" + "=" * 55)
print("DETECCIÓN COMPLETADA")
print("=" * 55)