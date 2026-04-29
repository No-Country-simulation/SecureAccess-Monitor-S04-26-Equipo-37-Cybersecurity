"""
SecureAccess Monitor — Análisis Exploratorio
============================================
Este script responde preguntas descriptivas sobre el dataset:
¿Qué hay en los datos? ¿Cómo se distribuyen? ¿Qué patrones generales existen?

Es el primer paso antes de aplicar reglas de detección.
"""

import pandas as pd

# ─────────────────────────────────────────────
# CARGA DEL DATASET
# ─────────────────────────────────────────────

# Cargamos el CSV desde la carpeta data
# '..' significa "subir un nivel" en la estructura de carpetas
df = pd.read_csv("../data/access_logs.csv")

# Convertimos la columna timestamp de texto a datetime
# Esto nos permite hacer operaciones con fechas y horas
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Extraemos columnas de tiempo útiles para el análisis
df["hora"]          = df["timestamp"].dt.hour
df["dia_semana"]    = df["timestamp"].dt.day_name()
df["mes"]           = df["timestamp"].dt.month_name()


# ─────────────────────────────────────────────
# BLOQUE 1 — VISTA GENERAL
# ─────────────────────────────────────────────

print("=" * 55)
print("BLOQUE 1 — VISTA GENERAL")
print("=" * 55)

# Dimensiones del dataset (filas, columnas)
filas, columnas = df.shape
print(f"\nTotal de eventos registrados : {filas}")
print(f"Total de columnas            : {columnas}")

# Listado de columnas y sus tipos de dato
print(f"\nColumnas y tipos de dato:")
print(df.dtypes.to_string())

# Verificación de valores vacíos (como un IS NULL en SQL)
print(f"\nValores vacíos por columna:")
nulos = df.isnull().sum()
if nulos.sum() == 0:
    print("  No hay valores vacíos. Dataset limpio.")
else:
    print(nulos[nulos > 0].to_string())

# Rango de fechas del dataset
print(f"\nPeríodo cubierto:")
print(f"  Desde : {df['timestamp'].min()}")
print(f"  Hasta : {df['timestamp'].max()}")

# Primeras 3 filas para ver cómo se ven los datos
print(f"\nMuestra de datos (primeras 3 filas):")
print(df.head(3).to_string())


# ─────────────────────────────────────────────
# BLOQUE 2 — ACTIVIDAD DE USUARIOS
# ─────────────────────────────────────────────

print("\n" + "=" * 55)
print("BLOQUE 2 — ACTIVIDAD DE USUARIOS")
print("=" * 55)

# Usuarios más activos (equivale a GROUP BY user_id ORDER BY COUNT DESC)
print(f"\nTop 10 usuarios más activos:")
print(df["user_id"].value_counts().head(10).to_string())

# Distribución de escenarios
print(f"\nDistribución de escenarios:")
escenarios = df["scenario"].value_counts()
for escenario, cantidad in escenarios.items():
    porcentaje = (cantidad / filas) * 100
    print(f"  {escenario:<25} {cantidad:>5} eventos  ({porcentaje:.1f}%)")

# Distribución de status (success vs failed)
print(f"\nDistribución de status:")
for status, cantidad in df["status"].value_counts().items():
    porcentaje = (cantidad / filas) * 100
    print(f"  {status:<10} {cantidad:>5} eventos  ({porcentaje:.1f}%)")

# Usuarios con más intentos fallidos
print(f"\nTop 10 usuarios con más accesos fallidos:")
fallidos = df[df["status"] == "failed"]["user_id"].value_counts().head(10)
print(fallidos.to_string())


# ─────────────────────────────────────────────
# BLOQUE 3 — GEOGRAFÍA Y RECURSOS
# ─────────────────────────────────────────────

print("\n" + "=" * 55)
print("BLOQUE 3 — GEOGRAFÍA Y RECURSOS")
print("=" * 55)

# Eventos por país
print(f"\nEventos por país:")
print(df["country"].value_counts().to_string())

# Risk score promedio por país (los más peligrosos arriba)
print(f"\nRisk score promedio por país (ordenado por riesgo):")
riesgo_pais = df.groupby("country")["risk_score"].mean().round(1).sort_values(ascending=False)
print(riesgo_pais.to_string())

# Recursos más accedidos
print(f"\nRecursos más accedidos:")
print(df["resource"].value_counts().to_string())

# Accesos a recursos sensibles por país
RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]
print(f"\nAccesos a recursos sensibles por país:")
sensibles = df[df["resource"].isin(RECURSOS_SENSIBLES)]
print(sensibles["country"].value_counts().to_string())


# ─────────────────────────────────────────────
# BLOQUE 4 — TIEMPO Y RIESGO
# ─────────────────────────────────────────────

print("\n" + "=" * 55)
print("BLOQUE 4 — TIEMPO Y RIESGO")
print("=" * 55)

# Actividad por hora del día
print(f"\nEventos por hora del día:")
actividad_hora = df["hora"].value_counts().sort_index()
for hora, cantidad in actividad_hora.items():
    barra = "█" * (cantidad // 20)  # Barra visual proporcional
    print(f"  {hora:02d}:00  {barra} ({cantidad})")

# Distribución del risk score
print(f"\nEstadísticas del risk score:")
print(df["risk_score"].describe().round(1).to_string())

# Clasificación por nivel de riesgo
print(f"\nEventos por nivel de riesgo:")
sin_riesgo  = len(df[df["risk_score"] == 0])
bajo        = len(df[(df["risk_score"] > 0)  & (df["risk_score"] < 40)])
medio       = len(df[(df["risk_score"] >= 40) & (df["risk_score"] < 70)])
alto        = len(df[df["risk_score"] >= 70])

print(f"  Sin riesgo  (score = 0)    : {sin_riesgo:>5} eventos  ({sin_riesgo/filas*100:.1f}%)")
print(f"  Bajo        (score 1-39)   : {bajo:>5} eventos  ({bajo/filas*100:.1f}%)")
print(f"  Medio       (score 40-69)  : {medio:>5} eventos  ({medio/filas*100:.1f}%)")
print(f"  Alto        (score >= 70)  : {alto:>5} eventos  ({alto/filas*100:.1f}%)")

# Eventos de alto riesgo — los más importantes para investigar
print(f"\nDetalle de eventos de alto riesgo (score >= 70):")
alto_riesgo = df[df["risk_score"] >= 70][["timestamp", "user_id", "country", "resource", "status", "risk_score", "scenario"]]
alto_riesgo = alto_riesgo.sort_values("risk_score", ascending=False)
print(alto_riesgo.head(15).to_string())

print("\n" + "=" * 55)
print("ANÁLISIS EXPLORATORIO COMPLETADO")
print("=" * 55)