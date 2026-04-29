"""
SecureAccess Monitor — Dashboard de Visualización
==================================================
Este script genera un dashboard con 6 gráficos que resumen
visualmente los resultados del análisis y la detección.

Output: visualization/dashboard.png
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

# ─────────────────────────────────────────────
# CONFIGURACIÓN VISUAL
# ─────────────────────────────────────────────

# Paleta de colores del proyecto
# Usamos rojo para peligro, verde para normal, naranja para advertencia
COLORES = {
    "normal"              : "#2ecc71",   # verde
    "brute_force"         : "#e74c3c",   # rojo
    "unusual_country"     : "#e67e22",   # naranja
    "compromised_account" : "#f39c12",   # amarillo
    "peligro"             : "#e74c3c",   # rojo
    "seguro"              : "#2ecc71",   # verde
    "neutro"              : "#3498db",   # azul
    "fondo"               : "#1a1a2e",   # azul oscuro (fondo del dashboard)
    "texto"               : "#ecf0f1",   # blanco suave
    "grid"                : "#2d2d4e",   # gris azulado
}

# Estilo general del dashboard
plt.style.use("dark_background")
sns.set_palette("husl")


# ─────────────────────────────────────────────
# CARGA DE DATOS
# ─────────────────────────────────────────────

df = pd.read_csv("../data/access_logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hora"] = df["timestamp"].dt.hour

df_alertas = pd.read_csv("../data/alertas.csv")


# ─────────────────────────────────────────────
# FIGURA PRINCIPAL
# ─────────────────────────────────────────────

# Creamos la figura con 2 filas y 3 columnas
fig, axes = plt.subplots(2, 3, figsize=(20, 11))

# Título principal del dashboard
fig.suptitle(
    "🔐 SecureAccess Monitor — Dashboard de Seguridad",
    fontsize=20,
    fontweight="bold",
    color=COLORES["texto"],
    y=1.02
)

# Color de fondo de toda la figura
fig.patch.set_facecolor(COLORES["fondo"])

# Aplicamos el color de fondo a cada panel
for ax in axes.flat:
    ax.set_facecolor(COLORES["fondo"])
    ax.tick_params(colors=COLORES["texto"])
    ax.xaxis.label.set_color(COLORES["texto"])
    ax.yaxis.label.set_color(COLORES["texto"])
    ax.title.set_color(COLORES["texto"])
    for spine in ax.spines.values():
        spine.set_edgecolor(COLORES["grid"])


# ─────────────────────────────────────────────
# GRÁFICO 1 — Distribución de escenarios (torta)
# axes[0, 0] = fila 0, columna 0
# ─────────────────────────────────────────────

ax1 = axes[0, 0]

conteo_escenarios = df["scenario"].value_counts()
colores_torta = [
    COLORES["normal"],
    COLORES["brute_force"],
    COLORES["unusual_country"],
    COLORES["compromised_account"]
]

# wedgeprops define el estilo de cada porción
# autopct muestra el porcentaje en cada porción
wedges, texts, autotexts = ax1.pie(
    conteo_escenarios.values,
    labels=conteo_escenarios.index,
    colors=colores_torta,
    autopct="%1.1f%%",
    startangle=90,
    wedgeprops={"edgecolor": COLORES["fondo"], "linewidth": 2}
)

# Estilo del texto dentro de la torta
for text in texts:
    text.set_color(COLORES["texto"])
    text.set_fontsize(8)
for autotext in autotexts:
    autotext.set_color("white")
    autotext.set_fontweight("bold")
    autotext.set_fontsize(8)

ax1.set_title("Distribución de Escenarios", fontweight="bold", pad=15)


# ─────────────────────────────────────────────
# GRÁFICO 2 — Actividad por hora del día
# axes[0, 1] = fila 0, columna 1
# ─────────────────────────────────────────────

ax2 = axes[0, 1]

actividad_hora = df["hora"].value_counts().sort_index()

# Coloreamos las barras de madrugada en rojo, el resto en azul
colores_hora = [
    COLORES["peligro"] if h < 6 else COLORES["neutro"]
    for h in actividad_hora.index
]

barras = ax2.bar(
    actividad_hora.index,
    actividad_hora.values,
    color=colores_hora,
    edgecolor=COLORES["fondo"],
    linewidth=0.5
)

# Línea de referencia: promedio de actividad
promedio = actividad_hora.mean()
ax2.axhline(
    y=promedio,
    color=COLORES["usual_country"] if "usual_country" in COLORES else "#e67e22",
    linestyle="--",
    linewidth=1.5,
    alpha=0.7,
    label=f"Promedio: {promedio:.0f}"
)

ax2.set_title("Actividad por Hora del Día", fontweight="bold")
ax2.set_xlabel("Hora")
ax2.set_ylabel("Cantidad de eventos")
ax2.set_xticks(range(0, 24, 2))

# Leyenda manual
parche_rojo  = mpatches.Patch(color=COLORES["peligro"], label="Horario sospechoso (00-05)")
parche_azul  = mpatches.Patch(color=COLORES["neutro"],  label="Horario normal")
ax2.legend(handles=[parche_rojo, parche_azul], fontsize=7,
          facecolor=COLORES["fondo"], labelcolor=COLORES["texto"])

ax2.grid(axis="y", color=COLORES["grid"], linewidth=0.5, alpha=0.5)


# ─────────────────────────────────────────────
# GRÁFICO 3 — Eventos por país
# axes[0, 2] = fila 0, columna 2
# ─────────────────────────────────────────────

ax3 = axes[0, 2]

PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
eventos_pais = df["country"].value_counts()

colores_pais = [
    COLORES["peligro"] if p in PAISES_SOSPECHOSOS else COLORES["seguro"]
    for p in eventos_pais.index
]

# Gráfico de barras horizontal (barh) para que los nombres de países sean legibles
ax3.barh(
    eventos_pais.index,
    eventos_pais.values,
    color=colores_pais,
    edgecolor=COLORES["fondo"],
    linewidth=0.5
)

# Etiquetas con el número exacto al final de cada barra
for i, (pais, valor) in enumerate(zip(eventos_pais.index, eventos_pais.values)):
    ax3.text(
        valor + 5, i, str(valor),
        va="center", ha="left",
        color=COLORES["texto"], fontsize=8
    )

ax3.set_title("Eventos por País", fontweight="bold")
ax3.set_xlabel("Cantidad de eventos")

parche_rojo  = mpatches.Patch(color=COLORES["peligro"], label="País sospechoso")
parche_verde = mpatches.Patch(color=COLORES["seguro"],  label="País normal")
ax3.legend(handles=[parche_rojo, parche_verde], fontsize=7,
          facecolor=COLORES["fondo"], labelcolor=COLORES["texto"])

ax3.grid(axis="x", color=COLORES["grid"], linewidth=0.5, alpha=0.5)


# ─────────────────────────────────────────────
# GRÁFICO 4 — Risk score promedio por país
# axes[1, 0] = fila 1, columna 0
# ─────────────────────────────────────────────

ax4 = axes[1, 0]

riesgo_pais = (
    df.groupby("country")["risk_score"]
    .mean()
    .round(1)
    .sort_values(ascending=True)  # Ascendente para que el más peligroso quede arriba
)

colores_riesgo = [
    COLORES["peligro"] if p in PAISES_SOSPECHOSOS else COLORES["seguro"]
    for p in riesgo_pais.index
]

ax4.barh(
    riesgo_pais.index,
    riesgo_pais.values,
    color=colores_riesgo,
    edgecolor=COLORES["fondo"],
    linewidth=0.5
)

# Etiquetas con el score exacto
for i, (pais, score) in enumerate(zip(riesgo_pais.index, riesgo_pais.values)):
    ax4.text(
        score + 0.5, i, f"{score}",
        va="center", ha="left",
        color=COLORES["texto"], fontsize=8
    )

# Línea de umbral de alto riesgo
ax4.axvline(x=70, color="#e67e22", linestyle="--",
           linewidth=1.5, alpha=0.8, label="Umbral alto riesgo (70)")

ax4.set_title("Risk Score Promedio por País", fontweight="bold")
ax4.set_xlabel("Risk Score promedio")
ax4.set_xlim(0, 115)

ax4.legend(fontsize=7, facecolor=COLORES["fondo"], labelcolor=COLORES["texto"])
ax4.grid(axis="x", color=COLORES["grid"], linewidth=0.5, alpha=0.5)


# ─────────────────────────────────────────────
# GRÁFICO 5 — Alertas por tipo
# axes[1, 1] = fila 1, columna 1
# ─────────────────────────────────────────────

ax5 = axes[1, 1]

alertas_por_tipo = df_alertas["tipo_alerta"].value_counts()

colores_alertas = [
    COLORES["peligro"],
    COLORES["brute_force"],
    COLORES["unusual_country"],
    COLORES["compromised_account"]
]

barras_alertas = ax5.bar(
    alertas_por_tipo.index,
    alertas_por_tipo.values,
    color=colores_alertas[:len(alertas_por_tipo)],
    edgecolor=COLORES["fondo"],
    linewidth=0.5,
    width=0.6
)

# Número encima de cada barra
for barra in barras_alertas:
    altura = barra.get_height()
    ax5.text(
        barra.get_x() + barra.get_width() / 2,
        altura + 0.1,
        str(int(altura)),
        ha="center", va="bottom",
        color=COLORES["texto"], fontweight="bold", fontsize=10
    )

ax5.set_title("Alertas Generadas por Tipo", fontweight="bold")
ax5.set_ylabel("Cantidad de alertas")
ax5.set_xticklabels(alertas_por_tipo.index, rotation=15, ha="right", fontsize=8)
ax5.grid(axis="y", color=COLORES["grid"], linewidth=0.5, alpha=0.5)
ax5.set_ylim(0, alertas_por_tipo.max() + 3)


# ─────────────────────────────────────────────
# GRÁFICO 6 — Usuarios con más alertas
# axes[1, 2] = fila 1, columna 2
# ─────────────────────────────────────────────

ax6 = axes[1, 2]

usuarios_alertas = df_alertas["user_id"].value_counts().head(10)

# Gradiente de color: más alertas = más rojo
max_alertas = usuarios_alertas.max()
colores_usuarios = [
    plt.cm.RdYlGn_r(valor / max_alertas)
    for valor in usuarios_alertas.values
]

barras_usuarios = ax6.barh(
    usuarios_alertas.index[::-1],  # Invertimos para que el más peligroso quede arriba
    usuarios_alertas.values[::-1],
    color=colores_usuarios[::-1],
    edgecolor=COLORES["fondo"],
    linewidth=0.5
)

# Número al final de cada barra
for i, (usuario, valor) in enumerate(
    zip(usuarios_alertas.index[::-1], usuarios_alertas.values[::-1])
):
    ax6.text(
        valor + 0.05, i,
        f"{valor} alertas",
        va="center", ha="left",
        color=COLORES["texto"], fontsize=8
    )

ax6.set_title("Top Usuarios por Alertas (Prioridad)", fontweight="bold")
ax6.set_xlabel("Cantidad de alertas")
ax6.set_xlim(0, max_alertas + 1.5)
ax6.grid(axis="x", color=COLORES["grid"], linewidth=0.5, alpha=0.5)


# ─────────────────────────────────────────────
# EXPORTACIÓN
# ─────────────────────────────────────────────

plt.tight_layout(pad=2.0)

# Guardamos como PNG de alta resolución
# dpi=150 significa 150 puntos por pulgada (calidad suficiente para LinkedIn)
plt.savefig(
    "dashboard.png",
    dpi=150,
    bbox_inches="tight",
    facecolor=COLORES["fondo"],
    edgecolor="none"
)

print("✅ Dashboard exportado: visualization/dashboard.png")
plt.show()