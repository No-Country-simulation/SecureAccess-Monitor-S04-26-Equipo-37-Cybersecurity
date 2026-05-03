"""
SecureAccess Monitor — Panel simple de alertas con Streamlit
============================================================
Este script ofrece una visualización ligera de las alertas generadas
por el análisis de logs. Solo usa Python y Streamlit para mantener la
implementación mínima.

Ejecutar:
    streamlit run streamlit_app.py
"""

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SecureAccess Monitor",
    layout="wide",
    initial_sidebar_state="expanded",
)

@st.cache_data
def load_data():
    df_alertas = pd.read_csv("data/alertas.csv")
    df_logs = pd.read_csv("data/access_logs.csv", parse_dates=["timestamp"])
    return df_alertas, df_logs

try:
    df_alertas, df_logs = load_data()
except FileNotFoundError as exc:
    st.error(
        "No se encontró el dataset necesario. Ejecuta primero los scripts de generación y detección:\n"
        "python data/generate_dataset.py && python analysis/detection_rules.py"
    )
    st.stop()

# Página
st.title("SecureAccess Monitor — Panel de Alertas")
st.markdown(
    "Este panel muestra información básica de las alertas generadas por el análisis de eventos de acceso."
)

# Sidebar
st.sidebar.header("Controles")
if st.sidebar.button("Recargar datos"):
    try:
        st.experimental_rerun()
    except AttributeError:
        st.sidebar.info("Refresca la página en el navegador para recargar los datos.")

selected_types = st.sidebar.multiselect(
    "Filtrar por tipo de alerta",
    options=df_alertas["tipo_alerta"].unique(),
    default=df_alertas["tipo_alerta"].unique(),
)

filtered_alertas = df_alertas[df_alertas["tipo_alerta"].isin(selected_types)]

# Métricas principales
col1, col2, col3, col4 = st.columns(4)
col1.metric("Alertas totales", len(filtered_alertas))
col2.metric("Tipos de alerta", filtered_alertas["tipo_alerta"].nunique())
col3.metric("Usuarios con alerta", filtered_alertas["user_id"].nunique())
col4.metric("Eventos en logs", len(df_logs))

# Resumen de alertas
st.subheader("Resumen de alertas")
alertas_por_tipo = (
    filtered_alertas["tipo_alerta"]
    .value_counts()
    .rename_axis("tipo_alerta")
    .reset_index(name="conteo")
)

st.bar_chart(
    data=alertas_por_tipo.set_index("tipo_alerta"),
    y="conteo",
)

st.write("### Tabla de alertas filtradas")
st.dataframe(filtered_alertas.sort_values("primer_evento", ascending=False).reset_index(drop=True))

# Alertas recientes
st.subheader("Últimas alertas detectadas")
if not filtered_alertas.empty:
    latest_alerts = filtered_alertas.sort_values("primer_evento", ascending=False).head(5)
    st.table(latest_alerts[["tipo_alerta", "user_id", "pais", "resource", "risk_score_max", "total_eventos", "detalle"]])
else:
    st.info("No hay alertas para el filtro seleccionado.")

# Actividad y riesgos en los logs
st.subheader("Actividad de acceso en los logs")
col5, col6 = st.columns(2)
with col5:
    st.write("#### Distribución de status")
    status_counts = df_logs["status"].value_counts()
    st.bar_chart(status_counts)
with col6:
    st.write("#### Recursos más accedidos")
    resource_counts = df_logs["resource"].value_counts().head(10)
    st.bar_chart(resource_counts)

# Línea de tiempo simple de alertas
st.subheader("Tendencia de alertas por fecha")
if not filtered_alertas.empty:
    df_timeline = filtered_alertas.copy()
    df_timeline["fecha"] = pd.to_datetime(df_timeline["primer_evento"]).dt.date
    timeline = df_timeline["fecha"].value_counts().sort_index()
    st.line_chart(timeline)
else:
    st.write("No hay datos de alerta para la línea de tiempo.")

st.markdown(
    "---\n"
    "**Nota:** este panel es una vista ligera de las alertas y no requiere lógica de autenticación."
)
