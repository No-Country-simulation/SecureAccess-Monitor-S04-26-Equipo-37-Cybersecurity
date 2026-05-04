"""
SecureAccess Monitor — Live Dashboard
======================================
Servidor web con WebSockets que transmite eventos
y alertas en tiempo real al navegador.

Tecnologías:
- FastAPI  → servidor web en Python
- WebSocket → conexión en vivo servidor ↔ navegador
- HTML/JS  → dashboard en el navegador
"""

import asyncio
import json
import pandas as pd
from datetime import datetime, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI()

# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]
UMBRAL_FALLOS      = 5
UMBRAL_VENTANA_SEG = 120
DELAY_NORMAL       = 0.05
DELAY_ALERTA       = 0.5

# Estado global del sistema
estado_usuarios  = {}
total_eventos    = 0
total_alertas    = 0
alertas_log      = []
eventos_recientes = []


# ─────────────────────────────────────────────
# LÓGICA DE DETECCIÓN (igual que realtime_detector)
# ─────────────────────────────────────────────

def inicializar_usuario(user_id):
    estado_usuarios[user_id] = {
        "paises_vistos"      : set(),
        "fallos_recientes"   : [],
        "recursos_accedidos" : set(),
        "recursos_recientes" : set(),
        "total_eventos"      : 0,
        "alertas_disparadas" : set()
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
                        "detalle": f"Primer acceso a {evento['resource']} tras {estado['total_eventos']} eventos normales"})
        estado["alertas_disparadas"].add(clave_cc)

    return alertas


# ─────────────────────────────────────────────
# DASHBOARD HTML
# ─────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureAccess Monitor</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Courier New', monospace;
    background: #0a0e1a;
    color: #e0e6f0;
    min-height: 100vh;
    padding: 20px;
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 24px;
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    margin-bottom: 20px;
  }

  header h1 {
    font-size: 18px;
    color: #60a5fa;
    letter-spacing: 2px;
  }

  .dot {
    width: 10px; height: 10px;
    background: #22c55e;
    border-radius: 50%;
    animation: pulse 1.5s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .status-bar {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }

  .kpi {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }

  .kpi .val {
    font-size: 28px;
    font-weight: bold;
    color: #60a5fa;
  }

  .kpi .val.red   { color: #f87171; }
  .kpi .val.green { color: #4ade80; }
  .kpi .val.amber { color: #fbbf24; }

  .kpi .lbl {
    font-size: 11px;
    color: #6b7280;
    margin-top: 4px;
    letter-spacing: 1px;
    text-transform: uppercase;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  .panel {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    overflow: hidden;
  }

  .panel-header {
    padding: 10px 16px;
    background: #0f172a;
    border-bottom: 1px solid #1e3a5f;
    font-size: 12px;
    letter-spacing: 2px;
    color: #60a5fa;
    text-transform: uppercase;
  }

  .panel-body {
    padding: 8px;
    height: 360px;
    overflow-y: auto;
  }

  .panel-body::-webkit-scrollbar { width: 4px; }
  .panel-body::-webkit-scrollbar-track { background: #0a0e1a; }
  .panel-body::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }

  .evento {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    border-radius: 4px;
    margin-bottom: 2px;
    font-size: 11px;
    animation: fadeIn 0.3s ease;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .evento.normal    { color: #4ade80; }
  .evento.warning   { color: #fbbf24; background: rgba(251,191,36,0.05); }
  .evento.critical  { color: #f87171; background: rgba(248,113,113,0.08); border-left: 2px solid #f87171; }

  .alerta {
    padding: 10px 14px;
    margin-bottom: 6px;
    border-radius: 6px;
    font-size: 12px;
    border-left: 3px solid;
    animation: fadeIn 0.4s ease;
  }

  .alerta.FUERZA_BRUTA       { background: rgba(239,68,68,0.1);  border-color: #ef4444; color: #fca5a5; }
  .alerta.PAIS_SOSPECHOSO    { background: rgba(249,115,22,0.1); border-color: #f97316; color: #fdba74; }
  .alerta.HORARIO_INUSUAL    { background: rgba(234,179,8,0.1);  border-color: #eab308; color: #fde047; }
  .alerta.CUENTA_COMPROMETIDA{ background: rgba(168,85,247,0.1); border-color: #a855f7; color: #d8b4fe; }

  .alerta .tipo {
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
  }

  .alerta .info {
    font-size: 11px;
    margin-top: 3px;
    opacity: 0.8;
  }

  .tag {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 99px;
    background: rgba(96,165,250,0.15);
    color: #60a5fa;
  }

  .score-high { color: #f87171; font-weight: bold; }
  .score-mid  { color: #fbbf24; }
  .score-low  { color: #4ade80; }
</style>
</head>
<body>

<header>
  <div class="dot"></div>
  <h1>🔐 SECUREACCESS MONITOR</h1>
  <span style="margin-left:auto; font-size:11px; color:#6b7280;" id="clock"></span>
</header>

<div class="status-bar">
  <div class="kpi">
    <div class="val green" id="total-eventos">0</div>
    <div class="lbl">Eventos procesados</div>
  </div>
  <div class="kpi">
    <div class="val red" id="total-alertas">0</div>
    <div class="lbl">Alertas generadas</div>
  </div>
  <div class="kpi">
    <div class="val amber" id="tasa">0.00%</div>
    <div class="lbl">Tasa de detección</div>
  </div>
  <div class="kpi">
    <div class="val" id="usuarios-alertados">0</div>
    <div class="lbl">Usuarios alertados</div>
  </div>
</div>

<div class="grid">
  <div class="panel">
    <div class="panel-header">🚨 Alertas en vivo</div>
    <div class="panel-body" id="alertas-panel">
      <div style="color:#374151; font-size:12px; padding:20px; text-align:center;">
        Esperando alertas...
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">📡 Feed de eventos</div>
    <div class="panel-body" id="eventos-panel"></div>
  </div>
</div>

<script>
  // Reloj en vivo
  setInterval(() => {
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
  }, 1000);

  // Usuarios alertados (set para no repetir)
  const usuariosAlertados = new Set();

  // Conectamos el WebSocket al servidor Python
  const ws = new WebSocket("ws://localhost:8000/ws");

  ws.onmessage = function(event) {
    const data = JSON.parse(event.data);

    // Actualizamos los KPIs
    document.getElementById('total-eventos').textContent = data.total_eventos;
    document.getElementById('total-alertas').textContent = data.total_alertas;
    document.getElementById('tasa').textContent = data.tasa + '%';

    // Si hay alertas, las mostramos
    if (data.alertas && data.alertas.length > 0) {
      const panel = document.getElementById('alertas-panel');

      // Limpiamos el mensaje inicial
      if (panel.querySelector('div[style]')) panel.innerHTML = '';

      data.alertas.forEach(alerta => {
        usuariosAlertados.add(data.user_id);
        document.getElementById('usuarios-alertados').textContent = usuariosAlertados.size;

        const div = document.createElement('div');
        div.className = `alerta ${alerta.tipo}`;
        div.innerHTML = `
          <div class="tipo">⚡ ${alerta.tipo.replace('_', ' ')}</div>
          <div class="info">
            <strong>${data.user_id}</strong> · ${data.pais} ·
            ${data.timestamp.substring(5, 16)}
          </div>
          <div class="info">${alerta.detalle}</div>
          <div class="info">Risk score: <strong>${data.score}</strong></div>
        `;
        panel.insertBefore(div, panel.firstChild);

        // Máximo 50 alertas visibles
        if (panel.children.length > 50) panel.removeChild(panel.lastChild);
      });
    }

    // Agregamos el evento al feed
    const feedPanel = document.getElementById('eventos-panel');
    const scoreClass = data.score >= 70 ? 'score-high' : data.score > 0 ? 'score-mid' : 'score-low';
    const clase = data.alertas.length > 0 ? 'critical' : data.score > 0 ? 'warning' : 'normal';
    const icono = data.alertas.length > 0 ? '🚨' : data.score > 0 ? '⚠' : '✓';

    const div = document.createElement('div');
    div.className = `evento ${clase}`;
    div.innerHTML = `
      <span>${icono}</span>
      <span class="tag">${data.user_id}</span>
      <span>${data.pais.substring(0,8)}</span>
      <span style="color:#9ca3af">${data.recurso}</span>
      <span style="margin-left:auto" class="${scoreClass}">${data.score > 0 ? 'score:'+data.score : ''}</span>
    `;
    feedPanel.insertBefore(div, feedPanel.firstChild);

    if (feedPanel.children.length > 100) feedPanel.removeChild(feedPanel.lastChild);
  };

  ws.onclose = function() {
    document.querySelector('.dot').style.background = '#ef4444';
    document.querySelector('.dot').style.animation = 'none';
  };
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────
# RUTAS DEL SERVIDOR
# ─────────────────────────────────────────────

@app.get("/")
async def get():
    """Sirve el dashboard HTML al navegador."""
    return HTMLResponse(HTML)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Endpoint WebSocket: acepta la conexión del navegador
    y empieza a transmitir eventos en tiempo real.
    """
    global total_eventos, total_alertas

    await websocket.accept()

    df = pd.read_csv("data/access_logs.csv")
    df = df.sort_values("timestamp").reset_index(drop=True)

    try:
        for _, evento in df.iterrows():
            user_id = evento["user_id"]

            actualizar_estado(user_id, evento)
            estado = estado_usuarios[user_id]
            score  = calcular_riesgo(evento, estado)
            alertas = evaluar_reglas(user_id, evento, score)

            total_eventos += 1
            total_alertas += len(alertas)

            tasa = f"{(total_alertas/total_eventos*100):.2f}" if total_eventos > 0 else "0.00"

            # Enviamos los datos al navegador como JSON
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
                "alertas"       : alertas
            })

            delay = DELAY_ALERTA if alertas else DELAY_NORMAL
            await asyncio.sleep(delay)

    except WebSocketDisconnect:
        pass


# ─────────────────────────────────────────────
# INICIO DEL SERVIDOR
# ─────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)