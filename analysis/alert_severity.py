"""
SecureAccess Monitor — Sistema de Severidad de Alertas
=======================================================
Clasifica las alertas por nivel de severidad y genera
recomendaciones automáticas de respuesta a incidentes.

Niveles: CRÍTICO → ALTO → MEDIO → BAJO
"""

# ─────────────────────────────────────────────
# DEFINICIÓN DE NIVELES DE SEVERIDAD
# ─────────────────────────────────────────────

NIVELES = {
    "CRITICO" : {"min": 90,  "max": 100, "color_terminal": "\033[91m",  "emoji": "🔴"},
    "ALTO"    : {"min": 70,  "max": 89,  "color_terminal": "\033[33m",  "emoji": "🟠"},
    "MEDIO"   : {"min": 40,  "max": 69,  "color_terminal": "\033[93m",  "emoji": "🟡"},
    "BAJO"    : {"min": 1,   "max": 39,  "color_terminal": "\033[94m",  "emoji": "🔵"},
    "NORMAL"  : {"min": 0,   "max": 0,   "color_terminal": "\033[92m",  "emoji": "✅"},
}

# Tiempos de respuesta recomendados por nivel
TIEMPOS_RESPUESTA = {
    "CRITICO" : "INMEDIATO — actuar en los próximos minutos",
    "ALTO"    : "URGENTE — actuar en menos de 1 hora",
    "MEDIO"   : "MODERADO — revisar en menos de 24 horas",
    "BAJO"    : "RUTINARIO — incluir en revisión diaria",
    "NORMAL"  : "Sin acción requerida",
}

# ─────────────────────────────────────────────
# RECOMENDACIONES POR TIPO DE ALERTA Y SEVERIDAD
# ─────────────────────────────────────────────

RECOMENDACIONES = {
    "FUERZA_BRUTA": {
        "CRITICO": [
            "Bloquear la IP de origen inmediatamente",
            "Resetear las credenciales del usuario afectado",
            "Verificar si hubo algún acceso exitoso durante el ataque",
            "Activar autenticación multifactor (MFA) para el usuario",
            "Revisar logs de los últimos 30 minutos del mismo origen",
        ],
        "ALTO": [
            "Bloquear temporalmente la IP de origen",
            "Notificar al usuario sobre actividad sospechosa",
            "Revisar intentos de acceso exitosos recientes",
            "Considerar activar MFA preventivamente",
        ],
        "MEDIO": [
            "Registrar la IP para monitoreo continuo",
            "Revisar el patrón de intentos fallidos del usuario",
            "Verificar si el usuario reportó problemas de acceso",
        ],
        "BAJO": [
            "Registrar el evento para análisis posterior",
            "Incluir en reporte diario de actividad",
        ],
    },

    "PAIS_SOSPECHOSO": {
        "CRITICO": [
            "Bloquear el acceso geográfico inmediatamente",
            "Suspender la sesión activa del usuario",
            "Contactar al usuario por canal alternativo verificado",
            "Auditar todos los recursos accedidos en esta sesión",
            "Iniciar protocolo de respuesta a incidentes",
        ],
        "ALTO": [
            "Verificar si el usuario tiene viaje autorizado al país",
            "Solicitar verificación de identidad adicional",
            "Monitorear la sesión en tiempo real",
            "Considerar bloqueo geográfico temporal",
        ],
        "MEDIO": [
            "Documentar el acceso inusual",
            "Verificar con el usuario si reconoce la actividad",
            "Revisar política de acceso geográfico",
        ],
        "BAJO": [
            "Registrar para análisis de patrones geográficos",
            "Incluir en reporte semanal",
        ],
    },

    "HORARIO_INUSUAL": {
        "CRITICO": [
            "Verificar identidad del usuario inmediatamente",
            "Revisar recursos accedidos en la sesión nocturna",
            "Comparar comportamiento con historial del usuario",
            "Considerar suspender sesión hasta verificación",
        ],
        "ALTO": [
            "Contactar al usuario para confirmar la actividad",
            "Revisar si hay justificación para el acceso nocturno",
            "Monitorear el resto de la sesión activamente",
        ],
        "MEDIO": [
            "Registrar el patrón horario inusual",
            "Verificar con el usuario o su supervisor",
            "Comparar con historial de accesos del último mes",
        ],
        "BAJO": [
            "Documentar el cambio de patrón horario",
            "Incluir en análisis de comportamiento mensual",
        ],
    },

    "CUENTA_COMPROMETIDA": {
        "CRITICO": [
            "Suspender la cuenta inmediatamente",
            "Revocar todos los tokens de sesión activos",
            "Auditar todos los recursos accedidos recientemente",
            "Iniciar investigación forense de la cuenta",
            "Notificar al equipo de seguridad y al usuario",
        ],
        "ALTO": [
            "Forzar cierre de sesión y re-autenticación",
            "Revisar cambios realizados en recursos sensibles",
            "Activar MFA obligatorio para el usuario",
            "Monitorear la cuenta con atención elevada",
        ],
        "MEDIO": [
            "Solicitar re-autenticación al usuario",
            "Revisar historial de accesos recientes",
            "Verificar si el comportamiento tiene justificación",
        ],
        "BAJO": [
            "Registrar el cambio de comportamiento",
            "Hacer seguimiento en los próximos días",
        ],
    },
}


# ─────────────────────────────────────────────
# FUNCIONES PRINCIPALES
# ─────────────────────────────────────────────

def clasificar_severidad(score):
    """
    Determina el nivel de severidad basado en el risk score.
    Devuelve el nombre del nivel como string.
    """
    if score >= 90:
        return "CRITICO"
    elif score >= 70:
        return "ALTO"
    elif score >= 40:
        return "MEDIO"
    elif score > 0:
        return "BAJO"
    else:
        return "NORMAL"


def obtener_recomendaciones(tipo_alerta, severidad):
    """
    Devuelve la lista de recomendaciones para un tipo de alerta
    y nivel de severidad específicos.
    """
    if tipo_alerta not in RECOMENDACIONES:
        return ["Revisar el evento manualmente"]

    nivel = severidad if severidad in RECOMENDACIONES[tipo_alerta] else "BAJO"
    return RECOMENDACIONES[tipo_alerta][nivel]


def construir_alerta_completa(tipo_alerta, user_id, pais, recurso, score, timestamp, detalle):
    """
    Construye un objeto de alerta completo con severidad,
    tiempo de respuesta y recomendaciones incluidas.

    Este es el objeto que viaja al dashboard y al email.
    """
    severidad      = clasificar_severidad(score)
    recomendaciones = obtener_recomendaciones(tipo_alerta, severidad)
    nivel_info     = NIVELES[severidad]

    return {
        "tipo_alerta"     : tipo_alerta,
        "severidad"       : severidad,
        "emoji"           : nivel_info["emoji"],
        "user_id"         : user_id,
        "pais"            : pais,
        "recurso"         : recurso,
        "score"           : score,
        "timestamp"       : str(timestamp),
        "detalle"         : detalle,
        "tiempo_respuesta": TIEMPOS_RESPUESTA[severidad],
        "recomendaciones" : recomendaciones,
    }


def formatear_para_terminal(alerta):
    """
    Formatea una alerta para imprimirla en la terminal con colores.
    """
    nivel_info = NIVELES[alerta["severidad"]]
    color      = nivel_info["color_terminal"]
    reset      = "\033[0m"

    lineas = [
        f"\n{color}{'─' * 55}{reset}",
        f"{color}{alerta['emoji']} ALERTA {alerta['severidad']} — {alerta['tipo_alerta']}{reset}",
        f"  Usuario    : {alerta['user_id']}",
        f"  País       : {alerta['pais']}",
        f"  Recurso    : {alerta['recurso']}",
        f"  Score      : {alerta['score']}/100",
        f"  Timestamp  : {alerta['timestamp']}",
        f"  Detalle    : {alerta['detalle']}",
        f"{color}  ⏱ Tiempo de respuesta: {alerta['tiempo_respuesta']}{reset}",
        f"{color}  📋 Recomendaciones:{reset}",
    ]

    for i, rec in enumerate(alerta["recomendaciones"], 1):
        lineas.append(f"     {i}. {rec}")

    lineas.append(f"{color}{'─' * 55}{reset}")
    return "\n".join(lineas)


def formatear_para_email(alerta):
    """
    Genera el HTML del email con la alerta completa
    incluyendo severidad y recomendaciones.
    """
    colores_severidad = {
        "CRITICO": "#ef4444",
        "ALTO"   : "#f97316",
        "MEDIO"  : "#eab308",
        "BAJO"   : "#3b82f6",
    }
    color = colores_severidad.get(alerta["severidad"], "#6b7280")

    recomendaciones_html = "".join([
        f"<li style='margin-bottom:6px; color:#e0e6f0;'>{rec}</li>"
        for rec in alerta["recomendaciones"]
    ])

    return f"""
    <html>
    <body style="font-family:monospace; background:#0a0e1a; color:#e0e6f0; padding:24px;">
    <div style="max-width:600px; margin:0 auto;">

        <div style="background:#111827; border:2px solid {color};
                    border-radius:8px; padding:24px; margin-bottom:16px;">
            <h1 style="color:{color}; font-size:18px; margin:0 0 4px;">
                {alerta['emoji']} ALERTA {alerta['severidad']} — {alerta['tipo_alerta'].replace('_',' ')}
            </h1>
            <p style="color:#9ca3af; font-size:11px; margin:0;">
                SecureAccess Monitor · {alerta['timestamp']}
            </p>
        </div>

        <div style="background:#111827; border:1px solid #1e3a5f;
                    border-radius:8px; padding:20px; margin-bottom:16px;">
            <table style="width:100%; border-collapse:collapse;">
                <tr><td style="color:#6b7280; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">USUARIO</td>
                    <td style="color:#60a5fa; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">{alerta['user_id']}</td></tr>
                <tr><td style="color:#6b7280; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">PAÍS</td>
                    <td style="color:#e0e6f0; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">{alerta['pais']}</td></tr>
                <tr><td style="color:#6b7280; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">RECURSO</td>
                    <td style="color:#e0e6f0; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">{alerta['recurso']}</td></tr>
                <tr><td style="color:#6b7280; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">RISK SCORE</td>
                    <td style="color:{color}; font-weight:bold; font-size:12px; padding:5px 0; border-bottom:1px solid #1e3a5f;">{alerta['score']}/100</td></tr>
                <tr><td style="color:#6b7280; font-size:12px; padding:5px 0;">DETALLE</td>
                    <td style="color:#e0e6f0; font-size:12px; padding:5px 0;">{alerta['detalle']}</td></tr>
            </table>
        </div>

        <div style="background:rgba(234,179,8,0.08); border:1px solid rgba(234,179,8,0.3);
                    border-radius:8px; padding:16px; margin-bottom:16px;">
            <p style="color:#fde047; font-size:12px; font-weight:bold; margin:0 0 4px;">
                ⏱ TIEMPO DE RESPUESTA RECOMENDADO
            </p>
            <p style="color:#fef9c3; font-size:12px; margin:0;">{alerta['tiempo_respuesta']}</p>
        </div>

        <div style="background:#111827; border:1px solid #1e3a5f;
                    border-radius:8px; padding:16px;">
            <p style="color:#60a5fa; font-size:12px; font-weight:bold; margin:0 0 12px;">
                📋 RECOMENDACIONES DE ACCIÓN
            </p>
            <ol style="margin:0; padding-left:20px;">
                {recomendaciones_html}
            </ol>
        </div>

    </div>
    </body>
    </html>
    """