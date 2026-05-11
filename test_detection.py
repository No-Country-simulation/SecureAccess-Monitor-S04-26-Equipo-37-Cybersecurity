"""
SecureAccess Monitor — Tests Automatizados
==========================================
Verifica que las reglas de detección funcionen correctamente.

Cómo correr los tests:
    pytest test_detection.py -v

El flag -v (verbose) muestra el nombre de cada test y si pasó o falló.
"""

import pytest
from datetime import datetime, timedelta


# ─────────────────────────────────────────────
# CONFIGURACIÓN (copiada del sistema principal)
# ─────────────────────────────────────────────

PAISES_SOSPECHOSOS = ["Rusia", "China", "Corea del Norte", "Nigeria", "Iran"]
RECURSOS_SENSIBLES = ["admin_panel", "database", "billing"]
RECURSOS_NORMALES  = ["login", "dashboard", "api", "file_storage"]
UMBRAL_FALLOS      = 5
UMBRAL_VENTANA_SEG = 120


# ─────────────────────────────────────────────
# FUNCIONES A TESTEAR (extraídas del sistema)
# ─────────────────────────────────────────────

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
    if intentos_fallidos > UMBRAL_FALLOS:
        score += 10
    return min(score, 100)


def inicializar_estado():
    """Crea un estado de usuario limpio para cada test."""
    return {
        "paises_vistos"     : set(),
        "fallos_recientes"  : [],
        "recursos_accedidos": set(),
        "recursos_recientes": set(),
        "total_eventos"     : 0,
        "alertas_disparadas": set()
    }


def evaluar_fuerza_bruta(estado, timestamp):
    """Evalúa la regla de fuerza bruta contra el estado actual."""
    clave = f"fb_{timestamp.strftime('%Y%m%d%H%M')}"
    if (len(estado["fallos_recientes"]) > UMBRAL_FALLOS and
            clave not in estado["alertas_disparadas"]):
        estado["alertas_disparadas"].add(clave)
        return True
    return False


def evaluar_pais_sospechoso(estado, pais, recurso):
    """Evalúa la regla de país sospechoso."""
    clave = f"ps_{pais}"
    if (pais in PAISES_SOSPECHOSOS and
            recurso in RECURSOS_SENSIBLES and
            clave not in estado["alertas_disparadas"]):
        estado["alertas_disparadas"].add(clave)
        return True
    return False


def evaluar_horario_inusual(estado, hora, recurso, timestamp):
    """Evalúa la regla de horario inusual."""
    clave = f"hi_{timestamp.strftime('%Y%m%d')}"
    if (hora < 6 and
            recurso in RECURSOS_SENSIBLES and
            clave not in estado["alertas_disparadas"]):
        estado["alertas_disparadas"].add(clave)
        return True
    return False


def evaluar_cuenta_comprometida(estado, recurso):
    """Evalúa la regla de cuenta comprometida."""
    clave = f"cc_{recurso}"
    recursos_nuevos = estado["recursos_recientes"] - estado["recursos_accedidos"]
    if (recurso in RECURSOS_SENSIBLES and
            recurso in recursos_nuevos and
            estado["total_eventos"] > 50 and
            clave not in estado["alertas_disparadas"]):
        estado["alertas_disparadas"].add(clave)
        return True
    return False


# ─────────────────────────────────────────────
# TESTS — calcular_riesgo()
# ─────────────────────────────────────────────

class TestCalcularRiesgo:
    """
    En pytest, agrupamos tests relacionados en clases.
    Cada método que empiece con 'test_' es un test individual.
    """

    def test_evento_completamente_normal(self):
        """Un usuario normal en horario laboral desde país seguro debe tener score 0."""
        score = calcular_riesgo(
            status="success",
            pais="Argentina",
            recurso="dashboard",
            hora=14
        )
        # assert verifica que la condición sea verdadera
        # Si no lo es, el test falla y pytest te dice exactamente dónde
        assert score == 0, f"Se esperaba 0 pero se obtuvo {score}"

    def test_pais_sospechoso_suma_30(self):
        """Un acceso desde país sospechoso debe sumar 30 puntos."""
        score = calcular_riesgo(
            status="success",
            pais="Rusia",
            recurso="dashboard",
            hora=14
        )
        assert score == 30, f"Se esperaba 30 pero se obtuvo {score}"

    def test_recurso_sensible_suma_25(self):
        """Acceso a recurso sensible desde país normal debe sumar 25 puntos."""
        score = calcular_riesgo(
            status="success",
            pais="Argentina",
            recurso="admin_panel",
            hora=14
        )
        assert score == 25, f"Se esperaba 25 pero se obtuvo {score}"

    def test_acceso_fallido_suma_20(self):
        """Un intento fallido debe sumar 20 puntos."""
        score = calcular_riesgo(
            status="failed",
            pais="Argentina",
            recurso="dashboard",
            hora=14
        )
        assert score == 20, f"Se esperaba 20 pero se obtuvo {score}"

    def test_horario_madrugada_suma_15(self):
        """Acceso a las 3am debe sumar 15 puntos."""
        score = calcular_riesgo(
            status="success",
            pais="Argentina",
            recurso="dashboard",
            hora=3
        )
        assert score == 15, f"Se esperaba 15 pero se obtuvo {score}"

    def test_ataque_maximo_score_100(self):
        """Un ataque completo desde país sospechoso debe dar score máximo."""
        score = calcular_riesgo(
            status="failed",
            pais="Rusia",
            recurso="admin_panel",
            hora=2,
            intentos_fallidos=10
        )
        assert score == 100, f"Se esperaba 100 pero se obtuvo {score}"

    def test_score_nunca_supera_100(self):
        """El score nunca debe superar 100 aunque se acumulen muchos factores."""
        score = calcular_riesgo(
            status="failed",
            pais="China",
            recurso="database",
            hora=1,
            intentos_fallidos=100
        )
        assert score <= 100, f"El score superó 100: {score}"

    def test_todos_paises_sospechosos_detectados(self):
        """Todos los países de la lista negra deben sumar puntos."""
        for pais in PAISES_SOSPECHOSOS:
            score = calcular_riesgo("success", pais, "dashboard", 14)
            assert score == 30, f"{pais} no sumó los 30 puntos esperados"

    def test_todos_recursos_sensibles_detectados(self):
        """Todos los recursos sensibles deben sumar puntos."""
        for recurso in RECURSOS_SENSIBLES:
            score = calcular_riesgo("success", "Argentina", recurso, 14)
            assert score == 25, f"{recurso} no sumó los 25 puntos esperados"


# ─────────────────────────────────────────────
# TESTS — Regla de fuerza bruta
# ─────────────────────────────────────────────

class TestFuerzaBruta:

    def test_detecta_multiples_fallos_en_ventana(self):
        """Debe detectar fuerza bruta con más de 5 fallos en 2 minutos."""
        estado = inicializar_estado()
        ahora  = datetime(2024, 3, 15, 0, 0, 0)

        # Simulamos 6 fallos en 90 segundos
        for i in range(6):
            estado["fallos_recientes"].append(ahora + timedelta(seconds=i * 15))

        detectado = evaluar_fuerza_bruta(estado, ahora + timedelta(seconds=90))
        assert detectado == True, "No detectó fuerza bruta con 6 fallos en 90 segundos"

    def test_no_dispara_con_pocos_fallos(self):
        """No debe detectar fuerza bruta con 3 fallos normales."""
        estado = inicializar_estado()
        ahora  = datetime(2024, 3, 15, 10, 0, 0)

        # Solo 3 fallos — usuario que se equivocó de contraseña
        for i in range(3):
            estado["fallos_recientes"].append(ahora + timedelta(seconds=i * 30))

        detectado = evaluar_fuerza_bruta(estado, ahora + timedelta(seconds=90))
        assert detectado == False, "Falso positivo: detectó fuerza bruta con solo 3 fallos"

    def test_no_repite_la_misma_alerta(self):
        """La misma alerta no debe dispararse dos veces en el mismo minuto."""
        estado = inicializar_estado()
        ahora  = datetime(2024, 3, 15, 0, 0, 0)

        for i in range(10):
            estado["fallos_recientes"].append(ahora + timedelta(seconds=i * 5))

        primera  = evaluar_fuerza_bruta(estado, ahora)
        segunda  = evaluar_fuerza_bruta(estado, ahora)  # Mismo minuto

        assert primera == True,  "La primera alerta no se disparó"
        assert segunda == False, "La alerta se repitió en el mismo minuto"


# ─────────────────────────────────────────────
# TESTS — Regla de país sospechoso
# ─────────────────────────────────────────────

class TestPaisSospechoso:

    def test_detecta_pais_sospechoso_con_recurso_sensible(self):
        """Debe detectar acceso desde Rusia a admin_panel."""
        estado    = inicializar_estado()
        detectado = evaluar_pais_sospechoso(estado, "Rusia", "admin_panel")
        assert detectado == True

    def test_no_dispara_para_pais_normal(self):
        """No debe detectar acceso desde Argentina."""
        estado    = inicializar_estado()
        detectado = evaluar_pais_sospechoso(estado, "Argentina", "admin_panel")
        assert detectado == False

    def test_no_dispara_para_recurso_normal(self):
        """No debe detectar acceso desde Rusia al dashboard (recurso normal)."""
        estado    = inicializar_estado()
        detectado = evaluar_pais_sospechoso(estado, "Rusia", "dashboard")
        assert detectado == False, "Falso positivo: Rusia + dashboard no debería alertar"

    def test_detecta_todos_los_paises_sospechosos(self):
        """Todos los países de la lista negra deben generar alerta."""
        for pais in PAISES_SOSPECHOSOS:
            estado    = inicializar_estado()
            detectado = evaluar_pais_sospechoso(estado, pais, "database")
            assert detectado == True, f"{pais} no generó alerta"


# ─────────────────────────────────────────────
# TESTS — Regla de horario inusual
# ─────────────────────────────────────────────

class TestHorarioInusual:

    def test_detecta_acceso_en_madrugada(self):
        """Debe detectar acceso a database a las 3am."""
        estado    = inicializar_estado()
        timestamp = datetime(2024, 3, 15, 3, 0, 0)
        detectado = evaluar_horario_inusual(estado, 3, "database", timestamp)
        assert detectado == True

    def test_no_dispara_en_horario_laboral(self):
        """No debe detectar acceso en horario laboral normal."""
        estado    = inicializar_estado()
        timestamp = datetime(2024, 3, 15, 14, 0, 0)
        detectado = evaluar_horario_inusual(estado, 14, "database", timestamp)
        assert detectado == False

    def test_no_dispara_para_recurso_normal_en_madrugada(self):
        """Dashboard a las 3am no debe generar alerta (solo recursos sensibles)."""
        estado    = inicializar_estado()
        timestamp = datetime(2024, 3, 15, 3, 0, 0)
        detectado = evaluar_horario_inusual(estado, 3, "dashboard", timestamp)
        assert detectado == False

    @pytest.mark.parametrize("hora", [0, 1, 2, 3, 4, 5])
    def test_todas_las_horas_de_madrugada(self, hora):
        """Todas las horas entre 0 y 5 deben generar alerta con recurso sensible."""
        estado    = inicializar_estado()
        timestamp = datetime(2024, 3, 15, hora, 0, 0)
        detectado = evaluar_horario_inusual(estado, hora, "admin_panel", timestamp)
        assert detectado == True, f"No detectó acceso sospechoso a las {hora}:00"


# ─────────────────────────────────────────────
# TESTS — Regla de cuenta comprometida
# ─────────────────────────────────────────────

class TestCuentaComprometida:

    def test_detecta_recurso_nuevo_sensible(self):
        """Debe detectar cuando un usuario accede a un recurso sensible nuevo."""
        estado = inicializar_estado()
        estado["total_eventos"] = 60  # Simula historial largo

        # En la primera mitad solo usó recursos normales
        estado["recursos_accedidos"] = {"login", "dashboard", "api"}

        # En la segunda mitad accede a admin_panel por primera vez
        estado["recursos_recientes"] = {"admin_panel"}

        detectado = evaluar_cuenta_comprometida(estado, "admin_panel")
        assert detectado == True

    def test_no_dispara_con_historial_corto(self):
        """No debe alertar si el usuario tiene poco historial (podría ser nuevo)."""
        estado = inicializar_estado()
        estado["total_eventos"] = 10  # Historial corto

        estado["recursos_accedidos"] = {"login"}
        estado["recursos_recientes"] = {"admin_panel"}

        detectado = evaluar_cuenta_comprometida(estado, "admin_panel")
        assert detectado == False

    def test_no_dispara_si_ya_usaba_ese_recurso(self):
        """No debe alertar si el usuario ya usaba ese recurso antes."""
        estado = inicializar_estado()
        estado["total_eventos"] = 60

        # Ya usaba admin_panel desde el principio
        estado["recursos_accedidos"] = {"login", "dashboard", "admin_panel"}
        estado["recursos_recientes"] = {"admin_panel"}

        detectado = evaluar_cuenta_comprometida(estado, "admin_panel")
        assert detectado == False, "Falso positivo: el usuario ya usaba ese recurso"