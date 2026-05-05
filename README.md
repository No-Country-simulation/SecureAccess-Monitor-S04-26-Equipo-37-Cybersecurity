# 🔐 SecureAccess Monitor

> Sistema de Monitoreo y Análisis de Accesos en Infraestructura Cloud  
> Proyecto desarrollado en el marco de **No Country** — Simulación Laboral Tech

---

## 📌 ¿Qué es este proyecto?

Las organizaciones que operan en la nube reciben miles de eventos de acceso a sus sistemas cada día. Sin herramientas adecuadas, es muy difícil distinguir un acceso legítimo de uno potencialmente malicioso.

**SecureAccess Monitor** es una solución orientada a analizar y detectar patrones de acceso sospechosos dentro de una infraestructura cloud simulada. El sistema registra, analiza y evalúa eventos de acceso a recursos digitales, permitiendo identificar comportamientos anómalos antes de que se conviertan en incidentes de seguridad.

---

## 🎯 Objetivo

Construir un sistema capaz de:

- Registrar y estructurar eventos de acceso simulados (logs)
- Identificar patrones de comportamiento sospechoso
- Generar alertas ante posibles riesgos de seguridad
- Visualizar la actividad de usuarios de forma clara

---

## 🏢 Contexto de negocio

Este tipo de solución es crítica para:

- Plataformas SaaS
- Servicios financieros digitales
- Comercio electrónico
- Cualquier organización que maneje datos sensibles en la nube

---

## 🗂️ Estructura del proyecto

```
secureaccess-monitor/
│
├── data/
│   ├── generate_dataset.py       # Generación del dataset sintético
│   ├── access_logs.csv           # Dataset de 2.516 eventos
│   └── alertas.csv               # Alertas generadas por el sistema
│
├── analysis/
│   ├── exploratory_analysis.py   # Análisis exploratorio (EDA)
│   └── detection_rules.py        # 4 reglas de detección de anomalías
│
├── visualization/
│   └── dashboard.py              # Dashboard matplotlib (análisis estático)
│
├── templates/
│   ├── login.html                # Pantalla de login
│   └── dashboard.html            # Dashboard web en vivo
│
├── docs/
│
├── realtime_detector.py          # Detector en tiempo real (terminal)
├── live_dashboard.py             # Dashboard web con WebSockets
├── secure_dashboard.py           # Dashboard con autenticación JWT y roles
├── streamlit_app.py              # Dashboard público deployado en Streamlit
└── README.md
```

---

## 📋 Etapa 1 — Diseño del sistema

### ¿Por qué empezar por el diseño?

Antes de escribir código, definimos exactamente qué datos vamos a manejar y qué comportamientos queremos detectar. Esto evita reescribir lógica más adelante y garantiza que el análisis tenga sentido desde el principio.

---

### Estructura de un evento de acceso (log)

Cada evento registrado en el sistema representa una acción de un usuario sobre un recurso de la plataforma. La estructura elegida responde las preguntas fundamentales de cualquier análisis de seguridad:

| Campo        | Descripción                        | Ejemplo                   |
|--------------|------------------------------------|---------------------------|
| `timestamp`  | Cuándo ocurrió el evento           | `2024-03-15 03:42:11`     |
| `user_id`    | Quién realizó la acción            | `user_042`                |
| `ip_address` | Dirección IP de origen             | `192.168.1.45`            |
| `country`    | País de origen de la conexión      | `Argentina`               |
| `action`     | Qué acción intentó realizar        | `login`, `file_access`    |
| `status`     | Si la acción fue exitosa o no      | `success`, `failed`       |
| `resource`   | A qué recurso intentó acceder      | `admin_panel`, `database` |
| `risk_score` | Puntuación de riesgo del evento    | `0` a `100`               |

---

### Parámetros del dataset

| Parámetro              | Valor elegido | Justificación                                              |
|------------------------|---------------|------------------------------------------------------------|
| Cantidad de usuarios   | 30            | Suficiente variedad sin complejidad excesiva               |
| Cantidad de eventos    | 3.000         | Permite análisis estadístico y visualizaciones significativas |
| Países "normales"      | Argentina, Brasil, México, España, Colombia | Coherente con una empresa SaaS latinoamericana |
| Países "sospechosos"   | Rusia, China, Corea del Norte, Nigeria, Irán | Basado en reportes reales de threat intelligence |
| Recursos del sistema   | `login`, `dashboard`, `admin_panel`, `database`, `api`, `file_storage`, `billing` | Simula una plataforma SaaS típica |

---

### Perfiles de usuarios simulados

En vez de generar eventos aleatorios, cada usuario tiene un **perfil de comportamiento**. Esto hace que los patrones anómalos sean detectables y coherentes:

#### 👤 Usuario normal
- Accede de lunes a viernes, en horario laboral (8:00 - 20:00)
- Se conecta desde su país habitual
- Accede a recursos estándar: `dashboard`, `api`, `file_storage`
- Tasa de intentos fallidos: muy baja

#### 🔴 Usuario atacante externo
- Genera decenas de intentos fallidos en minutos (ataque de fuerza bruta)
- Se conecta desde países marcados como sospechosos
- Intenta acceder a recursos sensibles: `admin_panel`, `database`

#### 🟠 Usuario comprometido
- Historial de comportamiento normal
- En un punto determinado comienza a actuar de forma inusual:
  - Accesos en horarios atípicos (madrugada)
  - Cambio repentino de país de origen
  - Acceso a recursos que nunca antes utilizó

---

### Escenarios de riesgo a simular

| Escenario                   | Descripción                                              | Señales clave                                  |
|-----------------------------|----------------------------------------------------------|------------------------------------------------|
| Fuerza bruta                | Múltiples intentos fallidos del mismo usuario en poco tiempo | >5 fallos en menos de 2 minutos           |
| Acceso desde país inusual   | Conexión desde un país que el usuario nunca usó antes   | País nuevo + recursos sensibles                |
| Horario inusual             | Acceso en horarios atípicos para ese usuario            | Conexión entre 00:00 y 05:00                   |
| Uso anómalo de credenciales | Acceso a recursos sensibles sin historial previo        | `admin_panel` o `database` sin accesos previos |

---

## 🛠️ Etapa 2 — Generación del dataset

### ¿Por qué generar el dataset con código y no a mano?

Construir el dataset con un script Python garantiza tres propiedades fundamentales:

- **Reproducibilidad** → cualquier miembro del equipo puede correr el script y obtener exactamente el mismo resultado (`random.seed(42)`)
- **Control** → decidimos con precisión cuántos eventos normales, cuántos sospechosos y con qué distribución
- **Escalabilidad** → si necesitamos 10.000 eventos en vez de 3.000, cambiamos un número

---

### Herramientas utilizadas

| Librería | Uso | Equivalente conocido |
|---|---|---|
| `pandas` | Construir y exportar la tabla de datos | Power BI / Excel |
| `random` | Generar valores aleatorios controlados | =ALEATORIO.ENTRE() en Excel |
| `datetime` | Operar con fechas y horas | DATEADD en SQL |

---

### Entorno de desarrollo

El proyecto usa un **entorno virtual de Python** (`venv`) para aislar las dependencias. Esto garantiza que las librerías instaladas no interfieran con otros proyectos del sistema.

Para configurarlo desde cero:

```bash
# Crear el entorno virtual
python -m venv venv

# Activarlo (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Instalar dependencias
pip install pandas
```

---

### Arquitectura del script

El script está organizado en capas con responsabilidades claras:

```
CAPA 1 — Constantes
    Países normales y sospechosos, recursos, fechas del período

CAPA 2 — Funciones auxiliares
    generar_ip()              → genera IPs según el país de origen
    fecha_aleatoria_laboral() → fechas en horario de trabajo
    fecha_aleatoria_madrugada() → fechas en horario inusual
    calcular_riesgo()         → score de 0 a 100 según factores de riesgo

CAPA 3 — Perfiles de usuario
    generar_eventos_normales()        → usuario legítimo
    generar_fuerza_bruta()            → atacante externo
    generar_acceso_pais_inusual()     → credenciales desde ubicación extraña
    generar_usuario_comprometido()    → cuenta tomada por un atacante

CAPA 4 — Función principal
    generar_dataset() → orquesta todo y exporta el CSV
```

---

### Lógica de scoring de riesgo

El `risk_score` de cada evento se calcula sumando factores de riesgo independientes:

| Factor | Puntos | Justificación |
|---|---|---|
| País sospechoso | +30 | El origen geográfico es el indicador más fuerte |
| Recurso sensible | +25 | El destino del acceso importa casi tanto como el origen |
| Acceso fallido | +20 | Un fallo es una señal de alerta directa |
| Horario inusual (00:00-05:59) | +15 | Contexto temporal relevante |
| Más de 5 intentos fallidos | +10 | Agravante de patrón de fuerza bruta |
| **Máximo posible** | **100** | Limitado con `min(score, 100)` |

Esta lógica es la base de sistemas SIEM reales como Splunk o Microsoft Sentinel.

---

### Distribución del dataset generado

| Escenario | Eventos | Porcentaje | Risk Score promedio |
|---|---|---|---|
| `normal` | 2.359 | 93.7% | 0.7 |
| `brute_force` | 111 | 4.4% | 97.1 |
| `unusual_country` | 24 | 1.0% | 72.5 |
| `compromised_account` | 22 | 0.9% | 40.0 |
| **Total** | **2.516** | **100%** | — |

La distribución es intencionalmente realista: en sistemas reales, la gran mayoría del tráfico es legítimo y los eventos maliciosos son una minoría que hay que saber detectar.

---

### Cómo correr el script

```bash
cd data
python generate_dataset.py
```

El script genera automáticamente el archivo `access_logs.csv` en la misma carpeta.

---

### Resultado: estructura del CSV generado

```
timestamp            | user_id  | ip_address     | country   | action        | status  | resource    | risk_score | scenario
---------------------|----------|----------------|-----------|---------------|---------|-------------|------------|------------------
2024-01-03 09:14:22  | user_001 | 172.45.23.11   | Argentina | access        | success | dashboard   | 0          | normal
2024-01-03 03:42:11  | user_019 | 23.187.45.2    | China     | login_attempt | failed  | admin_panel | 75         | brute_force
```

---

## 🔎 Etapa 3 — Análisis y detección

Esta etapa transforma los datos crudos en información útil. Está dividida en dos scripts con responsabilidades claramente separadas.

---

### 3.1 — Análisis Exploratorio (`exploratory_analysis.py`)

El EDA (Exploratory Data Analysis) es el primer paso que hace cualquier analista cuando recibe un dataset. El objetivo es conocer los datos antes de sacar conclusiones.

**Hallazgos principales:**

| Hallazgo | Valor | Implicancia |
|---|---|---|
| Total de eventos | 2.516 | Volumen manejable para análisis |
| Eventos sin riesgo (score = 0) | 90.6% | La mayoría del tráfico es legítimo |
| Eventos de alto riesgo (score ≥ 70) | 5.4% | La señal que hay que detectar |
| Risk score promedio — Rusia | 97.3 | Tráfico casi completamente malicioso |
| Risk score promedio — Argentina | 1.1 | Tráfico casi completamente legítimo |
| Pico de actividad anómala | 00:00 (137 eventos) | Ataques concentrados en medianoche |

**Feature engineering aplicado:** a partir del `timestamp` original se derivaron tres columnas nuevas (`hora`, `dia_semana`, `mes`) para facilitar el análisis temporal. Esto es una práctica estándar en ciencia de datos.

**Cómo correrlo:**
```bash
cd analysis
python exploratory_analysis.py
```

---

### 3.2 — Reglas de Detección (`detection_rules.py`)

Implementa 4 reglas de seguridad inspiradas en sistemas SIEM reales (Splunk, Microsoft Sentinel). Cada regla genera alertas estructuradas que se exportan a `data/alertas.csv`.

**Las 4 reglas implementadas:**

| Regla | Lógica | Umbral |
|---|---|---|
| Fuerza bruta | Intentos fallidos del mismo usuario en ventana de tiempo | >10 fallos en 2 minutos |
| País sospechoso | Acceso a recursos sensibles desde países de alto riesgo | Cualquier evento desde lista negra |
| Horario inusual | Acceso a recursos sensibles en madrugada | Entre 00:00 y 05:59 |
| Cuenta comprometida | Usuario con historial normal que accede a recursos nuevos y sensibles | >2 accesos a recursos nunca utilizados |

**Resultados de la detección:**

| Tipo de alerta | Alertas generadas | Risk score máximo |
|---|---|---|
| `HORARIO_INUSUAL` | 12 | 100 |
| `PAIS_SOSPECHOSO` | 9 | 100 |
| `FUERZA_BRUTA` | 6 | 100 |
| `CUENTA_COMPROMETIDA` | 3 | 90 |
| **Total** | **30** | — |

**Tasa de detección:** 30 alertas sobre 2.516 eventos = **1.19%**. Este número es intencionalmente bajo y realista: un sistema que genera demasiadas alertas es inútil porque los analistas se ahogan en falsos positivos.

**Usuarios más comprometidos (mayor cantidad de alertas):**

```
user_022 → 4 alertas  ← prioridad máxima de investigación
user_019 → 3 alertas
user_020 → 3 alertas
user_021 → 3 alertas
user_023 → 3 alertas
user_028 → 1 alerta   ← cuenta comprometida, menor urgencia
```

**Insight clave:** un atacante externo (fuerza bruta desde país sospechoso) dispara 3 reglas simultáneamente con risk score 100. Una cuenta comprometida dispara 1-2 reglas con risk score 40. Esa diferencia de intensidad permite **priorizar incidentes** exactamente como lo hace un SOC real.

**Cómo correrlo:**
```bash
cd analysis
python detection_rules.py
```

Genera automáticamente `data/alertas.csv` con todas las alertas estructuradas.

---

### Pipeline completo de la Etapa 3

```
access_logs.csv
      │
      ├──► exploratory_analysis.py  →  comprensión del dataset
      │
      └──► detection_rules.py       →  alertas.csv
```

---

## ⚡ Etapa 4 — Detección en tiempo real

En vez de analizar un CSV estático, el sistema procesa los eventos **uno por uno** simulando un stream en vivo. Esto replica el comportamiento de sistemas SIEM reales como Apache Kafka o AWS Kinesis.

**Concepto clave — Estado acumulado:** cada usuario tiene un perfil en memoria que se actualiza con cada evento. Las reglas se evalúan contra ese estado actualizado, no contra el evento aislado. Esto permite detectar patrones que solo son visibles en el tiempo (como fuerza bruta o cuentas comprometidas).

**Output en terminal con colores:**
```
✓  normal    → verde
⚠  sospechoso → amarillo
🚨 alerta crítica → rojo con pausa
```

**Cómo correrlo:**
```bash
python realtime_detector.py
```

---

## 🌐 Etapa 5 — Dashboard web en vivo

Convierte el detector de terminal en una **aplicación web** accesible desde el navegador que se actualiza sola sin recargar la página.

**Tecnologías:**

| Tecnología | Rol | Por qué |
|---|---|---|
| FastAPI | Servidor web en Python | Liviano, moderno, async nativo |
| WebSocket | Conexión en vivo servidor ↔ navegador | El servidor avisa al navegador sin que este pregunte |
| HTML/JS | Dashboard en el navegador | Sin frameworks, puro y portable |

**La diferencia con HTTP normal:**
```
HTTP:     navegador pregunta → servidor responde (cada vez)
WebSocket: servidor avisa solo cuando hay algo nuevo (conexión persistente)
```

**Cómo correrlo:**
```bash
python live_dashboard.py
# Abrir: http://localhost:8000
```

---

## 🔐 Etapa 6 — Autenticación JWT y control de roles (RBAC)

El dashboard requiere login. Implementa autenticación con el estándar de la industria y control de acceso basado en roles.

**Conceptos implementados:**

**JWT (JSON Web Token):** credencial firmada digitalmente que el servidor genera tras el login. El navegador la guarda y la envía en cada request. El servidor verifica la firma sin consultar una base de datos.

**bcrypt:** las contraseñas nunca se guardan en texto plano. Se guardan como hashes irreversibles. Si alguien roba la base de datos, no puede recuperar las contraseñas.

**RBAC (Role Based Access Control):** cada usuario tiene un rol que determina qué puede ver y hacer.

**Diferencias entre roles:**

| Funcionalidad | Admin | Analista |
|---|---|---|
| Ver dashboard y alertas | ✅ | ✅ |
| Ver IPs completas | ✅ `192.168.1.45` | ❌ `192.168.xxx.xxx` |
| Panel exclusivo admin | ✅ | ❌ |
| Exportar alertas a CSV | ✅ | ❌ |

**Principio de mínimo privilegio:** cada usuario tiene acceso solo a lo que necesita para su trabajo. Es uno de los principios fundamentales de ciberseguridad.

**Credenciales de prueba:**
```
admin    / admin123    → acceso total
analista / analista123 → solo lectura
```

**Cómo correrlo:**
```bash
python secure_dashboard.py
# Abrir: http://localhost:8001
```

---

## 📧 Etapa 7 — Notificaciones automáticas por email

Cuando el sistema detecta una alerta crítica (risk score ≥ 70), envía automáticamente un email al administrador con los detalles del incidente.

**Tecnología:** SMTP con Mailtrap (entorno de testing). En producción se reemplaza por SendGrid, AWS SES o cualquier proveedor SMTP real.

**Contenido del email:**
- Tipo de alerta
- Usuario involucrado
- País de origen
- Risk score
- Timestamp del evento
- Detalle técnico del incidente

**Anti-spam integrado:** el sistema no manda el mismo tipo de alerta para el mismo usuario más de una vez, evitando saturar la bandeja del admin.

**Pipeline completo del sistema:**
```
access_logs.csv
      │
      ▼
realtime_detector / secure_dashboard
      │
      ├── WebSocket → dashboard web en vivo
      ├── Reglas de detección → alertas
      └── Score ≥ 70 → email automático al admin
```

---

## 🛠️ Stack tecnológico completo

| Tecnología | Uso |
|---|---|
| Python 3.14 | Lenguaje principal |
| pandas | Análisis y manipulación de datos |
| FastAPI | Servidor web y API |
| WebSockets | Comunicación en tiempo real |
| JWT (python-jose) | Autenticación stateless |
| bcrypt | Hashing seguro de contraseñas |
| smtplib | Envío de emails |
| Mailtrap | Testing de emails |
| Streamlit | Dashboard público deployado |
| Power BI | Visualización histórica |
| Git | Control de versiones |

---

## 🚀 Cómo instalar y correr el proyecto

```bash
# 1. Clonar el repositorio
git clone https://github.com/No-Country-simulation/SecureAccess-Monitor-S04-26-Equipo-37-Cybersecurity.git

# 2. Crear y activar entorno virtual
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows PowerShell

# 3. Instalar dependencias
pip install fastapi uvicorn websockets pandas bcrypt python-jose python-multipart colorama

# 4. Generar el dataset
cd data
python generate_dataset.py
cd ..

# 5. Correr el sistema completo
python secure_dashboard.py

# 6. Abrir en el navegador
# http://localhost:8001
```

---

## 🔗 Links

- [Dashboard público (Streamlit)](https://secureaccess-cyber.streamlit.app/)
- [Repositorio GitHub](https://github.com/No-Country-simulation/SecureAccess-Monitor-S04-26-Equipo-37-Cybersecurity)

---

## ✅ Estado del proyecto

- ~~Etapa 1 — Diseño del sistema~~ ✅
- ~~Etapa 2 — Generación del dataset~~ ✅
- ~~Etapa 3 — Análisis y detección~~ ✅
- ~~Etapa 4 — Detección en tiempo real~~ ✅
- ~~Etapa 5 — Dashboard web en vivo~~ ✅
- ~~Etapa 6 — Autenticación JWT y roles~~ ✅
- ~~Etapa 7 — Notificaciones por email~~ ✅

---

## 👥 Equipo

Proyecto desarrollado en **No Country** — Simulación Laboral Tech

---

## 📄 Licencia

Este proyecto fue creado con fines educativos y de práctica profesional.
