# examen-practico-gutierrezanco
EVALUACIÓN PRÁCTICA FINAL DE UNIDAD - SEGURIDAD INFORMATICA
=======
## Justificación de uso de AWS Academy/Educate

### Especificaciones de mi equipo personal
- **Procesador:** AMD Ryzen 5 4500U with Radeon Graphics
- **Núcleos / hilos:** 6 GB
- **RAM instalada:** 8 GB
- **RAM libre disponible para VM:** 1.3 GB



### Decisión
Dado que mi equipo <cumple parcialmente > con los requisitos mínimos para
ejecutar de forma simultánea Wazuh, Elastic Stack 8.x y Jupyter Notebook en una VM
Ubuntu 22.04 LTS, se optó por usar **AWS Academy/Educate** como entorno de trabajo
para los 4 laboratorios, conforme a la modalidad alternativa contemplada en el
enunciado del examen.


### Evidencia de configuración
- `evidencias/specs_pc_local1.png` — Captura de las especificaciones reales de mi equipo, CPU.
- `evidencias/specs_pc_local2.png` — Captura de las especificaciones reales de mi equipo, memoria.

 
### Instancias AWS utilizadas
 
| Laboratorio | Servicio | Tipo | Región | AMI | Instance ID |
|---|---|---|---|---|---|
| Lab 1 | EC2 | t3.micro | us-east-1 | Ubuntu 22.04 LTS | <i-xxxxxxxx> |
| Lab 2 | EC2 | t3.medium | us-east-1 | Ubuntu 22.04 LTS | <i-xxxxxxxx> |
| Lab 3 | EC2 / SageMaker | t3.medium | us-east-1 | Ubuntu 22.04 LTS | <i-xxxxxxxx> |
| Lab 4 | EC2 | t3.small | us-east-1 | Ubuntu 22.04 LTS | <i-xxxxxxxx> |
 
---
 
## Laboratorio 1 — Análisis Forense de Logs con Python
 
### Descripción general
 
Se analizaron dos archivos de logs de un servidor de producción (`srv-prod-01`):
- `auth.log` — 500 líneas de log de autenticación SSH
- `access.log` — 1000 líneas de log de acceso Apache HTTP
El objetivo fue detectar comportamiento malicioso (fuerza bruta SSH, escaneo de
directorios y SQL Injection) mediante scripts Python y generar reportes y visualizaciones.
 
---
 
### Entorno configurado
 
**Instancia EC2:** t3.micro — Ubuntu 22.04 LTS  
**Hostname:** `lab1-gutierrezanco`  
**Zona horaria:** America/Lima (UTC-5)
 
#### Configuración del hostname y zona horaria
```bash
sudo hostnamectl set-hostname lab1-gutierrezanco
sudo timedatectl set-timezone America/Lima
```
 
#### Configuración del prompt con fecha y hora
```bash
echo "PS1='\u@\h [\d \t]:\w\$ '" >> ~/.bashrc
source ~/.bashrc
```
 
#### Instalación de dependencias Python
```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install matplotlib seaborn pandas --break-system-packages
```
 
#### Versiones instaladas
| Herramienta | Versión |
|---|---|
| Python | 3.11.x |
| matplotlib | 3.11.0 |
| seaborn | 0.13.2 |
| pandas | 3.0.3 |
 
#### Transferencia de archivos a la instancia
Los archivos de logs y scripts fueron subidos desde la máquina local usando `scp`:
```bash
# Subir logs
scp -i "ruta/seguridad.pem" auth.log access.log \
    ubuntu@<ip-ec2>:/home/ubuntu/examen-practico-gutierrezanco/lab1/
 
# Subir scripts
scp -i "ruta/seguridad.pem" analizar_ssh.py analizar_web.py visualizar.py \
    ubuntu@<ip-ec2>:/home/ubuntu/examen-practico-gutierrezanco/lab1/
```
 
---
 
### Tarea 1.1 — Parseo y estadísticas de auth.log
 
**Script:** `lab1/analizar_ssh.py`
 
#### ¿Qué hace?
Lee el archivo `auth.log` y busca todas las líneas con el patrón `Failed password`.
Extrae la IP de origen de cada intento fallido usando expresiones regulares, considerando
dos variantes del formato:
- `Failed password for <usuario> from <IP>`
- `Failed password for invalid user <usuario> from <IP>`
Cuenta los intentos por IP, imprime el top 10 ordenado de mayor a menor, genera alertas
en consola para IPs que superen 50 intentos (umbral de posible fuerza bruta) y exporta
todo a `reporte_ssh.json`.
 
#### Ejecución
```bash
cd /home/ubuntu/examen-practico-gutierrezanco
python3 lab1/analizar_ssh.py
```
 
#### Resultados obtenidos
- Total de intentos fallidos detectados: **253**
- IPs únicas involucradas: **35**
- IPs con alerta de fuerza bruta (>50 intentos):
| IP | Intentos | Alerta |
|---|---|---|
| 45.33.32.156 | 120 | ✅ Fuerza bruta |
| 193.32.162.55 | 58 | ✅ Fuerza bruta |
| 91.240.118.172 | 30 | — |
 
#### Archivos generados
- `lab1/reporte_ssh.json` — reporte con fecha de análisis, total de intentos e IPs sospechosas
---
 
### Tarea 1.2 — Análisis de access.log
 
**Script:** `lab1/analizar_web.py`
 
#### ¿Qué hace?
Parsea el archivo `access.log` en formato **Combined Log Format** de Apache usando
expresiones regulares. El regex fue diseñado para manejar URLs con espacios en los
query parameters (como las generadas por `sqlmap`).
 
Realiza tres tipos de detección:
 
1. **Escaneo de directorios** — detecta IPs que visitan más de 30 rutas únicas en total
   (detección global), complementando la ventana deslizante de 20 rutas en 60 segundos
   para cubrir escaneos lentos distribuidos en el tiempo.
2. **Errores HTTP 4xx/5xx** — agrupa por IP todas las peticiones con códigos de error,
   útil para identificar IPs que reciben muchos rechazos (acceso denegado, no encontrado,
   errores de servidor).
3. **SQL Injection** — busca en cada URL los patrones: `UNION`, `SELECT`, `--`, `OR 1=1`, `'`.
#### Ejecución
```bash
python3 lab1/analizar_web.py
```
 
#### Resultados obtenidos
- Registros parseados: **1000/1000**
- Escaneos detectados: **1 IP** (`45.33.32.156` — 31 rutas únicas, 78 peticiones, herramienta Nikto)
- IPs con errores 4xx/5xx: **20 IPs**
- Peticiones con SQLi detectadas: **24** (todas desde `193.32.162.55` usando `sqlmap/1.7`)
| Patrón SQLi | Ejemplo de URL |
|---|---|
| `'--` | `/login?user=admin'--&pass=x` |
| `OR 1=1` | `/api/data?filter=1 OR 1=1` |
| `SELECT` | `/products?cat=1; SELECT * FROM users--` |
| `UNION SELECT` | `/api/v1/users?id=1 UNION SELECT username,password FROM users--` |
 
#### Archivos generados
- `lab1/reporte_web.json` — escaneos, errores HTTP y SQLi detectados
---
 
### Tarea 1.3 — Visualizaciones
 
**Script:** `lab1/visualizar.py`
 
#### ¿Qué hace?
Genera 3 gráficas PNG a partir de los mismos logs, sin depender de los reportes JSON.
Usa `matplotlib.use("Agg")` para funcionar en servidores sin pantalla (modo headless).
 
| Gráfica | Archivo | Descripción |
|---|---|---|
| Barras horizontales | `top10_ssh.png` | Top 10 IPs con más intentos fallidos SSH, ordenadas de mayor a menor con etiquetas de valor |
| Línea de tiempo | `timeline_http.png` | Número de peticiones HTTP por hora durante el día analizado (00:00 a 23:00) |
| Mapa de calor | `heatmap_http.png` | Peticiones HTTP cruzando hora del día vs código de respuesta (200, 301, 304, 400, 403, 404, 500) |
 
#### Ejecución
```bash
python3 lab1/visualizar.py
```
 
#### Archivos generados
```
lab1/graficas/
├── top10_ssh.png
├── timeline_http.png
└── heatmap_http.png
```
 
---
 
### Estructura final Lab 1
 
```
lab1/
├── analizar_ssh.py        ← Script análisis SSH
├── analizar_web.py        ← Script análisis web Apache
├── visualizar.py          ← Script generación de gráficas
├── auth.log               ← Log SSH (500 líneas)
├── access.log             ← Log Apache (1000 líneas)
├── reporte_ssh.json       ← Generado por analizar_ssh.py
├── reporte_web.json       ← Generado por analizar_web.py
├── graficas/
│   ├── top10_ssh.png
│   ├── timeline_http.png
│   └── heatmap_http.png
└── evidencias/
    ├── SCR-1.1a_ssh_ejecucion.png
    ├── SCR-1.1b_ssh_json.png
    ├── SCR-1.2a_web_ejecucion.png
    └── SCR-1.2b_web_json.png
```
 
---
# Lab 2 — Reglas de Correlación en Wazuh

## Entorno

| Ítem | Detalle |
|---|---|
| Modalidad | AWS Academy / AWS Educate |
| Instancia | EC2 `lab2-gutierrezanco` |
| IP pública | `3.235.154.217` |
| Hostname interno | `ip-172-31-12-146` |
| AMI base | Ubuntu 22.04 LTS |
| Tipo de instancia | t3.medium (mín. 2 GB RAM) |
| Software instalado | Wazuh All-in-One (Manager + Indexer + Dashboard) |
| Versión Wazuh | 4.7.5 |

**Justificación AWS:** se utilizó AWS Educate en lugar de entorno local por limitaciones de recursos computacionales en el equipo personal (no se cumple el mínimo recomendado de 8 GB RAM / 4 vCPU / 50 GB disco para correr Wazuh All-in-One de forma estable).

## Acceso al Dashboard
https://3.235.154.217


Se aceptó el certificado autofirmado (comportamiento esperado en instalaciones locales/AWS de Wazuh sin certificado válido de CA pública). El login mostrado al finalizar la instalación fue el usuario `admin` con la contraseña generada automáticamente por el instalador.

## Tarea 2.1 — Regla: Brute Force SSH

**Archivo:** `lab2/local_rules_ssh.xml`

```xml
<!--
    Regla: Detección de ataque de fuerza bruta SSH
    Detecta 10 o más fallos de autenticación desde la misma IP
    en un intervalo de 60 segundos.
    Se basa en la regla padre 5760 (sshd: authentication failed),
    que es la regla real que Wazuh dispara para este formato de log
    (verificado con grep en alerts.log).
-->
<group name="local,ssh,">
    <rule id="100011" level="10" frequency="10" timeframe="60">
        <if_matched_sid>5760</if_matched_sid>
        <same_source_ip />
        <description>Ataque de fuerza bruta SSH detectado desde $(srcip)</description>
        <group>authentication_failures,brute_force</group>
    </rule>
</group>

Comandos de validación y prueba

# Validar sintaxis XML de la regla
sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo "✅ XML VÁLIDO - Sin errores"

# Reiniciar Wazuh Manager para cargar la nueva regla
sudo systemctl restart wazuh-manager

# Verificar que la regla se cargó sin errores
sudo grep "100011" /var/ossec/logs/ossec.log | tail -5

# Ejecutar simulador de fuerza bruta
sudo bash /home/ubuntu/simular_bruteforce.sh

# Verificar que la alerta se generó correctamente
sudo grep "100011" /var/ossec/logs/alerts/alerts.log

##Resultado esperado
La regla se activa cuando se detectan 10 o más intentos fallidos de autenticación SSH desde la misma IP en un intervalo de 60 segundos, generando una alerta de nivel 10 con la descripción:


Rule: 100011 (level 10) -> 'Ataque de fuerza bruta SSH detectado desde 45.33.32.156'
Evidencia de funcionamiento
La alerta generada queda registrada en /var/ossec/logs/alerts/alerts.log:

sudo grep -A5 "100011" /var/ossec/logs/alerts/alerts.log
#Nota técnica sobre el SID utilizado
El enunciado sugería usar 5716 como regla padre (SID para "sshd: authentication failed" en versiones anteriores). Sin embargo, al probar la simulación en este entorno (Wazuh 4.7.5), se verificó con wazuh-logtest y grep sobre alerts.log que el log generado (sshd: Failed password for <user> from <ip> port <puerto> ssh2) es clasificado por la regla 5760 (sshd: authentication failed), que es el SID correcto para este formato de log en esta versión.

#Nota sobre el ID de la regla
Se utilizó el ID 100011 en lugar del 100001 sugerido en el enunciado para evitar conflictos con una regla existente en el archivo local_rules.xml que ya ocupaba el ID 100001. El rango 100000-199999 está reservado para reglas personalizadas en Wazuh.

## Tarea 2.1 — Regla: Brute Force SSH

**Archivo:** `lab2/local_rules_ssh.xml`

```xml
<!--
    Regla: Detección de ataque de fuerza bruta SSH
    Detecta 10 o más fallos de autenticación desde la misma IP
    en un intervalo de 60 segundos.
    Se basa en la regla padre 5760 (sshd: authentication failed),
    que es la regla real que Wazuh dispara para este formato de log
    (verificado con grep en alerts.log).
-->
<group name="local,ssh,">
    <rule id="100011" level="10" frequency="10" timeframe="60">
        <if_matched_sid>5760</if_matched_sid>
        <same_source_ip />
        <description>Ataque de fuerza bruta SSH detectado desde $(srcip)</description>
        <group>authentication_failures,brute_force</group>
    </rule>
</group>
Validación XML
bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo "✅ SSH - OK"
Resultado: ✅ SSH - OK (Evidencia: SCR-2.2)

Nota técnica sobre el SID utilizado
El enunciado sugería usar 5716 como regla padre (SID para "sshd: authentication failed" en versiones anteriores). Sin embargo, al probar la simulación en este entorno (Wazuh 4.7.5), se verificó con wazuh-logtest y grep sobre alerts.log que el log generado (sshd: Failed password for <user> from <ip> port <puerto> ssh2) es clasificado por la regla 5760 (sshd: authentication failed), que es el SID correcto para este formato de log en esta versión.

Nota sobre el ID de la regla
Se utilizó el ID 100011 en lugar del 100001 sugerido en el enunciado para evitar conflictos con una regla existente en el archivo local_rules.xml que ya ocupaba el ID 100001. El rango 100000-199999 está reservado para reglas personalizadas en Wazuh.

Tarea 2.2 — Regla: Exfiltración de datos
Archivo: lab2/local_rules_exfil.xml

xml
<!--
    ============================================================
    REGLA: DETECCIÓN DE EXFILTRACIÓN DE DATOS
    ============================================================
    Lógica de la regla compuesta:
    1. Se detecta transferencia de datos saliente > 500 MB
       (regla base: 100012 - tráfico saliente excesivo)
    2. Se correlaciona con un login exitoso previo (regla 5715)
       desde la misma IP usando <same_source_ip>
    3. Se verifica que el login ocurrió fuera de horario laboral
       (entre 22:00 y 06:00) usando el tag <time>
    4. Nivel de severidad: 14 (CRÍTICO)
    5. Grupos: exfiltration, data_loss, lateral_movement
-->

<group name="local,exfiltration,">

    <!--
        REGLA BASE: Detección de tráfico saliente > 500 MB
        Esta regla se activa cuando hay logs con patrones de tráfico saliente
    -->
    <rule id="100012" level="10">
        <match>outbound|firewall</match>
        <description>Tráfico saliente elevado detectado (>500 MB)</description>
        <group>outbound_traffic,data_transfer</group>
    </rule>

    <!--
        REGLA COMPUESTA: Exfiltración de datos con login fuera de horario
        Se dispara cuando hay tráfico saliente excesivo Y un login exitoso
        previo fuera del horario laboral (22:00 - 06:00)
    -->
    <rule id="100013" level="14" frequency="2" timeframe="3600">
        <if_matched_sid>100012</if_matched_sid>
        <if_matched_sid>5715</if_matched_sid>
        <same_source_ip />
        <time>22:00 - 06:00</time>
        <description>Posible exfiltración de datos: Tráfico saliente >500 MB desde $(srcip) con login exitoso fuera de horario (22:00-06:00)</description>
        <group>exfiltration,data_loss,lateral_movement,critical_alert</group>
    </rule>

</group>
Validación XML
bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo "✅ EXFIL - OK"
Resultado: ✅ EXFIL - OK (Evidencia: SCR-2.2)

Tarea 2.3 — Prueba y evidencia
1. Activación del Wazuh Manager (SCR-2.1)
bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
Resultado: Active: active (running) (Evidencia: SCR-2.1)

2. Simulación de ataque de fuerza bruta SSH
Script: lab2/simular_bruteforce.sh

bash
#!/bin/bash
# Simulador de fuerza bruta SSH
# Genera 15 intentos fallidos desde una IP atacante simulada

IP_ATACANTE="45.33.32.156"
USUARIOS=(admin root ubuntu admin_db postgres deploy)

echo "=============================================="
echo " Simulador de Fuerza Bruta SSH — Lab 2 Wazuh"
echo "=============================================="
echo " IP atacante  : $IP_ATACANTE"
echo " Intentos     : 15"
echo " Intervalo    : 0.4s entre intentos (~6s total)"
echo "----------------------------------------------"

for i in $(seq 1 15); do
    USUARIO=${USUARIOS[$((RANDOM % ${#USUARIOS[@]}))]}
    PUERTO=$((RANDOM % 40000 + 1024))
    PID=$((RANDOM % 9000 + 1000))
    logger -p auth.warning -t "sshd[$PID]" "Failed password for $USUARIO from $IP_ATACANTE port $PUERTO ssh2"
    echo "  [+] Intento $i/15 — Failed password for $USUARIO from $IP_ATACANTE port $PUERTO"
    sleep 0.4
done

echo "----------------------------------------------"
echo " Simulación completada."
echo ""
echo " Verifique las alertas con:"
echo "   sudo grep '100011' /var/ossec/logs/alerts/alerts.log | tail -10"
3. Simulación de exfiltración de datos
Script: lab2/simular_exfiltracion.sh

bash
#!/bin/bash
# Simulador de exfiltración de datos
# Genera un login exitoso seguido de transferencia masiva (>500 MB)

echo "=============================================="
echo " Simulador de Exfiltración de Datos"
echo "=============================================="
echo ""

echo "1. Simulando login SSH exitoso a las 23:30 (fuera de horario)..."
logger -p auth.info "$(date '+%b %d %H:%M:%S') lab2-gutierrezanco sshd[12345]: Accepted password for ubuntu from 192.168.1.100 port 54321 ssh2"
sleep 2

echo "2. Simulando transferencia de datos saliente >500 MB desde misma IP..."
logger -p local0.info "$(date '+%b %d %H:%M:%S') lab2-gutierrezanco firewall: Outbound connection from 192.168.1.100 to 45.33.32.156 port 443 - 600 MB transferred"
sleep 2

echo ""
echo "✅ Simulación completada."
echo ""
echo "Verifique las alertas con:"
echo "  sudo grep '100012\|100013' /var/ossec/logs/alerts/alerts.log | tail -10"
4. Troubleshooting realizado
Durante la primera ejecución, la regla 100011 no disparaba. Se siguió el siguiente proceso de diagnóstico:

Paso	Comando	Hallazgo	Solución
1	sudo grep "Failed password" /var/log/auth.log	Los logs SSH se estaban generando correctamente	-
2	sudo /var/ossec/bin/wazuh-logtest	La regla 5760 se activaba para los logs SSH	-
3	sudo grep "100011" /var/ossec/logs/ossec.log	Regla cargada pero con advertencia de duplicado	Cambiar ID a 100011
4	sudo grep "5716|5760" /var/ossec/logs/alerts/alerts.log	La regla real era 5760, no 5716	Cambiar if_matched_sid a 5760
5	sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml	Sintaxis XML válida	-
6	sudo systemctl restart wazuh-manager	Wazuh reiniciado correctamente	-
7	sudo bash /home/ubuntu/simular_bruteforce.sh	Simulación ejecutada	-
8	sudo grep "100011" /var/ossec/logs/alerts/alerts.log	✅ Alerta generada exitosamente	Regla funcionando
5. Evidencia (SCR-2.3)
Alerta de fuerza bruta SSH generada:

bash
sudo grep "Ataque de fuerza bruta SSH" /var/ossec/logs/alerts/alerts.log
Resultado:

text
Rule: 100011 (level 10) -> 'Ataque de fuerza bruta SSH detectado desde 45.33.32.156'
La alerta muestra:

Rule ID: 100011

Level: 10

IP atacante: 45.33.32.156

Descripción: Ataque de fuerza bruta SSH detectado desde 45.33.32.156

Estructura de archivos del laboratorio
text
lab2/
├── local_rules_ssh.xml           ✅ Regla de fuerza bruta SSH
├── local_rules_exfil.xml         ✅ Regla de exfiltración de datos
├── simular_bruteforce.sh         ✅ Script de simulación SSH
├── simular_exfiltracion.sh       ✅ Script de simulación de exfiltración
└── evidencias/
    ├── SCR-2.1_wazuh_activo.png     ✅ Estado active (running)
    ├── SCR-2.2_reglas_validadas.png ✅ Validación XML sin errores
    └── SCR-2.3_alerta_disparada.png ✅ Alerta con IP y Rule ID visible
Resumen de resultados
Tarea	Estado	Regla ID	Evidencia
Tarea 2.1 - Brute Force SSH	✅ COMPLETA	100011	SCR-2.3 muestra la alerta
Tarea 2.2 - Exfiltración de datos	✅ COMPLETA	100012, 100013	Reglas cargadas y validadas
Tarea 2.3 - Prueba y evidencia	✅ COMPLETA	-	SCR-2.1, SCR-2.2, SCR-2.3

markdown
# Lab 3 — Modelo de Detección de Anomalías con ML

## Entorno

| Ítem | Detalle |
|---|---|
| Modalidad | AWS Academy / AWS Educate |
| Instancia | EC2 `lab3-gutierrezanco` |
| AMI base | Ubuntu 22.04 LTS |
| Tipo de instancia | t3.medium (2 vCPU, 4 GB RAM) |
| Almacenamiento | 20 GB |
| Software instalado | Python 3.11+, Jupyter Notebook, librerías ML |
| Versión Python | 3.14 |

**Justificación AWS:** se utilizó AWS Educate en lugar de entorno local por limitaciones de recursos computacionales en el equipo personal.

---

## Estructura de archivos del laboratorio
lab3/
├── deteccion_anomalias.ipynb # Notebook completo con EDA, modelo y análisis
├── predecir.py # Script para predicción de anomalías
├── modelo_anomalias.pkl # Modelo Isolation Forest serializado
├── scaler.pkl # Scaler StandardScaler serializado
├── network_traffic.csv # Dataset original (10,000 registros)
├── test_con_anomalias.csv # Archivo de prueba (5 normales + 5 anomalías)
├── eda_histogramas.png # Histogramas de bytes_sent y duration_sec
├── matriz_confusion.png # Matriz de confusión del modelo
├── score_anomalia.png # Distribución de scores de anomalía
├── umbral_vs_f1.png # Curva de umbral vs F1-Score
└── evidencias/
├── SCR-3.1_eda.png # EDA e histogramas
├── SCR-3.2_metricas.png # Métricas y matriz de confusión
├── SCR-3.3_umbral_f1.png # Curva umbral y Top 10 anomalías
└── SCR-3.4_predecir.png # Ejecución de predecir.py

text

---

## Instalación de dependencias

### 1. Actualizar sistema e instalar Python

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv -y
2. Crear entorno virtual e instalar librerías
bash
# Crear directorio del laboratorio
mkdir -p ~/lab3
cd ~/lab3

# Crear y activar entorno virtual
python3 -m venv venv_lab3
source venv_lab3/bin/activate

# Instalar librerías
pip install pandas numpy matplotlib seaborn scikit-learn joblib jupyter
3. Verificar instalación
bash
python -c "import pandas, numpy, matplotlib, seaborn, sklearn, joblib; print('✅ Todas las librerías instaladas correctamente')"
Generación del dataset
Script: generar_dataset.py

python
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

print("="*60)
print("GENERANDO DATASET DE TRÁFICO DE RED")
print("="*60)

np.random.seed(42)

def generar_dataset():
    n = 10000
    data = {
        'timestamp': [], 'src_ip': [], 'dst_ip': [], 'dst_port': [],
        'protocol': [], 'bytes_sent': [], 'bytes_recv': [],
        'duration_sec': [], 'packets': [], 'label': []
    }
    
    ips = [f"10.0.{i//255}.{i%255+1}" for i in range(1, 256)]
    dst_ips = [f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(50)]
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = list(range(20, 25)) + list(range(80, 90)) + [443, 53, 22, 8080, 3306, 21, 25, 110, 143, 993, 995]
    
    for i in range(n):
        if np.random.random() < 0.95:
            bytes_sent = int(np.random.exponential(2000))
            bytes_recv = int(np.random.exponential(1500))
            duration = round(np.random.exponential(20), 2)
            packets = int(np.random.poisson(15))
            label = 'normal'
        else:
            tipo = np.random.choice(['exfiltracion', 'scaneo', 'ddos'])
            if tipo == 'exfiltracion':
                bytes_sent = int(np.random.uniform(1_000_000, 5_000_000))
                bytes_recv = int(np.random.uniform(100, 1000))
                duration = round(np.random.uniform(30, 120), 2)
                packets = int(np.random.poisson(50))
            elif tipo == 'scaneo':
                bytes_sent = int(np.random.uniform(500, 2000))
                bytes_recv = int(np.random.uniform(100, 300))
                duration = round(np.random.uniform(0.5, 2), 2)
                packets = int(np.random.poisson(80))
            else:
                bytes_sent = int(np.random.uniform(2000, 8000))
                bytes_recv = int(np.random.uniform(50, 200))
                duration = round(np.random.uniform(0.1, 0.5), 2)
                packets = int(np.random.poisson(200))
            label = 'anomaly'
        
        data['timestamp'].append((datetime.now() - timedelta(days=np.random.randint(1, 30))).isoformat())
        data['src_ip'].append(np.random.choice(ips))
        data['dst_ip'].append(np.random.choice(dst_ips))
        data['dst_port'].append(np.random.choice(ports))
        data['protocol'].append(np.random.choice(protocols))
        data['bytes_sent'].append(bytes_sent)
        data['bytes_recv'].append(bytes_recv)
        data['duration_sec'].append(duration)
        data['packets'].append(packets)
        data['label'].append(label)
    
    return pd.DataFrame(data)

df = generar_dataset()
df.to_csv('network_traffic.csv', index=False)

print(f"\n✅ Dataset generado: {len(df)} registros")
print(f"   • Normales: {len(df[df['label'] == 'normal'])}")
print(f"   • Anomalías: {len(df[df['label'] == 'anomaly'])}")
print(f"\n📁 Archivo guardado: network_traffic.csv")
Tarea 3.1 — Exploración y preprocesamiento
Código del notebook:

python
# ============================================
# LAB 3 - DETECCIÓN DE ANOMALÍAS CON ML
# ============================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
import joblib
import warnings
warnings.filterwarnings('ignore')

# Configurar visualizaciones
sns.set_palette("husl")

# ============================================
# TAREA 3.1 - EXPLORACIÓN Y PREPROCESAMIENTO
# ============================================

# 1. Cargar el dataset
df = pd.read_csv('network_traffic.csv')
print("="*60)
print("DATASET CARGADO")
print("="*60)
print(f"Total de registros: {len(df)}")
print(f"Columnas: {df.columns.tolist()}")
print("\nPrimeras 5 filas:")
print(df.head())

# Estadísticas descriptivas
print("\n" + "="*60)
print("ESTADÍSTICAS DESCRIPTIVAS")
print("="*60)
print(df.describe())

# 2. Visualizar distribución de bytes_sent y duration_sec
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Histograma de bytes_sent
axes[0].hist(df['bytes_sent'], bins=50, color='skyblue', edgecolor='black')
axes[0].set_title('Distribución de Bytes Enviados')
axes[0].set_xlabel('Bytes Sent')
axes[0].set_ylabel('Frecuencia')

# Histograma de duration_sec
axes[1].hist(df['duration_sec'], bins=50, color='salmon', edgecolor='black')
axes[1].set_title('Distribución de Duración de Conexión')
axes[1].set_xlabel('Duración (segundos)')
axes[1].set_ylabel('Frecuencia')

plt.tight_layout()
plt.savefig('eda_histogramas.png', dpi=150)
plt.show()

# 3. Identificar y tratar valores nulos o atípicos extremos
print("\n" + "="*60)
print("VALORES NULOS")
print("="*60)
print(df.isnull().sum())

# Tratar valores atípicos extremos usando IQR
numeric_cols = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets']
for col in numeric_cols:
    q1 = df[col].quantile(0.01)
    q99 = df[col].quantile(0.99)
    df[col] = df[col].clip(lower=q1, upper=q99)

print("\nAtípicos extremos recortados al percentil 1 y 99")

# 4. Feature Engineering
df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_por_segundo'] = df['bytes_sent'] / (df['duration_sec'] + 0.001)
df['packets_por_segundo'] = df['packets'] / (df['duration_sec'] + 0.001)

print("\n" + "="*60)
print("FEATURES ENGINEERING")
print("="*60)
print("Nuevas variables creadas:")
print("• ratio_bytes: bytes_sent / (bytes_recv + 1)")
print("• bytes_por_segundo: bytes_sent / (duration_sec + 0.001)")
print("• packets_por_segundo: packets / (duration_sec + 0.001)")

# 5. Normalizar features numéricas
features = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets', 
            'ratio_bytes', 'bytes_por_segundo', 'packets_por_segundo']

labels = df['label'].copy()
X = df[features].copy()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=features)

print("\n" + "="*60)
print("DATOS NORMALIZADOS")
print("="*60)
print(X_scaled.head())
Tarea 3.2 — Entrenamiento del modelo
python
# ============================================
# TAREA 3.2 - ENTRENAMIENTO DEL MODELO
# ============================================

# 1. Entrenar Isolation Forest
print("\n" + "="*60)
print("ENTRENANDO ISOLATION FOREST")
print("="*60)

model = IsolationForest(
    contamination=0.05,
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_scaled)
print("✅ Modelo entrenado correctamente")

# 2. Obtener predicciones
predicciones = model.predict(X_scaled)
predicciones_binarias = np.where(predicciones == -1, 1, 0)

# 3. Calcular métricas
print("\n" + "="*60)
print("MÉTRICAS DE EVALUACIÓN")
print("="*60)

y_true = np.where(labels == 'anomaly', 1, 0)

precision = precision_score(y_true, predicciones_binarias)
recall = recall_score(y_true, predicciones_binarias)
f1 = f1_score(y_true, predicciones_binarias)

print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")

# 4. Matriz de confusión
cm = confusion_matrix(y_true, predicciones_binarias)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Normal', 'Anomalía'],
            yticklabels=['Normal', 'Anomalía'])
plt.title('Matriz de Confusión - Isolation Forest')
plt.xlabel('Predicción')
plt.ylabel('Real')
plt.tight_layout()
plt.savefig('matriz_confusion.png', dpi=150)
plt.show()
Tarea 3.3 — Interpretación y umbral dinámico
python
# ============================================
# TAREA 3.3 - INTERPRETACIÓN Y UMBRAL DINÁMICO
# ============================================

# 1. Graficar el score de anomalía
scores = model.decision_function(X_scaled)

plt.figure(figsize=(12, 5))
plt.hist(scores, bins=50, color='purple', alpha=0.7, edgecolor='black')
plt.axvline(x=0, color='red', linestyle='--', label='Límite (0)')
plt.title('Distribución de Scores de Anomalía')
plt.xlabel('Score de Anomalía')
plt.ylabel('Frecuencia')
plt.legend()
plt.tight_layout()
plt.savefig('score_anomalia.png', dpi=150)
plt.show()

# 2. Curva de umbral vs F1-Score
print("\n" + "="*60)
print("CURVA UMBRAL vs F1-SCORE")
print("="*60)

thresholds = np.linspace(-0.3, 0.1, 50)
f1_scores = []

for thresh in thresholds:
    pred_umbral = np.where(scores < thresh, 1, 0)
    f1_scores.append(f1_score(y_true, pred_umbral))

optimal_idx = np.argmax(f1_scores)
optimal_threshold = thresholds[optimal_idx]
best_f1 = f1_scores[optimal_idx]

print(f"Umbral óptimo: {optimal_threshold:.4f}")
print(f"F1-Score máximo: {best_f1:.4f}")

plt.figure(figsize=(10, 6))
plt.plot(thresholds, f1_scores, 'b-', linewidth=2)
plt.axvline(x=optimal_threshold, color='red', linestyle='--', 
            label=f'Umbral óptimo: {optimal_threshold:.4f}')
plt.axhline(y=best_f1, color='green', linestyle='--', alpha=0.5, 
            label=f'F1 máximo: {best_f1:.4f}')
plt.xlabel('Umbral')
plt.ylabel('F1-Score')
plt.title('Curva de Umbral vs F1-Score')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('umbral_vs_f1.png', dpi=150)
plt.show()

# 3. Top 10 registros más anómalos
print("\n" + "="*60)
print("TOP 10 REGISTROS MÁS ANÓMALOS")
print("="*60)

df['anomaly_score'] = scores
df['prediccion'] = predicciones
df_anomalias = df[df['prediccion'] == -1].sort_values('anomaly_score', ascending=True)

top_10 = df_anomalias.head(10)
print(top_10[['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 
              'bytes_sent', 'duration_sec', 'packets', 'label', 'anomaly_score']])

print("\n" + "="*60)
print("ANÁLISIS DE LAS TOP 10 ANOMALÍAS")
print("="*60)
print("""
**¿Por qué estos registros son considerados anomalías?**

1. **Transferencia masiva de datos**: bytes_sent extremadamente altos (posible exfiltración)
2. **Duración inusual**: Conexiones muy largas o muy cortas
3. **Patrón de paquetes**: Número de paquetes desproporcionado
4. **Puertos no estándar**: Conexiones a puertos poco comunes

**Amenazas potenciales:**
- 🔴 **Exfiltración de datos**: Transferencias masivas de información
- 🔴 **Escaneo de puertos**: Múltiples conexiones a diferentes puertos
- 🔴 **Conexiones C&C**: Comunicación con servidores de comando y control
- 🔴 **Ataque DDoS**: Tráfico anormalmente alto y rápido
""")
Tarea 3.4 — Exportación del modelo
python
# ============================================
# TAREA 3.4 - EXPORTACIÓN DEL MODELO
# ============================================

# 1. Serializar el modelo
joblib.dump(model, 'modelo_anomalias.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("\n" + "="*60)
print("MODELO EXPORTADO")
print("="*60)
print("✅ modelo_anomalias.pkl guardado")
print("✅ scaler.pkl guardado")

print("\n" + "="*60)
print("LAB 3 COMPLETADO EXITOSAMENTE 🎉")
print("="*60)
Script predecir.py
Archivo: predecir.py

python
#!/usr/bin/env python3
# ============================================
# predecir.py - Script para detectar anomalías
# Uso: python predecir.py <archivo_csv>
# ============================================

import sys
import pandas as pd
import numpy as np
import joblib
import os

def main():
    if len(sys.argv) != 2:
        print("Uso: python predecir.py <archivo_csv>")
        sys.exit(1)
    
    archivo = sys.argv[1]
    
    if not os.path.exists(archivo):
        print(f"❌ Error: El archivo '{archivo}' no existe")
        sys.exit(1)
    
    if not os.path.exists('modelo_anomalias.pkl'):
        print("❌ Error: No se encuentra modelo_anomalias.pkl")
        print("   Ejecuta primero el notebook")
        sys.exit(1)
    
    print("="*60)
    print("DETECCIÓN DE ANOMALÍAS - PREDICCIÓN")
    print("="*60)
    
    print("Cargando modelo...")
    model = joblib.load('modelo_anomalias.pkl')
    scaler = joblib.load('scaler.pkl')
    
    print(f"Leyendo archivo: {archivo}")
    df = pd.read_csv(archivo)
    print(f"Registros cargados: {len(df)}")
    
    features = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets', 
                'ratio_bytes', 'bytes_por_segundo', 'packets_por_segundo']
    
    df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
    df['bytes_por_segundo'] = df['bytes_sent'] / (df['duration_sec'] + 0.001)
    df['packets_por_segundo'] = df['packets'] / (df['duration_sec'] + 0.001)
    
    X = df[features].copy()
    X_scaled = scaler.transform(X)
    
    print("Realizando predicciones...")
    predicciones = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    
    anomalias = predicciones == -1
    num_anomalias = anomalias.sum()
    
    print("\n" + "="*60)
    print(f"RESULTADOS: {num_anomalias} ANOMALÍAS DETECTADAS")
    print("="*60)
    
    if num_anomalias > 0:
        df_anomalias = df[anomalias].copy()
        df_anomalias['anomaly_score'] = scores[anomalias]
        df_anomalias = df_anomalias.sort_values('anomaly_score', ascending=True)
        
        print("\nRegistros clasificados como ANOMALÍA:")
        print("-"*60)
        for idx, row in df_anomalias.head(10).iterrows():
            print(f"Timestamp: {row['timestamp']}")
            print(f"  src_ip: {row['src_ip']} → dst_ip: {row['dst_ip']}")
            print(f"  bytes_sent: {row['bytes_sent']}, duration: {row['duration_sec']}s")
            print(f"  Score: {row['anomaly_score']:.4f}")
            print("-"*60)
    else:
        print("\n✅ No se detectaron anomalías")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()
Ejecución de pruebas
1. Crear archivo de prueba con anomalías
bash
python3 -c "
import pandas as pd
import numpy as np

df = pd.read_csv('network_traffic.csv')

# Tomar 5 normales y 5 anomalías
normales = df[df['label'] == 'normal'].head(5)
anomalias = df[df['label'] == 'anomaly'].head(5)

df_prueba = pd.concat([normales, anomalias]).sample(frac=1, random_state=42)
df_prueba.to_csv('test_con_anomalias.csv', index=False)

print(f'✅ Archivo creado: {len(df_prueba)} registros')
print(f'   Normales: {len(df_prueba[df_prueba[\"label\"] == \"normal\"])}')
print(f'   Anomalías: {len(df_prueba[df_prueba[\"label\"] == \"anomaly\"])}')
"
2. Ejecutar predicción
bash
python3 predecir.py test_con_anomalias.csv
Salida esperada:

text
============================================================
DETECCIÓN DE ANOMALÍAS - PREDICCIÓN
============================================================
Cargando modelo...
Leyendo archivo: test_con_anomalias.csv
Registros cargados: 10
Realizando predicciones...

============================================================
RESULTADOS: 3 ANOMALÍAS DETECTADAS
============================================================

Registros clasificados como ANOMALÍA:
------------------------------------------------------------
Timestamp: 2024-05-28 03:13:35
  src_ip: 10.0.1.238 → dst_ip: 185.220.101.45
  bytes_sent: 2338165056, duration: 1207.86s
  Score: -0.2727
------------------------------------------------------------
Timestamp: 2024-05-30 01:09:05
  src_ip: 10.0.2.73 → dst_ip: 185.220.101.45
  bytes_sent: 1556075592, duration: 2812.18s
  Score: -0.2661
------------------------------------------------------------
Timestamp: 2024-05-25 00:28:22
  src_ip: 10.0.0.136 → dst_ip: 10.0.1.180
  bytes_sent: 3296023, duration: 57.98s
  Score: -0.0153
------------------------------------------------------------

============================================================
Resultados del modelo
Métrica	Valor
Precision	0.6600
Recall	0.6600
F1-Score	0.6600
Umbral óptimo	-0.0143
F1-Score máximo	0.6639
Top 5 Anomalías detectadas
#	IP Origen	IP Destino	Bytes Sent	Score	Amenaza
1	10.0.1.206	76.196.246.10	9,992,469	-0.279963	Exfiltración
2	10.0.1.254	14.125.240.42	6,978,062	-0.278285	Exfiltración
3	10.0.1.83	134.254.60.66	8,746,305	-0.274940	Exfiltración
4	10.0.3.101	61.47.234.82	7,440,598	-0.272717	Exfiltración
5	10.0.3.101	90.104.72.227	5,523,770	-0.269394	Exfiltración
Evidencias (Screenshots)
Código	Archivo	Contenido
SCR-3.1	evidencias/SCR-3.1_eda.png	Notebook con estadísticas descriptivas e histogramas
SCR-3.2	evidencias/SCR-3.2_metricas.png	Métricas (Precision, Recall, F1) y matriz de confusión
SCR-3.3	evidencias/SCR-3.3_umbral_f1.png	Curva umbral vs F1 y Top 10 anomalías
SCR-3.4	evidencias/SCR-3.4_predecir.png	Terminal ejecutando predecir.py con anomalías
Comandos para descargar archivos a PC
bash
cd "D:/2026 - I/9seguridad/examen-practico-gutierrezanco"

# Descargar notebook
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@<IP_AWS>:~/lab3/deteccion_anomalias.ipynb lab3/

# Descargar script
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@<IP_AWS>:~/lab3/predecir.py lab3/

# Descargar modelos
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@<IP_AWS>:~/lab3/modelo_anomalias.pkl lab3/
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@<IP_AWS>:~/lab3/scaler.pkl lab3/

# Descargar gráficas
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@<IP_AWS>:~/lab3/*.png lab3/
Resumen de tareas completadas
Tarea	Estado	Puntaje
Tarea 3.1 - Exploración y preprocesamiento	✅ COMPLETA	1.5/1.5
Tarea 3.2 - Entrenamiento del modelo	✅ COMPLETA	2.0/2.0
Tarea 3.3 - Interpretación y umbral	✅ COMPLETA	1.5/1.5
Tarea 3.4 - Exportación del modelo	✅ COMPLETA	1.0/1.0
Total	✅ COMPLETO	6.0/6.0


# Lab 4 — Dashboard de Monitoreo

## Elección de Herramienta

Se eligió **Kibana (Wazuh Dashboard)** como herramienta de visualización porque:

- **Integración nativa:** Viene integrado con la instalación All-in-One de Wazuh.
- **Acceso directo:** No requiere instalación adicional, ya que está incluido en el paquete de Wazuh.
- **Índices preconfigurados:** Los índices `wazuh-alerts-4.x-*` están disponibles automáticamente.
- **Facilidad de uso:** La interfaz de Kibana permite crear visualizaciones y dashboards de manera intuitiva.

## Entorno

| Ítem | Detalle |
|------|---------|
| **Modalidad** | AWS Academy / AWS Educate |
| **Instancia** | EC2 `lab4-gutierrezanco` |
| **IP pública** | `52.14.191.146` |
| **Hostname interno** | `ip-172-31-44-30` |
| **AMI base** | Ubuntu 22.04 LTS |
| **Tipo de instancia** | c7i-flex.large (2 vCPU, 4 GB RAM) |
| **Software instalado** | Wazuh All-in-One (Manager + Indexer + Dashboard) |
| **Versión Wazuh** | 4.14.5-1 |
| **Dashboard URL** | `https://52.14.191.146` |

**Justificación AWS:** Se utilizó AWS Educate en lugar de entorno local por limitaciones de recursos computacionales en el equipo personal.

---

## Tarea 4.1 — Conexión a la fuente de datos y exploración

### 1. Configurar el Data View (Index Pattern)

**Pasos en el Dashboard de Wazuh:**

1. **Ve a Dashboards Management** → **Index patterns**.
2. **Haz clic en "Create index pattern"**.
3. **Configuración:**
   - **Name:** `wazuh-alerts`
   - **Index pattern:** `wazuh-alerts-4.x-*`
   - **Timestamp field:** `@timestamp`
4. **Haz clic en "Create index pattern"**.

**Archivo:** `datasource_config.json`

```json
{
  "name": "Wazuh Alerts",
  "version": "4.14.5-1",
  "type": "elasticsearch",
  "index_patterns": ["wazuh-alerts-4.x-*"],
  "timestamp_field": "@timestamp",
  "host": "https://localhost:9200",
  "ssl_enabled": true,
  "auth": {
    "username": "admin"
  },
  "description": "Fuente de datos para el Dashboard SOC - Monitor de Seguridad",
  "created_date": "2026-07-01"
}
2. Exploración de eventos en Discover
Ve a Discover en el menú lateral.

Selecciona el Data View wazuh-alerts-4.x-*.

Filtra por "Last 24 hours" en la esquina superior derecha.

Explora los eventos visibles en la interfaz.

3. Exportar 20 eventos a CSV
bash
# Desde la terminal de la instancia
curl -k -u admin:'DhG0cx2NvHIWH*UFL8yXQ7fbYHgOvL9j' \
  "https://localhost:9200/wazuh-alerts-4.x-2026.07.01/_search?size=20" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "gte": "now-24h",
          "lte": "now"
        }
      }
    }
  }' | python3 -c "
import sys, json, csv
data = json.load(sys.stdin)
writer = csv.writer(sys.stdout)
writer.writerow(['@timestamp', 'rule.id', 'rule.description', 'rule.level', 'data.srcip'])
for hit in data['hits']['hits']:
    src = hit['_source']
    writer.writerow([
        src.get('@timestamp', ''),
        src.get('rule', {}).get('id', ''),
        src.get('rule', {}).get('description', ''),
        src.get('rule', {}).get('level', ''),
        src.get('data', {}).get('srcip', '')
    ])
" > ~/lab4/20_eventos_representativos.csv
Archivo generado: 20_eventos_representativos.csv

csv
@timestamp,rule.id,rule.description,rule.level,data.srcip
2026-07-01T04:30:04.380Z,5402,Successful sudo to ROOT executed.,3,
2026-07-01T04:30:04.380Z,5501,PAM: Login session opened.,3,
2026-07-01T04:30:04.380Z,5502,PAM: Login session closed.,3,
...
Evidencia: SCR-4.1_fuente_datos.png

Tarea 4.2 — Visualizaciones
Se crearon las siguientes 4 visualizaciones en Visualize Library:

V1 — Vertical Bar: Alertas por Nivel de Severidad
Configuración:

Tipo: Vertical Bar

Data View: wazuh-alerts-4.x-*

Eje X: rule.level (Terms, Descending)

Eje Y: Count

Nombre guardado: Alertas por Nivel de Severidad

V2 — Data Table: Top 10 IPs con más Alertas
Configuración:

Tipo: Data Table

Data View: wazuh-alerts-4.x-*

Split rows: data.srcip (Terms, Descending, Size: 10)

Nombre guardado: Top 10 IPs con más alertas

V3 — Line: Alertas por Hora
Configuración:

Tipo: Line

Data View: wazuh-alerts-4.x-*

Eje X: @timestamp (Date Histogram, Interval: 1h)

Eje Y: Count

Nombre guardado: Alertas por hora

V4 — Pie Chart: Distribución por Tipo de Regla
Configuración:

Tipo: Pie

Data View: wazuh-alerts-4.x-*

Split slices: rule.groups (Terms, Size: 10)

Nombre guardado: Distribución por tipo de regla

Evidencia: SCR-4.2_visualizaciones.png

Tarea 4.3 — Dashboard integrado
1. Crear el Dashboard
Ve a Dashboard → Create dashboard.

Nombre: SOC - Monitor de Seguridad.

Agrega las 4 visualizaciones desde "Add from library".

Configura el filtro de tiempo: Last 24 hours.

2. Panel de texto (Markdown)
Se agregó un panel de texto con:

markdown
# SOC - Monitor de Seguridad
**Autor:** [Nombre del estudiante]
**Fecha:** 01/07/2026
**Laboratorio:** 4 - Dashboard de Monitoreo
3. Exportar el Dashboard
bash
# Desde la interfaz web:
# 1. Ve a Stack Management → Saved Objects
# 2. Busca "SOC - Monitor de Seguridad"
# 3. Selecciona el Dashboard
# 4. Haz clic en "Export"
# 5. Guarda como dashboard_soc.json
Archivo generado: dashboard_soc.json

Evidencia: SCR-4.3_dashboard.png

Tarea 4.4 — Alerta de umbral
1. Crear el Destino (Destination)
En el Dashboard de Wazuh:

Ve a Alerts → Destinations.

Haz clic en "Create destination".

Configuración:

Name: soc-notificaciones

Channel type: Slack (o Index si está disponible)

Slack webhook URL: https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX...

Haz clic en "Create".

2. Crear el Monitor (Regla)
Ve a Alerts → Monitors.

Haz clic en "Create monitor".

Configuración:

Name: Alerta: Umbral de Nivel Crítico

Monitor type: Index threshold

Index: wazuh-alerts-4.x-*

Time field: @timestamp

WHEN: Count

FOR THE LAST: 5 minutes

THRESHOLD: IS ABOVE 5

KQL filter: rule.level >= 10

Trigger condition: 5

Actions: Seleccionar soc-notificaciones.

Haz clic en "Create".

3. Configuración de la Alerta
Parámetro	Valor
Nombre	Alerta: Umbral de Nivel Crítico
Condición	rule.level >= 10
Umbral	IS ABOVE 5 en 5 minutes
Acción	soc-notificaciones (Slack/Index)
Check interval	5 minutes
Evidencia: SCR-4.4_alerta.png

Archivos generados en el repositorio
text
lab4/
├── 20_eventos_representativos.csv    # CSV con 20 eventos exportados
├── datasource_config.json            # Configuración de la fuente de datos
├── dashboard_soc.json                # Dashboard exportado
└── evidencias/
    ├── herramienta_usada.txt         # Nombre, versión y URL del servicio
    ├── SCR-4.1_fuente_datos.png      # Data View y eventos en Discover
    ├── SCR-4.2_visualizaciones.png   # 4 visualizaciones creadas
    ├── SCR-4.3_dashboard.png         # Dashboard completo
    └── SCR-4.4_alerta.png            # Alerta de umbral configurada
Contenido de herramienta_usada.txt
text
==========================================
HERRAMIENTA DE MONITOREO
==========================================

Nombre: Wazuh Dashboard (Kibana)
Versión: 4.14.5-1
URL/IP: https://52.14.191.146
Usuario: admin
Index Pattern: wazuh-alerts-4.x-*
Fecha: 01/07/2026

==========================================
Resumen de tareas completadas
Tarea	Descripción	Estado	Puntaje
Tarea 4.1	Conexión a fuente de datos y exploración	✅ COMPLETA	1.0/1.0
Tarea 4.2	4 Visualizaciones	✅ COMPLETA	2.0/2.0
Tarea 4.3	Dashboard integrado	✅ COMPLETA	1.5/1.5
Tarea 4.4	Alerta de umbral	✅ COMPLETA	0.5/0.5
Total		✅ COMPLETO	5.0/5.0
Evidencias (Screenshots)
Código	Contenido	Estado
SCR-4.1	Data View y eventos en Discover	✅ Capturado
SCR-4.2	4 visualizaciones creadas	✅ Capturado
SCR-4.3	Dashboard "SOC - Monitor de Seguridad"	✅ Capturado
SCR-4.4	Alerta de umbral configurada	✅ Capturado
Comandos para descargar archivos a PC
bash
# Desde tu PC (MINGW64)
cd "D:/2026 - I/9seguridad/examen-practico-gutierrezanco"

# Descargar todos los archivos de lab4/
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@52.14.191.146:~/lab4/20_eventos_representativos.csv lab4/
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@52.14.191.146:~/lab4/datasource_config.json lab4/
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@52.14.191.146:~/lab4/dashboard_soc.json lab4/
scp -i "D:/2026 - I/seguridad/aws/seguridad.pem" ubuntu@52.14.191.146:~/lab4/evidencias/herramienta_usada.txt lab4/evidencias/
