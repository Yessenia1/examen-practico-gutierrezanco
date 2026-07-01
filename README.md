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



## Tarea 2.2 — Regla: Exfiltración de datos

Archivo: `lab2/local_rules_exfil.xml`

```xml
<!--
    Regla: Detección de exfiltración de datos
    Lógica compuesta en dos pasos:

    Regla 100002 — Detecta transferencia saliente superior a 500 MB
    en una sola conexión desde un host interno (bytes_out > 524288000).
    Se basa en reglas de firewall/tráfico de red (grupo firewall).

    Regla 100003 — Correlaciona la transferencia masiva (100002) con
    un login exitoso previo fuera del horario laboral (22:00 a 06:00),
    indicando posible exfiltración intencional tras acceso no autorizado.
    Nivel 14 = crítico, requiere respuesta inmediata.
-->
<group name="local,exfiltration,">

    <!-- Paso 1: Detectar transferencia saliente mayor a 500 MB -->
    <rule id="100002" level="10">
        <if_group>firewall</if_group>
        <match>bytes_out</match>
        <regex>bytes_out: [5-9]\d{8}|bytes_out: \d{9,}</regex>
        <description>Transferencia de datos saliente superior a 500 MB detectada desde host interno</description>
        <group>data_exfiltration,large_transfer</group>
    </rule>

    <!-- Paso 2: Correlacionar con login exitoso fuera de horario laboral -->
    <rule id="100003" level="14" timeframe="3600">
        <if_matched_sid>100002</if_matched_sid>
        <if_matched_sid>5501</if_matched_sid>
        <same_source_ip />
        <time>22:00-06:00</time>
        <description>CRITICO: Posible exfiltración de datos — Transferencia masiva correlacionada con login fuera de horario laboral desde $(srcip)</description>
        <group>data_exfiltration,policy_violation</group>
    </rule>

</group>
```

### Validación XML

```bash
sudo apt install libxml2-utils -y   # necesario, xmllint no viene instalado por defecto
sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo "SSH OK"
sudo xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo "EXFIL OK"
```

Resultado: ambos archivos válidos (`SSH OK`, `EXFIL OK`). *(Evidencia: SCR-2.2)*

## Tarea 2.3 — Prueba y evidencia

### 1. Activación del Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Resultado: `Active: active (running)`. *(Evidencia: SCR-2.1)*

### 2. Script de simulación

No se contó con el script `simular_bruteforce.sh` del repositorio del curso, por lo que se
creó uno propio (`lab2/simular_bruteforce.sh`) que genera, mediante `logger`, 15 eventos de
`Failed password` desde la IP simulada `45.33.32.156` contra distintos usuarios, en un
intervalo de ~6 segundos:

```bash
#!/bin/bash
IP_ATACANTE="45.33.32.156"
USUARIOS=(admin root ubuntu admin_db postgres deploy)

for i in $(seq 1 15); do
    USUARIO=${USUARIOS[$((RANDOM % ${#USUARIOS[@]}))]}
    PUERTO=$((RANDOM % 40000 + 1024))
    PID=$((RANDOM % 9000 + 1000))
    logger -p auth.warning -t "sshd[$PID]" "Failed password for $USUARIO from $IP_ATACANTE port $PUERTO ssh2"
    sleep 0.5
done
```

### 3. Troubleshooting realizado

Durante la primera ejecución, la regla `100001` no disparaba. Se siguió el siguiente proceso
de diagnóstico:

| Paso | Comando | Hallazgo |
|---|---|---|
| 1 | `grep "auth" ossec.conf \| grep localfile` | Wazuh no tenía configurado el monitoreo de `/var/log/auth.log` |
| 2 | Se agregó `<localfile>` para `/var/log/auth.log` (`log_format syslog`) en `ossec.conf` | Wazuh empezó a leer el archivo correctamente (se vieron alertas `5501` de PAM) |
| 3 | `grep "5716" alerts.log` → vacío. `grep "Failed password" alerts.log` → con resultados | Los eventos se registraban, pero no bajo la regla `5716` esperada |
| 4 | `grep -B6 "Failed password..." alerts.log` | Se confirmó que la regla real disparada era **`5760`**, no `5716` |
| 5 | Se corrigió `if_matched_sid` de `5716` a `5760` en `local_rules_ssh.xml` | — |
| 6 | Tras reiniciar y volver a simular, `100001` seguía sin aparecer | Se sospechó que el manager no había recargado el archivo |
| 7 | `grep -A20 "<rules>" ossec.conf` | *(en verificación)* — Wazuh solo carga reglas locales explícitamente declaradas en `<rules><include>...</include></rules>`; los archivos `local_rules_ssh.xml` y `local_rules_exfil.xml` deben añadirse ahí manualmente, ya que por defecto solo se incluye `local_rules.xml` |

> Esta sección se actualizará con el resultado final una vez confirmada la corrección del
> `<include>` en `ossec.conf` y la captura de la alerta `100001` disparando correctamente.

### 4. Evidencia

Carpeta `lab2/evidencias/`:

- `SCR-2.1_wazuh_activo.png` — salida de `systemctl status wazuh-manager` (`active (running)`)
- `SCR-2.2_reglas_validadas.png` — validación XML sin errores (`xmllint --noout ... && echo OK`)
- `SCR-2.3_alerta_disparada.png` — *(pendiente)* extracto de `alerts.log` mostrando `Rule: 100001` disparada, con IP atacante `45.33.32.156` visible

## Estructura de archivos del laboratorio

```
lab2/
├── local_rules_ssh.xml
├── local_rules_exfil.xml
├── simular_bruteforce.sh
└── evidencias/
    ├── SCR-2.1_wazuh_activo.png
    ├── SCR-2.2_reglas_validadas.png
    └── SCR-2.3_alerta_disparada.png
```
