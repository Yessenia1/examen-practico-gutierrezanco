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
