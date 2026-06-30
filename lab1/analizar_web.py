"""
analizar_web.py
Tarea 1.2 — Análisis de access.log Apache
Curso: Seguridad Informática — Laboratorio 1
"""

import re
import json
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────
RUTA_LOG            = "lab1/access.log"
RUTA_REPORTE        = "lab1/reporte_web.json"
UMBRAL_ESCANEO_RUTAS = 20       # rutas distintas en ventana de tiempo
VENTANA_ESCANEO_SEG  = 60       # en segundos
UMBRAL_RUTAS_GLOBAL  = 30       # rutas únicas totales (sin importar tiempo)

# Patrones de SQL Injection a detectar en la URL
PATRONES_SQLI = [
    r"UNION",
    r"SELECT",
    r"--",
    r"OR\s+1=1",
    r"'",
]
REGEX_SQLI = re.compile("|".join(PATRONES_SQLI), re.IGNORECASE)

# Regex para parsear Combined Log Format de Apache:
# IP - - [fecha:hora zona] "METODO /ruta HTTP/version" codigo bytes "-" "user-agent"
PATRON_ACCESS = re.compile(
    r'(?P<ip>\S+)'                          # IP origen
    r'\s+\S+\s+\S+\s+'                      # ident, authuser
    r'\[(?P<fecha>[^\]]+)\]'                # [fecha:hora +zona]
    r'\s+"(?P<metodo>\S+)'                  # "METODO
    r'\s+(?P<ruta>.+?)'                     # /ruta (puede tener espacios en query params)
    r'\s+HTTP/[\d.]+"\s+'                   # HTTP/x.x"
    r'(?P<codigo>\d{3})'                    # código respuesta
    r'\s+(?P<bytes>\d+)'                    # bytes
    r'.*?"(?P<useragent>[^"]*)"$'           # "user-agent"
)

FORMATO_FECHA = "%d/%b/%Y:%H:%M:%S %z"


# ─────────────────────────────────────────────
# FUNCIONES
# ─────────────────────────────────────────────

def leer_log(ruta: str) -> list[str]:
    """Lee el archivo de log y devuelve sus líneas."""
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def parsear_lineas(lineas: list[str]) -> list[dict]:
    """
    Parsea cada línea del log y devuelve una lista
    de registros como diccionarios.
    """
    registros = []
    for linea in lineas:
        m = PATRON_ACCESS.match(linea.strip())
        if m:
            registros.append({
                "ip":        m.group("ip"),
                "timestamp": datetime.strptime(m.group("fecha"), FORMATO_FECHA),
                "metodo":    m.group("metodo"),
                "ruta":      m.group("ruta"),
                "codigo":    int(m.group("codigo")),
                "bytes":     int(m.group("bytes")),
                "useragent": m.group("useragent"),
            })
    return registros


def detectar_escaneo(registros: list[dict]) -> list[dict]:
    """
    Detecta IPs que hacen más de UMBRAL_ESCANEO_RUTAS peticiones
    a rutas distintas en menos de VENTANA_ESCANEO_SEG segundos.
    Retorna lista de hallazgos con IP, ventana y rutas.
    """
    # Agrupar por IP, ordenado por timestamp
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)
    for ip in por_ip:
        por_ip[ip].sort(key=lambda x: x["timestamp"])

    hallazgos = []
    ips_ya_detectadas = set()

    for ip, reqs in por_ip.items():
        if ip in ips_ya_detectadas:
            continue

        # Detección global: muchas rutas únicas en total (escaneo lento/distribuido)
        rutas_totales = set(r["ruta"] for r in reqs)
        if len(rutas_totales) >= UMBRAL_RUTAS_GLOBAL:
            hallazgos.append({
                "ip":           ip,
                "inicio":       "global",
                "rutas_unicas": len(rutas_totales),
                "peticiones":   len(reqs),
            })
            ips_ya_detectadas.add(ip)
            print(
                f"  [ESCANEO] IP: {ip} — {len(rutas_totales)} rutas únicas "
                f"en total ({len(reqs)} peticiones) — Escaneo global detectado"
            )
            continue

        # Ventana deslizante
        for i in range(len(reqs)):
            ventana = [reqs[i]]
            for j in range(i + 1, len(reqs)):
                delta = (reqs[j]["timestamp"] - reqs[i]["timestamp"]).total_seconds()
                if delta <= VENTANA_ESCANEO_SEG:
                    ventana.append(reqs[j])
                else:
                    break
            rutas_unicas = set(r["ruta"] for r in ventana)
            if len(rutas_unicas) > UMBRAL_ESCANEO_RUTAS:
                hallazgos.append({
                    "ip":           ip,
                    "inicio":       reqs[i]["timestamp"].strftime("%H:%M:%S"),
                    "rutas_unicas": len(rutas_unicas),
                    "peticiones":   len(ventana),
                })
                ips_ya_detectadas.add(ip)
                print(
                    f"  [ESCANEO] IP: {ip} — {len(rutas_unicas)} rutas distintas "
                    f"en {VENTANA_ESCANEO_SEG}s a partir de {reqs[i]['timestamp'].strftime('%H:%M:%S')}"
                )
                break

    return hallazgos


def detectar_errores_http(registros: list[dict]) -> dict:
    """
    Agrupa peticiones con códigos 4xx y 5xx por IP.
    Retorna diccionario {ip: {codigo: cantidad}}.
    """
    errores = defaultdict(lambda: defaultdict(int))
    for r in registros:
        if 400 <= r["codigo"] < 600:
            errores[r["ip"]][str(r["codigo"])] += 1
    return errores


def detectar_sqli(registros: list[dict]) -> list[dict]:
    """
    Detecta peticiones con patrones de SQL Injection en la URL.
    Retorna lista de hallazgos con IP, ruta y patrón detectado.
    """
    hallazgos = []
    for r in registros:
        if REGEX_SQLI.search(r["ruta"]):
            patron_encontrado = []
            for p in PATRONES_SQLI:
                if re.search(p, r["ruta"], re.IGNORECASE):
                    patron_encontrado.append(p.replace(r"\s+", " "))
            hallazgos.append({
                "ip":       r["ip"],
                "ruta":     r["ruta"],
                "codigo":   r["codigo"],
                "patrones": patron_encontrado,
            })
            print(f"  [SQLi]    IP: {r['ip']} — {r['ruta'][:70]}")
    return hallazgos


def imprimir_resumen_errores(errores: dict) -> None:
    """Imprime tabla resumen de errores 4xx/5xx por IP."""
    print(f"\n  {'IP':<20} {'Código':<10} {'Cantidad':>8}")
    print("  " + "-" * 40)
    for ip, codigos in sorted(errores.items(), key=lambda x: sum(x[1].values()), reverse=True):
        for codigo, cantidad in sorted(codigos.items()):
            print(f"  {ip:<20} {codigo:<10} {cantidad:>8}")


def exportar_json(escaneos, errores, sqli, ruta: str) -> None:
    """Exporta todos los hallazgos al archivo JSON indicado."""

    # Convertir errores al formato serializable
    errores_lista = [
        {
            "ip":     ip,
            "errores": {cod: cant for cod, cant in codigos.items()}
        }
        for ip, codigos in errores.items()
    ]

    reporte = {
        "fecha_analisis":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones":  None,   # se rellena en main
        "escaneos_detectados": escaneos,
        "errores_http":      errores_lista,
        "sqli_detectados":   sqli,
    }

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=4, ensure_ascii=False)

    print(f"\n  Reporte exportado → {ruta}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("\n" + "=" * 55)
    print("  ANÁLISIS FORENSE — access.log (Apache HTTP)")
    print("=" * 55)

    # 1. Leer y parsear
    lineas    = leer_log(RUTA_LOG)
    registros = parsear_lineas(lineas)
    print(f"\n  Archivo leído:      {RUTA_LOG}  ({len(lineas)} líneas)")
    print(f"  Registros parseados: {len(registros)}")

    # 2. Detectar escaneo de directorios
    print("\n" + "─" * 55)
    print("  DETECCIÓN DE ESCANEO DE DIRECTORIOS")
    print("─" * 55)
    escaneos = detectar_escaneo(registros)
    if not escaneos:
        print("  Sin escaneos detectados.")

    # 3. Errores 4xx / 5xx por IP
    print("\n" + "─" * 55)
    print("  ERRORES HTTP 4xx / 5xx POR IP")
    print("─" * 55)
    errores = detectar_errores_http(registros)
    imprimir_resumen_errores(errores)

    # 4. SQL Injection
    print("\n" + "─" * 55)
    print("  DETECCIÓN DE SQL INJECTION EN URLs")
    print("─" * 55)
    sqli = detectar_sqli(registros)
    print(f"\n  Total de peticiones con SQLi detectadas: {len(sqli)}")

    # 5. Exportar JSON
    reporte_data = {
        "fecha_analisis":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones":    len(registros),
        "escaneos_detectados": escaneos,
        "errores_http": [
            {"ip": ip, "errores": dict(codigos)}
            for ip, codigos in errores.items()
        ],
        "sqli_detectados": sqli,
    }

    with open(RUTA_REPORTE, "w", encoding="utf-8") as f:
        json.dump(reporte_data, f, indent=4, ensure_ascii=False)

    print(f"\n  Reporte exportado → {RUTA_REPORTE}")
    print("\n  Análisis finalizado.\n")


if __name__ == "__main__":
    main()
