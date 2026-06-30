"""
analizar_ssh.py
Tarea 1.1 — Parseo y estadísticas de auth.log
Curso: Seguridad Informática — Laboratorio 1
"""

import re
import json
from datetime import datetime
from collections import Counter


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────
RUTA_LOG       = "lab1/auth.log"
RUTA_REPORTE   = "lab1/reporte_ssh.json"
UMBRAL_ALERTA  = 50
TOP_N          = 10

# Patrón para extraer la IP de líneas con "Failed password"
# Ejemplo de línea:
# May 10 03:21:04 server sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2
PATRON_FAILED = re.compile(
    r"Failed password.*?from\s+([\d]{1,3}(?:\.[\d]{1,3}){3})"
)


# ─────────────────────────────────────────────
# FUNCIONES
# ─────────────────────────────────────────────

def leer_log(ruta: str) -> list[str]:
    """Lee el archivo de log y devuelve sus líneas."""
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def extraer_ips_fallidas(lineas: list[str]) -> list[str]:
    """Extrae todas las IPs de líneas con intentos fallidos SSH."""
    ips = []
    for linea in lineas:
        match = PATRON_FAILED.search(linea)
        if match:
            ips.append(match.group(1))
    return ips


def imprimir_ranking(conteo: Counter, top_n: int) -> None:
    """Imprime el ranking de las N IPs con más intentos fallidos."""
    print("\n" + "=" * 55)
    print(f"  TOP {top_n} IPs CON MÁS INTENTOS FALLIDOS SSH")
    print("=" * 55)
    print(f"  {'#':<4} {'IP':<18} {'Intentos':>10}")
    print("-" * 55)

    for i, (ip, total) in enumerate(conteo.most_common(top_n), start=1):
        print(f"  {i:<4} {ip:<18} {total:>10}")

    print("=" * 55)


def generar_alertas(conteo: Counter, umbral: int) -> list[dict]:
    """
    Muestra alertas en consola y devuelve la lista
    de IPs sospechosas para el reporte JSON.
    """
    print("\n" + "─" * 55)
    print("  ANÁLISIS DE ALERTAS")
    print("─" * 55)

    ips_sospechosas = []
    hay_alertas = False

    for ip, total in sorted(conteo.items(), key=lambda x: x[1], reverse=True):
        es_alerta = total > umbral
        if es_alerta:
            hay_alertas = True
            print(
                f"  [ALERTA] IP: {ip} — {total} intentos fallidos "
                f"— Posible ataque de fuerza bruta"
            )
        ips_sospechosas.append({
            "ip":       ip,
            "intentos": total,
            "alerta":   es_alerta
        })

    if not hay_alertas:
        print(f"  Sin IPs que superen el umbral de {umbral} intentos.")

    return ips_sospechosas


def exportar_json(total: int, ips_sospechosas: list[dict], ruta: str) -> None:
    """Exporta el reporte al archivo JSON indicado."""
    reporte = {
        "fecha_analisis":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total,
        "ips_sospechosas":      ips_sospechosas
    }
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=4, ensure_ascii=False)

    print(f"\n  Reporte exportado → {ruta}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("\n" + "=" * 55)
    print("  ANÁLISIS FORENSE — auth.log (SSH)")
    print("=" * 55)

    # 1. Leer el log
    lineas = leer_log(RUTA_LOG)
    print(f"\n  Archivo leído: {RUTA_LOG}  ({len(lineas)} líneas)")

    # 2. Extraer IPs con intentos fallidos
    ips_fallidas = extraer_ips_fallidas(lineas)
    conteo       = Counter(ips_fallidas)
    total        = len(ips_fallidas)
    print(f"  Total de intentos fallidos encontrados: {total}")
    print(f"  IPs únicas involucradas:                {len(conteo)}")

    # 3. Ranking top N
    imprimir_ranking(conteo, TOP_N)

    # 4. Alertas por umbral
    ips_sospechosas = generar_alertas(conteo, UMBRAL_ALERTA)

    # 5. Exportar JSON
    exportar_json(total, ips_sospechosas, RUTA_REPORTE)

    print("\n  Análisis finalizado.\n")


if __name__ == "__main__":
    main()
