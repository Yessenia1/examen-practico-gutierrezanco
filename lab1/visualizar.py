"""
visualizar.py
Tarea 1.3 — Visualización de resultados
Curso: Seguridad Informática — Laboratorio 1
"""

import re
import json
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # modo sin pantalla (servidor sin GUI)
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
from collections import Counter
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────
RUTA_AUTH       = "lab1/auth.log"
RUTA_ACCESS     = "lab1/access.log"
RUTA_GRAFICAS   = Path("lab1/graficas")
TOP_N           = 10

PATRON_FAILED   = re.compile(
    r"Failed password.*?from\s+([\d]{1,3}(?:\.[\d]{1,3}){3})"
)
PATRON_ACCESS   = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<fecha>[^\]]+)\]'
    r'\s+"\S+\s+.+?\s+HTTP/[\d.]+"\s+'
    r'(?P<codigo>\d{3})\s+\d+'
)
FORMATO_FECHA   = "%d/%b/%Y:%H:%M:%S %z"


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def preparar_carpeta():
    RUTA_GRAFICAS.mkdir(parents=True, exist_ok=True)


def leer_lineas(ruta: str) -> list[str]:
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


# ─────────────────────────────────────────────
# GRÁFICA 1 — Barras: Top 10 IPs SSH
# ─────────────────────────────────────────────

def grafica_top10_ssh():
    lineas = leer_lineas(RUTA_AUTH)
    ips = [
        m.group(1)
        for linea in lineas
        if (m := PATRON_FAILED.search(linea))
    ]
    conteo = Counter(ips)
    top10  = conteo.most_common(TOP_N)
    ips_top, intentos = zip(*top10)

    fig, ax = plt.subplots(figsize=(12, 6))
    colores = sns.color_palette("Reds_r", TOP_N)
    bars = ax.barh(list(ips_top)[::-1], list(intentos)[::-1], color=colores[::-1])

    # Etiquetas de valor al lado de cada barra
    for bar, val in zip(bars, list(intentos)[::-1]):
        ax.text(
            bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
            str(val), va="center", ha="left", fontsize=10, fontweight="bold"
        )

    ax.set_title("Top 10 IPs con más intentos fallidos SSH", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Número de intentos fallidos", fontsize=11)
    ax.set_ylabel("Dirección IP", fontsize=11)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    sns.despine(left=True, bottom=False)

    plt.tight_layout()
    salida = RUTA_GRAFICAS / "top10_ssh.png"
    fig.savefig(salida, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Guardada → {salida}")


# ─────────────────────────────────────────────
# GRÁFICA 2 — Línea: Peticiones HTTP por hora
# ─────────────────────────────────────────────

def grafica_timeline_http():
    lineas  = leer_lineas(RUTA_ACCESS)
    horas   = []

    for linea in lineas:
        m = PATRON_ACCESS.match(linea.strip())
        if m:
            try:
                dt = datetime.strptime(m.group("fecha"), FORMATO_FECHA)
                horas.append(dt.hour)
            except ValueError:
                continue

    conteo_horas = Counter(horas)
    df = pd.DataFrame(
        [(h, conteo_horas.get(h, 0)) for h in range(24)],
        columns=["hora", "peticiones"]
    )

    fig, ax = plt.subplots(figsize=(13, 5))
    ax.plot(df["hora"], df["peticiones"], marker="o", linewidth=2,
            color="#2563EB", markersize=5, markerfacecolor="white",
            markeredgewidth=2)
    ax.fill_between(df["hora"], df["peticiones"], alpha=0.15, color="#2563EB")

    ax.set_title("Peticiones HTTP por hora — 14/Jun/2024", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Hora del día (UTC)", fontsize=11)
    ax.set_ylabel("Número de peticiones", fontsize=11)
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}:00" for h in range(24)], rotation=45, ha="right", fontsize=8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    sns.despine()

    plt.tight_layout()
    salida = RUTA_GRAFICAS / "timeline_http.png"
    fig.savefig(salida, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Guardada → {salida}")


# ─────────────────────────────────────────────
# GRÁFICA 3 — Heatmap: Peticiones por hora y código
# ─────────────────────────────────────────────

def grafica_heatmap_http():
    lineas   = leer_lineas(RUTA_ACCESS)
    registros = []
    codigos_interes = {"200", "301", "304", "400", "403", "404", "500"}

    for linea in lineas:
        m = PATRON_ACCESS.match(linea.strip())
        if m:
            try:
                dt     = datetime.strptime(m.group("fecha"), FORMATO_FECHA)
                codigo = m.group("codigo")
                if codigo in codigos_interes:
                    registros.append({"hora": dt.hour, "codigo": codigo})
            except ValueError:
                continue

    df = pd.DataFrame(registros)
    pivot = (
        df.groupby(["hora", "codigo"])
        .size()
        .unstack(fill_value=0)
        .reindex(index=range(24), fill_value=0)
    )
    # Ordenar columnas por código
    pivot = pivot.reindex(sorted(pivot.columns), axis=1)

    fig, ax = plt.subplots(figsize=(13, 6))
    sns.heatmap(
        pivot.T,
        ax=ax,
        cmap="YlOrRd",
        linewidths=0.4,
        linecolor="white",
        annot=True,
        fmt="d",
        annot_kws={"size": 8},
        cbar_kws={"label": "Número de peticiones"}
    )

    ax.set_title("Peticiones HTTP por hora y código de respuesta", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Hora del día (UTC)", fontsize=11)
    ax.set_ylabel("Código de respuesta", fontsize=11)
    ax.set_xticklabels([f"{h:02d}h" for h in range(24)], rotation=45, ha="right", fontsize=8)

    plt.tight_layout()
    salida = RUTA_GRAFICAS / "heatmap_http.png"
    fig.savefig(salida, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Guardada → {salida}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("\n" + "=" * 55)
    print("  GENERACIÓN DE GRÁFICAS — Lab 1")
    print("=" * 55 + "\n")

    preparar_carpeta()

    print("  [1/3] Gráfica de barras — Top 10 IPs SSH...")
    grafica_top10_ssh()

    print("  [2/3] Línea de tiempo — Peticiones HTTP por hora...")
    grafica_timeline_http()

    print("  [3/3] Heatmap — Peticiones por hora y código HTTP...")
    grafica_heatmap_http()

    print("\n  Las 3 gráficas fueron guardadas en lab1/graficas/")
    print("  Archivos: top10_ssh.png | timeline_http.png | heatmap_http.png\n")


if __name__ == "__main__":
    main()
