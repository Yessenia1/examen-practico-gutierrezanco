#!/usr/bin/env python3
# ============================================
# predecir.py - Script para detectar anomalías
# Uso: python predecir.py nuevo_trafico.csv
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
