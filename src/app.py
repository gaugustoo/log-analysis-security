import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="SOC Dashboard - Incidentes", page_icon="🛡️", layout="wide")

st.title("🛡️ SecOps Dashboard - Monitoramento de Incidentes")
st.markdown("Análise visual de ataques de força bruta detectados pelo script de automação.")

ARQUIVO_CSV = "data/relatorio_incidentes.csv"

if os.path.exists(ARQUIVO_CSV):
    # Carrega os dados da nossa planilha gerada pelo script principal
    df = pd.read_csv(ARQUIVO_CSV)
    
    # KPIs rápidos no topo da tela
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total de Incidentes", len(df))
    with col2:
        st.metric("IPs Únicos Bloqueados", df["IP Suspeito"].nunique())
    with col3:
        st.metric("Total de Ataques Barrados", df["Tentativas"].sum())
        
    st.markdown("---")
    
    # Gráficos de análise
    col_esquerda, col_direita = st.columns(2)
    
    with col_esquerda:
        st.subheader("📌 Ranking de IPs Ofensores")
        # Conta quantas vezes cada IP gerou incidentes
        contagem_ips = df["IP Suspeito"].value_counts()
        st.bar_chart(contagem_ips)
        
    with col_direita:
        st.subheader("📋 Histórico Recente de Alertas (Logs do CSV)")
        st.dataframe(df.sort_values(by="Data Detecção", ascending=False), use_container_width=True)
else:
    st.info("💡 Nenhum incidente registrado ainda. Rode o script de monitoramento e simule ataques para popular o dashboard!")

