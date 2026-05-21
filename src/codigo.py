import argparse
import csv
import os
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
import requests
from dotenv import load_dotenv

# 1. Configuração Avançada de Logs do Sistema (Opção 2)
# Garante que logs do próprio script sejam salvos em arquivo e mostrados no terminal
os.makedirs("data", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("data/sistema.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Carrega as variáveis de ambiente do .env
load_dotenv()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

ARQUIVO_SAIDA_CSV = "data/relatorio_incidentes.csv"

def enviar_alerta_telegram(mensagem):
    """Envia alertas críticos para o Telegram com tratamento de falhas resiliente."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.error("Credenciais do Telegram não encontradas no arquivo .env")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": mensagem}
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logging.info("Notificação enviada com sucesso para o Telegram!")
        else:
            logging.error(f"Erro na API do Telegram (Status {response.status_code}): {response.text}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Falha de rede ao tentar conectar com o Telegram: {e}")

def registrar_incidente_csv(ip, tentativas, inicio, fim):
    """Salva o incidente detectado na planilha CSV sem duplicar cabeçalhos."""
    existe = os.path.exists(ARQUIVO_SAIDA_CSV)
    try:
        with open(ARQUIVO_SAIDA_CSV, mode="a", newline="", encoding="utf-8") as f:
            escritor = csv.writer(f)
            if not existe:
                escritor.writerow(["IP Suspeito", "Tentativas", "Horário Início", "Horário Fim", "Data Detecção"])
            escritor.writerow([ip, tentativas, inicio.strftime('%Y-%m-%d %H:%M:%S'), fim.strftime('%Y-%m-%d %H:%M:%S'), datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        logging.info(f"Incidente do IP {ip} registrado com sucesso em CSV.")
    except Exception as e:
        logging.error(f"Erro ao salvar relatório CSV: {e}")

def processar_linha_log(linha, historico_falhas, limite_tentativas, janela_minutos):
    """Processa uma única linha de log e valida regras de força bruta."""
    if "Erro de login" not in linha:
        return

    try:
        # Exemplo: 2026-05-20 21:05:00 - Erro de login - root - 192.168.1.99
        partes = linha.strip().split(" - ")
        timestamp_str = partes[0]
        ip = partes[3]
        
        horario = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        
        historico_falhas[ip].append(horario)
        
        # Filtra falhas dentro da janela de tempo configurada
        tempo_limite = horario - timedelta(minutes=janela_minutos)
        historico_falhas[ip] = [t for t in historico_falhas[ip] if t >= tempo_limite]
        
        # Se estourar o limite, gera o alerta
        if len(historico_falhas[ip]) >= limite_tentativas:
            primeira_falha = min(historico_falhas[ip])
            
            msg = f"🚨 [ALERTA DE SEGURANÇA]\n\nAtaque de Força Bruta detectado!\nIP: {ip}\nTentativas: {len(historico_falhas[ip])}\nJanela: {janela_minutos} min"
            enviar_alerta_telegram(msg)
            registrar_incidente_csv(ip, len(historico_falhas[ip]), primeira_falha, horario)
            
            # Limpa o histórico do IP para não disparar em loops subsequentes na mesma janela
            historico_falhas[ip].clear()
            
    except Exception as e:
        logging.error(f"Erro ao parsear linha de log: {e}")

def monitorar_logs_tempo_real(caminho_arquivo, limite_tentativas, janela_minutos):
    """Monitora o arquivo de log continuamente em tempo real (Tail -f) (Opção 1)."""
    logging.info(f"Iniciando monitoramento SecOps em tempo real no arquivo: {caminho_arquivo}")
    logging.info(f"Configuração ativa: Limite={limite_tentativas} tentativas | Janela={janela_minutos} minutos")
    
    historico_falhas = defaultdict(list)
    
    # Garante que o arquivo exista para não quebrar o script
    if not os.path.exists(caminho_arquivo):
        with open(caminho_arquivo, "w") as f:
            f.write("")
            
    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        # Move o ponteiro do arquivo para o final (ignora o histórico antigo ao iniciar)
        f.seek(0, os.SEEK_END)
        
        while True:
            linha = f.readline()
            if not linha:
                time.sleep(1) # Aguarda 1 segundo por novas linhas sem estressar a CPU
                continue
                
            processar_linha_log(linha, historico_falhas, limite_tentativas, janela_minutos)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisador de Logs de Segurança SecOps em Tempo Real")
    parser.add_argument("-a", "--arquivo", type=str, default="data/import.txt", help="Caminho do arquivo de log")
    parser.add_argument("-t", "--tentativas", type=int, default=3, help="Limite de tentativas falhas")
    parser.add_argument("-j", "--janela", type=int, default=2, help="Janela de tempo em minutos")
    
    args = parser.parse_args()
    
    try:
        monitorar_logs_tempo_real(args.arquivo, args.tentativas, args.janela)
    except KeyboardInterrupt:
        logging.info("\n[-] Monitoramento interrompido pelo usuário. Desligando SOC.")
