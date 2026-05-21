import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta
import requests
from dotenv import load_dotenv

# Carrega as variáveis salvas no arquivo .env oculto
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def enviar_alerta_telegram(mensagem):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Erro: Credenciais do Telegram não encontradas no arquivo .env")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensagem
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            print(f"[!] Erro ao enviar para o Telegram: {response.text}")
    except Exception as e:
        print(f"[!] Erro de conexão ao enviar alerta: {e}")

def gerar_relatorio_csv(ip, tentativas, data_inicio, data_fim):
    arquivo_csv = "relatorio_incidentes.csv"
    # Verifica se o arquivo já existe para não ficar repetindo o cabeçalho
    existe = os.path.exists(arquivo_csv)
    
    try:
        with open(arquivo_csv, mode="a", newline="", encoding="utf-8") as f:
            escritor = csv.writer(f)
            if not existe:
                # Cabeçalho profissional da planilha
                escritor.writerow(["Data/Hora Registro", "IP Suspeito", "Qtd Tentativas Falhas", "Janela Inicio", "Janela Fim", "Classificacao"])
            
            agora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            escritor.writerow([agora_str, ip, tentativas, data_inicio, data_fim, "Forca Bruta Detectada"])
        print(f"[+] Relatório atualizado com sucesso em '{arquivo_csv}'!")
    except Exception as e:
        print(f"[!] Erro ao gerar o arquivo de relatório: {e}")

def carregar_logs(arquivo):
    logs = []
    try:
        with open(arquivo, "r", encoding="utf-8") as f:
            for linha in f:
                logs.append(linha.strip())
    except FileNotFoundError:
        print(f"[ERRO] O arquivo '{arquivo}' não foi encontrado!")
    return logs

def analisar_logs(logs, limite_tentativas, janela_minutos):
    tentativas = defaultdict(list)
    print("\n[+] Iniciando análise profissional de logs...")
    
    for log in logs:
        try:
            partes = log.split(" - ")
            if len(partes) < 4:
                continue
                
            data_str = partes[0]
            evento = partes[1]
            ip = partes[3]
            
            data = datetime.strptime(data_str, "%Y-%m-%d %H:%M:%S")
            
            if "Erro de login" in evento:
                tentativas[ip].append(data)
                
        except Exception:
            continue

    print("--- RESULTADO DA ANÁLISE ---")
    alertas = 0
    for ip, horarios in tentativas.items():
        horarios.sort()
        for i in range(len(horarios)):
            janela_fim = horarios[i] + timedelta(minutes=janela_minutos)
            dentro_da_janela = [h for h in horarios[i:] if h <= janela_fim]
            
            if len(dentro_da_janela) >= limite_tentativas:
                # 1. Monta e exibe o alerta no terminal
                msg_terminal = f"⚠️ [ALERTA DE SEGURANÇA] IP {ip} detectado realizando Força Bruta! Total: {len(dentro_da_janela)} tentativas falhas."
                print(msg_terminal)
                
                # 2. Envia a notificação push para o Telegram pessoal
                msg_telegram = (
                    f"⚠️ <b>[ALERTA DE SEGURANÇA]</b>\n\n"
                    f"<b>Alvo:</b> Servidor de Autenticação\n"
                    f"<b>IP Atacante:</b> <code>{ip}</code>\n"
                    f"<b>Incidente:</b> Ataque de Força Bruta Detectado\n"
                    f"<b>Bloqueio:</b> Automatizado via CLI\n"
                    f"<b>Total de Eventos:</b> {len(dentro_da_janela)} falhas consecutivas."
                )
                enviar_alerta_telegram(msg_telegram)
                print("[+] Notificação enviada com sucesso para o Telegram!")
                
                # 3. Salva o incidente de forma persistente em formato de planilha (CSV)
                inicio_str = dentro_da_janela[0].strftime("%Y-%m-%d %H:%M:%S")
                fim_str = dentro_da_janela[-1].strftime("%Y-%m-%d %H:%M:%S")
                gerar_relatorio_csv(ip, len(dentro_da_janela), inicio_str, fim_str)
                
                alertas += 1
                break
                
    if alertas == 0:
        print("[-] Nenhum comportamento suspeito detectado nos logs.")
    print("----------------------------\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisador de Logs de Segurança SecOps Edition.")
    parser.add_argument("-a", "--arquivo", type=str, default="import.txt", help="Caminho do arquivo de log")
    parser.add_argument("-t", "--tentativas", type=int, default=3, help="Limite de tentativas falhas")
    parser.add_argument("-j", "--janela", type=int, default=2, help="Janela de tempo em minutos")
    
    args = parser.parse_args()

    logs_carregados = carregar_logs(args.arquivo)
    if logs_carregados:
        analisar_logs(logs_carregados, args.tentativas, args.janela)
