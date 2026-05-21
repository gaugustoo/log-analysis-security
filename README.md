# 🛡️ SOC Log Monitor & Security Parser

Um analisador de logs profissional desenvolvido em **Python** focado em operações de segurança (SOC). A ferramenta monitora e analisa arquivos de log de autenticação estruturados para identificar, bloquear e alertar em tempo real tentativas de ataques de **Força Bruta (Brute Force)**.

## 🚀 Funcionalidades

* **Análise Temporal Dinâmica:** Identifica acessos suspeitos baseando-se em janelas de tempo customizáveis.
* **Interface de Linha de Comando (CLI):** Permite configurar limites de tentativas, janelas de tempo e arquivos de entrada diretamente pelo terminal.
* **Integração com SOC (Telegram Bot):** Dispara alertas críticos e notificações push em tempo real diretamente para o canal de resposta a incidentes no Telegram.
* **Segurança de Credenciais:** Implementação de boas práticas de SecOps ocultando chaves de API e tokens usando variáveis de ambiente (`.env`).

---

## 🛠️ Tecnologias e Bibliotecas

* **Python 3.x**
* **Requests** (Comunicação com a API do Telegram)
* **Python-Dotenv** (Gerenciamento seguro de variáveis de ambiente)
* **Argparse** (Criação de interface via CLI nativa)

---

## 🔧 Configuração e Instalação

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/gaugustoo/log-analysis-security.git](https://github.com/gaugustoo/log-analysis-security.git)
   cd log-analysis-security
=======
 

from collections import defaultdict
from datetime import datetime, timedelta

# CONFIGURAÇÕES
LIMITE_TENTATIVAS = 3
JANELA_TEMPO_MINUTOS = 2


def carregar_logs(arquivo):
    logs = []
    try:
        with open(arquivo, "r", encoding="utf-8") as f:
            for linha in f:
                logs.append(linha.strip())
    except FileNotFoundError:
        print("Arquivo de log não encontrado!")
    return logs


def analisar_logs(logs):
    tentativas = defaultdict(list)

    print("\nIniciando analise profissional de logs...\n")

    for log in logs:
        try:
            # Formato esperado:
            # 2026-04-01 10:01:00 - Erro de login - user2 - 192.168.1.10
            partes = log.split(" - ")

            data_str = partes[0]
            evento = partes[1]
            usuario = partes[2]
            ip = partes[3]

            data = datetime.strptime(data_str, "%Y-%m-%d %H:%M:%S")

            if "Erro de login" in evento:
                chave = f"{usuario} | {ip}"
                tentativas[chave].append(data)

        except Exception as e:
            print(f"Erro ao processar log: {log}")

    gerar_alertas(tentativas)


def gerar_alertas(tentativas):
    print("\nRELATORIO DE SEGURANCA:\n")

    for chave, datas in tentativas.items():
        datas.sort()

        for i in range(len(datas)):
            contador = 1

            for j in range(i + 1, len(datas)):
                diferenca = datas[j] - datas[i]

                if diferenca <= timedelta(minutes=JANELA_TEMPO_MINUTOS):
                    contador += 1
                else:
                    break

            if contador >= LIMITE_TENTATIVAS:
                print(f"ALERTA: Possivel ataque detectado!")
                print(f"Alvo: {chave}")
                print(f"Tentativas: {contador}")
                print(f"Periodo: {datas[i]} ate {datas[j-1]}")
                print("-" * 50)
                break


if __name__ == "__main__":
    arquivo = "logs.txt"
    logs = carregar_logs(arquivo)
    analisar_logs(logs)
>>>>>>> 1f97dc72241efcc49b05eef888ad22bc166d9418
