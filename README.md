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
