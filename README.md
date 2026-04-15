# log-analysis-security

import sys
sys.stdout.reconfigure(encoding='utf-8')

logs = [
    "2026-04-01 10:01:00 - Erro de login - user2",
    "2026-04-01 10:02:00 - Erro de login - user2",
    "2026-04-01 10:03:00 - Erro de login - user2",
    "2026-04-01 10:05:00 - Erro de login - user4",
    "2026-04-01 10:06:00 - Erro de login - user4",
    "2026-04-01 10:07:00 - Erro de login - user4"
]

def analisar_logs(lista_logs):
    tentativas = {}

    print("\nIniciando analise de logs...\n")

    for log in lista_logs:
        partes = log.split(" - ")

        data = partes[0]
        evento = partes[1]
        usuario = partes[2]

        if "Erro de login" in evento:
            if usuario not in tentativas:
                tentativas[usuario] = []

            tentativas[usuario].append(data)

    print("\nRESULTADO:\n")

    for user, datas in tentativas.items():
        print(f"Usuario: {user}")
        print(f"Tentativas falhas: {len(datas)}")

        for d in datas:
            print(f" - {d}")

        if len(datas) >= 3:
            print("ALERTA: Possivel ataque de forca bruta!")

        print("-" * 30)


if __name__ == "__main__":
    analisar_logs(logs)