import json
from pathlib import Path

from defense.indicators import extrair_indicadores
from ransomware.file_generator import LAB_TARGET_DIR
from ransomware.key_manager import LOG_FILE


MITRE_POR_REGRA = {
    "DET-RANSOM-001": {
        "tatica": "Impact",
        "tatica_id": "TA0040",
        "tecnica": "Data Encrypted for Impact",
        "tecnica_id": "T1486",
    },
    "DET-KEYLOG-001": {
        "tatica": "Collection",
        "tatica_id": "TA0009",
        "tecnica": "Input Capture (GUI Input Capture)",
        "tecnica_id": "T1056.002",
    },
    "DET-PERSIST-001": {
        "tatica": "Persistence",
        "tatica_id": "TA0003",
        "tecnica": "Boot or Logon Autostart Execution",
        "tecnica_id": "T1547",
    },
    "DET-EXFIL-001": {
        "tatica": "Exfiltration",
        "tatica_id": "TA0010",
        "tecnica": "Exfiltration Over Alternative Protocol",
        "tecnica_id": "T1048",
    },
}


def avaliar_comportamentos(
    arquivo_log: Path = LOG_FILE,
    diretorio_alvo: Path = LAB_TARGET_DIR,
) -> dict:
    """Aplica regras heurísticas sobre os indicadores extraídos do laboratório."""
    indicadores = extrair_indicadores(arquivo_log=arquivo_log, diretorio_alvo=diretorio_alvo)
    alertas: list[dict] = []

    arquivos_cifrados_log = indicadores.get("arquivos_cifrados_no_log", 0)
    nota_resgate = indicadores.get("nota_resgate_presente", False)
    arquivos_enc_atuais = indicadores.get("arquivos_enc_atuais", [])

    if arquivos_cifrados_log > 0 or nota_resgate or len(arquivos_enc_atuais) > 0:
        alertas.append(
            {
                "regra_id": "DET-RANSOM-001",
                "severidade": "ALTA",
                "titulo": "Comportamento compatível com cifragem simulada e nota de resgate",
                "mitre_attack": MITRE_POR_REGRA["DET-RANSOM-001"],
                "evidencias": {
                    "arquivos_cifrados_no_log": arquivos_cifrados_log,
                    "nota_resgate_presente": nota_resgate,
                    "arquivos_enc_atuais": arquivos_enc_atuais,
                },
            }
        )

    sessoes_encerradas = indicadores.get("sessoes_keylogger_encerradas", 0)
    total_teclas = indicadores.get("total_teclas_registadas_em_sessoes", 0)
    log_teclas = indicadores.get("log_teclas_presente", False)

    if sessoes_encerradas > 0 or total_teclas > 0 or log_teclas:
        alertas.append(
            {
                "regra_id": "DET-KEYLOG-001",
                "severidade": "MEDIA",
                "titulo": "Registro de entradas de teclado observado em sessão simulada",
                "mitre_attack": MITRE_POR_REGRA["DET-KEYLOG-001"],
                "evidencias": {
                    "sessoes_encerradas": sessoes_encerradas,
                    "total_teclas_sessoes": total_teclas,
                    "log_teclas_presente": log_teclas,
                },
            }
        )

    acoes_persistencia = indicadores.get("acoes_persistencia_log", 0)
    arquivo_persistencia = indicadores.get("arquivo_sim_persistence_presente", False)

    if acoes_persistencia > 0 or arquivo_persistencia:
        alertas.append(
            {
                "regra_id": "DET-PERSIST-001",
                "severidade": "BAIXA",
                "titulo": "Artefato/ação de persistência simulada detectado",
                "mitre_attack": MITRE_POR_REGRA["DET-PERSIST-001"],
                "evidencias": {
                    "acoes_persistencia_log": acoes_persistencia,
                    "arquivo_sim_persistence": arquivo_persistencia,
                },
            }
        )

    transmissoes_sucesso = indicadores.get("transmissoes_rede_sucesso", 0)
    transmissoes_sem_receptor = indicadores.get("transmissoes_rede_sem_receptor", 0)
    destinos = indicadores.get("destinos_rede_simulados", [])

    if transmissoes_sucesso > 0 or transmissoes_sem_receptor > 0 or len(destinos) > 0:
        alertas.append(
            {
                "regra_id": "DET-EXFIL-001",
                "severidade": "ALTA",
                "titulo": "Tentativa ou ocorrência de transmissão de dados simulada em rede",
                "mitre_attack": MITRE_POR_REGRA["DET-EXFIL-001"],
                "evidencias": {
                    "transmissoes_sucesso": transmissoes_sucesso,
                    "transmissoes_sem_receptor": transmissoes_sem_receptor,
                    "destinos_observados": destinos,
                },
            }
        )

    return {
        "total_alertas": len(alertas),
        "alertas": alertas,
    }


if __name__ == "__main__":
    resultado = avaliar_comportamentos()
    print(json.dumps(resultado, indent=2, ensure_ascii=False))