import json
from pathlib import Path
from defense.indicators import extrair_indicadores
from ransomware.file_generator import LAB_TARGET_DIR
from ransomware.key_manager import LOG_FILE, registrar_evento


def avaliar_comportamentos(
    arquivo_log: Path = LOG_FILE,
    diretorio_alvo: Path = LAB_TARGET_DIR,
) -> dict:
    """Aplica regras heurísticas/comportamentais sobre os indicadores do laboratório."""
    indicadores = extrair_indicadores(arquivo_log=arquivo_log, diretorio_alvo=diretorio_alvo)
    por_acao = indicadores.get("por_acao", {})
    artefactos = indicadores.get("artefactos", {})
    destinos_rede = indicadores.get("destinos_rede_simulados", [])
    total_teclas = indicadores.get("total_teclas_registadas_em_sessoes", 0)

    alertas: list[dict] = []

    # Regra 1: Cifragem de arquivos e/ou artefato de resgate
    cifragens = por_acao.get("criptografar_arquivo_sucesso", 0)
    nota_presente = bool(artefactos.get("nota_resgate_presente", False))
    if cifragens > 0 or nota_presente:
        severidade = "ALTA" if (cifragens > 0 and nota_presente) else "MEDIA"
        alertas.append(
            {
                "regra_id": "DET-RANSOM-001",
                "severidade": severidade,
                "titulo": "Comportamento compatível com cifragem simulada e nota de resgate",
                "evidencias": {
                    "arquivos_cifrados_no_log": cifragens,
                    "nota_resgate_presente": nota_presente,
                    "arquivos_enc_atuais": artefactos.get("ficheiros_cifrados_enc", []),
                },
            }
        )

    # Regra 2: Captura de entradas de teclado em janela de teste
    sessoes_encerradas = por_acao.get("sessao_captura_encerrada", 0)
    if total_teclas > 0 or sessoes_encerradas > 0:
        alertas.append(
            {
                "regra_id": "DET-KEYLOG-001",
                "severidade": "MEDIA",
                "titulo": "Registro de entradas de teclado observado em sessão simulada",
                "evidencias": {
                    "sessoes_encerradas": sessoes_encerradas,
                    "total_teclas_sessoes": total_teclas,
                    "log_teclas_presente": artefactos.get("artefactos_logs", {}).get(
                        "keylogger_simulado_txt", False
                    ),
                },
            }
        )

    # Regra 3: Simulação de persistência
    persistencias = por_acao.get("simular_persistencia_sucesso", 0)
    if persistencias > 0 or artefactos.get("artefactos_logs", {}).get("sim_persistence_json", False):
        alertas.append(
            {
                "regra_id": "DET-PERSIST-001",
                "severidade": "BAIXA",
                "titulo": "Artefato/ação de persistência simulada detectado",
                "evidencias": {
                    "acoes_persistencia_log": persistencias,
                    "arquivo_sim_persistence": artefactos.get("artefactos_logs", {}).get(
                        "sim_persistence_json", False
                    ),
                },
            }
        )

    # Regra 4: Transmissão/exfiltração simulada pela rede
    envios_ok = por_acao.get("simular_transmissao_sucesso", 0)
    envios_sem_receptor = por_acao.get("simular_transmissao_sem_receptor", 0)
    if envios_ok > 0 or envios_sem_receptor > 0 or destinos_rede:
        severidade_rede = "ALTA" if envios_ok > 0 else "MEDIA"
        alertas.append(
            {
                "regra_id": "DET-EXFIL-001",
                "severidade": severidade_rede,
                "titulo": "Tentativa ou ocorrência de transmissão de dados simulada em rede",
                "evidencias": {
                    "transmissoes_sucesso": envios_ok,
                    "transmissoes_sem_receptor": envios_sem_receptor,
                    "destinos_observados": destinos_rede,
                },
            }
        )

    resultado = {
        "total_alertas": len(alertas),
        "alertas": alertas,
    }

    registrar_evento(
        modulo="defense.detection",
        acao="avaliacao_comportamental_concluida",
        detalhes={"total_alertas": len(alertas)},
    )
    return resultado


if __name__ == "__main__":
    relatorio_deteccao = avaliar_comportamentos()
    print(json.dumps(relatorio_deteccao, indent=2, ensure_ascii=False))