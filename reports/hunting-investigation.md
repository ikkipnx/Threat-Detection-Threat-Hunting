# Threat Hunting Investigation — Process Execution Chain

## 1. Objetivo

Investigar uma sequência simulada de criação de processos no Windows, identificando relações entre processos e indicadores que justifiquem análise adicional.

## 2. Escopo e fonte de dados

- Fonte: `logs/sysmon/process-creation.jsonl`
- Computador: `WS-FIN-023`
- Usuário: `CORP\user.finance`
- Eventos analisados: 3
- Período: 08/10/2026, das 09:15:00 às 09:16:15

Os eventos são simulados para fins educacionais e não representam telemetria coletada de um ambiente real.

## 3. Evidências observadas

| Horário | Processo | PID | Processo pai | PID pai |
|---|---|---:|---|---:|
| 09:15:00 | explorer.exe | 4120 | userinit.exe | Não disponível |
| 09:16:12 | mshta.exe | 5084 | explorer.exe | 4120 |
| 09:16:15 | powershell.exe | 6216 | mshta.exe | 5084 |

A linha de comando do PowerShell contém `-NoProfile -ExecutionPolicy Bypass -File suspicious-script.ps1`.

## 4. Análise

A correlação por PID confirmou, no conjunto simulado, a sequência:

`explorer.exe` → `mshta.exe` → `powershell.exe`

A execução de PowerShell como processo filho de `mshta.exe`, combinada com `-ExecutionPolicy Bypass`, justifica investigação adicional.

Esses elementos não comprovam, isoladamente, execução maliciosa. Em um ambiente real, seria necessário verificar o conteúdo do script, a origem do arquivo HTA, a legitimidade da atividade e outros eventos do endpoint.

## 5. Resultado

- HN-001: relação entre `mshta.exe` e seu processo filho identificada.
- HN-002: execução de PowerShell com `-ExecutionPolicy Bypass` observada.
- HN-003: sequência de processos reconstruída usando os PIDs registrados.

## 6. Limitações

- Os eventos são simulados.
- Não há evidência do conteúdo real do arquivo HTA ou do script PowerShell.
- O evento de `userinit.exe` não está disponível.
- A análise demonstra correlação de processos, não comprovação de comprometimento.

## 7. Conclusão

O exercício demonstrou como correlacionar eventos de criação de processos, identificar comportamentos que merecem investigação e documentar limitações e possíveis falsos positivos. Em um ambiente real, a conclusão dependeria de evidências adicionais e validação contextual.
