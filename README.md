# Threat Detection & Threat Hunting Lab

## Objetivo

Projeto prático de Cybersecurity focado em detecção de comportamentos suspeitos, Threat Hunting, correlação de eventos e documentação de investigações.

O laboratório utiliza eventos sintéticos de criação de processos no Windows para simular uma investigação de uma possível cadeia de execução suspeita.

## Cenário investigado

A sequência analisada é:

`explorer.exe` → `mshta.exe` → `powershell.exe`

O evento de PowerShell contém o parâmetro `-ExecutionPolicy Bypass`, que pode justificar investigação adicional, mas não comprova atividade maliciosa isoladamente.

## Componentes

- `attack-scenario/`: descrição do cenário.
- `logs/`: eventos sintéticos de criação de processos.
- `detections/`: hipóteses de detecção e regra Sigma.
- `hunting/`: scripts de hunting, correlação de processos e consultas documentadas.
- `reports/`: relatório da investigação.
- `test_detection.py`: teste em Python da lógica de detecção.

## Técnicas MITRE ATT&CK relacionadas

- T1218.005 — Mshta
- T1059.001 — PowerShell

O mapeamento representa a hipótese investigada no cenário, não a confirmação de comprometimento.

## Como executar

Na raiz do projeto, execute:

```bash
python3 test_detection.py
python3 hunting/hunt_mshta.py
python3 hunting/correlate_events.py
```

## Limitações

- Os eventos são sintéticos e não foram coletados de um ambiente real.
- O teste Python verifica uma lógica equivalente à regra, mas não executa a regra em um mecanismo Sigma ou SIEM.
- Os resultados demonstram o funcionamento do exercício, não a detecção de um incidente real.

## Próximas melhorias

- Adicionar testes para falsos positivos e cenários benignos.
- Validar a regra com um mecanismo compatível com Sigma.
- Expandir os eventos e enriquecer a investigação com contexto adicional.
