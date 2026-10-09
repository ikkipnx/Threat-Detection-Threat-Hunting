# Detection Hypotheses

## DH-001 — PowerShell iniciado por MSHTA

### Objetivo

Identificar execuções de `powershell.exe` cujo processo pai seja `mshta.exe`, comportamento que pode indicar abuso de um binário legítimo do Windows para executar scripts.

### Contexto

No cenário simulado deste laboratório, o evento de criação de processo registra o `powershell.exe` sendo iniciado pelo `mshta.exe`, com o argumento `-ExecutionPolicy Bypass`.

Essa combinação justifica investigação, mas não confirma, isoladamente, uma atividade maliciosa.

### Sinais de interesse

* Processo filho: `powershell.exe`
* Processo pai: `mshta.exe`
* Argumento relevante: `-ExecutionPolicy Bypass`
* Contexto adicional: usuário, computador, horário e processos imediatamente anteriores.

### Hipótese

Se `mshta.exe` iniciar `powershell.exe`, especialmente com argumentos que reduzam restrições de execução de scripts, pode haver uma cadeia de execução suspeita que merece investigação.

### Possíveis falsos positivos

* Scripts administrativos legítimos.
* Ferramentas internas que utilizem MSHTA e PowerShell.
* Testes autorizados de segurança.

### Procedimento de investigação

1. Confirmar a relação entre processo pai e processo filho.
2. Analisar a linha de comando completa.
3. Verificar usuário, computador e horário.
4. Correlacionar com eventos anteriores e posteriores.
5. Procurar evidências adicionais antes de classificar a atividade como maliciosa.

### Mapeamento MITRE ATT&CK

* T1218.005 — Mshta
* T1059.001 — PowerShell

### Fonte dos dados

`logs/sysmon/process-creation.jsonl`

Os eventos deste laboratório são simulados para fins educacionais e não representam evidência de um incidente real.
### Triage e análise de falsos positivos

Antes de classificar um alerta como malicioso, o analista deve:

1. Validar a relação entre o processo pai e o processo filho.
2. Examinar a linha de comando completa.
3. Identificar o usuário e o computador envolvidos.
4. Correlacionar eventos anteriores e posteriores.
5. Verificar se a execução está associada a uma atividade administrativa ou teste autorizado.
6. Buscar evidências adicionais antes de decidir pelo escalonamento ou contenção.

**Critério de classificação:** a presença de `mshta.exe` iniciando `powershell.exe` justifica investigação, mas não confirma, isoladamente, um incidente de segurança.

**Limitação:** os registros utilizados neste laboratório são simulados e não permitem concluir que houve comprometimento real.
