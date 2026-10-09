# Threat Hunting Queries

## HN-001 — Processos iniciados por MSHTA

### Objetivo

Identificar processos iniciados pelo `mshta.exe` e investigar possíveis cadeias de execução suspeitas.

### Consulta lógica

* Fonte: eventos de criação de processos
* Campo do processo pai: `ParentImage`
* Critério: caminho do processo pai termina em `\mshta.exe`

### Justificativa

O `mshta.exe` é um executável legítimo do Windows que pode ser abusado para executar conteúdo ou iniciar outros processos. Identificar seus processos filhos ajuda a encontrar comportamentos que merecem investigação.

### Limitação

Esta consulta identifica processos filhos de `mshta.exe`, mas não confirma atividade maliciosa. É necessário analisar a linha de comando, o usuário, o computador e os eventos relacionados.

## HN-002 — PowerShell com argumentos suspeitos

### Objetivo

Localizar execuções de PowerShell com argumentos que merecem análise adicional.

### Consulta lógica

* Fonte: eventos de criação de processos
* Campo: `Image`
* Critério: processo executado é `powershell.exe`
* Indicador adicional: linha de comando contém `-ExecutionPolicy Bypass`

### Justificativa

Esse argumento pode aparecer em atividades legítimas, mas também pode ser usado para executar scripts em contextos que contornam a política de execução configurada.

### Limitação

O argumento, isoladamente, não comprova um ataque. A investigação deve considerar o contexto e outras evidências.

## HN-003 — Correlação entre processos

### Objetivo

Reconstruir relações entre processos para entender a sequência de execução observada.

### Consulta lógica

* Agrupar eventos por computador e usuário.
* Ordenar os eventos por horário.
* Correlacionar processo pai, processo filho e linha de comando.

### Resultado esperado

Identificar a sequência simulada `explorer.exe` → `mshta.exe` → `powershell.exe`.

### Limitação

A sequência é baseada em registros simulados deste laboratório e não representa evidência de comprometimento real.
