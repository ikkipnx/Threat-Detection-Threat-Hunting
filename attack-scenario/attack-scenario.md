# Attack Scenario — FIN7 Detection & Threat Hunting Lab

## 1. Objetivo

Este projeto simula uma investigação de segurança realizada por uma equipe de SOC após a identificação de comportamentos suspeitos em uma estação de trabalho corporativa.

O cenário foi construído com base em técnicas e comportamentos associados ao grupo FIN7, investigados no Projeto 01 — Threat Intelligence Investigation.

O objetivo é transformar informações de Cyber Threat Intelligence (CTI) em hipóteses de detecção e atividades de Threat Hunting.

---

## 2. Ambiente simulado

O ambiente representa uma organização fictícia com:

* Estações Windows;
* Active Directory;
* Servidores corporativos;
* Firewall;
* SIEM;
* EDR;
* Sysmon;
* Ferramenta de ITSM para gerenciamento de incidentes.

A estação analisada neste cenário será identificada como:

`WS-FIN-023`

Usuário:

`user.finance`

---

## 3. Cenário inicial

A equipe de SOC recebe um alerta relacionado à execução suspeita de comandos em uma estação Windows utilizada pelo departamento financeiro.

O primeiro evento observado indica a execução de `mshta.exe`, seguida pela execução de PowerShell.

A atividade chama a atenção porque a cadeia de execução apresenta características compatíveis com técnicas utilizadas por grupos de ameaça conhecidos.

A investigação será iniciada a partir desses eventos.

---

## 4. Hipótese inicial

A hipótese inicial do SOC é que um usuário possa ter executado um arquivo malicioso recebido por meio de uma campanha de phishing.

A possível cadeia de ataque é:

`Spearphishing → Malicious File → LNK → Mshta → PowerShell → Payload`

A investigação deverá determinar:

1. Como a execução foi iniciada;
2. Qual processo iniciou a atividade;
3. Quais comandos foram executados;
4. Se houve comportamento suspeito de PowerShell;
5. Se houve comunicação de rede associada;
6. Quais técnicas MITRE ATT&CK estão presentes;
7. Se os eventos representam um incidente real ou um falso positivo.

---

## 5. Técnicas MITRE ATT&CK relacionadas

A investigação terá como foco inicial as seguintes técnicas:

| Técnica   | Nome                           | Relação com o cenário                               |
| --------- | ------------------------------ | --------------------------------------------------- |
| T1204.002 | User Execution: Malicious File | Usuário executando arquivo potencialmente malicioso |
| T1218.005 | Mshta                          | Execução através do `mshta.exe`                     |
| T1059.001 | PowerShell                     | Execução de comandos através do PowerShell          |

Novas técnicas poderão ser adicionadas conforme a investigação encontrar evidências adicionais.

---

## 6. Objetivo da investigação

O objetivo não é apenas identificar um processo suspeito.

A investigação deverá reconstruir a cadeia de execução e determinar se os eventos observados representam uma atividade maliciosa.

O SOC deverá correlacionar:

`Processos → Usuário → Comandos → Arquivos → Rede → Técnicas MITRE ATT&CK`

A partir dessa correlação, serão desenvolvidas detecções e hipóteses de Threat Hunting.

---

## 7. Resultado esperado

Ao final da investigação, o projeto deverá produzir:

* Detecções baseadas em Sigma;
* Consultas de Threat Hunting;
* Mapeamento MITRE ATT&CK;
* Timeline da atividade;
* Investigação do incidente;
* Avaliação de falso positivo;
* Relatório técnico;
* Recomendações de melhoria de detecção.

---

## 8. Relação com o Projeto 01

O Projeto 01 teve como objetivo realizar uma investigação de Cyber Threat Intelligence sobre o FIN7, identificando:

`IOCs → Enrichment → TTPs → MITRE ATT&CK → Attack Chain`

O Projeto 02 utiliza essas informações como ponto de partida para uma abordagem defensiva:

`CTI → TTPs → Detection Hypothesis → Logs → Detection → Threat Hunting → Investigation`

Dessa forma, os dois projetos representam etapas diferentes do mesmo processo de defesa cibernética.
