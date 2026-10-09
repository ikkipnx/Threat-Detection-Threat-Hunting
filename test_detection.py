
import json
import yaml

# Carrega a regra Sigma
with open("detections/sigma/powershell_from_mshta.yml") as f:
    rule = yaml.safe_load(f)

# Carrega os eventos simulados
with open("logs/sysmon/process-creation.jsonl") as f:
    events = [json.loads(line) for line in f if line.strip()]

# Obtém os valores esperados na regra
selection = rule["detection"]["selection"]
expected_parent = selection["ParentImage|endswith"].lower()
expected_process = selection["Image|endswith"].lower()

# Testa cada evento
matches = []

for event in events:
    parent = event.get("ParentImage", "").lower()
    process = event.get("Image", "").lower()

    if parent.endswith(expected_parent) and process.endswith(expected_process):
        matches.append(event)

# Exibe o resultado
print(f"Eventos analisados: {len(events)}")
print(f"Eventos correspondentes à regra: {len(matches)}")

for event in matches:
    print("Computador:", event["Computer"])
    print("Processo:", event["Image"].split("\\")[-1])
    print("Processo pai:", event["ParentImage"].split("\\")[-1])
