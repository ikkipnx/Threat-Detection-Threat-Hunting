
import json

log_path = "logs/sysmon/process-creation.jsonl"

with open(log_path, encoding="utf-8") as f:
    events = [json.loads(line) for line in f if line.strip()]

# Procura todos os processos iniciados pelo mshta.exe
matches = [
    event for event in events
    if event.get("ParentImage", "").lower().endswith("\\mshta.exe")
]

print(f"Eventos analisados: {len(events)}")
print(f"Processos iniciados por mshta.exe: {len(matches)}")

for event in matches:
    print("-" * 40)
    print("Horário:", event.get("UtcTime"))
    print("Computador:", event.get("Computer"))
    print("Usuário:", event.get("User"))
    print("Processo filho:", event.get("Image"))
    print("Linha de comando:", event.get("CommandLine"))
