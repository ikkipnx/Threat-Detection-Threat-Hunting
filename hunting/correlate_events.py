import json
import ntpath

log_path = "logs/sysmon/process-creation.jsonl"

with open(log_path, encoding="utf-8") as f:
    events = [
        json.loads(line)
        for line in f
        if line.strip()
    ]

events.sort(key=lambda event: event.get("UtcTime", ""))

print("=== LINHA DO TEMPO DA INVESTIGAÇÃO ===")

for event in events:
    process = ntpath.basename(event.get("Image", ""))
    parent = ntpath.basename(event.get("ParentImage", ""))

    pid = event.get("ProcessId")
    parent_pid = event.get("ParentProcessId")

    print(f"\nHorário: {event.get('UtcTime')}")
    print(f"Computador: {event.get('Computer')}")
    print(f"Usuário: {event.get('User')}")
    print(f"Processo pai: {parent} (PID: {parent_pid})")
    print(f"Processo executado: {process} (PID: {pid})")
    print(f"Linha de comando: {event.get('CommandLine')}")

    previous = [
        earlier for earlier in events
        if earlier.get("ProcessId") == parent_pid
        and earlier.get("Computer") == event.get("Computer")
        and earlier.get("UtcTime", "") < event.get("UtcTime", "")
    ]

    if previous:
        print("Correlação: processo pai confirmado pelo PID.")
    else:
        print("Correlação: processo pai não encontrado nos eventos anteriores.")
