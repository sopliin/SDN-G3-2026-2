#!/usr/bin/env python3
"""Campaña de R4 sobre el slice: ataques DDoS reales y cadena medida.

AVISO (2026-11-13): los internals de esta campaña aún asumen el corte
nativo del slice anterior (rutas /opt/campus-sdn/.venv, IAM en 192.168.0.10).
El acceso (bench/slice.py) ya apunta al slice nuevo; la lógica interna
se reescribe con la red de datos, según docs/05-secuencia-y-validacion.md.

Por cada ensayo: un host con sesión inunda al servidor víctima (h3) con
hping3 mientras otro host hace de cliente legítimo (ping cada 200 ms). Se
mide, con las marcas de la auditoría (ms) y los contadores del monitor:

- tiempo de detección   : inicio del ataque (reloj del atacante, NTP)
                          → AnomalyDetected
- tiempo de decisión    : AnomalyDetected → MitigationRequired
- tiempo de aplicación  : MitigationRequired → MitigationApplied (I2/ONOS)
- tiempo de efecto      : MitigationApplied → primera ventana del monitor
                          con la tasa hacia la víctima ≤ objetivo
- atribución            : ¿los orígenes son exactamente el atacante?
- daño colateral        : pérdida y RTT del cliente legítimo
- recuperación          : la regla de mitigación desaparece sola (TTL)

Además, una ventana de solo tráfico legítimo para la tasa de falsos
positivos, y el consumo de CPU/RAM del controlador y de los switches
durante un ataque. Todo queda en bench/results/<fecha>-r4/.

uso: SLICE_SUDO_PASSWORD=… python3 bench/r4_campaign.py [--quick]
"""

import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import slice as s  # noqa: E402

VICTIM = "h3"
RATE_LIMIT_PPS = 200          # debe coincidir con /etc/campus-sdn/services.env
ATTACK_S = 12
SETTLE_S = 8                  # reposo tras el ataque (rearmado: 5 ventanas)

# (atacante, cliente legítimo, tipo, opciones de hping3, tasa nominal)
TRIALS = [
    ("h1", "h4", "udp-flood", "--flood --udp -p 9999 -d 64", "max"),
    ("h2", "h4", "syn-flood", "--flood -S -p 80", "max"),
    ("h4", "h1", "udp-flood", "--flood --udp -p 9999 -d 64", "max"),
    ("h1", "h4", "icmp-flood", "--flood -1 -d 64", "max"),
    ("h2", "h4", "udp-5k", "-i u200 --udp -p 9999 -d 64", "5000"),
    ("h4", "h1", "syn-flood", "--flood -S -p 80", "max"),
    ("h1", "h4", "udp-2k", "-i u500 --udp -p 9999 -d 64", "2000"),
    ("h2", "h4", "icmp-flood", "--flood -1 -d 64", "max"),
    ("h4", "h1", "udp-5k", "-i u200 --udp -p 9999 -d 64", "5000"),
    ("h1", "h4", "udp-flood-1200B", "--flood --udp -p 9999 -d 1200", "max"),
    # Por debajo del piso de detección (1000 pps): se espera que NO se
    # detecte — documenta la sensibilidad, no cuenta como ataque fallido.
    ("h2", "h4", "udp-500 (bajo umbral)", "-i u2000 --udp -p 9999 -d 64", "500"),
]

COMMUNITY = {"h1": ("USR-0001", "user_0001"), "h2": ("USR-0002", "user_0002"),
             "h4": None}  # h4 es servidor declarado (confianza 60)


def login(host):
    if COMMUNITY.get(host) is None:
        return {"status": "server-trust"}
    username, password = COMMUNITY[host]
    return s.api(":8001/verify", "POST", {
        "population": "university", "username": username,
        "password": password, "device": s.HOSTS[host]["mac"].upper()})


def mitigation_flows():
    flows = []
    for dpid in s.DPIDS.values():
        flows += [f for f in s.onos(f"/flows/{dpid}").get("flows", [])
                  if f.get("priority") == 1000]
    return flows


def wait_mitigations_gone(limit_s=90):
    started = time.time()
    while time.time() - started < limit_s:
        if not mitigation_flows():
            return time.time()
        time.sleep(1)
    return None


VICTIM_SAMPLER = (
    # rx_packets de ens4 de la víctima cada 50 ms: el efecto real en el
    # plano de datos, sin el retardo de las estadísticas de ONOS.
    "python3 -c \"import time,sys\n"
    "f='/sys/class/net/ens4/statistics/rx_packets'\n"
    "end=time.time()+float(sys.argv[1])\n"
    "while time.time()<end:\n"
    "  print(time.time(),open(f).read().strip(),flush=True); time.sleep(0.05)\" ")


def victim_series(raw):
    """[(t, pps)] a partir de las lecturas acumuladas de rx_packets."""
    points = []
    for line in raw.strip().split("\n"):
        try:
            t, count = line.split()
            points.append((float(t), int(count)))
        except ValueError:
            continue
    return [(t2, (c2 - c1) / (t2 - t1))
            for (t1, c1), (t2, c2) in zip(points, points[1:]) if t2 > t1]


def run_trial(index, attacker, probe, kind, options, nominal):
    print(f"== ensayo {index}: {attacker} → {VICTIM} {kind}", flush=True)
    t_mark = time.time() - 1
    since = s.epoch_to_iso(t_mark)
    victim_proc = s.spawn(VICTIM, VICTIM_SAMPLER + str(ATTACK_S + SETTLE_S + 4))
    probe_proc = s.spawn(probe, f"ping -i 0.2 -w {ATTACK_S + 6} "
                         f"{s.HOSTS[VICTIM]['ip']}", sudo=True)
    time.sleep(2)
    code, out = s.ssh(attacker, (
        "date +%s.%N; "
        f"timeout {ATTACK_S} hping3 {options} {s.HOSTS[VICTIM]['ip']} "
        ">/tmp/hping.out 2>&1; date +%s.%N; tail -3 /tmp/hping.out"),
        sudo=True, timeout=ATTACK_S + 30)
    lines = out.split("\n")
    t_start, t_end = float(lines[0]), float(lines[1])
    probe_out, _ = probe_proc.communicate(timeout=60)
    time.sleep(SETTLE_S)
    victim_raw, _ = victim_proc.communicate(timeout=60)
    series = victim_series(victim_raw)

    events = s.audit_events(since, types={
        "AnomalyDetected", "IncidentOpened", "MitigationRequired",
        "MitigationApplied", "MitigationVerified"})
    detected = [e for e in events if e["type"] == "AnomalyDetected"
                and e["payload"]["target"]["ip"] == s.HOSTS[VICTIM]["ip"]]
    first = detected[0] if detected else None
    chain = {}
    if first:
        chain["AnomalyDetected"] = first
        incident = next((e for e in events if e["type"] == "IncidentOpened"
                         and s.iso_to_epoch(e["timestamp"])
                         >= s.iso_to_epoch(first["timestamp"]) - 0.001), None)
        if incident:
            chain["IncidentOpened"] = incident
            inc_id = incident["payload"]["incident"]
            for kind_ in ("MitigationRequired", "MitigationApplied",
                          "MitigationVerified"):
                found = next((e for e in events if e["type"] == kind_
                              and e["payload"].get("incident") == inc_id), None)
                if found:
                    chain[kind_] = found
    metrics = s.api(f":8003/metrics?destination={s.HOSTS[VICTIM]['ip']}"
                    f"&since={t_mark}").get("metrics", [])

    def at(name):
        return s.iso_to_epoch(chain[name]["timestamp"]) if name in chain else None

    t_detect, t_required, t_applied = (at("AnomalyDetected"),
                                       at("MitigationRequired"),
                                       at("MitigationApplied"))
    action = chain.get("MitigationRequired", {}).get("payload", {}).get("action")
    objective = RATE_LIMIT_PPS * 1.5 if action == "RATE_LIMIT" else 50
    t_effect = None
    if t_applied:
        after = [m for m in metrics if m["at"] >= t_applied]
        t_effect = next((m["at"] for m in after if m["pps"] <= objective), None)
    during = [m["pps"] for m in metrics if t_start <= m["at"] <= t_end]
    # En la víctima: inicio real (primera muestra > 1000 pps), pico y
    # primer instante tras MitigationApplied con la tasa ya en objetivo
    # durante 3 muestras seguidas (150 ms).
    onset = next((t for t, pps in series if pps > 1000 and t >= t_start - 1), None)
    victim_peak = max((pps for t, pps in series), default=0.0)
    victim_effect = None
    if t_applied:
        tail = [(t, pps) for t, pps in series if t >= t_applied]
        for i in range(len(tail) - 2):
            if all(pps <= objective for _, pps in tail[i:i + 3]):
                victim_effect = tail[i][0]
                break
    victim_after = [pps for t, pps in series
                    if victim_effect and victim_effect <= t <= t_end]
    origins = first["payload"]["origins"] if first else []
    attributed = sorted(o["mac"] for o in origins)
    loss = next((l for l in probe_out.split("\n") if "packet loss" in l), "")
    rtt = next((l for l in probe_out.split("\n") if "rtt" in l), "")
    t_gone = wait_mitigations_gone() if t_applied else None

    result = {
        "index": index, "attacker": attacker, "probe": probe, "kind": kind,
        "nominal_pps": nominal, "attack_start": t_start, "attack_end": t_end,
        "peak_pps": max(during) if during else 0.0,
        "detected": bool(first),
        "detection_s": round(t_detect - t_start, 3) if t_detect else None,
        "decision_ms": round((t_required - t_detect) * 1000, 1)
        if t_required and t_detect else None,
        "apply_ms": round((t_applied - t_required) * 1000, 1)
        if t_applied and t_required else None,
        "effect_s": round(t_effect - t_applied, 3)
        if t_effect and t_applied else None,
        "start_to_mitigated_s": round(t_effect - t_start, 3) if t_effect else None,
        "victim_onset_lag_s": round(onset - t_start, 3) if onset else None,
        "victim_peak_pps": round(victim_peak, 1),
        "victim_effect_after_apply_s": round(victim_effect - t_applied, 3)
        if victim_effect and t_applied else None,
        "victim_start_to_mitigated_s": round(victim_effect - t_start, 3)
        if victim_effect else None,
        "victim_pps_mitigated_mean": round(statistics.mean(victim_after), 1)
        if victim_after else None,
        "victim_series": series,
        "action": action,
        "severity": first["payload"]["proposed_severity"] if first else None,
        "attributed": attributed,
        "attribution_ok": attributed == [s.HOSTS[attacker]["mac"]],
        "verified": chain.get("MitigationVerified", {}).get("payload"),
        "probe_loss": loss.strip(), "probe_rtt": rtt.strip(),
        "recovery_after_apply_s": round(t_gone - t_applied, 1)
        if t_gone and t_applied else None,
        "chain": chain, "metrics": metrics,
        "hping_tail": "\n".join(lines[2:]),
    }
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("chain", "metrics")}, ensure_ascii=False),
          flush=True)
    return result


def resource_snapshot(duration_s, attacker="h1"):
    """CPU (% de un núcleo) y RSS de los procesos clave durante un ataque."""
    sampler = (
        "import os,time,sys\n"
        "names=sys.argv[1].split(',')\n"
        "hz=os.sysconf('SC_CLK_TCK')\n"
        "def pids():\n"
        "  out={}\n"
        "  for p in os.listdir('/proc'):\n"
        "    if p.isdigit():\n"
        "      try: cmd=open(f'/proc/{p}/cmdline','rb').read().replace(b'\\0',b' ').decode()\n"
        "      except OSError: continue\n"
        "      for n in names:\n"
        "        if n in cmd and n not in out: out[n]=p\n"
        "  return out\n"
        "def ticks(p):\n"
        "  f=open(f'/proc/{p}/stat').read().split(')')[1].split()\n"
        "  return int(f[11])+int(f[12])\n"
        "def rss(p):\n"
        "  for l in open(f'/proc/{p}/status'):\n"
        "    if l.startswith('VmRSS'): return int(l.split()[1])//1024\n"
        "ps=pids(); prev={n:ticks(p) for n,p in ps.items()}\n"
        "for _ in range(int(sys.argv[2])):\n"
        "  time.sleep(1); row={}\n"
        "  for n,p in ps.items():\n"
        "    t=ticks(p); row[n]=[round((t-prev[n])*100/hz,1),rss(p)]; prev[n]=t\n"
        "  print(time.time(),row,flush=True)\n")
    targets = {"controller": "run_services.py,org.apache.karaf,beam.smp",
               "sw2": "ovs-vswitchd", "sw3": "ovs-vswitchd"}
    import base64
    encoded = base64.b64encode(sampler.encode()).decode()
    procs = {node: s.spawn(node, f"echo {encoded} | base64 -d > /tmp/sampler.py; "
                           f"python3 /tmp/sampler.py {names} {duration_s}",
                           sudo=True)
             for node, names in targets.items()}
    time.sleep(8)  # reposo: línea de comparación sin ataque
    s.ssh(attacker, f"timeout {duration_s - 16} hping3 --flood --udp -p 9999 "
          f"-d 64 {s.HOSTS[VICTIM]['ip']} >/dev/null 2>&1", sudo=True,
          timeout=duration_s + 30)
    rows = {}
    for node, proc in procs.items():
        out, _ = proc.communicate(timeout=duration_s + 30)
        rows[node] = out.strip().split("\n")
    flows = {name: len(s.onos(f"/flows/{dpid}").get("flows", []))
             for name, dpid in s.DPIDS.items()}
    return {"samples": rows, "flows_per_switch": flows}


def legit_window(duration_s):
    """Solo tráfico legítimo hacia h3: HTTP, ping e iperf3 limitado."""
    print(f"== ventana legítima de {duration_s} s", flush=True)
    since = s.epoch_to_iso(time.time())
    # «[h]ttp» evita que pkill -f se mate a sí mismo (su línea contiene
    # el patrón).
    # Matar y arrancar en llamadas separadas: si van juntas, pkill -f
    # encuentra el patrón en su propia línea de comandos y se mata.
    s.ssh(VICTIM, "pkill -f '[h]ttp.server 80' ; pkill -x iperf3", sudo=True)
    s.ssh(VICTIM, "cd /tmp && (setsid nohup python3 -m http.server 80 "
          ">/dev/null 2>&1 &) ; iperf3 -s -D", sudo=True)
    time.sleep(2)
    ip = s.HOSTS[VICTIM]["ip"]
    clients = [
        s.spawn("h1", f"end=$((SECONDS+{duration_s})); n=0; while [ $SECONDS -lt $end ]; "
                f"do curl -s -o /dev/null http://{ip}/ && n=$((n+1)); sleep 0.5; done; echo http=$n"),
        s.spawn("h2", f"ping -i 0.5 -w {duration_s} {ip} | tail -2"),
        s.spawn("h4", f"end=$((SECONDS+{duration_s})); while [ $SECONDS -lt $end ]; "
                f"do iperf3 -c {ip} -b 4M -t 10 2>&1 | grep -E 'sender|receiver'; sleep 5; done"),
    ]
    outputs = [c.communicate(timeout=duration_s + 60)[0] for c in clients]
    time.sleep(3)
    alerts = s.audit_events(since, types={"AnomalyDetected"})
    metrics = s.api(f":8003/metrics?destination={ip}&since="
                    f"{s.iso_to_epoch(since)}").get("metrics", [])
    pps = [m["pps"] for m in metrics]
    s.ssh(VICTIM, "pkill -f '[h]ttp.server 80' ; pkill -x iperf3", sudo=True)
    return {"duration_s": duration_s, "alerts": alerts,
            "false_positives": len(alerts), "client_output": outputs,
            "pps_mean": round(statistics.mean(pps), 1) if pps else 0,
            "pps_max": max(pps) if pps else 0, "samples": len(pps)}


def main():
    if not s.SUDO_PASSWORD:
        sys.exit("definir SLICE_SUDO_PASSWORD")
    quick = "--quick" in sys.argv
    out_dir = s.results_dir("r4")
    # Sesiones limpias: se retiran las reglas de sesión huérfanas (de
    # reinicios previos del IAM) y se vuelve a entrar.
    for dpid in s.DPIDS.values():
        for flow in s.onos(f"/flows/{dpid}").get("flows", []):
            if flow.get("priority") == 200:
                s.ssh("controller", "curl -s -u karaf:karaf -X DELETE "
                      f"http://127.0.0.1:8181/onos/v1/flows/{dpid}/{flow['id']}")
    for host in ("h1", "h2"):
        print("login", host, json.dumps(login(host))[:160], flush=True)
    trials = TRIALS[:3] if quick else TRIALS
    results = [run_trial(i + 1, *t) for i, t in enumerate(trials)]
    legit = legit_window(60 if quick else 180)
    resources = resource_snapshot(30)
    json.dump({"trials": results, "legit": legit, "resources": resources},
              open(os.path.join(out_dir, "raw.json"), "w"), indent=1,
              ensure_ascii=False)
    with open(os.path.join(out_dir, "trials.csv"), "w") as handle:
        keys = ["index", "attacker", "kind", "nominal_pps", "peak_pps",
                "detected", "detection_s", "decision_ms", "apply_ms",
                "effect_s", "start_to_mitigated_s", "action", "severity",
                "attribution_ok", "probe_loss", "recovery_after_apply_s"]
        handle.write(",".join(keys) + "\n")
        for r in results:
            handle.write(",".join(json.dumps(r[k], ensure_ascii=False)
                                  for k in keys) + "\n")
    print("resultados en", out_dir)


if __name__ == "__main__":
    main()
