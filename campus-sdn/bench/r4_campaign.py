#!/usr/bin/env python3
"""Campaña de R4 en el slice de 14 VMs: ataques DDoS reales y cadena medida.

Escenario: h4 hace de servidor web de la intranet (víctima, en SW6,
declarado con confianza 60 en el esqueleto). Los atacantes son equipos
académicos con sesión (h1 y h2, PC1/PC2 en SW3): el ataque recorre el
árbol SW3→SW2→SW1→SW4→SW5→SW6 y la mitigación debe instalarse en el
puerto de ingreso del atacante, en SW3. El cliente legítimo es el otro
host académico o, si ambos atacan, el gateway (servidor declarado).

Por cada ensayo se mide, con las marcas de la auditoría (ms) y los
contadores del monitor y de la víctima:

- tiempo de detección   : inicio del ataque (reloj del atacante, NTP)
                          → AnomalyDetected
- tiempo de decisión    : AnomalyDetected → MitigationRequired
- tiempo de aplicación  : MitigationRequired → MitigationApplied (I2/ONOS)
- tiempo de efecto      : MitigationApplied → tasa en la víctima ≤ objetivo
- atribución            : ¿los orígenes son exactamente los atacantes?
- daño colateral        : pérdida y RTT del cliente legítimo
- recuperación          : la regla de mitigación desaparece sola (TTL)

Además, una ventana de solo tráfico legítimo (falsos positivos) y el
consumo de CPU/RAM del plano de control y de los switches durante un
ataque. Todo queda en bench/results/<fecha>-r4/.

Precondiciones (docs/pruebas/07-campanas-en-el-slice.md §2): cadena R4
cableada en una sola instancia, h4 en SKELETON_SERVERS, hosts aprendidos
por ONOS y clave SSH en las VMs.

uso: SLICE_SUDO_PASSWORD=… python3 bench/r4_campaign.py [--quick]
"""

import base64
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import slice as s  # noqa: E402

VICTIM = "h4"
# Debe coincidir con RATE_LIMIT_PPS de Políticas (deploy/compose/s3-services.yml).
RATE_LIMIT_PPS = int(os.environ.get("BENCH_RATE_LIMIT_PPS", "1000"))
# Debe coincidir con MITIGATION_TTL_S: cada ensayo espera a que la regla
# expire sola antes del siguiente (con 300 s la campaña dura ~1 h).
MITIGATION_TTL_S = int(os.environ.get("BENCH_MITIGATION_TTL_S", "300"))
ATTACK_S = 12
SETTLE_S = 8                  # reposo tras el ataque (rearmado de la detección)
ACADEMIC = {"h1": 1, "h2": 2}  # host → índice de la cuenta USR-000N

UDP = "--flood --udp -p 9999 -d 64"
SYN = "--flood -S -p 80"
ICMP = "--flood -1 -d 64"

# (atacantes, cliente legítimo, tipo, opciones de hping3, tasa nominal)
TRIALS = [
    (["h1"], "h2", "udp-flood", UDP, "max"),
    (["h2"], "h1", "syn-flood", SYN, "max"),
    (["h1"], "h2", "icmp-flood", ICMP, "max"),
    (["h1", "h2"], "gw", "udp-flood distribuido", UDP, "max"),
    (["h2"], "h1", "udp-5k", "-i u200 --udp -p 9999 -d 64", "5000"),
    (["h1"], "h2", "syn-flood", SYN, "max"),
    (["h2"], "h1", "udp-2k", "-i u500 --udp -p 9999 -d 64", "2000"),
    (["h1", "h2"], "gw", "syn-flood distribuido", SYN, "max"),
    (["h1"], "h2", "udp-flood-1200B", "--flood --udp -p 9999 -d 1200", "max"),
    (["h2"], "h1", "icmp-flood", ICMP, "max"),
    # Por debajo del piso de detección: se espera que NO se detecte —
    # documenta la sensibilidad, no cuenta como ataque fallido.
    (["h2"], "h1", "udp-500 (bajo umbral)", "-i u2000 --udp -p 9999 -d 64", "500"),
]

VICTIM_SAMPLER = (
    # rx_packets de la NIC de datos de la víctima cada 50 ms: el efecto
    # real en el plano de datos, sin el retardo de las estadísticas.
    "import time,sys\n"
    "f='/sys/class/net/%s/statistics/rx_packets'\n"
    "end=time.time()+float(sys.argv[1])\n"
    "while time.time()<end:\n"
    "  print(time.time(),open(f).read().strip(),flush=True); time.sleep(0.05)\n")


def academic_session(host):
    """Sesión fresca por el portal desde el propio host."""
    user, password = s.community_account(ACADEMIC[host])
    reply = s.portal_login(host, {"population": "university",
                                  "username": user, "password": password})
    network = reply["data"].get("network", {})
    print(f"login {host} ({user}): {reply['status']} red={network.get('status')}",
          flush=True)
    if reply["status"] != 200 or network.get("status") != "applied":
        raise SystemExit(f"{host}: el login no dejó regla de sesión: {reply['data']}")
    return reply["data"]["session"]


def mitigation_flows():
    return [f for sw in s.DPIDS for f in s.flows(sw, 1000)]


def wait_mitigations_gone(limit_s=None):
    limit_s = limit_s or MITIGATION_TTL_S + 60
    started = time.time()
    while time.time() - started < limit_s:
        if not mitigation_flows():
            return time.time()
        time.sleep(2)
    return None


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


def spawn_python(node, code, args, sudo=False):
    encoded = base64.b64encode(code.encode()).decode()
    path = f"/tmp/bench-{os.getpid()}-{node}.py"
    return s.spawn(node, f"echo {encoded} | base64 -d > {path}; python3 {path} "
                   + " ".join(str(a) for a in args), sudo=sudo)


def attack_chain(events, first):
    """AnomalyDetected → IncidentOpened → Mitigation* del mismo incidente."""
    chain = {"AnomalyDetected": first}
    incident = next((e for e in events if e["type"] == "IncidentOpened"
                     and s.iso_to_epoch(e["timestamp"])
                     >= s.iso_to_epoch(first["timestamp"]) - 0.001), None)
    if incident:
        chain["IncidentOpened"] = incident
        inc_id = incident["payload"]["incident"]
        for kind in ("MitigationRequired", "MitigationApplied",
                     "MitigationVerified"):
            found = next((e for e in events if e["type"] == kind
                          and e["payload"].get("incident") == inc_id), None)
            if found:
                chain[kind] = found
    return chain


def run_trial(index, attackers, probe, kind, options, nominal):
    victim = s.HOSTS[VICTIM]
    # Cada ensayo arranca sin mitigaciones vigentes: un meter del ensayo
    # anterior limitaría al atacante y falsearía el pico.
    if mitigation_flows() and not wait_mitigations_gone():
        raise SystemExit("hay reglas de mitigación que no expiran; revisar el TTL")
    print(f"== ensayo {index}: {'+'.join(attackers)} → {VICTIM} {kind}", flush=True)
    t_mark = time.time() - 1
    since = s.epoch_to_iso(t_mark)
    victim_proc = spawn_python(VICTIM, VICTIM_SAMPLER % victim["iface"],
                               [ATTACK_S + SETTLE_S + 4])
    probe_proc = s.spawn(probe, f"ping -i 0.2 -w {ATTACK_S + 6} {victim['ip']}",
                         sudo=True)
    time.sleep(2)
    command = ("date +%s.%N; "
               f"timeout {ATTACK_S} hping3 {options} {victim['ip']} "
               ">/tmp/hping.out 2>&1; date +%s.%N; tail -3 /tmp/hping.out")
    procs = {a: s.spawn(a, command, sudo=True) for a in attackers}
    outputs = {a: p.communicate(timeout=ATTACK_S + 60)[0] for a, p in procs.items()}
    starts, ends, tails = [], [], {}
    for attacker, out in outputs.items():
        lines = out.split("\n")
        starts.append(float(lines[0]))
        ends.append(float(lines[1]))
        tails[attacker] = "\n".join(lines[2:])
    t_start, t_end = min(starts), max(ends)
    probe_out, _ = probe_proc.communicate(timeout=60)
    time.sleep(SETTLE_S)
    victim_raw, _ = victim_proc.communicate(timeout=60)
    series = victim_series(victim_raw)

    events = s.audit_events(since, types={
        "AnomalyDetected", "IncidentOpened", "MitigationRequired",
        "MitigationApplied", "MitigationVerified"})
    detected = [e for e in events if e["type"] == "AnomalyDetected"
                and e["payload"]["target"]["ip"] == victim["ip"]]
    first = detected[0] if detected else None
    chain = attack_chain(events, first) if first else {}
    metrics = s.monitor_metrics(victim["ip"], t_mark)

    def at(name):
        return s.iso_to_epoch(chain[name]["timestamp"]) if name in chain else None

    t_detect, t_required, t_applied = (at("AnomalyDetected"),
                                       at("MitigationRequired"),
                                       at("MitigationApplied"))
    required = chain.get("MitigationRequired", {}).get("payload", {})
    action = required.get("action")
    objective = RATE_LIMIT_PPS * 1.5 * len(attackers) if action == "RATE_LIMIT" else 50
    t_effect = None
    if t_applied:
        t_effect = next((m["at"] for m in metrics
                         if m["at"] >= t_applied and m["pps"] <= objective), None)
    during = [m["pps"] for m in metrics if t_start <= m["at"] <= t_end]
    # En la víctima: inicio real (primera muestra > 1000 pps), pico y primer
    # instante tras MitigationApplied con la tasa en objetivo durante 3
    # muestras seguidas (150 ms).
    onset = next((t for t, pps in series if pps > 1000 and t >= t_start - 1), None)
    victim_peak = max((pps for _, pps in series), default=0.0)
    victim_effect = None
    if t_applied:
        tail = [(t, pps) for t, pps in series if t >= t_applied]
        for i in range(len(tail) - 2):
            if all(pps <= objective for _, pps in tail[i:i + 3]):
                victim_effect = tail[i][0]
                break
    victim_after = [pps for t, pps in series
                    if victim_effect and victim_effect <= t <= t_end]
    origins = first["payload"].get("origins", []) if first else []
    attributed = sorted(o["mac"].lower() for o in origins)
    expected = sorted(s.HOSTS[a]["mac"] for a in attackers)
    # Dónde quedó la mitigación: debe ser SW3 (ingreso de h1/h2).
    mitigated_at = sorted({sw for sw in s.DPIDS for _ in s.flows(sw, 1000)})
    loss = next((l for l in probe_out.split("\n") if "packet loss" in l), "")
    rtt = next((l for l in probe_out.split("\n") if "rtt" in l), "")
    # La espera depende de las reglas instaladas, no del evento: si
    # MitigationApplied no llegara al bus, igual se mide la expiración.
    t_gone = wait_mitigations_gone() if (t_applied or mitigated_at) else None
    t_installed = t_applied or t_required

    def secs(a, b, scale=1.0, digits=3):
        return round((a - b) * scale, digits) if a and b else None

    result = {
        "index": index, "attackers": attackers, "probe": probe, "kind": kind,
        "nominal_pps": nominal, "attack_start": t_start, "attack_end": t_end,
        "peak_pps": max(during) if during else 0.0,
        "detected": bool(first),
        "detection_s": secs(t_detect, t_start),
        "decision_ms": secs(t_required, t_detect, 1000, 1),
        "apply_ms": secs(t_applied, t_required, 1000, 1),
        "effect_s": secs(t_effect, t_applied),
        "start_to_mitigated_s": secs(t_effect, t_start),
        "victim_onset_lag_s": secs(onset, t_start),
        "victim_peak_pps": round(victim_peak, 1),
        "victim_effect_after_apply_s": secs(victim_effect, t_applied),
        "victim_start_to_mitigated_s": secs(victim_effect, t_start),
        "victim_pps_mitigated_mean": round(statistics.mean(victim_after), 1)
        if victim_after else None,
        "victim_series": series,
        "action": action,
        "severity": first["payload"].get("proposed_severity") if first else None,
        "attributed": attributed,
        "attribution_ok": attributed == expected,
        "mitigated_at": mitigated_at,
        "verified": chain.get("MitigationVerified", {}).get("payload"),
        "probe_loss": loss.strip(), "probe_rtt": rtt.strip(),
        "recovery_after_apply_s": secs(t_gone, t_installed, 1, 1),
        "chain": chain, "metrics": metrics, "hping_tail": tails,
    }
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("chain", "metrics", "victim_series")},
                     ensure_ascii=False), flush=True)
    return result


SAMPLER = (
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

# Procesos por VM (los contenedores se ven en /proc del anfitrión: el
# nombre es el módulo de uvicorn). ONOS es el java de Karaf.
RESOURCE_TARGETS = {
    "srv1": "org.apache.karaf,services.controller_adapter",
    "srv2": "org.apache.karaf,services.monitor,services.detection,"
            "services.incidents,services.policies,services.audit,"
            "services.controller_adapter",
    "srv3": "org.apache.karaf",
    "sw3": "ovs-vswitchd", "sw1": "ovs-vswitchd", "sw6": "ovs-vswitchd",
}


def resource_snapshot(duration_s, attacker="h1"):
    """CPU (% de un núcleo) y RSS de los procesos clave: 8 s de reposo y
    luego un ataque UDP sostenido."""
    procs = {node: spawn_python(node, SAMPLER, [names, duration_s], sudo=True)
             for node, names in RESOURCE_TARGETS.items()}
    time.sleep(8)
    s.ssh(attacker, f"timeout {duration_s - 16} hping3 {UDP} "
          f"{s.HOSTS[VICTIM]['ip']} >/dev/null 2>&1", sudo=True,
          timeout=duration_s + 30)
    rows = {node: proc.communicate(timeout=duration_s + 30)[0].strip().split("\n")
            for node, proc in procs.items()}
    flow_counts = {sw: len(s.flows(sw)) for sw in s.DPIDS}
    return {"samples": rows, "flows_per_switch": flow_counts,
            "attack_starts_after_s": 8}


def legit_window(duration_s):
    """Solo tráfico legítimo hacia h4: HTTP, ping e iperf3 limitado."""
    print(f"== ventana legítima de {duration_s} s", flush=True)
    since = s.epoch_to_iso(time.time())
    ip = s.HOSTS[VICTIM]["ip"]
    clients = [
        s.spawn("h1", f"end=$((SECONDS+{duration_s})); n=0; while [ $SECONDS -lt $end ]; "
                f"do curl -s -o /dev/null http://{ip}/ && n=$((n+1)); sleep 0.5; done; echo http=$n"),
        s.spawn("gw", f"ping -i 0.5 -w {duration_s} {ip} | tail -2"),
        s.spawn("h2", f"end=$((SECONDS+{duration_s})); while [ $SECONDS -lt $end ]; "
                f"do iperf3 -c {ip} -b 4M -t 10 2>&1 | grep -E 'sender|receiver'; sleep 5; done"),
    ]
    outputs = [c.communicate(timeout=duration_s + 60)[0] for c in clients]
    time.sleep(3)
    alerts = s.audit_events(since, types={"AnomalyDetected"})
    metrics = s.monitor_metrics(ip, s.iso_to_epoch(since))
    pps = [m["pps"] for m in metrics]
    return {"duration_s": duration_s, "alerts": alerts,
            "false_positives": len(alerts), "client_output": outputs,
            "pps_mean": round(statistics.mean(pps), 1) if pps else 0,
            "pps_max": max(pps) if pps else 0, "samples": len(pps)}


def victim_services(start):
    """Servidor web e iperf3 en la víctima (h4) durante la campaña.
    Matar y arrancar van en llamadas separadas: si van juntas, pkill -f
    encuentra el patrón en su propia línea de comandos y se mata."""
    s.ssh(VICTIM, "pkill -f '[h]ttp.server 80' ; pkill -x iperf3", sudo=True)
    if start:
        s.ssh(VICTIM, "cd /tmp && (setsid nohup python3 -m http.server 80 "
              ">/dev/null 2>&1 &) ; iperf3 -s -D", sudo=True)


def preconditions():
    """Lo que la campaña necesita del slice; falla con el motivo exacto."""
    s.preflight(["gw", "h1", "h2", "h4"] + list(RESOURCE_TARGETS))
    problems = []
    known = {h["mac"].lower() for h in s.onos("/hosts").get("hosts", [])}
    for host in ("h1", "h2", "h4", "gw"):
        if s.HOSTS[host]["mac"] not in known:
            problems.append(f"ONOS no conoce a {host} (arping desde el host)")
    victim_trust = [f for f in s.flows("sw6", 60)
                    if s.criterion(f, "ETH_SRC", "mac") == s.HOSTS[VICTIM]["mac"]]
    if not victim_trust:
        problems.append("h4 sin confianza 60 en SW6 (SKELETON_SERVERS)")
    samplers = [i for i in s.INSTANCES
                if s.http("gw", "GET", f"http://{i}:8003/metrics")["data"].get("metrics")]
    if len(samplers) != 1:
        problems.append(f"se espera un solo monitor muestreando; hay {len(samplers)}")
    tools = s.ssh("h1", "command -v hping3 iperf3")[1].split()
    if len(tools) < 2:
        problems.append("faltan hping3/iperf3 en los hosts")
    if problems:
        raise SystemExit("precondiciones de R4 sin cumplir:\n- " + "\n- ".join(problems))


def main():
    if not s.SUDO_PASSWORD:
        sys.exit("definir SLICE_SUDO_PASSWORD")
    quick = "--quick" in sys.argv
    preconditions()
    out_dir = s.results_dir("r4")
    sessions = {host: academic_session(host) for host in ACADEMIC}
    victim_services(start=True)
    try:
        trials = TRIALS[:3] if quick else TRIALS
        results = [run_trial(i + 1, *t) for i, t in enumerate(trials)]
        legit = legit_window(60 if quick else 180)
        resources = resource_snapshot(30)
    finally:
        victim_services(start=False)
        for host, token in sessions.items():
            s.portal_logout(host, token)
    json.dump({"victim": VICTIM, "rate_limit_pps": RATE_LIMIT_PPS,
               "mitigation_ttl_s": MITIGATION_TTL_S,
               "trials": results, "legit": legit, "resources": resources},
              open(os.path.join(out_dir, "raw.json"), "w"), indent=1,
              ensure_ascii=False)
    with open(os.path.join(out_dir, "trials.csv"), "w") as handle:
        keys = ["index", "attackers", "kind", "nominal_pps", "peak_pps",
                "detected", "detection_s", "decision_ms", "apply_ms",
                "effect_s", "start_to_mitigated_s", "action", "severity",
                "attribution_ok", "mitigated_at", "probe_loss",
                "recovery_after_apply_s"]
        handle.write(",".join(keys) + "\n")
        for r in results:
            handle.write(",".join(json.dumps(r[k], ensure_ascii=False)
                                  for k in keys) + "\n")
    print("resultados en", out_dir)


if __name__ == "__main__":
    main()
