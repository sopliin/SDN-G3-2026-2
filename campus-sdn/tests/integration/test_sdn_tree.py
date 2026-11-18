"""Pruebas del agente del árbol generador SDN (deploy/scripts/sdn_tree.py).

La lógica pura (árbol, asignación de VLAN, orden de aplicación) se prueba
aquí sin tocar el slice; el failover real se verifica en el runbook 05.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "deploy" / "scripts"))
import sdn_tree  # noqa: E402

# Las diez aristas físicas del slice como pares (dpid, puerto) canónicos.
EDGES = [
    ((1, 4), (4, 4)),  # SW1.ens7  <-> SW4.ens7   (árbol)
    ((1, 5), (4, 5)),  # SW1.ens8  <-> SW4.ens8   (redundante)
    ((1, 6), (2, 1)),  # SW1.ens9  <-> SW2.ens4   (árbol)
    ((1, 7), (5, 1)),  # SW1.ens10 <-> SW5.ens4   (redundante)
    ((2, 2), (4, 6)),  # SW2.ens5  <-> SW4.ens9   (redundante)
    ((2, 3), (3, 1)),  # SW2.ens6  <-> SW3.ens4   (árbol)
    ((2, 4), (6, 1)),  # SW2.ens7  <-> SW6.ens4   (redundante)
    ((3, 2), (5, 3)),  # SW3.ens5  <-> SW5.ens6   (redundante)
    ((4, 7), (5, 2)),  # SW4.ens10 <-> SW5.ens5   (árbol)
    ((5, 4), (6, 2)),  # SW5.ens7  <-> SW6.ens5   (árbol)
]

PREFERRED = {
    ((1, 4), (4, 4)),
    ((1, 6), (2, 1)),
    ((2, 3), (3, 1)),
    ((4, 7), (5, 2)),
    ((5, 4), (6, 2)),
}

BACKUP_2_3 = ((3, 2), (5, 3))  # respaldo que reconecta SW3 cuando cae 2-3


def raw_links(edges=EDGES, drop=(), inactive=()):
    """Genera /onos/v1/links con ambas direcciones ACTIVAS (o según toque)."""
    out = []
    for edge in edges:
        if edge in drop:
            continue
        for src, dst in (edge, edge[::-1]):
            state = "INACTIVE" if edge in inactive else "ACTIVE"
            out.append({
                "src": {"device": f"of:{src[0]:016x}", "port": str(src[1])},
                "dst": {"device": f"of:{dst[0]:016x}", "port": str(dst[1])},
                "type": "INDIRECT",
                "state": state,
            })
    return out


def env(edges=EDGES, drop=(), dpid=1):
    return {
        "endpoints": ["http://127.0.0.1:8181"],
        "user": "karaf",
        "password": "karaf",
        "bridge": "br0",
        "dpid": dpid,
        "preferred": sdn_tree.preferred_edges_from_env(json.dumps(
            [[list(a), list(b)] for a, b in PREFERRED])),
        "state_file": "/tmp/tree_ports_test.json",
    }


def tree_of(edges=EDGES, drop=()):
    return sdn_tree.spanning_tree(sdn_tree.active_edges(raw_links(edges, drop)),
                                  PREFERRED)


def test_preferred_tree_when_healthy():
    assert tree_of() == PREFERRED


def test_tree_connects_all_six_switches():
    tree = tree_of()
    assert len(tree) == 5
    nodos = {n for edge in tree for n in (edge[0][0], edge[1][0])}
    assert nodos == {1, 2, 3, 4, 5, 6}


def test_link_2_3_down_reconnects_via_backup():
    tree = tree_of(drop={((2, 3), (3, 1))})
    assert tree == (PREFERRED - {((2, 3), (3, 1))}) | {BACKUP_2_3}


def test_recovery_restores_preferred_tree():
    assert tree_of() == PREFERRED


def test_determinism_against_shuffled_input():
    import random
    random.seed(42)
    for _ in range(20):
        edges = EDGES[:]
        random.shuffle(edges)
        assert tree_of(edges=edges) == PREFERRED
    caidas = EDGES[:]
    random.shuffle(caidas)
    assert (tree_of(edges=caidas, drop={((2, 3), (3, 1))})
            == (PREFERRED - {((2, 3), (3, 1))}) | {BACKUP_2_3})


def test_active_edge_requires_both_directions():
    links = raw_links(inactive={((2, 3), (3, 1))})
    active = sdn_tree.active_edges(links)
    assert ((2, 3), (3, 1)) not in active
    assert ((1, 6), (2, 1)) in active
    # una sola dirección presente tampoco basta
    solo_una = [l for l in links if l["state"] == "ACTIVE"][:1]
    assert not sdn_tree.active_edges(solo_una)


def test_vlan_assignment_with_broken_link():
    tree = tree_of(drop={((2, 3), (3, 1))})
    managed = {port for edge in EDGES for dpid, port in edge if dpid == 2}
    deseado = sdn_tree.desired_ports(2, tree, managed)
    assert deseado[3] == "block"      # SW2.ens6: enlace caído, fuera de datos
    assert deseado[1] == "data"       # SW2.ens4: sigue en el árbol
    managed5 = {port for edge in EDGES for dpid, port in edge if dpid == 5}
    deseado5 = sdn_tree.desired_ports(5, tree, managed5)
    assert deseado5[3] == "data"      # SW5.ens6: respaldo incorporado al árbol
    assert deseado5[1] == "block"     # SW5.ens4: redundante sigue bloqueado


def test_apply_blocks_before_enabling():
    # Recuperación del enlace 2-3: hay que bloquear el respaldo (5:3) antes
    # de volver a habilitar el puerto del árbol (2:3) para no formar un
    # bucle temporal con dos caminos activos.
    current = {1: "data", 2: "data", 3: "block", 4: "data"}
    desired = {1: "data", 2: "data", 3: "data", 4: "block"}
    orden = []

    def set_vlan(port, state):
        orden.append((port, state))

    assert sdn_tree.apply_plan(current, desired, set_vlan)
    assert orden == [(4, "block"), (3, "data")]


def test_no_changes_applies_nothing():
    current = {1: "data", 2: "block"}
    assert not sdn_tree.apply_plan(current, dict(current), lambda p, s: None)


def test_current_vlan_reading():
    lecturas = {
        "ens4": "10\n[10, 20, 30]\n",
        "ens5": "99\n[99]\n",
        "ens6": "10\n[]\n",
        "ens7": "20\n[20]\n",
    }
    actual = sdn_tree.read_current([1, 2, 3, 4], "br0",
                                   get_vlan=lambda i: lecturas[i])
    assert actual == {1: "data", 2: "block", 3: "otra", 4: "otra"}


def test_managed_ports_memory(tmp_path):
    path = tmp_path / "tree_ports.json"
    sdn_tree.save_state(str(path), {3, 6})
    assert sdn_tree.load_state(str(path)) == {3, 6}
    assert sdn_tree.load_state(str(tmp_path / "no_existe.json")) == set()


def test_port_without_edge_stays_blocked():
    # Si ONOS purgara el enlace caído por completo, la memoria de puertos
    # gestionados lo mantiene bloqueado en lugar de devolverlo a datos.
    links = raw_links(drop={((2, 3), (3, 1))})
    presence = sdn_tree.edge_presence(links)
    vistos = {port for edge in presence for dpid, port in edge if dpid == 3}
    assert vistos == {2}  # purgado: sw3 solo aparece ya por su respaldo
    memoria = {port for edge in EDGES for dpid, port in edge if dpid == 3}
    gestionados = vistos | memoria
    assert 1 in gestionados
    deseado = sdn_tree.desired_ports(3, tree_of(drop={((2, 3), (3, 1))}),
                                     gestionados)
    assert deseado[1] == "block"  # sin arista visible y sin árbol: bloqueado
    assert deseado[2] == "data"   # el respaldo está en el árbol nuevo
