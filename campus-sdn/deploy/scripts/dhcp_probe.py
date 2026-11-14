#!/usr/bin/env python3
"""Sonda DHCP del perfil BASE: DISCOVER en difusión y espera el OFFER.

Se ejecuta como root en el host de pruebas (puerto 68) sobre la interfaz
de datos. Usa la MAC real de la interfaz para que dnsmasq aplique la
reserva. La interfaz conserva su dirección estática: sin dirección, la
respuesta de difusión se descarta por rp_filter.

Uso: sudo python3 dhcp_probe.py [interfaz]   (por defecto ens4)
Sale 0 al recibir el OFFER e imprime el servidor y la dirección.
"""
import socket
import struct
import sys

IFACE = sys.argv[1] if len(sys.argv) > 1 else "ens4"
mac = bytes.fromhex(open(f"/sys/class/net/{IFACE}/address").read().strip().replace(":", ""))

xid = 0x12345678
header = struct.pack(
    "!BBBBIHH4s4s4s4s16s64s128s",
    1, 1, 6, 0, xid, 0, 0x8000,
    b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
    mac.ljust(16, b"\x00"), b"\x00" * 64, b"\x00" * 128,
)
discover = header + b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\xff"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Sin dirección en la interfaz no hay ruta: el DISCOVER se iría por la
# ruta por defecto (la NIC de gestión). Se fija la interfaz de datos.
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode())
sock.bind(("0.0.0.0", 68))
sock.settimeout(3)

for attempt in range(1, 4):
    sock.sendto(discover, ("255.255.255.255", 67))
    try:
        data, addr = sock.recvfrom(2048)
    except socket.timeout:
        print(f"intento {attempt}: sin respuesta")
        continue
    print(f"intento {attempt}: respuesta de {addr[0]} "
          f"yiaddr={socket.inet_ntoa(data[16:20])} "
          f"xid_ok={data[4:8] == struct.pack('!I', xid)}")
    sys.exit(0)
sys.exit(1)
