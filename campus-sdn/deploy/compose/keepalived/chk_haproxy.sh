#!/bin/sh
# Chequeo de HAProxy para keepalived. El contenedor comparte el espacio
# de PID del host (pid: host en el Compose), así que killall ve el
# proceso real de HAProxy. Sale 0 si está vivo y 1 si no.
exec /usr/bin/killall -0 haproxy
