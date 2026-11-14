# Clientes RADIUS (plantilla): el IAM vive en SRV-2/3 y llega al IdP
# primario (SRV-1) por la red de datos 10.0.0.0/24; en las réplicas de
# SRV-2/3 también puede entrar desde la red de Compose local.
# {{ radius_secret }} se reemplaza con RADIUS_SECRET del .env al
# desplegar (rol platform); el archivo generado (clients.conf) está
# ignorado por git. La imagen oficial no genera clientes por entorno:
# sin este archivo, el IAM no es cliente y FreeRADIUS descarta en
# silencio (verificado en el slice).
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    proto = *
    limit {
        max_connections = 16
        lifetime = 0
        idle_timeout = 900
    }
}

client campus_datos {
    ipaddr = 10.0.0.0/24
    secret = {{ radius_secret }}
    proto = udp
    limit {
        max_connections = 16
        lifetime = 0
        idle_timeout = 900
    }
}

client campus_iam {
    ipaddr = 172.18.0.0/16
    secret = {{ radius_secret }}
    proto = udp
    limit {
        max_connections = 16
        lifetime = 0
        idle_timeout = 900
    }
}
