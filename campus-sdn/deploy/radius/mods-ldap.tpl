# Módulo LDAP de FreeRADIUS (plantilla): el IdP simulado del prototipo
# (F-03 §2) — FreeRADIUS verifica contra OpenLDAP, como un eduroam real.
# {{ ldap_admin_password }} se reemplaza con LDAP_ADMIN_PASSWORD del .env
# al desplegar (rol platform); el archivo generado (mods-ldap) está
# ignorado por git.
ldap {
    server = 'openldap'
    port = 389
    identity = 'cn=admin,dc=campus,dc=local'
    password = '{{ ldap_admin_password }}'
    base_dn = 'dc=campus,dc=local'

    update {
        control:Password-With-Header += 'userPassword'
    }

    user {
        base_dn = 'ou=people,dc=campus,dc=local'
        filter = "{% raw %}(uid=%{%{Stripped-User-Name}:-%{User-Name}}){% endraw %}"
        scope = 'sub'
    }

    options {
        ldap_debug = 0x0028
        chase_referrals = no
        rebind = yes
        res_timeout = 5
        srv_timelimit = 5
        net_timeout = 5
        idle = 60
    }

    tls {
    }

    pool {
        start = 2
        min = 1
        max = 3
        spare = 2
        uses = 0
        retry_delay = 30
        lifetime = 0
        idle_timeout = 60
    }
}
