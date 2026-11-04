#!/usr/bin/env bash
# Instalación nativa del corte de campus-sdn en la VM controller de un slice
# con poco disco y RAM (sin imágenes Docker propias). ONOS sigue en su
# contenedor; RabbitMQ, OpenLDAP y FreeRADIUS van como paquetes del sistema
# y los servicios Python en un venv bajo /opt/campus-sdn.
#
# uso: sudo deploy/native/install_controller.sh      (desde /opt/campus-sdn)
# Idempotente: los secretos se generan una sola vez en /etc/campus-sdn/env.
set -euo pipefail

REPO=/opt/campus-sdn
ENV_FILE=/etc/campus-sdn/env
FR=/etc/freeradius/3.0
BACKUP=/root/campus-sdn-backup

mkdir -p /etc/campus-sdn "$BACKUP"

# --- secretos (una sola vez; nunca entran al repositorio)
if [[ ! -f "$ENV_FILE" ]]; then
  gen() { openssl rand -hex 12; }
  cat > "$ENV_FILE" <<EOF
RABBITMQ_USER=plataforma
RABBITMQ_PASSWORD=$(gen)
LDAP_ADMIN_PASSWORD=$(gen)
RADIUS_SECRET=$(gen)
EOF
  chmod 640 "$ENV_FILE"; chgrp ubuntu "$ENV_FILE"
  echo "secretos generados en $ENV_FILE"
fi
# Token de arranque del IAM: crea la primera cuenta de operador (P24)
grep -q '^IAM_BOOTSTRAP_TOKEN=' "$ENV_FILE" || \
  echo "IAM_BOOTSTRAP_TOKEN=$(openssl rand -hex 16)" >> "$ENV_FILE"
# shellcheck disable=SC1090
source "$ENV_FILE"

# --- RabbitMQ: usuario de la plataforma
if ! rabbitmqctl list_users -q | grep -q "^${RABBITMQ_USER}\b"; then
  rabbitmqctl add_user "$RABBITMQ_USER" "$RABBITMQ_PASSWORD" >/dev/null
  rabbitmqctl set_permissions -p / "$RABBITMQ_USER" ".*" ".*" ".*" >/dev/null
  echo "RabbitMQ: usuario $RABBITMQ_USER creado"
fi

# --- OpenLDAP: dc=campus,dc=local (respaldo previo del árbol existente)
current_suffix=$(ldapsearch -Q -LLL -Y EXTERNAL -H ldapi:/// -b cn=config \
  "(olcSuffix=*)" olcSuffix 2>/dev/null | awk '/^olcSuffix/{print $2}')
if [[ "$current_suffix" != "dc=campus,dc=local" ]]; then
  slapcat > "$BACKUP/slapd-${current_suffix:-none}-$(date +%s).ldif" || true
  debconf-set-selections <<EOF
slapd slapd/no_configuration boolean false
slapd slapd/domain string campus.local
slapd shared/organization string campus-sdn
slapd slapd/password1 password $LDAP_ADMIN_PASSWORD
slapd slapd/password2 password $LDAP_ADMIN_PASSWORD
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
EOF
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive slapd
  echo "OpenLDAP: reconfigurado a dc=campus,dc=local (respaldo en $BACKUP)"
fi
if ! ldapsearch -x -LLL -H ldap://127.0.0.1 -b ou=people,dc=campus,dc=local \
     -s base dn >/dev/null 2>&1; then
  grep -v '^#' "$REPO/deploy/ldap/seed-users.ldif" | ldapadd -x -H ldap://127.0.0.1 \
    -D cn=admin,dc=campus,dc=local -w "$LDAP_ADMIN_PASSWORD" >/dev/null
  echo "OpenLDAP: semilla de la comunidad cargada"
fi

# --- FreeRADIUS: módulo LDAP, sitio y un único cliente (el IAM, en esta VM)
if [[ ! -f "$BACKUP/freeradius-orig.tgz" ]]; then
  tar czf "$BACKUP/freeradius-orig.tgz" -C /etc freeradius
fi
sed -e "s|'openldap'|'127.0.0.1'|" -e "s|__LDAP_PASSWORD__|$LDAP_ADMIN_PASSWORD|" \
  "$REPO/deploy/radius/mods-ldap.tpl" > "$FR/mods-available/ldap"
ln -sf ../mods-available/ldap "$FR/mods-enabled/ldap"
cp "$REPO/deploy/radius/site-default" "$FR/sites-available/default"
rm -f "$FR/sites-enabled/inner-tunnel" "$FR/mods-enabled/eap"   # el IAM usa PAP
cat > "$FR/clients.conf" <<EOF
# Cliente único: el IAM, que corre en esta misma VM (127.0.0.1)
client campus_iam {
    ipaddr = 127.0.0.1
    secret = $RADIUS_SECRET
    proto = udp
}
EOF
chown -R freerad:freerad "$FR/mods-available/ldap" "$FR/clients.conf" "$FR/sites-available/default"
chmod 640 "$FR/mods-available/ldap" "$FR/clients.conf"
freeradius -C -X >/tmp/freeradius-check.log 2>&1 || { tail -20 /tmp/freeradius-check.log; exit 1; }
systemctl restart freeradius
echo "FreeRADIUS: configurado contra LDAP local"

# --- servicios Python: un proceso con todos los servidores (ver run_services.py)
install -m 644 "$REPO/deploy/native/campus-sdn.service" /etc/systemd/system/campus-sdn.service
systemctl daemon-reload
systemctl enable campus-sdn >/dev/null 2>&1
systemctl restart campus-sdn
echo "campus-sdn: servicio arrancado (journalctl -u campus-sdn -f)"
