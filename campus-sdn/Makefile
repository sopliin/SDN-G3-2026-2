# campus-sdn — puerta única de operación.
# Los objetivos de imágenes llaman a deploy/images/; el resto, a Ansible.
# ANSIBLE_ROLES_PATH evita depender de ansible.cfg (que solo aplica si se
# ejecuta desde deploy/ansible/); el Makefile siempre corre desde la raíz.
# -b activa become (sudo) sin depender de ansible.cfg; la contraseña de
# sudo viaja por ANSIBLE_BECOME_PASS en tiempo de ejecución:
#   ANSIBLE_BECOME_PASS=<clave> make deploy TAGS=...
# (este Ansible no honra ANSIBLE_BECOME_PASSWORD; solo _PASS).

export ANSIBLE_ROLES_PATH := deploy/ansible/roles

ANSIBLE := ansible-playbook -b -i deploy/ansible/inventory/slice.yml
SITE := deploy/ansible/playbooks/site.yml
TAGS ?=
IMAGES ?=

.PHONY: help images-pull images-verify images-save images-load \
        ping deploy up down status venv test test-ip7 verify native-sync native-install \
        native-skeleton native-test dhcp-probe slice-check env-pull r4-campaign-on r4-campaign-off bench-r4 bench-r1r2 \
        ldap-user ldap-list ldap-delete ldap-passwd operator operator-list

help: ## Muestra los objetivos disponibles
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "} {printf "  %-16s %s\n", $$1, $$2}'

images-pull: ## Descarga las imágenes del lock y fija sus digests
	./deploy/images/pull.sh

images-verify: ## Compara los digests locales con el lock
	./deploy/images/verify.sh

images-save: ## Empaqueta las imágenes en deploy/images/bundles/
	./deploy/images/save.sh

images-load: ## Carga bundles en el demonio local (IMAGES=onos[,rabbitmq])
	./deploy/images/load.sh $(IMAGES)

# Las VMs son x86_64: una laptop arm64 (Apple Silicon) construiría imágenes
# que no arrancan en el slice. Se fija la plataforma para cualquier anfitrión.
build: export DOCKER_DEFAULT_PLATFORM := linux/amd64
build: ## Construye las imágenes de los servicios propios (prefijo campus-sdn-) para linux/amd64
	# Los dummy solo satisfacen la interpolación de Compose al parsear el
	# archivo completo; el build no los usa. Los valores reales llegan por
	# .env al levantar.
	RADIUS_SECRET=dummy LDAP_ADMIN_PASSWORD=dummy LDAP_READONLY_PASSWORD=dummy \
	docker compose -p campus-sdn -f deploy/compose/s1-identity.yml build portal iam registry
	GRAFANA_ADMIN_PASSWORD=dummy \
	docker compose -p campus-sdn -f deploy/compose/s2-observability.yml build monitor detection sensor_adapter
	POSTGRES_PASSWORD=dummy \
	docker compose -p campus-sdn -f deploy/compose/s3-response.yml build incidents policies audit
	RABBITMQ_PASSWORD=dummy \
	docker compose -p campus-sdn -f deploy/compose/s4-governance.yml build console
	docker compose -p campus-sdn -f deploy/compose/onos.yml build controller_adapter

ping: ## Conectividad con todas las VMs del inventario
	ansible -i deploy/ansible/inventory/slice.yml all -m ping

deploy: ## Ejecuta site.yml (TAGS=base,images,platform,onos,switches,dataplane,identity,verify)
	$(ANSIBLE) $(if $(TAGS),--tags $(TAGS),) $(SITE)

up: ## Levanta los servicios
	$(ANSIBLE) --tags platform $(SITE)

down: ## Detiene los servicios
	$(ANSIBLE) --tags down $(SITE)

status: ## Salud de contenedores y servicios
	$(ANSIBLE) --tags verify $(SITE)

PYTHON312 ?= python3.12
UNIT_OUT := bench/results/$(shell date +%Y%m%d-%H%M%S)-unit

venv: ## Crea .venv (Python >= 3.12) con las dependencias de servicios y pruebas
	$(PYTHON312) -m venv .venv
	./.venv/bin/pip install -q -e ./services/common pyotp bcrypt pyrad httpx \
	  "psycopg[binary]" ldap3 "uvicorn[standard]" pyyaml pytest pytest-cov

test: ## Pruebas de contrato e integración (requiere .venv)
	./.venv/bin/pytest tests

test-ip7: ## Pruebas unitarias obligatorias R1/R2/R4 + suite: reporte JUnit y cobertura en bench/results/<fecha>-unit/
	mkdir -p $(UNIT_OUT)
	./.venv/bin/pytest tests -v -p no:cacheprovider \
	  --junitxml=$(UNIT_OUT)/junit.xml \
	  --cov=services --cov-report=term --cov-report=html:$(UNIT_OUT)/coverage \
	  2>&1 | tee $(UNIT_OUT)/pytest.txt
	./.venv/bin/pytest tests/unit/test_ip7_r1_authentication.py \
	  tests/unit/test_ip7_r2_authorization.py tests/unit/test_ip7_r4_ddos.py \
	  -v -p no:cacheprovider --junitxml=$(UNIT_OUT)/junit-ip7.xml \
	  --cov=services.iam --cov=sdn_common.authz \
	  --cov=services.controller_adapter --cov=services.monitor \
	  --cov=services.detection --cov=services.policies.main \
	  --cov=services.incidents --cov-branch --cov-report=term-missing \
	  --cov-report=json:$(UNIT_OUT)/coverage-ip7.json \
	  2>&1 | tee $(UNIT_OUT)/pytest-ip7.txt
	./.venv/bin/python tools/function_coverage.py $(UNIT_OUT)/coverage-ip7.json \
	  | tee $(UNIT_OUT)/coverage-ip7-functions.txt
	rm -f .coverage

policyctl: ## CLI de reglas y elevaciones (ARGS="rules list")
	./.venv/bin/python tools/policyctl.py $(ARGS)

# --- Esqueleto BASE del slice de 14 VMs (LLD 06_reglas §3) ---
ONOS_CTRL := ssh -o BatchMode=yes -p 5811 ubuntu@10.20.12.185
SKELETON_PORTAL ?= 10.0.0.10/32
# h4 (10.0.0.104) es el servidor web de la intranet de las campañas (víctima de R4).
SKELETON_SERVERS ?= 10.0.0.11,10.0.0.12,10.0.0.13,10.0.0.1,10.0.0.104
SKELETON_DHCP ?= 10.0.0.1
SKELETON_DNS ?= 10.0.0.1
SWITCH_DPIDS_JSON := {"sw1": "of:0000000000000001", "sw2": "of:0000000000000002", "sw3": "of:0000000000000003", "sw4": "of:0000000000000004", "sw5": "of:0000000000000005", "sw6": "of:0000000000000006"}

skeleton: ## Instala el esqueleto BASE por la API REST de ONOS (srv1)
	scp -q -P 5811 deploy/scripts/install_skeleton.py ubuntu@10.20.12.185:/tmp/
	$(ONOS_CTRL) 'SWITCH_DPIDS='"'"'$(SWITCH_DPIDS_JSON)'"'"' SKELETON_PORTAL=$(SKELETON_PORTAL) SKELETON_SERVERS=$(SKELETON_SERVERS) SKELETON_DHCP=$(SKELETON_DHCP) SKELETON_DNS=$(SKELETON_DNS) python3 /tmp/install_skeleton.py'

# La imagen no trae cliente DHCP; la sonda comprueba la concesión sin
# instalar nada en el host (DISCOVER en difusión, OFFER de vuelta).
PROBE_HOST ?= 10.20.12.185
PROBE_PORT ?= 5801
PROBE_IFACE ?= ens4

dhcp-probe: ## Sonda DHCP desde h1 por la red de datos (pide la clave de sudo)
	scp -q -P $(PROBE_PORT) deploy/scripts/dhcp_probe.py ubuntu@$(PROBE_HOST):/tmp/
	ssh -t -p $(PROBE_PORT) ubuntu@$(PROBE_HOST) 'sudo python3 /tmp/dhcp_probe.py $(PROBE_IFACE)'

# --- Identidades del slice ---
# La comunidad la crea el IdP (simulado con OpenLDAP); los operadores,
# la plataforma por la API del IAM (cadena P24 o bootstrap del primer
# operador). Los invitados se autoregistran.
LDAP_USER ?= USR-1000
LDAP_PASS ?= user_1000
LDAP_NAME ?= Usuario 1000
OPERATOR_USER ?= TI-0028
OPERATOR_PASS ?= operator_0028
OPERATOR_ROLE ?= super_admin
SESSION ?=
BOOTSTRAP_TOKEN := $(shell grep '^IAM_BOOTSTRAP_TOKEN=' deploy/env/.env 2>/dev/null | cut -d= -f2)

ldap-user: ## Crea una cuenta de comunidad en el IdP simulado (LDAP_USER, LDAP_PASS)
	$(ANSIBLE) -e "user=$(LDAP_USER) password=$(LDAP_PASS) name='$(LDAP_NAME)'" \
	  deploy/ansible/playbooks/ldap_user.yml

ldap-list: ## Lista las cuentas de comunidad del IdP simulado
	$(ANSIBLE) deploy/ansible/playbooks/ldap_list.yml

ldap-delete: ## Elimina una cuenta de comunidad del IdP simulado (LDAP_USER)
	$(ANSIBLE) -e "user=$(LDAP_USER)" deploy/ansible/playbooks/ldap_delete.yml

ldap-passwd: ## Cambia la contraseña de una cuenta de comunidad (LDAP_USER, LDAP_PASS)
	$(ANSIBLE) -e "user=$(LDAP_USER) password=$(LDAP_PASS)" \
	  deploy/ansible/playbooks/ldap_passwd.yml

operator: ## Crea un operador por la API del IAM (OPERATOR_*, SESSION o bootstrap)
	ssh -p 5812 ubuntu@10.20.12.185 "curl -s -X POST http://10.0.0.12:8001/operators \
	  -H 'Content-Type: application/json' \
	  -d '{\"username\":\"$(OPERATOR_USER)\",\"password\":\"$(OPERATOR_PASS)\",\"role\":\"$(OPERATOR_ROLE)\",\"session\":\"$(SESSION)\",\"bootstrap_token\":\"$(BOOTSTRAP_TOKEN)\"}'"

operator-list: ## Lista los operadores (SESSION de un operador con P24)
	ssh -p 5812 ubuntu@10.20.12.185 "curl -s 'http://10.0.0.12:8001/operators?session=$(SESSION)'"

# --- Corte nativo (DEL SLICE ANTERIOR, 10.20.11.x: en desuso desde el
# --- slice de 14 VMs, que corre todo en contenedores con disco 20 GB).
# --- La IP vigente del slice es 10.20.12.185; 10.20.11.24 se conserva
# --- solo para reproducir el registro del corte nativo. ---
SLICE_GATEWAY ?= 10.20.11.24
SSH_CTRL := ssh -o BatchMode=yes -p 5800 ubuntu@$(SLICE_GATEWAY)

native-sync: ## Copia el repositorio al controller del slice (/opt/campus-sdn)
	COPYFILE_DISABLE=1 tar czf - --exclude=deploy/images/bundles --exclude=.venv \
	  --exclude=__pycache__ --exclude=.pytest_cache --exclude=bench/results . | \
	  $(SSH_CTRL) 'tar xzf - -C /opt/campus-sdn 2>/dev/null'

native-install: native-sync ## Instala/actualiza el corte nativo (pide sudo en el controller)
	$(SSH_CTRL) -t 'cd /opt/campus-sdn && sudo deploy/native/install_controller.sh'

native-skeleton: ## Reinstala el esqueleto BASE + confianza 60 vía ONOS
	$(SSH_CTRL) 'cd /opt/campus-sdn && set -a && . /etc/campus-sdn/services.env && set +a && \
	  .venv/bin/python deploy/scripts/install_skeleton.py'

native-test: native-sync ## Suite de pruebas en el controller (Python 3.12 del slice)
	$(SSH_CTRL) 'cd /opt/campus-sdn && .venv/bin/pytest -q tests'

slice-check: ## Acceso SSH y sudo a las 14 VMs con bench/slice.env (no cambia nada)
	python3 bench/slice.py check

env-pull: ## Recupera los .env reales de srv1–srv3 a deploy/env/ (600, sin imprimir valores)
	python3 tools/pull_env.py

R4_COMPOSE := cd /opt/campus-sdn/deploy/compose && docker compose -p campus-sdn

r4-campaign-on: ## Cadena R4 de la campaña: solo en srv2 (override r4-campaign.yml), TTL 60 s
	for n in srv2 srv3; do python3 bench/slice.py run $$n --sudo \
	  "echo $$(base64 < deploy/compose/r4-campaign.yml | tr -d '\n') | base64 -d > /opt/campus-sdn/deploy/compose/r4-campaign.yml"; done
	python3 bench/slice.py run srv2 --sudo '$(R4_COMPOSE) -f srv2-platform.yml -f r4-campaign.yml up -d --no-build --no-deps monitor detection policies'
	python3 bench/slice.py run srv3 --sudo '$(R4_COMPOSE) -f srv3-platform.yml -f r4-campaign.yml up -d --no-build --no-deps policies && docker stop s2-monitor s2-detection s3-incidents'

r4-campaign-off: ## Devuelve monitor, detección, incidentes y políticas a la configuración base
	python3 bench/slice.py run srv2 --sudo '$(R4_COMPOSE) -f srv2-platform.yml up -d --no-build --no-deps monitor detection policies'
	python3 bench/slice.py run srv3 --sudo '$(R4_COMPOSE) -f srv3-platform.yml up -d --no-build --no-deps monitor detection incidents policies'

bench-r4: ## Campaña R4 en el slice (SLICE_SUDO_PASSWORD requerido)
	python3 bench/r4_campaign.py

bench-r1r2: ## Campaña R1/R2 en el slice (SLICE_SUDO_PASSWORD requerido)
	python3 bench/r1_r2_campaign.py

verify: ## Verificación completa del entorno
	$(MAKE) images-verify
	$(MAKE) ping
	$(MAKE) status
