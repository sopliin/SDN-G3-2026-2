# campus-sdn — puerta única de operación.
# Los objetivos de imágenes llaman a deploy/images/; el resto, a Ansible.
# ANSIBLE_ROLES_PATH evita depender de ansible.cfg (que solo aplica si se
# ejecuta desde deploy/ansible/); el Makefile siempre corre desde la raíz.

export ANSIBLE_ROLES_PATH := deploy/ansible/roles

ANSIBLE := ansible-playbook -i deploy/ansible/inventory/slice.yml
SITE := deploy/ansible/playbooks/site.yml
TAGS ?=
IMAGES ?=

.PHONY: help images-pull images-verify images-save images-load \
        ping deploy up down status test verify native-sync native-install \
        native-skeleton native-test bench-r4 bench-r1r2

help: ## Muestra los objetivos disponibles
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "} {printf "  %-16s %s\n", $$1, $$2}'

images-pull: ## Descarga las imágenes del lock y fija sus digests
	./deploy/images/pull.sh

images-verify: ## Compara los digests locales con el lock
	./deploy/images/verify.sh

images-save: ## Empaqueta las imágenes en deploy/images/bundles/
	./deploy/images/save.sh

images-load: ## Carga bundles en el demonio local (IMAGES=onos[,rabbitmq])
	./deploy/images/load.sh $(IMAGES)

build: ## Construye las imágenes de los servicios propios (prefijo campus-sdn-)
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
	RABBITMQ_PASSWORD=dummy RADIUS_SECRET=dummy LDAP_ADMIN_PASSWORD=dummy \
	LDAP_READONLY_PASSWORD=dummy \
	docker compose -p campus-sdn -f deploy/compose/minimal-slice.yml build portal iam registry

ping: ## Conectividad con todas las VMs del inventario
	ansible -i deploy/ansible/inventory/slice.yml all -m ping

deploy: ## Ejecuta site.yml (TAGS=base,images,platform,onos,switches,identity,verify)
	$(ANSIBLE) $(if $(TAGS),--tags $(TAGS),) $(SITE)

up: ## Levanta los servicios
	$(ANSIBLE) --tags platform $(SITE)

down: ## Detiene los servicios
	$(ANSIBLE) --tags down $(SITE)

status: ## Salud de contenedores y servicios
	$(ANSIBLE) --tags verify $(SITE)

test: ## Pruebas de contrato e integración (requiere .venv)
	./.venv/bin/pytest tests

# --- Corte nativo (slice con poco disco/RAM: sin imágenes propias) -----
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

bench-r4: ## Campaña R4 en el slice (SLICE_SUDO_PASSWORD requerido)
	python3 bench/r4_campaign.py

bench-r1r2: ## Campaña R1/R2 en el slice (SLICE_SUDO_PASSWORD requerido)
	python3 bench/r1_r2_campaign.py

verify: ## Verificación completa del entorno
	$(MAKE) images-verify
	$(MAKE) ping
	$(MAKE) status
