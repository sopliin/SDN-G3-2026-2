-- 001_directory.sql — read model académico del motor de reglas.
-- Tablas dir_* y attr_* con clave primaria textual, claves foráneas y las
-- columnas de sincronización incremental (source, source_version,
-- updated_at, vigencia y baja lógica). Idempotente: el registro de
-- versiones lo lleva schema_migrations (storage.apply_migrations).

CREATE TABLE IF NOT EXISTS dir_org_units (
    org_unit_id TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'department',
    parent_id TEXT REFERENCES dir_org_units (org_unit_id),
    building TEXT,
    floor INTEGER,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_people (
    person_id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    employee_type TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_affiliations (
    affiliation_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES dir_people (person_id),
    org_unit_id TEXT NOT NULL REFERENCES dir_org_units (org_unit_id),
    role TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_courses (
    course_id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    org_unit_id TEXT REFERENCES dir_org_units (org_unit_id),
    term TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES dir_people (person_id),
    course_id TEXT NOT NULL REFERENCES dir_courses (course_id),
    role TEXT NOT NULL DEFAULT 'student',
    status TEXT NOT NULL DEFAULT 'enrolled',
    exception BOOLEAN NOT NULL DEFAULT false,
    approved_by TEXT,
    reason TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_qualifications (
    qualification_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES dir_people (person_id),
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    org_unit_id TEXT REFERENCES dir_org_units (org_unit_id),
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_devices (
    device_id TEXT PRIMARY KEY,
    mac TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'workstation',
    label TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_device_assignments (
    assignment_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES dir_devices (device_id),
    person_id TEXT NOT NULL REFERENCES dir_people (person_id),
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_device_locations (
    location_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES dir_devices (device_id),
    building TEXT NOT NULL,
    floor INTEGER,
    zone TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

-- Una sola ubicación vigente por equipo; el histórico se conserva con
-- valid_to cerrado.
CREATE UNIQUE INDEX IF NOT EXISTS dir_device_locations_current_uk
    ON dir_device_locations (device_id)
    WHERE valid_to IS NULL AND active;

CREATE TABLE IF NOT EXISTS dir_resources (
    resource_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    subtype TEXT,
    classification TEXT NOT NULL DEFAULT 'internal',
    scope TEXT NOT NULL DEFAULT 'academic',
    cidr TEXT,
    course_id TEXT REFERENCES dir_courses (course_id),
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS dir_resource_grants (
    grant_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES dir_resources (resource_id),
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    grant_type TEXT NOT NULL DEFAULT 'normal',
    approved_by TEXT,
    reason TEXT,
    revoked_at TIMESTAMPTZ,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS attr_defs (
    attr_id TEXT PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    applies_to TEXT NOT NULL,
    multi_valued BOOLEAN NOT NULL DEFAULT false,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attr_values (
    value_id TEXT PRIMARY KEY,
    attr_id TEXT NOT NULL REFERENCES attr_defs (attr_id),
    owner_type TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    value TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS directory_sync_runs (
    sync_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'incremental',
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    upserts INTEGER NOT NULL DEFAULT 0,
    deletes INTEGER NOT NULL DEFAULT 0,
    watermark TEXT,
    idempotency_key TEXT UNIQUE,
    source_version TEXT NOT NULL DEFAULT '1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS directory_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key TEXT UNIQUE,
    source_version TEXT NOT NULL DEFAULT '1',
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dir_affiliations_person_idx
    ON dir_affiliations (person_id);
CREATE INDEX IF NOT EXISTS dir_enrollments_person_idx
    ON dir_enrollments (person_id);
CREATE INDEX IF NOT EXISTS dir_enrollments_course_idx
    ON dir_enrollments (course_id);
CREATE INDEX IF NOT EXISTS dir_device_assignments_person_idx
    ON dir_device_assignments (person_id);
CREATE INDEX IF NOT EXISTS dir_resource_grants_subject_idx
    ON dir_resource_grants (subject_type, subject_id);
CREATE INDEX IF NOT EXISTS attr_values_owner_idx
    ON attr_values (owner_type, owner_id);
