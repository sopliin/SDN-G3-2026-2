-- 003_decision_priority.sql — prioridad de la regla o concesión ganadora.
-- El motor (tarea 6) registra en cada decisión la prioridad que decidió;
-- la columna se añade de forma idempotente para bases ya migradas.

ALTER TABLE policy_decisions ADD COLUMN IF NOT EXISTS priority INTEGER;
