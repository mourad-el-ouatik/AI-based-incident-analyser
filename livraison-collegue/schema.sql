-- ============================================================================
--  SOC AI — SCHEMA DE REFERENCE (base propre, clé-en-main)
--  A executer sur une base neuve :   psql -U soc_user -d soc -f schema.sql
--
--  C'est le schema CIBLE corrige (cf. correction.txt). A donner aux collegues
--  pour repartir propre. Les 14 lignes de test actuelles ne sont pas reprises
--  (donnees de demo : le pipeline en regenerera).
--
--  Pour un RESET total volontaire (DESTRUCTIF — supprime les donnees),
--  decommenter les 2 DROP ci-dessous.
-- ============================================================================

-- DROP TABLE IF EXISTS public.audit_log;
-- DROP TABLE IF EXISTS public.incidents;


-- ----------------------------------------------------------------------------
-- TABLE incidents (schema corrige)
--  - champs DETECTION : remplis par le modele (Ollama)
--  - champs SUIVI : remplis par l'analyste via le dashboard (defauts ci-dessous)
--  - defauts sains : un INSERT incomplet ne casse pas, il prend une valeur par defaut
--  - inconnu reel = NULL (jamais chaine vide "")
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incidents (
    id                  serial PRIMARY KEY,

    -- --- Detection (modele) ---
    incident_id         varchar(50) UNIQUE NOT NULL,
    "timestamp"         timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    is_attack           boolean        NOT NULL DEFAULT false,
    attack_type         varchar(100)   NOT NULL DEFAULT 'Unknown',
    confidence          double precision NOT NULL DEFAULT 0.5,
    summary             text           NOT NULL DEFAULT '',
    score_wazuh         integer        NOT NULL DEFAULT 0,
    score_ia            integer        NOT NULL DEFAULT 0,
    score_final         integer        NOT NULL DEFAULT 0,
    recommended_action  varchar(20)    NOT NULL DEFAULT 'monitor',
    mitre_techniques    jsonb          NOT NULL DEFAULT '[]'::jsonb,
    source_ip           varchar(50),              -- NULL si inconnu
    target_user         varchar(100),             -- NULL si inconnu
    target_host         varchar(100),
    affected_service    varchar(50),              -- NULL si inconnu
    priority            varchar(20)    NOT NULL DEFAULT 'LOW',
    batch_size          integer,
    raw_alerts          jsonb          NOT NULL DEFAULT '[]'::jsonb,

    -- --- Suivi (analyste / dashboard) ---
    status              varchar(20)    NOT NULL DEFAULT 'new',
    analyst_action      varchar(20),
    analyst_user        varchar(100),
    decided_at          timestamp without time zone,
    thehive_case_id     varchar(100),
    pfsense_rule_id     varchar(100),
    blocked_ip          varchar(50),
    archived            boolean        NOT NULL DEFAULT false,
    archived_at         timestamp without time zone,

    -- --- Contraintes (garde-fous : valeurs hors liste rejetees) ---
    CONSTRAINT chk_priority   CHECK (priority IN ('HIGH','MEDIUM','LOW')),
    CONSTRAINT chk_reco       CHECK (recommended_action IN ('block_ip','escalate','monitor','false_positive')),
    CONSTRAINT chk_status     CHECK (status IN ('new','escalated','responded','closed')),
    CONSTRAINT chk_analyst_ac CHECK (analyst_action IS NULL OR analyst_action IN ('block_ip','escalate','monitor','false_positive'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON public.incidents ("timestamp");
CREATE INDEX IF NOT EXISTS idx_incidents_archived  ON public.incidents (archived);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON public.incidents (source_ip);


-- ----------------------------------------------------------------------------
-- TABLE audit_log (journal append-only — une ligne par action analyste)
--  Conservee indefiniment. Pas de FK : la trace survit meme si l'incident change.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_log (
    id            bigserial PRIMARY KEY,
    incident_id   varchar(50),
    action        varchar(20),
    target        varchar(20),                       -- pfSense | TheHive | NULL
    detail        text,
    analyst_user  varchar(100),
    created_at    timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_incident ON public.audit_log (incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_created  ON public.audit_log (created_at);


-- ----------------------------------------------------------------------------
-- DROITS (adapter le role si besoin)
-- ----------------------------------------------------------------------------
-- GRANT ALL ON ALL TABLES IN SCHEMA public TO soc_user;
-- GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO soc_user;


-- ----------------------------------------------------------------------------
-- EXEMPLE d'INSERT (ce que le modele doit produire — cf. model_system_prompt.md)
-- ----------------------------------------------------------------------------
-- INSERT INTO public.incidents
--   (incident_id, is_attack, attack_type, confidence, summary,
--    score_wazuh, score_ia, score_final, recommended_action, mitre_techniques,
--    source_ip, target_user, target_host, affected_service, priority, batch_size, raw_alerts)
-- VALUES
--   ('INC-20260519-801', true, 'Brute Force SSH', 0.9,
--    'Multiples tentatives SSH echouees depuis 10.0.0.5',
--    5, 8, 7, 'escalate', '["T1110.001"]'::jsonb,
--    '10.0.0.5', 'fakeuser', 'ubuntu-virtual-machine', 'SSH', 'HIGH', 3,
--    '[{"level":5,"rule_id":"5710","src_ip":"10.0.0.5"}]'::jsonb);

-- RETENTION : archiver les incidents > 3 mois (a planifier)
-- UPDATE public.incidents SET archived = true, archived_at = now()
--  WHERE "timestamp" < now() - interval '3 months' AND archived = false;
