-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 003_raw_ops
-- Prerequisiti: 001_foundation FINAL PASS, 002_catalog FINAL PASS (non modificate)
-- Specifica di riferimento: progettazione 003_raw_ops approvata + chiusura dei
--                           due punti tecnici (idempotenza raw.ingest_events,
--                           scope di ops.integration_cursors)
--
-- Contenuto di questa migration:
--   - ops.sync_runs
--   - raw.ingest_events
--   - ops.integration_cursors
--   - ops.mapping_queue
--   - ops.entity_raw_links
--   - ops.audit_log
--
-- NON incluso in questa migration (per istruzione esplicita):
--   - ops.data_quality_issues
--   - connection_id / integration_scope generico
--   - Nessun modulo restaurant/finance/workforce/CRM/marketing/analytics
--
-- Nota sul requisito "Implementa RLS secondo l'architettura già definita":
--   l'architettura già definita e approvata (Piano MVP v3 e progettazione
--   003_raw_ops) colloca esplicitamente l'abilitazione di RLS
--   (ENABLE ROW LEVEL SECURITY / CREATE POLICY) in 006_rls_policies, non
--   nelle migration di struttura dati. Questa migration implementa quindi
--   RLS "secondo l'architettura già definita" nel senso di predisporre
--   correttamente le fondamenta (organization_id NOT NULL ovunque tranne
--   l'eccezione già nota di audit_log, FK composite tenant-safe, nessuna
--   ambiguità di segregazione) — ma NON abilita RLS né crea policy qui,
--   per non anticipare 006 e restare coerente con quanto già approvato in
--   tutti i round precedenti. Segnalato esplicitamente in questo commento
--   perché l'istruzione era suscettibile di due letture: se l'intento era
--   diverso (RLS realmente abilitata già in questa migration), va
--   corretto esplicitamente prima di procedere a 004.
--
-- Documentazione di scelta rimandata (per istruzione esplicita, punto 6):
--   la gestione di più account/credenziali API per lo stesso
--   core.source_systems (stessa organization, stesso vendor, connessioni
--   multiple) non è coperta da questa migration. Se necessaria in futuro,
--   richiederà una valutazione dedicata (verosimilmente un affinamento di
--   core.source_systems o una nuova dimensione di scoping), da progettare
--   quando emergerà un caso d'uso reale — non introdotta ora per non
--   complicare il modello senza necessità concreta.
--
-- Convenzioni riusate da 001_foundation/002_catalog (invariate):
--   UUID v4 (gen_random_uuid()), timestamptz, numeric per valori economici/
--   confidence, organization_id NOT NULL su ogni tabella tenant-owned
--   (eccezione dichiarata: ops.audit_log.organization_id nullable, per
--   azioni di sistema non legate a un tenant — nessuna tabella referenzia
--   audit_log come genitore, quindi nessuna FK composita necessaria lì),
--   pattern FK composita tenant-safe (organization_id, id) ovunque il
--   genitore abbia organization_id NOT NULL, ON DELETE RESTRICT di default,
--   updated_at mantenuto da core.fn_set_updated_at() dove applicabile.
-- =============================================================================

BEGIN;

-- Già creata in 001_foundation: riasserita qui in modo idempotente perché
-- digest() (usata da payload_hash/ingestion_key) è una dipendenza diretta
-- e reale di questa migration, non solo ereditata implicitamente.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- 1. ops.sync_runs — ogni esecuzione di sincronizzazione
-- =============================================================================
CREATE TABLE ops.sync_runs (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    source_system_id    uuid        NOT NULL,

    -- Nullable: un'integrazione può essere org-wide (es. SuperBill
    -- centralizzato) oppure per sede (es. NetFood configurato per singola
    -- sede all'interno di un'unica registrazione core.source_systems).
    location_id         uuid,

    entity_type         text        NOT NULL,

    -- Self-reference: traccia esplicitamente la catena dei tentativi di
    -- retry di un run fallito.
    retry_of_run_id     uuid,

    status               text        NOT NULL DEFAULT 'running',
    started_at           timestamptz NOT NULL DEFAULT now(),
    finished_at          timestamptz,

    -- Watchdog anti-blocco: un run senza heartbeat recente viene
    -- considerato bloccato e chiuso come 'failed' da un job schedulato
    -- (logica applicativa, fuori schema).
    last_heartbeat_at    timestamptz,

    cursor_value_start   text,
    cursor_value_end     text,

    records_received     integer     NOT NULL DEFAULT 0,
    records_inserted     integer     NOT NULL DEFAULT 0,
    records_updated      integer     NOT NULL DEFAULT 0,
    records_skipped      integer     NOT NULL DEFAULT 0,
    records_duplicate    integer     NOT NULL DEFAULT 0,
    records_failed       integer     NOT NULL DEFAULT 0,
    records_retried      integer     NOT NULL DEFAULT 0,

    error_summary         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    -- Ancora tenant-safe: necessaria sia per retry_of_run_id (self-FK
    -- composita) sia per essere referenziata da raw.ingest_events.sync_run_id.
    CONSTRAINT uq_sync_runs_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_sync_runs_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sync_runs_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sync_runs_retry_of
        FOREIGN KEY (organization_id, retry_of_run_id)
        REFERENCES ops.sync_runs (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_sync_runs_status
        CHECK (status IN ('running', 'success', 'partial_success', 'failed'))
);

COMMENT ON TABLE ops.sync_runs IS
    'Ogni esecuzione di sincronizzazione da un sistema sorgente. location_id '
    'nullable distingue integrazioni org-wide da integrazioni per sede.';

-- Guardia di concorrenza: al più un run 'running' per (organization,
-- source_system, entity_type, location) — doppio indice parziale per gestire
-- correttamente il caso location_id NULL (org-wide), dove un semplice UNIQUE
-- non basterebbe (NULL non è mai uguale a NULL).
CREATE UNIQUE INDEX uq_sync_runs_running_by_location
    ON ops.sync_runs (organization_id, source_system_id, entity_type, location_id)
    WHERE status = 'running' AND location_id IS NOT NULL;

CREATE UNIQUE INDEX uq_sync_runs_running_orgwide
    ON ops.sync_runs (organization_id, source_system_id, entity_type)
    WHERE status = 'running' AND location_id IS NULL;

CREATE INDEX idx_sync_runs_org_source_entity_started
    ON ops.sync_runs (organization_id, source_system_id, entity_type, started_at);

-- Dashboard operative cross-tenant (piattaforma, non singolo tenant).
CREATE INDEX idx_sync_runs_status ON ops.sync_runs (status);

CREATE TRIGGER trg_sync_runs_set_updated_at
    BEFORE UPDATE ON ops.sync_runs
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 2. raw.ingest_events — payload originale, append-only, immutabile
-- =============================================================================
CREATE TABLE raw.ingest_events (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    location_id             uuid,
    source_system_id        uuid        NOT NULL,

    -- Tracciabilità verso il run che ha prodotto questo evento (osservabilità).
    sync_run_id             uuid,

    entity_type              text       NOT NULL,
    external_id               text,
    source_updated_at          timestamptz,
    received_at                 timestamptz NOT NULL DEFAULT now(),

    -- Byte esatti originali ricevuti dalla sorgente, prima di qualunque
    -- parsing: fedeltà legale/fiscale totale (es. XML FatturaPA da SuperBill),
    -- mai usati per il calcolo di identità/idempotenza.
    raw_payload                  bytea  NOT NULL,

    -- Rappresentazione canonicalizzata (jsonb normalizza ordine delle chiavi
    -- e whitespace strutturale): usata per query, normalizzazione e hashing.
    payload                      jsonb  NOT NULL,

    -- Calcolata dal database sul payload già canonicalizzato, mai
    -- dall'applicazione e mai sul testo grezzo.
    payload_hash                 text   GENERATED ALWAYS AS (
                                            encode(digest(payload::text, 'sha256'), 'hex')
                                         ) STORED,

    -- Nota tecnica: non può referenziare payload_hash (PostgreSQL vieta a una
    -- colonna GENERATED di referenziarne un'altra), quindi ricalcola
    -- autonomamente lo stesso digest.
    ingestion_key                text   GENERATED ALWAYS AS (
                                            CASE
                                                WHEN external_id IS NOT NULL
                                                    THEN 'eid:' || external_id
                                                ELSE 'nid:' || encode(digest(payload::text, 'sha256'), 'hex')
                                            END
                                         ) STORED,

    -- Metadati di trasporto (header, versione API...), distinti dal payload
    -- di business: immutabili quanto il payload stesso.
    metadata                     jsonb,

    processing_status            text   NOT NULL DEFAULT 'pending',
    processing_started_at        timestamptz,
    processed_at                  timestamptz,
    retry_count                   integer NOT NULL DEFAULT 0,
    error_message                  text,

    created_at                      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_ingest_events_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_ingest_events_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_ingest_events_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_ingest_events_sync_run
        FOREIGN KEY (organization_id, sync_run_id)
        REFERENCES ops.sync_runs (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_ingest_events_processing_status
        CHECK (processing_status IN ('pending', 'processing', 'processed', 'failed', 'skipped')),

    -- Idempotenza definitiva: nessun duplicato, con o senza external_id,
    -- nessuna collisione tra entity_type diversi, nessuna perdita di
    -- revisioni reali (payload_hash distingue le revisioni quando
    -- external_id è stabile).
    CONSTRAINT uq_ingest_events_idempotency
        UNIQUE (source_system_id, entity_type, ingestion_key, payload_hash)
);

COMMENT ON TABLE raw.ingest_events IS
    'Payload originale ricevuto da un sistema sorgente. Append-only: solo lo '
    'stato di elaborazione può cambiare dopo l''insert (vedi trigger di '
    'immutabilità). raw_payload conserva i byte esatti; payload è la '
    'rappresentazione canonicalizzata usata per idempotenza e normalizzazione.';

COMMENT ON COLUMN raw.ingest_events.raw_payload IS
    'Byte esatti originali, mai usati per il calcolo di ingestion_key/'
    'payload_hash: due retry tecnicamente diversi a livello di byte ma con lo '
    'stesso contenuto logico devono comunque deduplicare come lo stesso evento.';

CREATE INDEX idx_ingest_events_org_received ON raw.ingest_events (organization_id, received_at);

-- Per il polling della pipeline di elaborazione (ricerca di eventi da processare).
CREATE INDEX idx_ingest_events_source_status ON raw.ingest_events (source_system_id, processing_status);

CREATE INDEX idx_ingest_events_sync_run ON raw.ingest_events (sync_run_id);

-- ---------------------------------------------------------------------------
-- Immutabilità di raw.ingest_events: solo lo stato di elaborazione può
-- cambiare; nessuna riga può mai essere cancellata.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION raw.fn_protect_ingest_event_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'raw.ingest_events è append-only: DELETE non consentito (id=%)', OLD.id;
    END IF;

    -- TG_OP = 'UPDATE': ogni colonna identitaria/di contenuto deve restare
    -- invariata. Solo le colonne di stato di elaborazione sono mutabili
    -- (processing_status, processing_started_at, processed_at, retry_count,
    -- error_message) e non compaiono in questo controllo.
    IF NEW.organization_id   IS DISTINCT FROM OLD.organization_id OR
       NEW.location_id       IS DISTINCT FROM OLD.location_id OR
       NEW.source_system_id  IS DISTINCT FROM OLD.source_system_id OR
       NEW.sync_run_id       IS DISTINCT FROM OLD.sync_run_id OR
       NEW.entity_type       IS DISTINCT FROM OLD.entity_type OR
       NEW.external_id       IS DISTINCT FROM OLD.external_id OR
       NEW.source_updated_at IS DISTINCT FROM OLD.source_updated_at OR
       NEW.received_at       IS DISTINCT FROM OLD.received_at OR
       NEW.raw_payload       IS DISTINCT FROM OLD.raw_payload OR
       NEW.payload           IS DISTINCT FROM OLD.payload OR
       NEW.metadata          IS DISTINCT FROM OLD.metadata OR
       NEW.created_at        IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION
            'raw.ingest_events è immutabile: solo lo stato di elaborazione può cambiare (id=%)', OLD.id;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION raw.fn_protect_ingest_event_immutability() IS
    'Blocca DELETE incondizionatamente e UPDATE su qualunque colonna diversa '
    'dallo stato di elaborazione. payload_hash/ingestion_key non compaiono nel '
    'controllo: essendo GENERATED, PostgreSQL ne vieta già la scrittura diretta.';

CREATE TRIGGER trg_ingest_events_immutability
    BEFORE UPDATE OR DELETE ON raw.ingest_events
    FOR EACH ROW
    EXECUTE FUNCTION raw.fn_protect_ingest_event_immutability();

-- =============================================================================
-- 3. ops.integration_cursors — checkpoint per ciascuna integrazione
-- =============================================================================
CREATE TABLE ops.integration_cursors (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    source_system_id    uuid        NOT NULL,

    -- Nullable: stessa dimensione di scoping di ops.sync_runs/raw.ingest_events.
    location_id          uuid,

    entity_type           text        NOT NULL,
    cursor_type            text        NOT NULL,
    cursor_value             text       NOT NULL,
    last_success_at            timestamptz,
    updated_at                   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_integration_cursors_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_integration_cursors_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_integration_cursors_type
        CHECK (cursor_type IN ('timestamp', 'sequential_id', 'page_token', 'composite', 'other'))
);

COMMENT ON TABLE ops.integration_cursors IS
    'Checkpoint di sincronizzazione incrementale per integrazione. Il cursore '
    'avanza solo dopo che i dati corrispondenti sono stati committati con '
    'successo in raw.ingest_events, mai prima (garanzia di retry-safety).';

-- Stesso schema a doppio indice parziale di ops.sync_runs, per lo stesso
-- motivo: un semplice UNIQUE non basterebbe quando location_id è NULL.
CREATE UNIQUE INDEX uq_integration_cursors_by_location
    ON ops.integration_cursors (organization_id, source_system_id, entity_type, location_id)
    WHERE location_id IS NOT NULL;

CREATE UNIQUE INDEX uq_integration_cursors_orgwide
    ON ops.integration_cursors (organization_id, source_system_id, entity_type)
    WHERE location_id IS NULL;

CREATE TRIGGER trg_integration_cursors_set_updated_at
    BEFORE UPDATE ON ops.integration_cursors
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 4. ops.mapping_queue — record non mappabili automaticamente
-- =============================================================================
CREATE TABLE ops.mapping_queue (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    raw_event_id             uuid       NOT NULL,
    source_system_id          uuid      NOT NULL,

    -- Libero, estendibile: nuovi verticali introdurranno nuovi mapping_type
    -- senza richiedere una migration di schema.
    mapping_type                text    NOT NULL,

    -- Frammento non mappato (es. descrizione/codice riga sorgente).
    source_value                  jsonb  NOT NULL,

    -- Polimorfico, nessuna FK: coerente col resto del modello
    -- (finance.reconciliation_links, ops.entity_raw_links).
    proposed_entity_type             text,
    proposed_entity_id                uuid,

    confidence                          numeric(5,4),
    reason                                text,

    status                                 text NOT NULL DEFAULT 'pending',
    resolution_type                          text,

    -- Non FK: stesso pattern di ops.audit_log.actor_id (utente o attore di
    -- sistema, identificato liberamente, mai un vincolo referenziale rigido).
    resolved_by                                text,
    resolved_at                                  timestamptz,

    created_at                                     timestamptz NOT NULL DEFAULT now(),
    updated_at                                       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_mapping_queue_raw_event
        FOREIGN KEY (organization_id, raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_mapping_queue_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_mapping_queue_status
        CHECK (status IN ('pending', 'resolved', 'ignored')),

    CONSTRAINT chk_mapping_queue_resolution_type
        CHECK (resolution_type IS NULL OR resolution_type IN ('manual', 'automatic')),

    CONSTRAINT chk_mapping_queue_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

COMMENT ON TABLE ops.mapping_queue IS
    'Coda di elementi che la pipeline non è riuscita a mappare automaticamente '
    '(es. prodotto SuperBill non riconosciuto). Al più una voce pending per '
    '(organization, raw_event, mapping_type): un riprocessamento non duplica '
    'la stessa segnalazione irrisolta.';

CREATE UNIQUE INDEX uq_mapping_queue_pending
    ON ops.mapping_queue (organization_id, raw_event_id, mapping_type)
    WHERE status = 'pending';

CREATE INDEX idx_mapping_queue_org_status ON ops.mapping_queue (organization_id, status);
CREATE INDEX idx_mapping_queue_org_raw_event ON ops.mapping_queue (organization_id, raw_event_id);

CREATE TRIGGER trg_mapping_queue_set_updated_at
    BEFORE UPDATE ON ops.mapping_queue
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 5. ops.entity_raw_links — provenance RAW → CORE, storia completa
-- =============================================================================
-- Formalizza qui la tabella già approvata concettualmente in un round
-- precedente (Piano v3/Correzioni v5), necessaria al requisito di
-- provenance: source_raw_event_id (nelle CORE table delle migration
-- successive) punterà solo all'evento corrente; questa tabella conserva
-- l'intera storia di ogni evento RAW che ha originato, aggiornato o
-- stornato un record CORE.
CREATE TABLE ops.entity_raw_links (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    raw_event_id         uuid       NOT NULL,

    -- Polimorfico, nessuna FK: collega a qualunque tabella CORE futura senza
    -- accoppiamento strutturale.
    core_entity_type       text     NOT NULL,
    core_entity_id           uuid   NOT NULL,

    link_role                  text NOT NULL,
    applied_at                    timestamptz NOT NULL DEFAULT now(),
    created_at                      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_entity_raw_links_raw_event
        FOREIGN KEY (organization_id, raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_entity_raw_links_role
        CHECK (link_role IN ('origin', 'update', 'storno', 'correction', 'void', 'other')),

    -- Idempotenza del collegamento stesso: il riprocessamento dello stesso
    -- raw event non duplica il link di provenance.
    CONSTRAINT uq_entity_raw_links_dedup
        UNIQUE (raw_event_id, core_entity_type, core_entity_id, link_role)
);

COMMENT ON TABLE ops.entity_raw_links IS
    'Storia completa dei collegamenti RAW → CORE: quale evento RAW ha '
    'originato, aggiornato o stornato un record CORE, in ordine di applied_at. '
    'Interamente append-only (vedi trigger).';

CREATE INDEX idx_entity_raw_links_org_entity
    ON ops.entity_raw_links (organization_id, core_entity_type, core_entity_id);

-- ---------------------------------------------------------------------------
-- Funzione generica riusabile: blocca incondizionatamente UPDATE e DELETE.
-- Usata da ops.entity_raw_links e ops.audit_log, log di provenance/audit che
-- devono restare append-only al 100% (a differenza di raw.ingest_events, che
-- ammette la mutazione controllata dello stato di elaborazione).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ops.fn_block_modification()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% è append-only: % non consentito', TG_TABLE_NAME, TG_OP;
END;
$$;

COMMENT ON FUNCTION ops.fn_block_modification() IS
    'Trigger generico riusabile: blocca sempre UPDATE e DELETE. Applicata a '
    'tabelle interamente immutabili (entity_raw_links, audit_log).';

CREATE TRIGGER trg_entity_raw_links_immutability
    BEFORE UPDATE OR DELETE ON ops.entity_raw_links
    FOR EACH ROW
    EXECUTE FUNCTION ops.fn_block_modification();

-- =============================================================================
-- 6. ops.audit_log — traccia delle operazioni importanti
-- =============================================================================
CREATE TABLE ops.audit_log (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nullable per eccezione già accettata: azioni di sistema non legate a
    -- un singolo tenant. Nessuna tabella referenzia audit_log come genitore,
    -- quindi non serve alcuna FK composita qui.
    organization_id      uuid REFERENCES core.organizations(id) ON DELETE RESTRICT,

    actor_type              text NOT NULL,
    actor_id                  text,
    action                      text NOT NULL,
    entity_type                  text NOT NULL,
    entity_id                      uuid,
    before_data                      jsonb,
    after_data                         jsonb,
    occurred_at                          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT chk_audit_log_actor_type
        CHECK (actor_type IN ('user', 'system', 'api', 'ingestion_pipeline'))
);

COMMENT ON TABLE ops.audit_log IS
    'Traccia di ogni operazione rilevante su record CORE: chi/cosa, quando, '
    'before/after. Interamente append-only (vedi trigger).';

CREATE INDEX idx_audit_log_org_occurred ON ops.audit_log (organization_id, occurred_at);
CREATE INDEX idx_audit_log_entity ON ops.audit_log (entity_type, entity_id);

CREATE TRIGGER trg_audit_log_immutability
    BEFORE UPDATE OR DELETE ON ops.audit_log
    FOR EACH ROW
    EXECUTE FUNCTION ops.fn_block_modification();

COMMIT;
