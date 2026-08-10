-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 001_foundation
-- Specifica di riferimento: documento v5 (APPROVATO, source of truth definitiva)
-- Revisione: correzione chk_tax_rates_valid_period applicata (v FINAL)
--
-- Contenuto di questa migration:
--   - Schemas PostgreSQL (raw, core, restaurant, finance, workforce, crm,
--     marketing, analytics, ops)
--   - core.organizations
--   - core.locations
--   - core.source_systems
--   - core.units_of_measure
--   - core.tax_rates
--   - core.user_profiles
--   - core.user_organization_roles
--
-- NON incluso in questa migration (deliberatamente, per non anticipare
-- migration successive):
--   - Nessuna RLS policy (ENABLE ROW LEVEL SECURITY / CREATE POLICY):
--     pianificate in 006_rls_policies. Questa migration prepara solo la
--     struttura dati necessaria (core.user_organization_roles).
--   - Nessuna tabella raw/ops (003_raw_ops), nessuna tabella catalogo
--     (parties/products, 002_catalog), nessuna tabella sales/purchases.
--
-- Convenzioni applicate in tutta la migration:
--   - UUID come PK di default (principio 14), generate con gen_random_uuid().
--   - organization_id come chiave di segregazione multi-tenant (principio 2)
--     su ogni entità aziendale.
--   - timestamptz per ogni timestamp (principio 10).
--   - ON DELETE RESTRICT di default; CASCADE solo dove esplicitamente
--     motivato per record puramente dipendenti e non storici (vedi
--     core.user_profiles e core.user_organization_roles verso auth.users).
--   - Pattern tenant-safe: le tabelle che saranno referenziate da FK
--     composite nelle migration successive espongono già ora
--     UNIQUE (organization_id, id). Eccezione dichiarata: core.tax_rates,
--     che ammette righe globali (organization_id IS NULL) e verrà
--     protetta da FK composite non applicabili, tramite trigger di
--     validazione dedicato introdotto nelle migration successive.
--   - updated_at mantenuto automaticamente via trigger, mai delegato
--     alla disciplina applicativa.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------
-- 0. Estensioni
-- -----------------------------------------------------------------------
-- gen_random_uuid() è nativo da PostgreSQL 13, ma pgcrypto viene comunque
-- richiesta esplicitamente per portabilità: è l'estensione standard
-- disponibile su ogni progetto Supabase (piattaforma target, principio
-- non negoziabile "PostgreSQL/Supabase").
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------
-- 1. Schemas — separazione RAW / CORE / verticali (principio 3)
-- -----------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS restaurant;
CREATE SCHEMA IF NOT EXISTS finance;
CREATE SCHEMA IF NOT EXISTS workforce;
CREATE SCHEMA IF NOT EXISTS crm;
CREATE SCHEMA IF NOT EXISTS marketing;
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE SCHEMA IF NOT EXISTS ops;

COMMENT ON SCHEMA raw IS 'Dati grezzi provenienti dalle API sorgente. Append-only, immutabile.';
COMMENT ON SCHEMA core IS 'Modello dati comune, riusabile su verticali/settori diversi.';
COMMENT ON SCHEMA restaurant IS 'Verticale ristorazione. Non usato in questa migration.';
COMMENT ON SCHEMA finance IS 'Verticale finance. Non usato in questa migration.';
COMMENT ON SCHEMA workforce IS 'Verticale workforce. Non usato in questa migration.';
COMMENT ON SCHEMA crm IS 'Verticale CRM/prenotazioni. Non usato in questa migration.';
COMMENT ON SCHEMA marketing IS 'Verticale marketing. Non usato in questa migration.';
COMMENT ON SCHEMA analytics IS 'Viste/materialized view analitiche. Non usato in questa migration.';
COMMENT ON SCHEMA ops IS 'Osservabilità e governance delle integrazioni. Non usato in questa migration.';

-- -----------------------------------------------------------------------
-- 2. Funzione condivisa: mantenimento automatico di updated_at
-- -----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_set_updated_at() IS
    'Imposta automaticamente updated_at = now() ad ogni UPDATE su una riga. '
    'Applicata a tutte le tabelle di questa migration con colonna updated_at, '
    'cosi'' che la correttezza del valore non dipenda dalla disciplina applicativa.';

-- =============================================================================
-- 3. core.organizations — radice della multi-tenancy
-- =============================================================================
CREATE TABLE core.organizations (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name      text        NOT NULL,
    trade_name      text,
    vat_number      text,
    tax_code        text,
    business_sector text,
    base_currency   char(3)     NOT NULL DEFAULT 'EUR',
    country_code    char(2)     NOT NULL DEFAULT 'IT',
    timezone        text        NOT NULL DEFAULT 'Europe/Rome',
    active          boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.organizations IS
    'Tenant della piattaforma. Ogni altra tabella con organization_id referenzia '
    'questa PK: e'' la radice della segregazione multi-tenant (principio 2).';

CREATE TRIGGER trg_organizations_set_updated_at
    BEFORE UPDATE ON core.organizations
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 4. core.locations — sedi operative di una organization
-- =============================================================================
CREATE TABLE core.locations (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    code            text        NOT NULL,
    name            text        NOT NULL,
    location_type   text,
    address_line1   text,
    city            text,
    postal_code     text,
    country_code    char(2),
    timezone        text,
    active          boolean     NOT NULL DEFAULT true,
    opened_on       date,
    closed_on       date,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_locations_org_code UNIQUE (organization_id, code),

    -- Ancora per le FK composite tenant-safe delle migration successive
    -- (pattern approvato: ogni tabella genitore con organization_id NOT NULL
    -- espone UNIQUE(organization_id, id) per essere referenziata in modo
    -- tenant-safe da FK composite dei figli, es. sales_documents.location_id).
    CONSTRAINT uq_locations_org_id UNIQUE (organization_id, id)
);

COMMENT ON TABLE core.locations IS
    'Sedi operative di una organization. uq_locations_org_id e'' l''ancora per le '
    'FK composite tenant-safe verso questa tabella nelle migration successive.';

CREATE TRIGGER trg_locations_set_updated_at
    BEFORE UPDATE ON core.locations
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 5. core.source_systems — sistemi sorgente (NetFood, SuperBill, ...)
-- =============================================================================
CREATE TABLE core.source_systems (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    code                text        NOT NULL,
    name                text,
    category            text,
    provider            text,
    integration_mode    text,
    active              boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_source_systems_org_code UNIQUE (organization_id, code),

    -- Stessa ancora tenant-safe di core.locations: raw.ingest_events,
    -- sales_documents, purchase_documents e le tabelle ops referenzieranno
    -- questa tabella con FK composite a partire da 003_raw_ops.
    CONSTRAINT uq_source_systems_org_id UNIQUE (organization_id, id)
);

COMMENT ON TABLE core.source_systems IS
    'Sistemi sorgente configurati per organization (NetFood, SuperBill, Intesa, '
    'Nexi, buoni pasto, delivery, Meta, Google, sito, ...).';

CREATE TRIGGER trg_source_systems_set_updated_at
    BEFORE UPDATE ON core.source_systems
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 6. core.units_of_measure — unita'' di misura, riferimento globale
-- =============================================================================
-- Tabella intenzionalmente priva di organization_id: riferimento condiviso
-- da tutte le organization (kg, l, pz, ...), coerente con la specifica
-- originale che non la scopa per tenant. Nessun created_at/updated_at:
-- non presenti nella specifica originale per questa tabella di riferimento.
CREATE TABLE core.units_of_measure (
    id                  uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    code                text            NOT NULL UNIQUE,
    name                text            NOT NULL,
    dimension           text,
    base_unit_code      text,
    conversion_factor   numeric(18,8)
);

COMMENT ON TABLE core.units_of_measure IS
    'Unita'' di misura, riferimento globale condiviso da tutte le organization '
    '(non tenant-scoped per specifica). base_unit_code e'' testo libero: non '
    'era marcato come FK nella specifica originale, quindi non vincolato.';

-- =============================================================================
-- 7. core.tax_rates — aliquote fiscali, globali o per organization
-- =============================================================================
CREATE TABLE core.tax_rates (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NULL = aliquota globale condivisa da tutte le organization.
    -- Eccezione dichiarata al pattern FK composita tenant-safe: essendo
    -- organization_id nullable sul genitore, una FK composita non puo''
    -- referenziare correttamente le righe globali. La validazione di
    -- coerenza tenant per i riferimenti a questa tabella (da
    -- core.products, sales_lines, purchase_lines nelle migration
    -- successive) sara'' affidata a un trigger dedicato, non a una FK
    -- composita.
    organization_id uuid        REFERENCES core.organizations(id) ON DELETE RESTRICT,
    code            text        NOT NULL,
    rate            numeric(6,3) NOT NULL,
    description     text,
    valid_from      date        NOT NULL,
    valid_to        date,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- Impedisce periodi di validita'' temporalmente impossibili
    -- (correzione richiesta in revisione: valid_to precedente a valid_from).
    CONSTRAINT chk_tax_rates_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

COMMENT ON TABLE core.tax_rates IS
    'Aliquote fiscali. organization_id NULL = aliquota globale. Storicizzata '
    'via valid_from/valid_to: al piu'' una riga "attiva" (valid_to IS NULL) '
    'per codice, per organization (o globale). chk_tax_rates_valid_period '
    'impedisce periodi di validita'' temporalmente impossibili.';

-- Al piu'' una aliquota attiva per (organization_id, code).
CREATE UNIQUE INDEX uq_tax_rates_org_code_active
    ON core.tax_rates (organization_id, code)
    WHERE valid_to IS NULL AND organization_id IS NOT NULL;

-- Al piu'' una aliquota globale attiva per code.
CREATE UNIQUE INDEX uq_tax_rates_global_code_active
    ON core.tax_rates (code)
    WHERE valid_to IS NULL AND organization_id IS NULL;

-- Indice pieno necessario: i due indici unique sopra sono parziali
-- (solo righe attive) e non servono le query su tutte le righe storiche
-- di una organization.
CREATE INDEX idx_tax_rates_organization_id ON core.tax_rates (organization_id);

CREATE TRIGGER trg_tax_rates_set_updated_at
    BEFORE UPDATE ON core.tax_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 8. core.user_profiles — estensione del profilo utente Supabase
-- =============================================================================
-- Presuppone l'esistenza di auth.users (schema di autenticazione gestito da
-- Supabase, presente su ogni progetto Supabase fin dal provisioning, prima
-- di qualunque migration applicativa). Vedi assunzioni tecniche.
CREATE TABLE core.user_profiles (
    -- Non generato: deve coincidere con auth.users.id dell'utente.
    user_id                 uuid        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

    default_organization_id uuid        REFERENCES core.organizations(id) ON DELETE RESTRICT,
    first_name              text,
    last_name               text,
    active                  boolean     NOT NULL DEFAULT true,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.user_profiles IS
    'Estensione applicativa del profilo utente Supabase. ON DELETE CASCADE su '
    'user_id: un profilo non ha significato senza il relativo utente auth ed '
    'e'' un record puramente dipendente e non storico (eccezione motivata al '
    'default ON DELETE RESTRICT).';

-- INVARIANTE DOCUMENTATO (non ancora applicato a livello di schema, per
-- decisione esplicita: nessun trigger o nuova struttura in questa
-- migration): default_organization_id dovrebbe poter essere impostato
-- come default operativo SOLO se l'utente possiede almeno un ruolo attivo
-- per quella organization in core.user_organization_roles. Il controllo
-- sara'' implementato nel backend e/o nella fase RLS appropriata
-- (006_rls_policies o logica applicativa), non qui.
COMMENT ON COLUMN core.user_profiles.default_organization_id IS
    'Organization di default per la UI/sessione dell''utente. INVARIANTE '
    'NON ANCORA APPLICATO A LIVELLO DI SCHEMA: deve essere valorizzata solo '
    'se esiste un ruolo attivo dell''utente per questa organization in '
    'core.user_organization_roles. Il controllo va implementato nel backend '
    'e/o nella fase RLS (non in questa migration).';

CREATE INDEX idx_user_profiles_default_org ON core.user_profiles (default_organization_id);

CREATE TRIGGER trg_user_profiles_set_updated_at
    BEFORE UPDATE ON core.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 9. core.user_organization_roles — assegnazione utente-organization-ruolo
-- =============================================================================
-- Struttura di base per le RLS policy di 006_rls_policies. Nessuna RLS
-- viene abilitata in questa migration: solo la tabella che le policy
-- future interrogheranno.
CREATE TABLE core.user_organization_roles (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    role            text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_user_org_roles_user_org_role UNIQUE (user_id, organization_id, role),

    -- Ruoli iniziali definiti dalla specifica originale (sezione 15).
    -- Elenco chiuso, senza valvola di sfogo: e'' un elenco di ruoli di
    -- sicurezza, non un dominio operativo estendibile per verticale.
    CONSTRAINT chk_user_org_roles_role CHECK (
        role IN ('owner', 'admin', 'manager', 'finance', 'operations', 'read_only')
    )
);

COMMENT ON TABLE core.user_organization_roles IS
    'Assegnazione utente-organization-ruolo. Un utente puo'' avere piu'' ruoli '
    'su piu'' organization. ON DELETE CASCADE su user_id: stessa motivazione '
    'di core.user_profiles. Nessuna RLS abilitata qui: vedi 006_rls_policies.';

-- Copre le ricerche "di quali organization/ruoli dispone questo utente"
-- (leading column = user_id, gia'' coperta dal vincolo unique sopra).
-- Necessario invece un indice dedicato per "chi ha accesso a questa
-- organization", perche'' organization_id non e'' la colonna guida del
-- vincolo unique.
CREATE INDEX idx_user_org_roles_org_id ON core.user_organization_roles (organization_id);

COMMIT;
