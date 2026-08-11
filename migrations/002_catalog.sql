-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 002_catalog
-- Prerequisito: 001_foundation FINAL PASS (non modificata da questa migration)
-- Specifica di riferimento: v1 + Piano MVP v3 + Chiarimenti idempotenza v4 +
--                           Correzioni finali v5 + Analisi 002_catalog (approvata)
--
-- Contenuto di questa migration:
--   - core.parties
--   - core.party_roles
--   - core.products
--   - core.product_external_refs
--   - core.fn_validate_tax_rate_tenant() — funzione trigger riutilizzabile,
--     primo utilizzo su core.products.tax_rate_id, sarà riusata invariata
--     su sales_lines/purchase_lines in 004_sales/005_purchases.
--
-- NON incluso in questa migration (deliberatamente):
--   - Nessuna RLS (ENABLE ROW LEVEL SECURITY / CREATE POLICY): 006_rls_policies.
--   - Nessuna tabella raw/ops (003_raw_ops), sales/purchases (004/005),
--     finance/workforce/restaurant/crm/marketing.
--
-- Decisioni definitive applicate (round di approvazione 002_catalog):
--   1. default_uom_id NULLABLE, nessun CHECK dipendente da product_type.
--   2. sellable/purchasable/stock_managed NOT NULL, senza default.
--   3. Normalizzazione vat_number/tax_code: upper(trim(...)) via colonne
--      GENERATED STORED; nessuna rimozione prefisso paese, nessuna
--      validazione italiana specifica; valore originale sempre conservato.
--   4. mapping_status vincolato a CHECK ('proposed','confirmed','rejected').
--   5. confidence vincolata a CHECK (NULL oppure tra 0 e 1 inclusi).
--   6. core.fn_validate_tax_rate_tenant() creata qui, riusabile senza
--      duplicazione di logica (si basa sui nomi di colonna convenzionali
--      tax_rate_id/organization_id, presenti identici in ogni tabella che
--      la userà).
-- =============================================================================

BEGIN;

-- =============================================================================
-- 1. core.parties — identità del soggetto, non il ruolo
-- =============================================================================
CREATE TABLE core.parties (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    legal_name      text        NOT NULL,
    display_name    text,
    vat_number      text,
    tax_code        text,

    -- Colonne tecniche di deduplica: NON scrivibili direttamente, calcolate
    -- dal database. Normalizzazione minima e a basso rischio (trim + upper),
    -- nessuna rimozione di prefisso paese o validazione italiana specifica:
    -- decisione esplicita per restare riusabili fuori dall'Italia.
    vat_number_key  text        GENERATED ALWAYS AS (upper(trim(vat_number))) STORED,
    tax_code_key    text        GENERATED ALWAYS AS (upper(trim(tax_code))) STORED,

    email           text,
    phone           text,
    active          boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- Ancora per le FK composite tenant-safe delle tabelle figlie
    -- (core.party_roles ora; core.supplier_product_refs / purchase_documents
    -- nelle migration successive).
    CONSTRAINT uq_parties_org_id UNIQUE (organization_id, id)
);

COMMENT ON TABLE core.parties IS
    'Identità unica di una controparte (fornitore, cliente, altro). Il ruolo '
    'vive esclusivamente in core.party_roles: un soggetto con più ruoli non '
    'viene mai duplicato qui.';

COMMENT ON COLUMN core.parties.vat_number_key IS
    'Chiave tecnica di deduplica: upper(trim(vat_number)). Mai il valore da '
    'mostrare all''utente: usare vat_number per quello.';

COMMENT ON COLUMN core.parties.tax_code_key IS
    'Chiave tecnica di deduplica (fallback quando vat_number è assente): '
    'upper(trim(tax_code)).';

-- Deduplica primaria: al più un party per (organization, P.IVA normalizzata).
CREATE UNIQUE INDEX uq_parties_vat_active
    ON core.parties (organization_id, vat_number_key)
    WHERE vat_number_key IS NOT NULL;

-- Deduplica fallback: usata solo quando la P.IVA è assente.
CREATE UNIQUE INDEX uq_parties_taxcode_active
    ON core.parties (organization_id, tax_code_key)
    WHERE vat_number_key IS NULL AND tax_code_key IS NOT NULL;

CREATE TRIGGER trg_parties_set_updated_at
    BEFORE UPDATE ON core.parties
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 2. core.party_roles — ruoli di un party, storicizzati
-- =============================================================================
CREATE TABLE core.party_roles (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    party_id        uuid        NOT NULL,
    role            text        NOT NULL,
    valid_from      date        NOT NULL,
    valid_to        date,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- FK composita tenant-safe: un party_id di un'altra organization non può
    -- mai comparire qui, indipendentemente da cosa scrive organization_id.
    CONSTRAINT fk_party_roles_party
        FOREIGN KEY (organization_id, party_id)
        REFERENCES core.parties (organization_id, id)
        ON DELETE RESTRICT,

    -- Elenco chiuso volutamente minimo e non ristorazione-specifico.
    -- Estendibile in futuro solo tramite nuova migration versionata.
    CONSTRAINT chk_party_roles_role
        CHECK (role IN ('supplier', 'customer', 'other')),

    CONSTRAINT chk_party_roles_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

COMMENT ON TABLE core.party_roles IS
    'Ruoli di un party nel tempo. Un party può avere più ruoli attivi in '
    'parallelo (es. supplier e customer); non può avere due periodi '
    'sovrapposti dello stesso ruolo (uq_party_roles_active).';

-- Al più un ruolo attivo di un dato tipo per party.
CREATE UNIQUE INDEX uq_party_roles_active
    ON core.party_roles (organization_id, party_id, role)
    WHERE valid_to IS NULL;

-- Necessario perché l'indice sopra è parziale: serve un indice pieno per le
-- query su tutti i ruoli (inclusi quelli storici/chiusi) di un party.
CREATE INDEX idx_party_roles_org_party ON core.party_roles (organization_id, party_id);

CREATE TRIGGER trg_party_roles_set_updated_at
    BEFORE UPDATE ON core.party_roles
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 3. core.fn_validate_tax_rate_tenant() — validazione tenant non-FK
-- =============================================================================
-- core.tax_rates ammette righe globali (organization_id NULL): una FK
-- composita tenant-safe non è applicabile (non può fare match su un genitore
-- con organization_id NULL). Questa funzione sostituisce quella FK composita
-- impossibile con una validazione esplicita: la riga referenziata deve essere
-- globale oppure appartenere alla stessa organization del referenziatore.
--
-- Riutilizzabile senza modifiche su qualunque tabella che abbia colonne
-- "tax_rate_id" e "organization_id" con questi nomi esatti (convenzione già
-- rispettata in tutto il modello): usata ora da core.products, sarà usata
-- da core.sales_lines e core.purchase_lines nelle migration successive.
CREATE OR REPLACE FUNCTION core.fn_validate_tax_rate_tenant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_tax_rate_org uuid;
BEGIN
    IF NEW.tax_rate_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT organization_id INTO v_tax_rate_org
    FROM core.tax_rates
    WHERE id = NEW.tax_rate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'tax_rate_id % non esiste in core.tax_rates', NEW.tax_rate_id;
    END IF;

    IF v_tax_rate_org IS NOT NULL AND v_tax_rate_org <> NEW.organization_id THEN
        RAISE EXCEPTION
            'tax_rate_id % appartiene alla organization %, non a %',
            NEW.tax_rate_id, v_tax_rate_org, NEW.organization_id;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_validate_tax_rate_tenant() IS
    'Sostituisce la FK composita tenant-safe (impossibile per organization_id '
    'nullable su core.tax_rates): ammette aliquote globali o della stessa '
    'organization del referenziatore. Riusata da 004_sales/005_purchases.';

-- =============================================================================
-- 4. core.products — catalogo universale (materie prime, semilavorati,
--    prodotti finiti, voci vendute, servizi, voci di spesa)
-- =============================================================================
CREATE TABLE core.products (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    -- Opzionale per decisione approvata: l'UUID resta l'identificatore
    -- canonico. I codici dei sistemi esterni vivono nelle tabelle di mapping.
    code              text,
    name              text        NOT NULL,

    -- Testo libero, nessun CHECK: deve restare estendibile fuori dalla
    -- ristorazione. Valori applicativi noti: raw_material, semi_finished,
    -- finished_good, menu_item, service, expense_item, other.
    product_type      text        NOT NULL,
    category          text,

    -- Nullable per decisione approvata: non ogni product_type (es. service,
    -- expense_item) ha una unità di misura naturale. Nessun CHECK dipendente
    -- da product_type: quando una UoM reale esiste, la pipeline la valorizza.
    default_uom_id    uuid        REFERENCES core.units_of_measure(id) ON DELETE RESTRICT,

    -- FK semplice (non composita): core.tax_rates ammette righe globali.
    -- Coerenza tenant garantita da core.fn_validate_tax_rate_tenant(), non
    -- da un vincolo referenziale nativo.
    tax_rate_id       uuid        REFERENCES core.tax_rates(id) ON DELETE RESTRICT,

    -- Nessun default per decisione approvata: la classificazione deve essere
    -- sempre esplicita, mai un default silenzioso del database.
    sellable          boolean     NOT NULL,
    purchasable       boolean     NOT NULL,
    stock_managed     boolean     NOT NULL,

    active            boolean     NOT NULL DEFAULT true,
    valid_from        date        NOT NULL,
    valid_to          date,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    -- Ancora per le FK composite tenant-safe delle tabelle figlie
    -- (core.product_external_refs ora; sales_lines/purchase_lines/
    -- supplier_product_refs nelle migration successive).
    CONSTRAINT uq_products_org_id UNIQUE (organization_id, id)
);

COMMENT ON TABLE core.products IS
    'Catalogo unico di materie prime, semilavorati, prodotti finiti, voci '
    'vendute, servizi e voci di spesa. product_type resta testo libero per '
    'restare riusabile fuori dalla ristorazione.';

-- Al più un product per (organization, code) quando il code è valorizzato.
CREATE UNIQUE INDEX uq_products_org_code
    ON core.products (organization_id, code)
    WHERE code IS NOT NULL;

CREATE INDEX idx_products_default_uom_id ON core.products (default_uom_id);
CREATE INDEX idx_products_tax_rate_id ON core.products (tax_rate_id);

CREATE TRIGGER trg_products_set_updated_at
    BEFORE UPDATE ON core.products
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

CREATE TRIGGER trg_products_validate_tax_rate_tenant
    BEFORE INSERT OR UPDATE ON core.products
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_validate_tax_rate_tenant();

-- =============================================================================
-- 5. core.product_external_refs — mapping prodotto interno ↔ codice sorgente
-- =============================================================================
CREATE TABLE core.product_external_refs (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    product_id            uuid        NOT NULL,
    source_system_id      uuid        NOT NULL,

    external_id           text        NOT NULL,
    external_code         text,
    external_description  text,

    -- timestamptz per specifica originale di questa tabella (a differenza di
    -- party_roles/tax_rates, che usano date): preservato intenzionalmente.
    valid_from            timestamptz NOT NULL,
    valid_to              timestamptz,

    -- Elenco chiuso approvato per l'MVP: proposed / confirmed / rejected.
    mapping_status        text        NOT NULL,

    confidence            numeric(5,4),

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    -- FK composite tenant-safe: un product_id o source_system_id di
    -- un'altra organization non può mai comparire qui.
    CONSTRAINT fk_product_external_refs_product
        FOREIGN KEY (organization_id, product_id)
        REFERENCES core.products (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_external_refs_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_product_external_refs_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from),

    CONSTRAINT chk_product_external_refs_mapping_status
        CHECK (mapping_status IN ('proposed', 'confirmed', 'rejected')),

    CONSTRAINT chk_product_external_refs_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

COMMENT ON TABLE core.product_external_refs IS
    'Mappatura tra prodotto interno e codice/ID di un sistema sorgente. '
    'Storicizzata: al più un mapping attivo (valid_to IS NULL) per '
    '(organization, source_system, external_id).';

-- Al più un mapping attivo per (organization, source_system, external_id).
-- Un remap (stesso external_id spostato su un prodotto diverso) si fa
-- chiudendo la riga attiva e aprendone una nuova.
CREATE UNIQUE INDEX uq_product_external_refs_active
    ON core.product_external_refs (organization_id, source_system_id, external_id)
    WHERE valid_to IS NULL;

CREATE INDEX idx_product_external_refs_org_product
    ON core.product_external_refs (organization_id, product_id);

CREATE INDEX idx_product_external_refs_org_source
    ON core.product_external_refs (organization_id, source_system_id);

CREATE TRIGGER trg_product_external_refs_set_updated_at
    BEFORE UPDATE ON core.product_external_refs
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

COMMIT;
