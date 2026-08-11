-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 004_sales
-- Prerequisiti: 001_foundation FINAL PASS, 002_catalog FINAL PASS,
--               003_raw_ops FINAL PASS (nessuna delle tre modificata)
-- Specifica di riferimento: progettazione 004_sales approvata + Revisione
--                           finale (hardening architetturale, approvata)
--
-- Contenuto di questa migration:
--   - ALTER TABLE core.source_systems: aggiunta payment_sync_mode
--     (autorizzato esplicitamente in sede di Revisione Finale; il file
--     001_foundation.sql non viene toccato, questa è una migration
--     successiva che estende una tabella esistente — pratica normale ed
--     evolutiva nei sistemi di migration).
--   - core.payment_methods
--   - core.payment_method_external_refs
--   - core.management_rules
--   - core.sales_documents
--   - core.sales_lines
--   - core.sale_payments
--   - core.rule_classification_links
--
-- NON incluso in questa migration (deliberatamente):
--   - Nessuna RLS (ENABLE ROW LEVEL SECURITY / CREATE POLICY): 006_rls_policies.
--   - Nessuna tabella purchases/finance/workforce/restaurant/crm/marketing/
--     analytics, né ops.data_quality_issues.
--
-- Decisioni definitive applicate (Revisione Finale):
--   1. Tracciabilità management_date/service_period: core.rule_classification_links,
--      polimorfica sull'entità, fissa su management_rules — un documento può
--      avere più righe (una per regola concorrente), mai una singola FK
--      ingenua. Interamente append-only (riusa ops.fn_block_modification).
--   2. Pagamenti: la semantica (incrementale vs snapshot) è un contratto
--      dell'adapter dichiarato in core.source_systems.payment_sync_mode, non
--      un'assunzione hardcoded nel CORE. Refund/storno = nuova riga in
--      sale_payments (importo negativo, reversed_sale_payment_id), mai una
--      modifica distruttiva del pagamento originale.
--   3. Identità documento: sales_documents.external_id resta NOT NULL,
--      reinterpretato come "canonical source document key" (nativo o
--      adapter-derived — mai un hash del payload, che cambierebbe ad ogni
--      revisione). Nessuna seconda colonna: la distinzione nativo/derivato è
--      un contratto dell'adapter, documentato via commento, non un dato
--      interrogabile a runtime.
--   4. Reconciliation: nessun trigger/CHECK cross-tabella bloccante. Il
--      contratto futuro (matched / mismatch / incomplete_not_reconcilable)
--      è documentato ma non implementato qui.
-- =============================================================================

BEGIN;

-- =============================================================================
-- 0. ALTER core.source_systems — contratto dell'adapter per i pagamenti
-- =============================================================================
-- Autorizzato esplicitamente in sede di Revisione Finale. Non modifica il
-- file 001_foundation.sql (verificabile via MD5, invariato). NOT NULL con
-- default 'incremental': i source_systems già esistenti restano validi senza
-- richiedere un valore esplicito immediato.
ALTER TABLE core.source_systems
    ADD COLUMN payment_sync_mode text NOT NULL DEFAULT 'incremental';

ALTER TABLE core.source_systems
    ADD CONSTRAINT chk_source_systems_payment_sync_mode
    CHECK (payment_sync_mode IN ('incremental', 'snapshot'));

COMMENT ON COLUMN core.source_systems.payment_sync_mode IS
    'Contratto dell''adapter per core.sale_payments: "incremental" se la '
    'sorgente invia eventi di pagamento additivi (mai un delete/replace); '
    '"snapshot" se ogni evento rappresenta la collection completa e corrente '
    'dei pagamenti del documento (CORE riconcilia/sostituisce di conseguenza). '
    'Nessuna valvola di sfogo "other": guida un ramo di codice esplicito della '
    'pipeline, non una categoria di dominio libera.';

-- =============================================================================
-- 1. core.payment_methods — anagrafica canonica dei metodi di pagamento
-- =============================================================================
CREATE TABLE core.payment_methods (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    code            text        NOT NULL,
    name            text        NOT NULL,

    -- Elenco chiuso: method_type è la categoria canonica usata per il
    -- reporting cross-metodo (es. "quanto contante abbiamo incassato").
    -- Diverso da product_type/document_type/line_type (testo libero): qui la
    -- comparabilità tra organization/sorgenti è il punto stesso del campo.
    method_type     text        NOT NULL,

    provider        text,
    active          boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_payment_methods_org_code UNIQUE (organization_id, code),

    -- Ancora per le FK composite tenant-safe delle tabelle figlie
    -- (payment_method_external_refs, sale_payments).
    CONSTRAINT uq_payment_methods_org_id UNIQUE (organization_id, id),

    CONSTRAINT chk_payment_methods_method_type
        CHECK (method_type IN (
            'cash', 'card', 'satispay', 'meal_voucher', 'online',
            'delivery_platform', 'bank_transfer', 'other'
        ))
);

COMMENT ON TABLE core.payment_methods IS
    'Metodi di pagamento canonici di una organization. I nomi/codici delle '
    'sorgenti esterne si mappano qui tramite core.payment_method_external_refs.';

CREATE TRIGGER trg_payment_methods_set_updated_at
    BEFORE UPDATE ON core.payment_methods
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 2. core.payment_method_external_refs — mapping nomi sorgente → metodo canonico
-- =============================================================================
CREATE TABLE core.payment_method_external_refs (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    payment_method_id     uuid        NOT NULL,
    source_system_id      uuid        NOT NULL,

    external_id           text        NOT NULL,
    external_code         text,
    external_description  text,

    valid_from            timestamptz NOT NULL,
    valid_to              timestamptz,

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_payment_method_external_refs_method
        FOREIGN KEY (organization_id, payment_method_id)
        REFERENCES core.payment_methods (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_payment_method_external_refs_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_payment_method_external_refs_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

COMMENT ON TABLE core.payment_method_external_refs IS
    'Mappatura tra un metodo di pagamento canonico e il nome/codice usato da '
    'un sistema sorgente (es. "Carta Visa", "POS Nexi" → method cash/card '
    'canonico). Storicizzata: al più un mapping attivo per '
    '(organization, source_system, external_id), stesso pattern di '
    'core.product_external_refs.';

CREATE UNIQUE INDEX uq_payment_method_external_refs_active
    ON core.payment_method_external_refs (organization_id, source_system_id, external_id)
    WHERE valid_to IS NULL;

CREATE INDEX idx_payment_method_external_refs_org_method
    ON core.payment_method_external_refs (organization_id, payment_method_id);

CREATE INDEX idx_payment_method_external_refs_org_source
    ON core.payment_method_external_refs (organization_id, source_system_id);

CREATE TRIGGER trg_payment_method_external_refs_set_updated_at
    BEFORE UPDATE ON core.payment_method_external_refs
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 3. core.management_rules — regole configurabili (management_date, service_period)
-- =============================================================================
CREATE TABLE core.management_rules (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    -- NULL = regola org-wide (default); valorizzato = override per sede
    -- specifica. Entrambe possono coesistere attive: risoluzione a carico
    -- della pipeline (sede prevale su org-wide).
    location_id     uuid,

    rule_type       text        NOT NULL,
    rule_name       text        NOT NULL,

    -- Tie-break secondario quando più regole dello stesso livello potrebbero
    -- risultare applicabili. La risoluzione primaria resta la specificità
    -- (sede batte org-wide), non priority.
    priority        integer     NOT NULL DEFAULT 0,

    configuration   jsonb       NOT NULL,

    valid_from      date        NOT NULL,
    valid_to        date,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- Ancora per la FK composita tenant-safe di core.rule_classification_links.
    CONSTRAINT uq_management_rules_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_management_rules_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_management_rules_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

COMMENT ON TABLE core.management_rules IS
    'Regole configurabili per calcolare management_date/service_period senza '
    'hardcodare logica di business nel software. Storicizzata (valid_from/'
    'valid_to): nessun campo active separato, chiudere una regola = '
    'valorizzare valid_to, stesso pattern di tax_rates/party_roles/'
    'product_external_refs.';

-- Al più una regola attiva per sede, per (tipo, nome).
CREATE UNIQUE INDEX uq_management_rules_active_by_location
    ON core.management_rules (organization_id, location_id, rule_type, rule_name)
    WHERE valid_to IS NULL AND location_id IS NOT NULL;

-- Al più una regola org-wide attiva per (tipo, nome).
CREATE UNIQUE INDEX uq_management_rules_active_orgwide
    ON core.management_rules (organization_id, rule_type, rule_name)
    WHERE valid_to IS NULL AND location_id IS NULL;

CREATE TRIGGER trg_management_rules_set_updated_at
    BEFORE UPDATE ON core.management_rules
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 4. core.sales_documents — documento/scontrino/comanda consolidata
-- =============================================================================
CREATE TABLE core.sales_documents (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    -- NOT NULL: ogni vendita è attribuita a una sede, anche i canali senza
    -- sede fisica diretta (e-commerce/centrale), tramite una location
    -- virtuale esplicitamente censita in core.locations.
    location_id             uuid        NOT NULL,

    source_system_id        uuid        NOT NULL,

    -- Chiave canonica del documento sorgente: nativa se la sorgente la
    -- fornisce, altrimenti derivata deterministicamente dall'adapter da campi
    -- di business stabili — mai da un hash del payload (vedi commento sotto).
    external_id              text       NOT NULL,

    -- Stato RAW corrente. La storia completa (origin/update/storno) vive in
    -- ops.entity_raw_links.
    source_raw_event_id      uuid       NOT NULL,

    document_type            text       NOT NULL,
    document_number           text,

    -- Mai derivata da management_date: il dato fiscale originale.
    fiscal_date                date     NOT NULL,

    -- Calcolata da core.management_rules, liberamente ricalcolabile (vedi
    -- trigger di provenance più sotto): NON è dato fiscale.
    management_date             date    NOT NULL,

    -- Traccia se il valore corrente è stato calcolato dal motore regole o
    -- corretto manualmente. Il "perché" dettagliato vive in
    -- core.rule_classification_links.
    management_date_source        text NOT NULL DEFAULT 'rule_engine',

    service_period                  text,

    opened_at                         timestamptz,
    closed_at                          timestamptz NOT NULL,
    fiscal_issued_at                    timestamptz,

    customer_party_id                    uuid,

    -- Generico: NULL fuori dalla ristorazione, innocuo per altri verticali.
    covers                                 integer,
    channel                                  text,

    subtotal_net                              numeric(14,2) NOT NULL,
    discount_amount                            numeric(14,2) NOT NULL DEFAULT 0,
    service_charge_amount                       numeric(14,2) NOT NULL DEFAULT 0,
    tip_amount                                   numeric(14,2) NOT NULL DEFAULT 0,
    tax_amount                                    numeric(14,2) NOT NULL,
    rounding_amount                                numeric(14,2) NOT NULL DEFAULT 0,

    -- Totale fiscale autoritativo.
    total_gross                                     numeric(14,2) NOT NULL,

    currency                                          char(3) NOT NULL DEFAULT 'EUR',
    status                                              text NOT NULL DEFAULT 'open',

    created_at                                           timestamptz NOT NULL DEFAULT now(),
    updated_at                                            timestamptz NOT NULL DEFAULT now(),

    -- Ancora per le FK composite tenant-safe delle tabelle figlie
    -- (sales_lines, sale_payments, rule_classification_links via entity
    -- polimorfica).
    CONSTRAINT uq_sales_documents_org_id UNIQUE (organization_id, id),

    -- Idempotenza documento: nessun duplicato per lo stesso documento
    -- sorgente. Una revisione (stesso external_id, nuovo raw event) fa
    -- UPDATE di questa riga, mai un nuovo insert.
    CONSTRAINT uq_sales_documents_source_external UNIQUE (source_system_id, external_id),

    CONSTRAINT fk_sales_documents_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sales_documents_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sales_documents_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sales_documents_customer_party
        FOREIGN KEY (organization_id, customer_party_id)
        REFERENCES core.parties (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_sales_documents_status
        CHECK (status IN ('open', 'closed', 'voided', 'refunded', 'partially_refunded')),

    CONSTRAINT chk_sales_documents_management_date_source
        CHECK (management_date_source IN ('rule_engine', 'manual_override')),

    -- Unico CHECK temporale: non si può chiudere prima di aprire. Nessun
    -- altro vincolo temporale: non deve impedire servizio dopo mezzanotte,
    -- chiusure tardive, correzioni fiscali o vendite online (vedi
    -- progettazione approvata).
    CONSTRAINT chk_sales_documents_temporal
        CHECK (opened_at IS NULL OR closed_at >= opened_at)
);

COMMENT ON TABLE core.sales_documents IS
    'Documento di vendita consolidato (scontrino/comanda/ordine). '
    'fiscal_date e management_date sono sempre concetti distinti: la prima '
    'non è mai derivata dalla seconda né viceversa.';

COMMENT ON COLUMN core.sales_documents.external_id IS
    'Chiave canonica del documento sorgente. Nativa se la sorgente la '
    'fornisce; altrimenti derivata deterministicamente dall''adapter da campi '
    'di business stabili (es. terminale + data operativa + progressivo) — mai '
    'da un hash del payload, che cambierebbe ad ogni revisione facendola '
    'apparire come un documento nuovo.';

COMMENT ON COLUMN core.sales_documents.management_date IS
    'Data operativa di attribuzione (es. servizio cena 18:30→03:00: le '
    'vendite dopo mezzanotte restano sul giorno precedente). Calcolata da '
    'core.management_rules, mai derivata rigidamente da fiscal_date. '
    'Liberamente ricalcolabile: vedi trigger di provenance (non richiede un '
    'nuovo source_raw_event_id). Il dettaglio delle regole che hanno '
    'concorso al calcolo vive in core.rule_classification_links.';

CREATE INDEX idx_sales_documents_org_management_date
    ON core.sales_documents (organization_id, management_date);

CREATE INDEX idx_sales_documents_location_management_date
    ON core.sales_documents (location_id, management_date);

CREATE INDEX idx_sales_documents_org_fiscal_date
    ON core.sales_documents (organization_id, fiscal_date);

CREATE INDEX idx_sales_documents_source_raw_event
    ON core.sales_documents (source_raw_event_id);

CREATE INDEX idx_sales_documents_customer_party
    ON core.sales_documents (customer_party_id)
    WHERE customer_party_id IS NOT NULL;

CREATE TRIGGER trg_sales_documents_set_updated_at
    BEFORE UPDATE ON core.sales_documents
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- Trigger di provenance a tre livelli: protegge il dato fiscale senza
-- bloccare la classificazione gestionale.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_protect_sales_document_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Livello 1 — identità: mai modificabile, in nessun caso. Se questi
    -- campi devono cambiare, è un documento diverso, non una revisione.
    IF NEW.organization_id  IS DISTINCT FROM OLD.organization_id OR
       NEW.location_id      IS DISTINCT FROM OLD.location_id OR
       NEW.source_system_id IS DISTINCT FROM OLD.source_system_id OR
       NEW.external_id      IS DISTINCT FROM OLD.external_id
    THEN
        RAISE EXCEPTION
            'sales_documents: organization_id/location_id/source_system_id/external_id sono identità immutabili (id=%)',
            OLD.id;
    END IF;

    -- Livello 2 — dati fiscali/sorgente: modificabili solo insieme a un
    -- nuovo source_raw_event_id (evidenza RAW della revisione).
    IF (NEW.document_type         IS DISTINCT FROM OLD.document_type OR
        NEW.document_number       IS DISTINCT FROM OLD.document_number OR
        NEW.fiscal_date           IS DISTINCT FROM OLD.fiscal_date OR
        NEW.fiscal_issued_at      IS DISTINCT FROM OLD.fiscal_issued_at OR
        NEW.opened_at             IS DISTINCT FROM OLD.opened_at OR
        NEW.closed_at             IS DISTINCT FROM OLD.closed_at OR
        NEW.customer_party_id     IS DISTINCT FROM OLD.customer_party_id OR
        NEW.covers                IS DISTINCT FROM OLD.covers OR
        NEW.channel                IS DISTINCT FROM OLD.channel OR
        NEW.subtotal_net            IS DISTINCT FROM OLD.subtotal_net OR
        NEW.discount_amount          IS DISTINCT FROM OLD.discount_amount OR
        NEW.service_charge_amount     IS DISTINCT FROM OLD.service_charge_amount OR
        NEW.tip_amount                 IS DISTINCT FROM OLD.tip_amount OR
        NEW.tax_amount                  IS DISTINCT FROM OLD.tax_amount OR
        NEW.rounding_amount               IS DISTINCT FROM OLD.rounding_amount OR
        NEW.total_gross                    IS DISTINCT FROM OLD.total_gross OR
        NEW.currency                        IS DISTINCT FROM OLD.currency OR
        NEW.status                           IS DISTINCT FROM OLD.status)
       AND NEW.source_raw_event_id IS NOT DISTINCT FROM OLD.source_raw_event_id
    THEN
        RAISE EXCEPTION
            'sales_documents: campo fiscale modificato senza un nuovo source_raw_event_id (id=%)',
            OLD.id;
    END IF;

    -- Livello 3 — management_date, service_period, management_date_source:
    -- nessun controllo. Classificazione della Centrale, liberamente
    -- ricalcolabile senza un nuovo evento RAW.

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_sales_document_provenance() IS
    'Tre livelli: identità mai modificabile; dati fiscali modificabili solo '
    'con un nuovo source_raw_event_id; management_date/service_period/'
    'management_date_source liberamente ricalcolabili (non sono dato fiscale).';

CREATE TRIGGER trg_sales_documents_protect_provenance
    BEFORE UPDATE ON core.sales_documents
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_sales_document_provenance();

-- =============================================================================
-- 5. core.sales_lines — dettaglio riga per riga
-- =============================================================================
CREATE TABLE core.sales_lines (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    sales_document_id   uuid        NOT NULL,

    -- Nullable: una riga può non essere ancora mappata a un prodotto interno
    -- (in attesa di risoluzione, es. via ops.mapping_queue).
    product_id           uuid,

    -- Posizione business (stampata sullo scontrino), distinta da
    -- source_line_ordinal (tecnico, solo fallback di idempotenza).
    line_number            integer,

    source_raw_event_id      uuid    NOT NULL,
    source_line_id            text,
    source_line_ordinal        integer,

    description                  text,
    quantity                      numeric(14,4) NOT NULL,
    uom_id                          uuid,

    unit_price_gross                 numeric(14,4) NOT NULL,
    unit_price_net                    numeric(14,4),

    discount_amount                    numeric(14,2) NOT NULL DEFAULT 0,
    net_amount                          numeric(14,2) NOT NULL,
    tax_rate_id                          uuid,
    tax_amount                            numeric(14,2) NOT NULL,
    gross_amount                           numeric(14,2) NOT NULL,

    -- Libero: product, service, discount, cover_charge, tip, other... deve
    -- restare estendibile a righe future non ancora previste.
    line_type                                text NOT NULL,

    created_at                                 timestamptz NOT NULL DEFAULT now(),
    updated_at                                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_sales_lines_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_sales_lines_document
        FOREIGN KEY (organization_id, sales_document_id)
        REFERENCES core.sales_documents (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sales_lines_product
        FOREIGN KEY (organization_id, product_id)
        REFERENCES core.products (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sales_lines_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    -- FK semplice (non composita): core.units_of_measure è globale, nessuna
    -- colonna organization_id, nessuna questione tenant possibile.
    CONSTRAINT fk_sales_lines_uom
        FOREIGN KEY (uom_id)
        REFERENCES core.units_of_measure (id)
        ON DELETE RESTRICT,

    -- FK semplice (non composita): core.tax_rates ammette righe globali.
    -- Coerenza tenant garantita da core.fn_validate_tax_rate_tenant()
    -- (riusata invariata da 002_catalog).
    CONSTRAINT fk_sales_lines_tax_rate
        FOREIGN KEY (tax_rate_id)
        REFERENCES core.tax_rates (id)
        ON DELETE RESTRICT,

    -- Idempotenza righe: id stabile quando disponibile, altrimenti fallback
    -- ancorato allo specifico evento RAW che ha prodotto la riga (mai un
    -- ordinale "nel tempo", che non è stabile tra revisioni diverse).
    CONSTRAINT uq_sales_lines_stable_id
        UNIQUE (sales_document_id, source_line_id)
);

-- L'UNIQUE sopra su (sales_document_id, source_line_id) si applica solo
-- quando source_line_id è valorizzato (NULL non collide mai con NULL in
-- PostgreSQL): nessuna modifica necessaria, è già il comportamento corretto.
-- Serve invece un indice parziale esplicito per il fallback ordinale.
CREATE UNIQUE INDEX uq_sales_lines_fallback_ordinal
    ON core.sales_lines (sales_document_id, source_raw_event_id, source_line_ordinal)
    WHERE source_line_id IS NULL;

COMMENT ON TABLE core.sales_lines IS
    'Dettaglio riga per riga di un documento di vendita: prodotti, servizi, '
    'sconti, coperto, mance, altre righe future (line_type libero). Nessun '
    'CHECK sul segno di quantity/importi: righe di sconto possono avere '
    'legittimamente importi negativi.';

CREATE INDEX idx_sales_lines_org_document ON core.sales_lines (organization_id, sales_document_id);

CREATE INDEX idx_sales_lines_org_product
    ON core.sales_lines (organization_id, product_id)
    WHERE product_id IS NOT NULL;

CREATE INDEX idx_sales_lines_tax_rate ON core.sales_lines (tax_rate_id);

CREATE TRIGGER trg_sales_lines_set_updated_at
    BEFORE UPDATE ON core.sales_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

CREATE TRIGGER trg_sales_lines_validate_tax_rate_tenant
    BEFORE INSERT OR UPDATE ON core.sales_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_validate_tax_rate_tenant();

-- ---------------------------------------------------------------------------
-- Trigger di provenance a tre livelli, analogo a sales_documents: product_id
-- è l'unico campo di "classificazione CORE" liberamente ricalcolabile (una
-- risoluzione di mapping successiva non richiede un nuovo evento RAW).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_protect_sales_line_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Livello 1 — identità: mai modificabile.
    IF NEW.organization_id      IS DISTINCT FROM OLD.organization_id OR
       NEW.sales_document_id    IS DISTINCT FROM OLD.sales_document_id OR
       NEW.source_line_id       IS DISTINCT FROM OLD.source_line_id OR
       NEW.source_line_ordinal  IS DISTINCT FROM OLD.source_line_ordinal
    THEN
        RAISE EXCEPTION
            'sales_lines: organization_id/sales_document_id/source_line_id/source_line_ordinal sono identità immutabili (id=%)',
            OLD.id;
    END IF;

    -- Livello 2 — dati fiscali/sorgente: modificabili solo con un nuovo
    -- source_raw_event_id.
    IF (NEW.line_number      IS DISTINCT FROM OLD.line_number OR
        NEW.description       IS DISTINCT FROM OLD.description OR
        NEW.quantity           IS DISTINCT FROM OLD.quantity OR
        NEW.uom_id              IS DISTINCT FROM OLD.uom_id OR
        NEW.unit_price_gross     IS DISTINCT FROM OLD.unit_price_gross OR
        NEW.unit_price_net        IS DISTINCT FROM OLD.unit_price_net OR
        NEW.discount_amount        IS DISTINCT FROM OLD.discount_amount OR
        NEW.net_amount               IS DISTINCT FROM OLD.net_amount OR
        NEW.tax_rate_id                IS DISTINCT FROM OLD.tax_rate_id OR
        NEW.tax_amount                  IS DISTINCT FROM OLD.tax_amount OR
        NEW.gross_amount                  IS DISTINCT FROM OLD.gross_amount OR
        NEW.line_type                       IS DISTINCT FROM OLD.line_type)
       AND NEW.source_raw_event_id IS NOT DISTINCT FROM OLD.source_raw_event_id
    THEN
        RAISE EXCEPTION
            'sales_lines: campo fiscale modificato senza un nuovo source_raw_event_id (id=%)',
            OLD.id;
    END IF;

    -- Livello 3 — product_id: risoluzione di mapping, liberamente
    -- ricalcolabile senza un nuovo evento RAW.

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_sales_line_provenance() IS
    'Stesso modello a tre livelli di core.fn_protect_sales_document_provenance(): '
    'product_id (risoluzione di mapping) è l''unico campo liberamente '
    'ricalcolabile senza un nuovo source_raw_event_id.';

CREATE TRIGGER trg_sales_lines_protect_provenance
    BEFORE UPDATE ON core.sales_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_sales_line_provenance();

-- =============================================================================
-- 6. core.sale_payments — pagamenti effettivi del documento
-- =============================================================================
CREATE TABLE core.sale_payments (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id          uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    sales_document_id        uuid        NOT NULL,
    payment_method_id        uuid        NOT NULL,
    source_raw_event_id      uuid        NOT NULL,

    external_id                text,
    source_payment_ordinal      integer,

    -- Self-reference: un rimborso/storno è sempre una NUOVA riga (importo
    -- negativo) che punta al pagamento originale, mai una modifica
    -- distruttiva di quest'ultimo. Copre sia il rimborso totale sia quello
    -- parziale senza ambiguità: l'importo negativo netta correttamente la
    -- somma in entrambi i casi.
    reversed_sale_payment_id     uuid,

    amount                          numeric(14,2) NOT NULL,
    currency                          char(3) NOT NULL DEFAULT 'EUR',
    paid_at                            timestamptz NOT NULL,
    status                               text NOT NULL DEFAULT 'completed',

    created_at                            timestamptz NOT NULL DEFAULT now(),
    updated_at                             timestamptz NOT NULL DEFAULT now(),

    -- Ancora tenant-safe: necessaria per reversed_sale_payment_id (self-FK
    -- composita), stesso pattern di ops.sync_runs.retry_of_run_id.
    CONSTRAINT uq_sale_payments_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_sale_payments_document
        FOREIGN KEY (organization_id, sales_document_id)
        REFERENCES core.sales_documents (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sale_payments_method
        FOREIGN KEY (organization_id, payment_method_id)
        REFERENCES core.payment_methods (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sale_payments_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_sale_payments_reversed
        FOREIGN KEY (organization_id, reversed_sale_payment_id)
        REFERENCES core.sale_payments (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_sale_payments_status
        CHECK (status IN ('completed', 'pending', 'refunded', 'partially_refunded', 'failed', 'other')),

    CONSTRAINT uq_sale_payments_stable_id
        UNIQUE (sales_document_id, external_id)
);

CREATE UNIQUE INDEX uq_sale_payments_fallback_ordinal
    ON core.sale_payments (sales_document_id, source_raw_event_id, source_payment_ordinal)
    WHERE external_id IS NULL;

COMMENT ON TABLE core.sale_payments IS
    'Pagamenti effettivi di un documento di vendita, anche misti (es. carta + '
    'contanti + buoni pasto). Strategia di sincronizzazione (additiva o a '
    'sostituzione) determinata da core.source_systems.payment_sync_mode, non '
    'hardcoded qui.';

COMMENT ON COLUMN core.sale_payments.reversed_sale_payment_id IS
    'Valorizzato solo sulla riga che rappresenta un rimborso/storno: punta al '
    'pagamento originale reso reversibile. Il pagamento originale non viene '
    'mai cancellato né alterato nei suoi importi/paid_at originali.';

CREATE INDEX idx_sale_payments_org_document ON core.sale_payments (organization_id, sales_document_id);

CREATE INDEX idx_sale_payments_org_method_paid_at
    ON core.sale_payments (organization_id, payment_method_id, paid_at);

CREATE INDEX idx_sale_payments_reversed
    ON core.sale_payments (reversed_sale_payment_id)
    WHERE reversed_sale_payment_id IS NOT NULL;

CREATE TRIGGER trg_sale_payments_set_updated_at
    BEFORE UPDATE ON core.sale_payments
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

CREATE OR REPLACE FUNCTION core.fn_protect_sale_payment_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Livello 1 — identità: mai modificabile.
    IF NEW.organization_id           IS DISTINCT FROM OLD.organization_id OR
       NEW.sales_document_id         IS DISTINCT FROM OLD.sales_document_id OR
       NEW.payment_method_id         IS DISTINCT FROM OLD.payment_method_id OR
       NEW.external_id               IS DISTINCT FROM OLD.external_id OR
       NEW.source_payment_ordinal    IS DISTINCT FROM OLD.source_payment_ordinal OR
       NEW.reversed_sale_payment_id  IS DISTINCT FROM OLD.reversed_sale_payment_id
    THEN
        RAISE EXCEPTION
            'sale_payments: campi identitari immutabili modificati (id=%)', OLD.id;
    END IF;

    -- Livello 2 — dati fiscali: modificabili solo con un nuovo
    -- source_raw_event_id.
    IF (NEW.amount   IS DISTINCT FROM OLD.amount OR
        NEW.currency  IS DISTINCT FROM OLD.currency OR
        NEW.paid_at    IS DISTINCT FROM OLD.paid_at OR
        NEW.status      IS DISTINCT FROM OLD.status)
       AND NEW.source_raw_event_id IS NOT DISTINCT FROM OLD.source_raw_event_id
    THEN
        RAISE EXCEPTION
            'sale_payments: campo fiscale modificato senza un nuovo source_raw_event_id (id=%)',
            OLD.id;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_sale_payment_provenance() IS
    'Stesso modello a due livelli attivi di sales_documents/sales_lines '
    '(nessun campo di classificazione CORE su sale_payments, quindi nessun '
    'Livello 3).';

CREATE TRIGGER trg_sale_payments_protect_provenance
    BEFORE UPDATE ON core.sale_payments
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_sale_payment_provenance();

-- =============================================================================
-- 7. core.rule_classification_links — perché a management_date/service_period
-- =============================================================================
-- Stesso pattern polimorfico di ops.entity_raw_links (fisso sulla sorgente,
-- polimorfico sull'entità), applicato qui a core.management_rules invece che
-- a raw.ingest_events. Più righe con la stessa applied_at rappresentano più
-- regole che hanno concorso alla stessa classificazione: evita
-- deliberatamente una singola FK che non rappresenterebbe correttamente il
-- modello.
CREATE TABLE core.rule_classification_links (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    core_entity_type     text        NOT NULL,
    core_entity_id        uuid       NOT NULL,

    management_rule_id     uuid      NOT NULL,
    role                      text    NOT NULL,

    applied_at                  timestamptz NOT NULL DEFAULT now(),
    created_at                    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_rule_classification_links_rule
        FOREIGN KEY (organization_id, management_rule_id)
        REFERENCES core.management_rules (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_rule_classification_links_role
        CHECK (role IN ('service_period_match', 'operational_cutoff_fallback', 'manual_override', 'other')),

    CONSTRAINT uq_rule_classification_links_dedup
        UNIQUE (management_rule_id, core_entity_type, core_entity_id, role, applied_at)
);

COMMENT ON TABLE core.rule_classification_links IS
    'Storia completa di quali management_rules hanno concorso a determinare '
    'la management_date/service_period di un''entità CORE (oggi: '
    'sales_document). Interamente append-only (vedi trigger): mai modificata '
    'né cancellata.';

CREATE INDEX idx_rule_classification_links_org_entity
    ON core.rule_classification_links (organization_id, core_entity_type, core_entity_id);

-- Riusa la funzione generica già creata in 003_raw_ops (ops.fn_block_modification):
-- nessuna duplicazione di logica, stesso trigger applicato cross-schema a
-- ops.entity_raw_links, ops.audit_log e ora core.rule_classification_links.
CREATE TRIGGER trg_rule_classification_links_immutability
    BEFORE UPDATE OR DELETE ON core.rule_classification_links
    FOR EACH ROW
    EXECUTE FUNCTION ops.fn_block_modification();

COMMIT;
