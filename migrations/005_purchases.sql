-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 005_purchases
-- Prerequisiti: 001_foundation FINAL PASS, 002_catalog FINAL PASS,
--               003_raw_ops FINAL PASS, 004_sales FINAL PASS
--               (nessuna delle quattro modificata)
-- Specifica di riferimento: progettazione 005_purchases approvata +
--                           Revisione finale di hardening (approvata)
--
-- Contenuto di questa migration:
--   - core.purchase_documents
--   - core.purchase_lines
--   - core.supplier_product_refs
--   - core.product_purchase_prices
--
-- NON incluso in questa migration (deliberatamente):
--   - Nessuna RLS (ENABLE ROW LEVEL SECURITY / CREATE POLICY): 006_rls_policies.
--   - Nessun management_date/management_rules equivalente per gli acquisti:
--     document_date + received_at sono sufficienti (nessun problema di
--     attribuzione "a cavallo di mezzanotte" analogo alle vendite).
--   - Nessun prezzo contrattuale/listino: product_purchase_prices è
--     esclusivamente il prezzo osservato/transazionale.
--   - Nessuna tabella finance/workforce/restaurant/crm/marketing/analytics,
--     né landed cost/costo gestionale.
--   - Nessuna gerarchia di packaging strutturata multilivello.
--
-- Decisioni definitive applicate (progettazione + hardening):
--   1. Nota di credito = SEMPRE un purchase_documents separato
--      (document_type='credit_note', reversed_purchase_document_id), mai una
--      modifica distruttiva del documento originale.
--   2. purchase_lines.superseded_at: mai un delete fisico di una riga
--      revisionata, perché product_purchase_prices referenzia
--      purchase_lines.id con ON DELETE RESTRICT ed è essa stessa append-only.
--   3. supplier_product_refs è l'unico percorso di risoluzione prodotto per
--      gli acquisti in questo MVP; product_external_refs resta non
--      utilizzata da questo modulo.
--   4. product_purchase_prices è uno snapshot congelato e immutabile
--      (ops.fn_block_modification riusata una quarta volta): base_uom_id e
--      conversion_factor_applied sono congelati riga per riga, mai
--      risincronizzati da correzioni successive di supplier_product_refs.
--      product_id è congelato allo stesso modo (stessa filosofia di
--      management_date in 004_sales: stabilità storica dei report prevale
--      sulla sincronizzazione live con lo stato corrente).
--   5. unit_price_base_uom è sempre >= 0: la direzione della transazione
--      (acquisto vs nota di credito) è portata dal segno di
--      quantity_base_uom, mai dal prezzo unitario.
--   6. Nessun CHECK temporale su purchase_documents (a differenza di
--      sales_documents): document_date/received_at/due_date non hanno una
--      relazione d'ordine sempre garantita nella realtà.
--   7. purchase_documents.status è classificazione CORE di Livello 3
--      (liberamente ricalcolabile): una nota di credito che referenzia un
--      documento originale ne aggiorna lo status (es. 'credited') senza
--      richiedere un nuovo source_raw_event_id sul documento originale.
-- =============================================================================

BEGIN;

-- =============================================================================
-- 1. core.purchase_documents — fattura/documento di acquisto consolidato
-- =============================================================================
CREATE TABLE core.purchase_documents (
    id                              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id                 uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    -- Nullable: a differenza di sales_documents.location_id (NOT NULL), gli
    -- acquisti sono spesso centralizzati a livello di organization (un unico
    -- ufficio acquisti per più sedi).
    location_id                     uuid,

    source_system_id                uuid        NOT NULL,

    -- Identità del fornitore: Livello 1 (vedi trigger di provenance). Un
    -- fornitore diverso non è mai una revisione dello stesso documento, ma un
    -- documento diverso.
    supplier_id                     uuid        NOT NULL,

    -- Chiave canonica del documento sorgente: nativa se la sorgente la
    -- fornisce, altrimenti derivata deterministicamente dall'adapter da campi
    -- di business stabili — mai da un hash del payload (stesso trattamento di
    -- sales_documents.external_id).
    external_id                     text        NOT NULL,

    -- Stato RAW corrente. La storia completa (origin/update/storno) vive in
    -- ops.entity_raw_links.
    source_raw_event_id             uuid        NOT NULL,

    -- Self-reference: una nota di credito è sempre un documento fiscale a sé
    -- stante che punta al documento originale, mai una modifica distruttiva
    -- di quest'ultimo. Valorizzato solo sulla riga che rappresenta lo storno.
    reversed_purchase_document_id   uuid,

    -- Libero, nessun CHECK: purchase_invoice, credit_note, ddt, other... deve
    -- restare estendibile a tipi documento non ancora previsti.
    document_type                   text        NOT NULL,
    document_number                 text,

    -- Data fiscale/del fornitore (ruolo equivalente a fiscal_date).
    document_date                   date        NOT NULL,

    -- Quando il documento è stato effettivamente ricevuto (può differire
    -- significativamente da document_date).
    received_at                     timestamptz,
    due_date                        date,

    subtotal_net                    numeric(14,2) NOT NULL,
    discount_amount                 numeric(14,2) NOT NULL DEFAULT 0,
    tax_amount                      numeric(14,2) NOT NULL,
    rounding_amount                 numeric(14,2) NOT NULL DEFAULT 0,

    -- Totale fiscale autoritativo.
    total_gross                     numeric(14,2) NOT NULL,

    currency                        char(3)     NOT NULL DEFAULT 'EUR',

    -- Livello 3: classificazione amministrativa liberamente ricalcolabile
    -- dalla pipeline (es. quando una nota di credito collegata viene
    -- registrata), non dato fiscale originale. Vedi trigger di provenance.
    status                          text        NOT NULL DEFAULT 'open',

    created_at                      timestamptz NOT NULL DEFAULT now(),
    updated_at                      timestamptz NOT NULL DEFAULT now(),

    -- Ancora per le FK composite tenant-safe delle tabelle figlie
    -- (purchase_lines, product_purchase_prices) e per il self-FK.
    CONSTRAINT uq_purchase_documents_org_id UNIQUE (organization_id, id),

    -- Idempotenza documento: nessun duplicato per lo stesso documento
    -- sorgente. Una revisione (stesso external_id, nuovo raw event) fa UPDATE
    -- di questa riga, mai un nuovo insert.
    CONSTRAINT uq_purchase_documents_source_external UNIQUE (source_system_id, external_id),

    CONSTRAINT fk_purchase_documents_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_documents_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_documents_supplier
        FOREIGN KEY (organization_id, supplier_id)
        REFERENCES core.parties (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_documents_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_documents_reversed
        FOREIGN KEY (organization_id, reversed_purchase_document_id)
        REFERENCES core.purchase_documents (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_purchase_documents_status
        CHECK (status IN ('open', 'closed', 'voided', 'credited', 'partially_credited'))

    -- Nessun CHECK temporale (decisione esplicita, vedi header): a differenza
    -- di sales_documents.chk_sales_documents_temporal, qui non esiste una
    -- relazione d'ordine tra document_date/received_at/due_date abbastanza
    -- certa da vincolare senza rischiare di rifiutare documenti reali.
);

COMMENT ON TABLE core.purchase_documents IS
    'Documento di acquisto consolidato (fattura/nota di credito/DDT). Nessun '
    'campo "spese accessorie" a livello documento: trasporto/imballaggio sono '
    'rappresentati come purchase_lines proprie (line_type), non un '
    'sovrapprezzo aggregato duplicato.';

COMMENT ON COLUMN core.purchase_documents.external_id IS
    'Chiave canonica del documento sorgente. Nativa se la sorgente la '
    'fornisce; altrimenti derivata deterministicamente dall''adapter da campi '
    'di business stabili — mai da un hash del payload, che cambierebbe ad '
    'ogni revisione facendola apparire come un documento nuovo.';

COMMENT ON COLUMN core.purchase_documents.reversed_purchase_document_id IS
    'Valorizzato solo sulla riga che rappresenta una nota di credito/storno: '
    'punta al documento originale. Il documento originale non viene mai '
    'cancellato né alterato nei suoi importi/date fiscali originali.';

COMMENT ON COLUMN core.purchase_documents.status IS
    'Classificazione amministrativa di Livello 3 (vedi trigger di '
    'provenance): liberamente ricalcolabile, ad es. quando una nota di '
    'credito collegata via reversed_purchase_document_id viene registrata. '
    'Non è dato fiscale originale.';

CREATE INDEX idx_purchase_documents_org_document_date
    ON core.purchase_documents (organization_id, document_date);

CREATE INDEX idx_purchase_documents_location_document_date
    ON core.purchase_documents (location_id, document_date)
    WHERE location_id IS NOT NULL;

CREATE INDEX idx_purchase_documents_org_supplier
    ON core.purchase_documents (organization_id, supplier_id);

CREATE INDEX idx_purchase_documents_source_raw_event
    ON core.purchase_documents (source_raw_event_id);

CREATE INDEX idx_purchase_documents_reversed
    ON core.purchase_documents (reversed_purchase_document_id)
    WHERE reversed_purchase_document_id IS NOT NULL;

CREATE TRIGGER trg_purchase_documents_set_updated_at
    BEFORE UPDATE ON core.purchase_documents
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- Trigger di provenance a tre livelli, stesso modello di
-- core.fn_protect_sales_document_provenance(): status è l'unico campo di
-- classificazione CORE liberamente ricalcolabile (Livello 3).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_protect_purchase_document_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Livello 1 — identità: mai modificabile, in nessun caso. Se questi campi
    -- devono cambiare, è un documento diverso, non una revisione.
    IF NEW.organization_id                IS DISTINCT FROM OLD.organization_id OR
       NEW.location_id                    IS DISTINCT FROM OLD.location_id OR
       NEW.source_system_id               IS DISTINCT FROM OLD.source_system_id OR
       NEW.supplier_id                    IS DISTINCT FROM OLD.supplier_id OR
       NEW.external_id                    IS DISTINCT FROM OLD.external_id OR
       NEW.reversed_purchase_document_id  IS DISTINCT FROM OLD.reversed_purchase_document_id
    THEN
        RAISE EXCEPTION
            'purchase_documents: organization_id/location_id/source_system_id/supplier_id/external_id/reversed_purchase_document_id sono identità immutabili (id=%)',
            OLD.id;
    END IF;

    -- Livello 2 — dati fiscali/sorgente: modificabili solo insieme a un nuovo
    -- source_raw_event_id (evidenza RAW della revisione).
    IF (NEW.document_type    IS DISTINCT FROM OLD.document_type OR
        NEW.document_number  IS DISTINCT FROM OLD.document_number OR
        NEW.document_date    IS DISTINCT FROM OLD.document_date OR
        NEW.received_at      IS DISTINCT FROM OLD.received_at OR
        NEW.due_date         IS DISTINCT FROM OLD.due_date OR
        NEW.subtotal_net     IS DISTINCT FROM OLD.subtotal_net OR
        NEW.discount_amount  IS DISTINCT FROM OLD.discount_amount OR
        NEW.tax_amount       IS DISTINCT FROM OLD.tax_amount OR
        NEW.rounding_amount  IS DISTINCT FROM OLD.rounding_amount OR
        NEW.total_gross      IS DISTINCT FROM OLD.total_gross OR
        NEW.currency         IS DISTINCT FROM OLD.currency)
       AND NEW.source_raw_event_id IS NOT DISTINCT FROM OLD.source_raw_event_id
    THEN
        RAISE EXCEPTION
            'purchase_documents: campo fiscale modificato senza un nuovo source_raw_event_id (id=%)',
            OLD.id;
    END IF;

    -- Livello 3 — status: nessun controllo. Classificazione amministrativa
    -- della Centrale, liberamente ricalcolabile senza un nuovo evento RAW
    -- (es. propagazione dello stato da una nota di credito collegata).

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_purchase_document_provenance() IS
    'Tre livelli: identità (incluso reversed_purchase_document_id) mai '
    'modificabile; dati fiscali modificabili solo con un nuovo '
    'source_raw_event_id; status liberamente ricalcolabile (non è dato '
    'fiscale).';

CREATE TRIGGER trg_purchase_documents_protect_provenance
    BEFORE UPDATE ON core.purchase_documents
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_purchase_document_provenance();

-- =============================================================================
-- 2. core.purchase_lines — dettaglio riga per riga
-- =============================================================================
CREATE TABLE core.purchase_lines (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    purchase_document_id    uuid        NOT NULL,

    -- Nullable: una riga può non essere ancora mappata a un prodotto interno
    -- (in attesa di risoluzione, es. via ops.mapping_queue). Livello 3:
    -- risoluzione di mapping, liberamente ricalcolabile.
    product_id              uuid,

    -- NumeroLinea FatturaPA quando disponibile: normativo, stabile per
    -- costruzione. Distinto da source_line_ordinal (tecnico, solo fallback).
    line_number              integer,

    source_raw_event_id      uuid       NOT NULL,
    source_line_id            text,
    source_line_ordinal        integer,

    -- Codice del fornitore su questa riga specifica (può differire dal
    -- codice usato in supplier_product_refs se il fornitore lo cambia).
    supplier_item_code          text,
    description                   text,

    quantity                       numeric(14,4) NOT NULL,

    -- FK semplice (non composita): core.units_of_measure è globale.
    uom_id                           uuid,

    -- Solo netto: convenzione standard fattura fornitore, nessun equivalente
    -- gross esplicito (diverso da sales_lines.unit_price_gross).
    unit_price_net                    numeric(14,4) NOT NULL,

    discount_amount                     numeric(14,2) NOT NULL DEFAULT 0,
    net_amount                            numeric(14,2) NOT NULL,

    -- FK semplice (non composita): core.tax_rates ammette righe globali.
    -- Coerenza tenant garantita da core.fn_validate_tax_rate_tenant()
    -- (terzo riuso dopo core.products e core.sales_lines).
    tax_rate_id                            uuid,

    -- Nullable: alcune righe possono essere esenti/non ancora note.
    tax_amount                               numeric(14,2),
    gross_amount                              numeric(14,2),

    -- Libero: product, service, expense, discount, other... deve restare
    -- estendibile a righe future non ancora previste (es. trasporto,
    -- imballaggio come righe proprie invece di un campo documento).
    line_type                                  text NOT NULL,

    -- Livello 3: riclassificabile liberamente (es. food_cost, packaging,
    -- transport, other), non richiede un nuovo evento RAW.
    expense_category                             text,

    -- NULL = riga corrente. Valorizzato quando una revisione del documento
    -- fa scomparire questa riga (fallback ordinal) o quando viene sostituita.
    -- Mai un delete fisico: product_purchase_prices referenzia questa
    -- tabella con ON DELETE RESTRICT ed è essa stessa append-only.
    superseded_at                                 timestamptz,

    created_at                                     timestamptz NOT NULL DEFAULT now(),
    updated_at                                      timestamptz NOT NULL DEFAULT now(),

    -- Ancora per la FK composita tenant-safe di product_purchase_prices.
    CONSTRAINT uq_purchase_lines_org_id UNIQUE (organization_id, id),

    CONSTRAINT fk_purchase_lines_document
        FOREIGN KEY (organization_id, purchase_document_id)
        REFERENCES core.purchase_documents (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_lines_product
        FOREIGN KEY (organization_id, product_id)
        REFERENCES core.products (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_lines_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_lines_uom
        FOREIGN KEY (uom_id)
        REFERENCES core.units_of_measure (id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_purchase_lines_tax_rate
        FOREIGN KEY (tax_rate_id)
        REFERENCES core.tax_rates (id)
        ON DELETE RESTRICT

    -- Nessun CHECK sul segno di quantity/importi: le righe di nota di
    -- credito sono legittimamente negative (stesso trattamento di
    -- sales_lines per le righe di sconto).
);

COMMENT ON TABLE core.purchase_lines IS
    'Dettaglio riga per riga di un documento di acquisto: prodotti, servizi, '
    'spese accessorie, sconti (line_type libero). Nessun CHECK sul segno di '
    'quantity/importi: righe di nota di credito hanno legittimamente importi '
    'negativi. superseded_at sostituisce il delete fisico per le revisioni.';

COMMENT ON COLUMN core.purchase_lines.superseded_at IS
    'NULL = riga corrente/attiva. Valorizzato (mai più modificato, vedi '
    'trigger di provenance) quando una revisione del documento sostituisce '
    'questa riga. Necessario perché core.product_purchase_prices referenzia '
    'purchase_lines.id con ON DELETE RESTRICT ed è a sua volta append-only: '
    'un delete fisico qui romperebbe l''immutabilità dello storico prezzi.';

-- Idempotenza righe: id stabile quando disponibile, altrimenti fallback
-- ancorato allo specifico evento RAW che ha prodotto la riga. Entrambi gli
-- indici sono parziali su "WHERE superseded_at IS NULL": una revisione può
-- reinserire lo stesso source_line_id dopo che la riga precedente è stata
-- marcata superseded, senza collidere.
CREATE UNIQUE INDEX uq_purchase_lines_stable_id
    ON core.purchase_lines (purchase_document_id, source_line_id)
    WHERE source_line_id IS NOT NULL AND superseded_at IS NULL;

CREATE UNIQUE INDEX uq_purchase_lines_fallback_ordinal
    ON core.purchase_lines (purchase_document_id, source_raw_event_id, source_line_ordinal)
    WHERE source_line_id IS NULL AND superseded_at IS NULL;

CREATE INDEX idx_purchase_lines_org_document
    ON core.purchase_lines (organization_id, purchase_document_id);

-- Query più frequente: solo le righe correnti di un documento.
CREATE INDEX idx_purchase_lines_org_document_current
    ON core.purchase_lines (organization_id, purchase_document_id)
    WHERE superseded_at IS NULL;

CREATE INDEX idx_purchase_lines_org_product
    ON core.purchase_lines (organization_id, product_id)
    WHERE product_id IS NOT NULL;

CREATE INDEX idx_purchase_lines_tax_rate
    ON core.purchase_lines (tax_rate_id);

CREATE TRIGGER trg_purchase_lines_set_updated_at
    BEFORE UPDATE ON core.purchase_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

CREATE TRIGGER trg_purchase_lines_validate_tax_rate_tenant
    BEFORE INSERT OR UPDATE ON core.purchase_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_validate_tax_rate_tenant();

-- ---------------------------------------------------------------------------
-- Trigger di provenance a tre livelli, analogo a purchase_documents:
-- product_id/expense_category sono le classificazioni CORE liberamente
-- ricalcolabili. superseded_at è escluso da tutti i livelli: non è né
-- identità, né dato fiscale, né classificazione — è una transizione di
-- ciclo di vita, libera in un verso soltanto (una volta valorizzato non può
-- più essere azzerato né cambiato).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_protect_purchase_line_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- superseded_at: libero da NULL a un valore; mai il contrario, mai
    -- ri-valorizzato con un timestamp diverso una volta impostato.
    IF OLD.superseded_at IS NOT NULL
       AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at
    THEN
        RAISE EXCEPTION
            'purchase_lines: superseded_at è immutabile una volta valorizzato (id=%)',
            OLD.id;
    END IF;

    -- Livello 1 — identità: mai modificabile.
    IF NEW.organization_id      IS DISTINCT FROM OLD.organization_id OR
       NEW.purchase_document_id IS DISTINCT FROM OLD.purchase_document_id OR
       NEW.source_line_id       IS DISTINCT FROM OLD.source_line_id OR
       NEW.source_line_ordinal  IS DISTINCT FROM OLD.source_line_ordinal
    THEN
        RAISE EXCEPTION
            'purchase_lines: organization_id/purchase_document_id/source_line_id/source_line_ordinal sono identità immutabili (id=%)',
            OLD.id;
    END IF;

    -- Livello 2 — dati fiscali/sorgente: modificabili solo con un nuovo
    -- source_raw_event_id.
    IF (NEW.line_number         IS DISTINCT FROM OLD.line_number OR
        NEW.supplier_item_code  IS DISTINCT FROM OLD.supplier_item_code OR
        NEW.description         IS DISTINCT FROM OLD.description OR
        NEW.quantity             IS DISTINCT FROM OLD.quantity OR
        NEW.uom_id                IS DISTINCT FROM OLD.uom_id OR
        NEW.unit_price_net          IS DISTINCT FROM OLD.unit_price_net OR
        NEW.discount_amount           IS DISTINCT FROM OLD.discount_amount OR
        NEW.net_amount                  IS DISTINCT FROM OLD.net_amount OR
        NEW.tax_rate_id                   IS DISTINCT FROM OLD.tax_rate_id OR
        NEW.tax_amount                      IS DISTINCT FROM OLD.tax_amount OR
        NEW.gross_amount                      IS DISTINCT FROM OLD.gross_amount OR
        NEW.line_type                           IS DISTINCT FROM OLD.line_type)
       AND NEW.source_raw_event_id IS NOT DISTINCT FROM OLD.source_raw_event_id
    THEN
        RAISE EXCEPTION
            'purchase_lines: campo fiscale modificato senza un nuovo source_raw_event_id (id=%)',
            OLD.id;
    END IF;

    -- Livello 3 — product_id, expense_category: nessun controllo. Risoluzione
    -- di mapping/classificazione della Centrale, liberamente ricalcolabile.

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_purchase_line_provenance() IS
    'Stesso modello a tre livelli di core.fn_protect_sales_line_provenance(): '
    'product_id/expense_category sono liberamente ricalcolabili senza un '
    'nuovo source_raw_event_id. superseded_at è gestito a parte: libero solo '
    'da NULL a un valore, mai il contrario.';

CREATE TRIGGER trg_purchase_lines_protect_provenance
    BEFORE UPDATE ON core.purchase_lines
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_purchase_line_provenance();

-- =============================================================================
-- 3. core.supplier_product_refs — mapping codice/descrizione fornitore → prodotto
-- =============================================================================
CREATE TABLE core.supplier_product_refs (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    supplier_id             uuid        NOT NULL,
    source_system_id        uuid        NOT NULL,

    -- Chiave del mapping quando disponibile; alcuni fornitori/DDT non
    -- valorizzano un codice, solo una descrizione libera.
    supplier_item_code      text,
    supplier_description    text        NOT NULL,

    product_id               uuid       NOT NULL,

    -- Convenzione di packaging tipica del fornitore per questo prodotto (es.
    -- "cartone"). FK semplice: core.units_of_measure è globale.
    supplier_uom_id            uuid,

    -- Fattore di packaging a livello del fornitore: 1 unità della UOM
    -- fatturata (purchase_lines.uom_id) = conversion_factor * supplier_uom_id.
    -- Non presuppone di essere già nell'unità base finale del prodotto:
    -- l'eventuale ulteriore conversione fisica standard (core.units_of_measure,
    -- es. g→kg) viene composta con questo fattore dalla pipeline al momento
    -- del calcolo, e il risultato composto viene congelato in
    -- product_purchase_prices.conversion_factor_applied.
    conversion_factor          numeric(18,8) NOT NULL DEFAULT 1,

    -- Puramente descrittivo, MAI usato nei calcoli. Rende verificabile da un
    -- umano come conversion_factor è stato derivato quando riflette un
    -- packaging multilivello (es. "1 cartone = 6 confezioni da 1,5 kg").
    packaging_description       text,

    -- Elenco chiuso, stesso trattamento di core.product_external_refs.
    mapping_status                text     NOT NULL,
    confidence                      numeric(5,4),

    -- Osservazionale: quando questo mapping è stato visto la prima/ultima
    -- volta, distinto da valid_from/valid_to (storicizzazione dello stato
    -- attivo/chiuso). Entrambi mantenuti: non ridondanti.
    first_seen_at                     timestamptz NOT NULL DEFAULT now(),
    last_seen_at                        timestamptz NOT NULL DEFAULT now(),

    valid_from                            timestamptz NOT NULL,
    valid_to                                timestamptz,

    created_at                                timestamptz NOT NULL DEFAULT now(),
    updated_at                                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_supplier_product_refs_supplier
        FOREIGN KEY (organization_id, supplier_id)
        REFERENCES core.parties (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_supplier_product_refs_source_system
        FOREIGN KEY (organization_id, source_system_id)
        REFERENCES core.source_systems (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_supplier_product_refs_product
        FOREIGN KEY (organization_id, product_id)
        REFERENCES core.products (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_supplier_product_refs_uom
        FOREIGN KEY (supplier_uom_id)
        REFERENCES core.units_of_measure (id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_supplier_product_refs_valid_period
        CHECK (valid_to IS NULL OR valid_to >= valid_from),

    CONSTRAINT chk_supplier_product_refs_mapping_status
        CHECK (mapping_status IN ('proposed', 'confirmed', 'rejected')),

    CONSTRAINT chk_supplier_product_refs_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),

    CONSTRAINT chk_supplier_product_refs_conversion_factor
        CHECK (conversion_factor > 0)
);

COMMENT ON TABLE core.supplier_product_refs IS
    'Mappatura tra codice/descrizione di un fornitore e prodotto interno, con '
    'convenzione di packaging (supplier_uom_id/conversion_factor). Storicizzata '
    'come core.product_external_refs, con cui resta concettualmente distinta: '
    'qui il mapping è specifico del fornitore, là del sistema sorgente.';

COMMENT ON COLUMN core.supplier_product_refs.conversion_factor IS
    'Fattore di packaging composto e già appiattito (es. 1 cartone = 6 '
    'confezioni da 1,5 kg → 9): nessuna gerarchia di packaging strutturata su '
    'più righe. packaging_description ne documenta la derivazione per audit.';

COMMENT ON COLUMN core.supplier_product_refs.packaging_description IS
    'Testo libero, esclusivamente documentale: MAI usato in alcun calcolo. '
    'Serve solo a rendere verificabile da un umano il valore di '
    'conversion_factor in caso di audit o contestazione fornitore.';

-- Al più un mapping attivo per (organization, supplier, source_system,
-- supplier_item_code) quando il codice è presente. Un remap (stesso codice
-- spostato su un prodotto diverso, o fattore di conversione corretto) si fa
-- chiudendo la riga attiva e aprendone una nuova — mai un UPDATE in place.
CREATE UNIQUE INDEX uq_supplier_product_refs_active
    ON core.supplier_product_refs (organization_id, supplier_id, source_system_id, supplier_item_code)
    WHERE valid_to IS NULL AND supplier_item_code IS NOT NULL;

CREATE INDEX idx_supplier_product_refs_org_product
    ON core.supplier_product_refs (organization_id, product_id);

CREATE INDEX idx_supplier_product_refs_org_supplier
    ON core.supplier_product_refs (organization_id, supplier_id);

CREATE TRIGGER trg_supplier_product_refs_set_updated_at
    BEFORE UPDATE ON core.supplier_product_refs
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_set_updated_at();

-- =============================================================================
-- 4. core.product_purchase_prices — storico prezzi osservati, normalizzati
-- =============================================================================
CREATE TABLE core.product_purchase_prices (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,

    -- Copiato da purchase_documents.location_id al momento del calcolo per
    -- comodità di query; nullable per lo stesso motivo del documento.
    location_id                 uuid,

    -- Livello "congelato": riflette la classificazione CORE valida al
    -- momento del calcolo, non un puntatore vivo. Una riclassificazione
    -- successiva di supplier_product_refs/purchase_lines.product_id NON
    -- risincronizza retroattivamente questa colonna (stessa filosofia di
    -- sales_documents.management_date: stabilità storica dei report).
    product_id                  uuid        NOT NULL,

    supplier_id                 uuid        NOT NULL,

    -- Riga di fattura che ha originato questa osservazione.
    purchase_document_line_id   uuid        NOT NULL,

    -- Prova RAW di questa specifica osservazione.
    source_raw_event_id         uuid        NOT NULL,

    purchase_date                date       NOT NULL,

    -- Unità base a cui si riferiscono quantity_base_uom/unit_price_base_uom
    -- IN QUESTA RIGA SPECIFICA. Non presuppone uguaglianza con
    -- core.products.default_uom_id: congelarla riga per riga rende la riga
    -- autosufficiente e immune a future correzioni di mapping.
    base_uom_id                  uuid       NOT NULL,

    -- Fattore composto e congelato applicato per normalizzare:
    -- quantity_base_uom = purchase_lines.quantity * conversion_factor_applied.
    -- Combina, se necessario, sia il packaging del fornitore
    -- (supplier_product_refs.conversion_factor) sia l'eventuale conversione
    -- fisica standard (core.units_of_measure). Congelato: una correzione
    -- futura del mapping non altera questo valore retroattivamente.
    conversion_factor_applied     numeric(18,8) NOT NULL,

    -- Con segno: positivo per un acquisto, negativo per una nota di credito.
    -- La direzione della transazione vive qui, MAI nel prezzo unitario.
    quantity_base_uom               numeric(18,6) NOT NULL,

    -- Sempre >= 0: "quanto costa un'unità base di questo prodotto secondo
    -- questa osservazione", indipendentemente dal fatto che la transazione
    -- sia un acquisto o uno storno.
    unit_price_base_uom               numeric(18,6) NOT NULL,

    -- Solo created_at: la riga non viene mai aggiornata (vedi trigger di
    -- immutabilità sotto), quindi updated_at non avrebbe senso.
    created_at                          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT fk_product_purchase_prices_location
        FOREIGN KEY (organization_id, location_id)
        REFERENCES core.locations (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_purchase_prices_product
        FOREIGN KEY (organization_id, product_id)
        REFERENCES core.products (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_purchase_prices_supplier
        FOREIGN KEY (organization_id, supplier_id)
        REFERENCES core.parties (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_purchase_prices_line
        FOREIGN KEY (organization_id, purchase_document_line_id)
        REFERENCES core.purchase_lines (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_purchase_prices_raw_event
        FOREIGN KEY (organization_id, source_raw_event_id)
        REFERENCES raw.ingest_events (organization_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_product_purchase_prices_base_uom
        FOREIGN KEY (base_uom_id)
        REFERENCES core.units_of_measure (id)
        ON DELETE RESTRICT,

    -- Idempotenza: la stessa riga fattura, per lo stesso evento RAW, produce
    -- al più un'osservazione di prezzo.
    CONSTRAINT uq_product_purchase_prices_line_event
        UNIQUE (purchase_document_line_id, source_raw_event_id),

    CONSTRAINT chk_product_purchase_prices_conversion_factor
        CHECK (conversion_factor_applied > 0),

    CONSTRAINT chk_product_purchase_prices_quantity_nonzero
        CHECK (quantity_base_uom <> 0),

    CONSTRAINT chk_product_purchase_prices_price_nonnegative
        CHECK (unit_price_base_uom >= 0)
);

COMMENT ON TABLE core.product_purchase_prices IS
    'Storico prezzi OSSERVATI/transazionali normalizzati per unità base. '
    'Esclusivamente il prezzo realmente pagato: un eventuale prezzo '
    'contrattuale/listino è un concetto distinto, fuori scope. Interamente '
    'append-only e immutabile (vedi trigger). Ogni riga è uno snapshot '
    'congelato: product_id/base_uom_id/conversion_factor_applied riflettono '
    'lo stato al momento del calcolo, mai risincronizzati retroattivamente.';

COMMENT ON COLUMN core.product_purchase_prices.quantity_base_uom IS
    'Con segno: positivo per un acquisto, negativo per una nota di credito. '
    'La direzione della transazione vive esclusivamente qui, mai nel prezzo '
    'unitario (vedi unit_price_base_uom).';

COMMENT ON COLUMN core.product_purchase_prices.unit_price_base_uom IS
    'Sempre >= 0. Rappresenta quanto costa un''unità base del prodotto '
    'secondo questa osservazione, indipendentemente dalla direzione della '
    'transazione (che vive nel segno di quantity_base_uom). Una nota di '
    'credito non produce mai un "prezzo di mercato negativo".';

CREATE INDEX idx_product_purchase_prices_org_product_date
    ON core.product_purchase_prices (organization_id, product_id, purchase_date);

CREATE INDEX idx_product_purchase_prices_org_supplier
    ON core.product_purchase_prices (organization_id, supplier_id);

CREATE INDEX idx_product_purchase_prices_location
    ON core.product_purchase_prices (location_id)
    WHERE location_id IS NOT NULL;

-- Riusa la funzione generica già creata in 003_raw_ops (ops.fn_block_modification):
-- quarto riuso, dopo ops.entity_raw_links, ops.audit_log e
-- core.rule_classification_links.
CREATE TRIGGER trg_product_purchase_prices_immutability
    BEFORE UPDATE OR DELETE ON core.product_purchase_prices
    FOR EACH ROW
    EXECUTE FUNCTION ops.fn_block_modification();

COMMIT;
