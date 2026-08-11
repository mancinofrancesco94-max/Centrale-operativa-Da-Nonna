-- =============================================================================
-- Centrale Operativa — Data Hub
-- Migration: 006_rls_policies
-- Prerequisiti: 001_foundation, 002_catalog, 003_raw_ops, 004_sales,
--               005_purchases FINAL PASS (nessuna delle cinque modificata)
-- Specifica di riferimento: "006_rls_policies — REVISIONE 2" (approvata),
--                           trattata come specifica definitiva e vincolante.
--
-- Percorso non standard rispetto a 001-005 (migrations/) per istruzione
-- esplicita: questo file vive in supabase/migrations/, non in migrations/.
-- Nessuna delle cinque migration precedenti viene spostata né toccata.
--
-- Contenuto di questa migration:
--   0. Assunzioni di ambiente (auth.uid(), ruoli anon/authenticated/service_role)
--   1. 5 helper function (core.fn_current_user_*)
--   2. 2 nuovi invarianti (default_organization_id, ultimo owner)
--   3. ENABLE ROW LEVEL SECURITY su tutte le tabelle core/raw/ops
--   4. Policy RLS per tabella (nessuna policy per service_role, vedi sotto)
--   5. GRANT/REVOKE per anon / authenticated / service_role
--
-- NON incluso in questa migration (deliberatamente):
--   - FORCE ROW LEVEL SECURITY: NON attivato. FORCE_RLS_STATUS =
--     PENDING_REAL_DB_VERIFICATION (vedi commento esteso in fondo al file).
--   - Nessuna policy RLS "TO service_role": service_role possiede
--     l'attributo BYPASSRLS su Supabase (verificato, vedi Revisione 2
--     sezione B) e bypassa la valutazione delle policy RLS a monte, su
--     ogni tabella, indipendentemente da ENABLE/FORCE. Scrivere policy per
--     questo ruolo sarebbe codice morto, mai valutato, con falsa impressione
--     di protezione. Il controllo su service_role è interamente demandato a
--     GRANT mirati (sezione 5) + trigger di provenance/immutabilità già
--     esistenti (003/004/005), che si applicano sempre, a qualunque ruolo.
--   - Location-level ACL: non implementata (MVP = accesso a tutte le
--     location dell'organization). Nessuna struttura dati lo impedisce in
--     futuro: le funzioni helper accettano già solo organization_id, un
--     domani "fn_current_user_has_location_access(loc_id)" potrà essere
--     aggiunta senza ridisegnare le tabelle esistenti.
--   - Nessun meccanismo di creazione automatica di core.user_profiles al
--     signup (trigger su auth.users / edge function): PENDING DECISION,
--     vedi commento su core.user_profiles più sotto. Non inventato qui.
--   - Nessuna vista/API di lettura controllata per RAW: RAW resta
--     interamente inaccessibile a authenticated/anon in questa migration.
--
-- Decisioni definitive applicate (Revisione 2):
--   1. Multi-ruolo utente/organization = unione dei permessi (nessun
--      ranking, verifiche via ANY(ruoli)).
--   2. Sei ruoli invariati: owner, admin, manager, finance, operations,
--      read_only. Nessuna estensione.
--   3. raw.ingest_events: REVOKE ALL esplicito da authenticated/anon;
--      service_role riceve SELECT/INSERT/UPDATE (mai DELETE) via GRANT,
--      nessuna policy RLS.
--   4. Location-wide access per l'MVP (vedi sopra).
--   5. Nuovo invariante: user_profiles.default_organization_id deve
--      corrispondere a una membership reale.
--   6. Nuovo invariante: una organization non può restare senza owner.
--   7. Nessun ruolo umano riceve DELETE su dati fiscali/CORE.
--   8. ENABLE ROW LEVEL SECURITY ovunque; FORCE non attivato in attesa di
--      verifica reale (vedi sopra).
--   9. anon: zero grant, su ogni tabella, senza eccezioni.
--  10. Naming helper con prefisso fn_.
--  11. Nessuna scrittura tenant su core.units_of_measure / tax_rates
--      globali (organization_id IS NULL): solo service_role/migration.
--  12. service_role non riceve DELETE su alcuna tabella di questa
--      migration (append/reversal/supersession, mai cancellazione
--      distruttiva — esteso dal principio fiscale a tutto il modulo).
-- =============================================================================

BEGIN;

-- =============================================================================
-- 0. Assunzioni di ambiente
-- =============================================================================
-- auth.uid() è fornita dalla piattaforma Supabase (estensione auth), non da
-- questa migration: non viene creata né modificata qui. I ruoli Postgres
-- anon/authenticated/service_role sono provisionati dalla piattaforma prima
-- di qualunque migration applicativa (stesso trattamento già riservato ad
-- auth.users in 001_foundation). Per i test locali su PostgreSQL puro (non
-- Supabase) questi prerequisiti vengono simulati nello script di test,
-- MAI in questo file.

-- =============================================================================
-- 1. Helper function (SECURITY DEFINER solo dove realmente necessario)
-- =============================================================================

-- fn_current_user_id(): non tocca alcuna tabella protetta da RLS (puro
-- passthrough su auth.uid()), quindi SECURITY INVOKER è sufficiente e
-- preferibile per principio di minimo privilegio. Le altre 4 sono
-- SECURITY DEFINER per un motivo specifico (vedi sotto).
CREATE OR REPLACE FUNCTION core.fn_current_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
    SELECT auth.uid();
$$;

COMMENT ON FUNCTION core.fn_current_user_id() IS
    'Indirection su auth.uid() (fornita dalla piattaforma Supabase): '
    'testabilità/portabilità, nessun accesso a tabelle protette da RLS, '
    'SECURITY INVOKER sufficiente.';

-- Le 4 funzioni seguenti sono SECURITY DEFINER per un motivo specifico e
-- documentato: core.user_organization_roles è auto-referenziata dalla
-- propria policy di lettura (owner/admin deve vedere le righe di ALTRI
-- utenti, non solo la propria). PostgreSQL gestisce correttamente le policy
-- auto-referenzianti (esiste un ramo "riga propria" non ricorsivo), ma
-- valutarle sempre come SECURITY INVOKER è fragile/costoso: ogni chiamata
-- rivaluterebbe la RLS della stessa tabella. SECURITY DEFINER con owner
-- privilegiato (bypassa RLS nelle query interne) è il pattern raccomandato
-- da Supabase per esattamente questo scenario di team-membership lookup.
-- auth.uid() resta compatibile perché legge lo stato di sessione (JWT),
-- non il contesto di privilegio Postgres: rimane corretto anche qui dentro.
--
-- IMPORTANTE (anti cross-tenant escalation): nessuna di queste funzioni
-- accetta un parametro che rappresenti "l'identità del chiamante" — quella
-- è SEMPRE risolta internamente via core.fn_current_user_id() (→
-- auth.uid()), mai passata come argomento. L'unico parametro "utente"
-- (fn_current_user_shares_org_with) rappresenta sempre l'ALTRO utente da
-- confrontare, mai il chiamante stesso: non esiste alcun modo di passare un
-- parametro che faccia sì che la funzione ragioni "come se" il chiamante
-- fosse un altro utente.

CREATE OR REPLACE FUNCTION core.fn_current_user_has_org_access(p_organization_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = core, pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM core.user_organization_roles r
        WHERE r.user_id = core.fn_current_user_id()
          AND r.organization_id = p_organization_id
    );
$$;

COMMENT ON FUNCTION core.fn_current_user_has_org_access(uuid) IS
    'TRUE se l''utente corrente possiede QUALUNQUE ruolo nell''organization '
    'indicata. SECURITY DEFINER: vedi commento esteso sopra. search_path '
    'fissato, riferimenti completamente qualificati.';

CREATE OR REPLACE FUNCTION core.fn_current_user_has_org_role(p_organization_id uuid, p_roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = core, pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM core.user_organization_roles r
        WHERE r.user_id = core.fn_current_user_id()
          AND r.organization_id = p_organization_id
          AND r.role = ANY (p_roles)
    );
$$;

COMMENT ON FUNCTION core.fn_current_user_has_org_role(uuid, text[]) IS
    'TRUE se l''utente corrente possiede ALMENO UNO dei ruoli indicati '
    'nell''organization. Base di quasi tutte le policy di scrittura. '
    'Multi-ruolo per utente/org = unione dei permessi, per costruzione: '
    'basta che UNA delle righe possedute soddisfi il confronto ANY().';

CREATE OR REPLACE FUNCTION core.fn_current_user_can_write_org(p_organization_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = core, pg_catalog
AS $$
    SELECT core.fn_current_user_has_org_role(
        p_organization_id,
        ARRAY['owner','admin','manager','operations']
    );
$$;

COMMENT ON FUNCTION core.fn_current_user_can_write_org(uuid) IS
    'Scorciatoia per il caso "scrittura operativa" (owner/admin/manager/'
    'operations), riusata su catalogo/vendite/acquisti per evitare di '
    'ripetere lo stesso array letterale in decine di policy.';

CREATE OR REPLACE FUNCTION core.fn_current_user_shares_org_with(p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = core, pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM core.user_organization_roles mine
        JOIN core.user_organization_roles theirs
          ON theirs.organization_id = mine.organization_id
        WHERE mine.user_id = core.fn_current_user_id()
          AND theirs.user_id = p_user_id
    );
$$;

COMMENT ON FUNCTION core.fn_current_user_shares_org_with(uuid) IS
    'TRUE se l''utente corrente condivide almeno una organization con '
    'p_user_id. Usata esclusivamente per la visibilità di core.user_profiles '
    'tra colleghi della stessa organization. p_user_id è sempre L''ALTRO '
    'utente da confrontare, mai il chiamante.';

-- Nessuna EXECUTE pubblica: solo authenticated la invoca (dentro le policy,
-- nel contesto del ruolo chiamante). service_role non le incontra mai
-- (bypassa RLS a monte) quindi non ne ha bisogno.
REVOKE EXECUTE ON FUNCTION core.fn_current_user_id() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION core.fn_current_user_has_org_access(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION core.fn_current_user_has_org_role(uuid, text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION core.fn_current_user_can_write_org(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION core.fn_current_user_shares_org_with(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION core.fn_current_user_id() TO authenticated;
GRANT EXECUTE ON FUNCTION core.fn_current_user_has_org_access(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION core.fn_current_user_has_org_role(uuid, text[]) TO authenticated;
GRANT EXECUTE ON FUNCTION core.fn_current_user_can_write_org(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION core.fn_current_user_shares_org_with(uuid) TO authenticated;

-- =============================================================================
-- 2. Nuovi invarianti
-- =============================================================================

-- 2a. default_organization_id deve corrispondere a una membership reale.
-- SECURITY INVOKER: l'utente che aggiorna il PROPRIO profilo (unica
-- operazione ammessa, vedi policy più sotto) può sempre vedere le PROPRIE
-- righe in user_organization_roles (ramo non ricorsivo della policy),
-- quindi non serve bypassare RLS per effettuare questo controllo.
CREATE OR REPLACE FUNCTION core.fn_validate_default_organization()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = core, pg_catalog
AS $$
BEGIN
    IF NEW.default_organization_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM core.user_organization_roles r
            WHERE r.user_id = NEW.user_id
              AND r.organization_id = NEW.default_organization_id
        ) THEN
            RAISE EXCEPTION
                'user_profiles: default_organization_id % non è una organization a cui l''utente % appartiene',
                NEW.default_organization_id, NEW.user_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.fn_validate_default_organization() IS
    'Impone l''invariante documentato in 001_foundation (mai applicato fino '
    'ad ora): default_organization_id deve corrispondere a una riga reale '
    'in user_organization_roles per lo stesso utente.';

CREATE TRIGGER trg_user_profiles_validate_default_org
    BEFORE INSERT OR UPDATE ON core.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_validate_default_organization();

-- 2b. Un'organization non può mai restare senza almeno un owner.
-- SECURITY DEFINER: non strettamente indispensabile (owner/admin, gli unici
-- che possono raggiungere questo trigger via RLS, vedono già tutte le righe
-- della propria organization), ma mantenuta per coerenza con le altre
-- helper e per rendere il conteggio indipendente da qualunque sottigliezza
-- di valutazione RLS in corso.
CREATE OR REPLACE FUNCTION core.fn_protect_last_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, pg_catalog
AS $$
DECLARE
    v_org           uuid;
    v_owner_count   integer;
BEGIN
    v_org := OLD.organization_id;

    IF TG_OP = 'DELETE' THEN
        IF OLD.role <> 'owner' THEN
            RETURN OLD;
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.role <> 'owner' THEN
            RETURN NEW;
        END IF;
        IF NEW.role = 'owner' THEN
            RETURN NEW;
        END IF;
    END IF;

    -- Una riga 'owner' esistente sta per essere rimossa (DELETE) o
    -- declassata (UPDATE): verifica che ne resti almeno un'altra.
    SELECT count(*) INTO v_owner_count
    FROM core.user_organization_roles
    WHERE organization_id = v_org
      AND role = 'owner'
      AND id <> OLD.id;

    IF v_owner_count = 0 THEN
        RAISE EXCEPTION
            'user_organization_roles: organization % non può restare senza alcun owner',
            v_org;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

COMMENT ON FUNCTION core.fn_protect_last_owner() IS
    'Blocca DELETE/UPDATE che porterebbero il conteggio di righe role=''owner'' '
    'per una organization a zero. Difesa indipendente dalla regola RLS di '
    'auto-esclusione: protegge anche il caso in cui un owner tenti di '
    'rimuovere un ALTRO owner che risulti essere l''ultimo rimasto.';

CREATE TRIGGER trg_user_organization_roles_protect_last_owner
    BEFORE UPDATE OR DELETE ON core.user_organization_roles
    FOR EACH ROW
    EXECUTE FUNCTION core.fn_protect_last_owner();

-- =============================================================================
-- 3. ENABLE ROW LEVEL SECURITY (tutte le tabelle core/raw/ops)
-- =============================================================================
-- FORCE ROW LEVEL SECURITY: NON attivato in questa migration.
-- FORCE_RLS_STATUS = PENDING_REAL_DB_VERIFICATION (vedi commento esteso in
-- fondo al file per la query di verifica da eseguire sul progetto Supabase
-- reale prima di un'eventuale migration futura che attivi FORCE).

ALTER TABLE core.organizations                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.locations                     ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.source_systems                ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.units_of_measure              ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.tax_rates                     ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.user_profiles                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.user_organization_roles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.parties                       ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.party_roles                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.products                      ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.product_external_refs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.payment_methods               ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.payment_method_external_refs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.management_rules              ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.rule_classification_links     ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sales_documents               ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sales_lines                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sale_payments                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.purchase_documents            ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.purchase_lines                ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.supplier_product_refs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.product_purchase_prices       ENABLE ROW LEVEL SECURITY;

ALTER TABLE raw.ingest_events                  ENABLE ROW LEVEL SECURITY;

ALTER TABLE ops.sync_runs                      ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.integration_cursors            ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.mapping_queue                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.audit_log                      ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.entity_raw_links               ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- 4. Policy RLS per tabella
-- =============================================================================
-- Convenzione: nessuna policy scritta per un ruolo/operazione = default deny
-- per quel ruolo/operazione (comportamento standard PostgreSQL con RLS
-- abilitata). Non vengono quindi scritte policy "di rifiuto esplicito":
-- l'assenza stessa è il rifiuto. Nessuna policy è mai scritta per
-- service_role (vedi header).

-- ---------------------------------------------------------------------------
-- 4.1 core.organizations
-- ---------------------------------------------------------------------------
CREATE POLICY rls_organizations_select ON core.organizations
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(id));

CREATE POLICY rls_organizations_update ON core.organizations
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(id, ARRAY['owner','admin']))
    WITH CHECK (core.fn_current_user_has_org_role(id, ARRAY['owner','admin']));

-- Nessuna policy INSERT/DELETE per authenticated: creazione/cancellazione
-- organization non è un'operazione self-service nell'MVP (provisioning
-- controllato via service_role/piattaforma).

-- ---------------------------------------------------------------------------
-- 4.2 core.locations, core.source_systems (stessa forma: organization_id,
--     scrittura riservata a owner/admin)
-- ---------------------------------------------------------------------------
CREATE POLICY rls_locations_select ON core.locations
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

CREATE POLICY rls_locations_insert ON core.locations
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']));

CREATE POLICY rls_locations_update ON core.locations
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']))
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']));

CREATE POLICY rls_source_systems_select ON core.source_systems
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

CREATE POLICY rls_source_systems_insert ON core.source_systems
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']));

CREATE POLICY rls_source_systems_update ON core.source_systems
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']))
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin']));

-- ---------------------------------------------------------------------------
-- 4.3 core.units_of_measure (globale) — SELECT per tutti gli autenticati,
--     nessuna scrittura tenant (decisione 11)
-- ---------------------------------------------------------------------------
CREATE POLICY rls_units_of_measure_select ON core.units_of_measure
    FOR SELECT TO authenticated
    USING (true);

-- Nessuna policy INSERT/UPDATE/DELETE per authenticated: dato di
-- riferimento globale, scrivibile solo da service_role/migration.

-- ---------------------------------------------------------------------------
-- 4.4 core.tax_rates (globale quando organization_id IS NULL, altrimenti
--     tenant-owned)
-- ---------------------------------------------------------------------------
CREATE POLICY rls_tax_rates_select ON core.tax_rates
    FOR SELECT TO authenticated
    USING (
        organization_id IS NULL
        OR core.fn_current_user_has_org_access(organization_id)
    );

CREATE POLICY rls_tax_rates_insert ON core.tax_rates
    FOR INSERT TO authenticated
    WITH CHECK (
        organization_id IS NOT NULL
        AND core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance'])
    );

CREATE POLICY rls_tax_rates_update ON core.tax_rates
    FOR UPDATE TO authenticated
    USING (
        organization_id IS NOT NULL
        AND core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance'])
    )
    WITH CHECK (
        organization_id IS NOT NULL
        AND core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance'])
    );

-- Righe globali (organization_id IS NULL): nessuna policy INSERT/UPDATE le
-- rende scrivibili da authenticated, per costruzione (il WITH CHECK impone
-- sempre organization_id IS NOT NULL).

-- ---------------------------------------------------------------------------
-- 4.5 Catalogo operativo: parties, party_roles, products,
--     product_external_refs, supplier_product_refs — R per tutti i membri,
--     W per owner/admin/manager/operations
-- ---------------------------------------------------------------------------
CREATE POLICY rls_parties_select ON core.parties
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_parties_insert ON core.parties
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_parties_update ON core.parties
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_party_roles_select ON core.party_roles
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_party_roles_insert ON core.party_roles
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_party_roles_update ON core.party_roles
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_products_select ON core.products
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_products_insert ON core.products
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_products_update ON core.products
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_product_external_refs_select ON core.product_external_refs
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_product_external_refs_insert ON core.product_external_refs
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_product_external_refs_update ON core.product_external_refs
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_supplier_product_refs_select ON core.supplier_product_refs
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_supplier_product_refs_insert ON core.supplier_product_refs
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_supplier_product_refs_update ON core.supplier_product_refs
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

-- ---------------------------------------------------------------------------
-- 4.6 Configurazione finanziaria: payment_methods, payment_method_external_refs
--     — R per tutti i membri, W per owner/admin/finance
-- ---------------------------------------------------------------------------
CREATE POLICY rls_payment_methods_select ON core.payment_methods
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_payment_methods_insert ON core.payment_methods
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']));
CREATE POLICY rls_payment_methods_update ON core.payment_methods
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']))
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']));

CREATE POLICY rls_payment_method_external_refs_select ON core.payment_method_external_refs
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_payment_method_external_refs_insert ON core.payment_method_external_refs
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']));
CREATE POLICY rls_payment_method_external_refs_update ON core.payment_method_external_refs
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']))
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','finance']));

-- ---------------------------------------------------------------------------
-- 4.7 core.management_rules — R per tutti i membri, W per owner/admin/manager
-- ---------------------------------------------------------------------------
CREATE POLICY rls_management_rules_select ON core.management_rules
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_management_rules_insert ON core.management_rules
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','manager']));
CREATE POLICY rls_management_rules_update ON core.management_rules
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','manager']))
    WITH CHECK (core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin','manager']));

-- ---------------------------------------------------------------------------
-- 4.8 core.rule_classification_links — append-only, R ampio, W solo
--     service_role (nessuna policy INSERT per authenticated); UPDATE/DELETE
--     già bloccati incondizionatamente dal trigger di 004_sales.
-- ---------------------------------------------------------------------------
CREATE POLICY rls_rule_classification_links_select ON core.rule_classification_links
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

-- ---------------------------------------------------------------------------
-- 4.9 Vendite/Acquisti operativi: sales_documents/lines/payments,
--     purchase_documents/lines — R per tutti i membri, W per
--     owner/admin/manager/operations. Nessun DELETE per nessuno (decisione 7).
--     Resta comunque soggetto ai trigger di provenance a tre livelli di
--     004/005: RLS decide SE si può tentare, i trigger decidono QUALI campi.
-- ---------------------------------------------------------------------------
CREATE POLICY rls_sales_documents_select ON core.sales_documents
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_sales_documents_insert ON core.sales_documents
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_sales_documents_update ON core.sales_documents
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_sales_lines_select ON core.sales_lines
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_sales_lines_insert ON core.sales_lines
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_sales_lines_update ON core.sales_lines
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_sale_payments_select ON core.sale_payments
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_sale_payments_insert ON core.sale_payments
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_sale_payments_update ON core.sale_payments
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_purchase_documents_select ON core.purchase_documents
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_purchase_documents_insert ON core.purchase_documents
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_purchase_documents_update ON core.purchase_documents
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

CREATE POLICY rls_purchase_lines_select ON core.purchase_lines
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));
CREATE POLICY rls_purchase_lines_insert ON core.purchase_lines
    FOR INSERT TO authenticated
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));
CREATE POLICY rls_purchase_lines_update ON core.purchase_lines
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

-- ---------------------------------------------------------------------------
-- 4.10 core.product_purchase_prices — append-only, R ampio, W solo
--      service_role (nessuna policy INSERT per authenticated); UPDATE/DELETE
--      già bloccati incondizionatamente dal trigger di 005_purchases.
-- ---------------------------------------------------------------------------
CREATE POLICY rls_product_purchase_prices_select ON core.product_purchase_prices
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

-- ---------------------------------------------------------------------------
-- 4.11 core.user_profiles
-- ---------------------------------------------------------------------------
-- PENDING DECISION: il meccanismo di creazione della riga a signup (trigger
-- su auth.users vs passo esplicito del backend) non è deciso qui. Nessuna
-- policy INSERT per authenticated in questa migration: la creazione
-- self-service via client non è quindi permessa finché quella decisione non
-- viene presa. service_role riceve GRANT INSERT (sezione 5) per supportare
-- un futuro flusso di provisioning backend-driven, senza che questa
-- migration lo implementi.
CREATE POLICY rls_user_profiles_select ON core.user_profiles
    FOR SELECT TO authenticated
    USING (
        user_id = core.fn_current_user_id()
        OR core.fn_current_user_shares_org_with(user_id)
    );

CREATE POLICY rls_user_profiles_update ON core.user_profiles
    FOR UPDATE TO authenticated
    USING (user_id = core.fn_current_user_id())
    WITH CHECK (user_id = core.fn_current_user_id());

-- ---------------------------------------------------------------------------
-- 4.12 core.user_organization_roles — base dell'autorizzazione, modello
--      membership della Revisione 2 sezione G. Vedi anche il trigger
--      trg_user_organization_roles_protect_last_owner (sezione 2b).
-- ---------------------------------------------------------------------------
CREATE POLICY rls_user_organization_roles_select ON core.user_organization_roles
    FOR SELECT TO authenticated
    USING (
        user_id = core.fn_current_user_id()
        OR core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
    );

-- INSERT: base owner/admin, più il vincolo "solo owner crea owner".
CREATE POLICY rls_user_organization_roles_insert ON core.user_organization_roles
    FOR INSERT TO authenticated
    WITH CHECK (
        core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
        AND (
            role <> 'owner'
            OR core.fn_current_user_has_org_role(organization_id, ARRAY['owner'])
        )
    );

-- UPDATE: base owner/admin, mai la propria riga (auto-modifica sempre
-- bloccata, indipendentemente dal ruolo target), "solo owner tocca owner"
-- valutato sia sulla riga PRIMA (USING, OLD.role) sia sul valore risultante
-- DOPO (WITH CHECK, NEW.role).
CREATE POLICY rls_user_organization_roles_update ON core.user_organization_roles
    FOR UPDATE TO authenticated
    USING (
        core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
        AND user_id <> core.fn_current_user_id()
        AND (
            role <> 'owner'
            OR core.fn_current_user_has_org_role(organization_id, ARRAY['owner'])
        )
    )
    WITH CHECK (
        core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
        AND user_id <> core.fn_current_user_id()
        AND (
            role <> 'owner'
            OR core.fn_current_user_has_org_role(organization_id, ARRAY['owner'])
        )
    );

-- DELETE: stessa base di UPDATE (auto-modifica bloccata, solo owner rimuove
-- owner). La protezione "mai l'ultimo owner" è del trigger, non di questa
-- policy: la policy da sola permetterebbe a un owner di rimuovere un ALTRO
-- owner anche se fosse l'ultimo, per questo il trigger resta necessario.
CREATE POLICY rls_user_organization_roles_delete ON core.user_organization_roles
    FOR DELETE TO authenticated
    USING (
        core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
        AND user_id <> core.fn_current_user_id()
        AND (
            role <> 'owner'
            OR core.fn_current_user_has_org_role(organization_id, ARRAY['owner'])
        )
    );

-- ---------------------------------------------------------------------------
-- 4.13 raw.ingest_events — NESSUNA policy per authenticated/anon (default
--      deny) e NESSUNA policy per service_role (bypassa RLS, vedi header).
--      L'accesso di service_role è governato esclusivamente dai GRANT della
--      sezione 5, con REVOKE ALL esplicito da authenticated/anon.
-- ---------------------------------------------------------------------------
-- (Nessuna CREATE POLICY qui: intenzionale.)

-- ---------------------------------------------------------------------------
-- 4.14 ops.sync_runs, ops.integration_cursors, ops.entity_raw_links —
--      append-only/system controlled, R ampio, W solo service_role
-- ---------------------------------------------------------------------------
CREATE POLICY rls_sync_runs_select ON ops.sync_runs
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

CREATE POLICY rls_integration_cursors_select ON ops.integration_cursors
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

CREATE POLICY rls_entity_raw_links_select ON ops.entity_raw_links
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

-- ---------------------------------------------------------------------------
-- 4.15 ops.mapping_queue — R ampio, INSERT solo service_role, risoluzione
--      (UPDATE) da owner/admin/manager/operations
-- ---------------------------------------------------------------------------
CREATE POLICY rls_mapping_queue_select ON ops.mapping_queue
    FOR SELECT TO authenticated
    USING (core.fn_current_user_has_org_access(organization_id));

CREATE POLICY rls_mapping_queue_update ON ops.mapping_queue
    FOR UPDATE TO authenticated
    USING (core.fn_current_user_can_write_org(organization_id))
    WITH CHECK (core.fn_current_user_can_write_org(organization_id));

-- ---------------------------------------------------------------------------
-- 4.16 ops.audit_log — R solo owner/admin, e solo righe con organization_id
--      valorizzato (le righe di sistema, organization_id IS NULL, non sono
--      visibili a nessun ruolo tenant). W solo service_role.
-- ---------------------------------------------------------------------------
CREATE POLICY rls_audit_log_select ON ops.audit_log
    FOR SELECT TO authenticated
    USING (
        organization_id IS NOT NULL
        AND core.fn_current_user_has_org_role(organization_id, ARRAY['owner','admin'])
    );

-- =============================================================================
-- 5. GRANT / REVOKE
-- =============================================================================
-- Principio: REVOKE ALL da PUBLIC come baseline, poi GRANT mirati.
-- anon: zero grant su ogni oggetto di questa migration, senza eccezioni
-- (decisione 9). Nessun ruolo umano riceve mai DELETE su dati fiscali/CORE
-- (decisione 7). service_role non riceve MAI DELETE, su nessuna tabella di
-- questa migration (decisione 12).

-- --- USAGE sullo schema: prerequisito perché qualunque GRANT su tabella
--     abbia effetto. anon non riceve USAGE su alcuno schema applicativo.
REVOKE ALL ON SCHEMA core FROM PUBLIC;
REVOKE ALL ON SCHEMA raw  FROM PUBLIC;
REVOKE ALL ON SCHEMA ops  FROM PUBLIC;

GRANT USAGE ON SCHEMA core TO authenticated, service_role;
GRANT USAGE ON SCHEMA raw  TO service_role;
GRANT USAGE ON SCHEMA ops  TO authenticated, service_role;

-- --- Baseline: nessun privilegio residuo da PUBLIC su nessuna tabella.
REVOKE ALL ON ALL TABLES IN SCHEMA core FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA raw  FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ops  FROM PUBLIC;

-- --- authenticated: SELECT/INSERT/UPDATE secondo la matrice, mai DELETE
--     tranne su user_organization_roles (gestione membership, governata da
--     RLS + trigger, non è "dato fiscale/CORE").

-- Config amministrativa (R tutti, W owner/admin)
GRANT SELECT, UPDATE ON core.organizations TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.locations TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.source_systems TO authenticated;

-- Globale (solo SELECT)
GRANT SELECT ON core.units_of_measure TO authenticated;

-- tax_rates (R tutti/globale, W owner/admin/finance sulle righe tenant)
GRANT SELECT, INSERT, UPDATE ON core.tax_rates TO authenticated;

-- Catalogo operativo (R tutti, W owner/admin/manager/operations)
GRANT SELECT, INSERT, UPDATE ON core.parties TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.party_roles TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.products TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.product_external_refs TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.supplier_product_refs TO authenticated;

-- Configurazione finanziaria (R tutti, W owner/admin/finance)
GRANT SELECT, INSERT, UPDATE ON core.payment_methods TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.payment_method_external_refs TO authenticated;

-- management_rules (R tutti, W owner/admin/manager)
GRANT SELECT, INSERT, UPDATE ON core.management_rules TO authenticated;

-- Append-only/system controlled: solo SELECT per authenticated, nessun
-- INSERT/UPDATE/DELETE (scritte solo da service_role; UPDATE/DELETE sono
-- comunque bloccati dai trigger 003/004/005 indipendentemente dal grant).
GRANT SELECT ON core.rule_classification_links TO authenticated;
GRANT SELECT ON core.product_purchase_prices TO authenticated;

-- Vendite/Acquisti operativi (R tutti, W owner/admin/manager/operations,
-- mai DELETE)
GRANT SELECT, INSERT, UPDATE ON core.sales_documents TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.sales_lines TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.sale_payments TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.purchase_documents TO authenticated;
GRANT SELECT, INSERT, UPDATE ON core.purchase_lines TO authenticated;

-- user_profiles (R come da policy, W solo il proprio profilo, mai INSERT
-- self-service — PENDING DECISION, vedi 4.11 — mai DELETE)
GRANT SELECT, UPDATE ON core.user_profiles TO authenticated;

-- user_organization_roles: unica tabella "fiscale/CORE-adiacente" dove
-- authenticated riceve anche DELETE, governato interamente da RLS + trigger
-- anti-ultimo-owner.
GRANT SELECT, INSERT, UPDATE, DELETE ON core.user_organization_roles TO authenticated;

-- raw.ingest_events: ZERO per authenticated (decisione 5/requisito 5),
-- REVOKE esplicito oltre al REVOKE ALL già fatto sopra (ridondante ma
-- intenzionale: rende il rifiuto leggibile senza dover risalire al REVOKE
-- ALL generico).
REVOKE ALL ON raw.ingest_events FROM authenticated;
REVOKE ALL ON raw.ingest_events FROM anon;

-- ops.* per authenticated: SELECT ampio, UPDATE solo su mapping_queue
-- (risoluzione umana), nessun INSERT/DELETE.
GRANT SELECT ON ops.sync_runs TO authenticated;
GRANT SELECT ON ops.integration_cursors TO authenticated;
GRANT SELECT ON ops.entity_raw_links TO authenticated;
GRANT SELECT, UPDATE ON ops.mapping_queue TO authenticated;
GRANT SELECT ON ops.audit_log TO authenticated;

-- --- service_role: SELECT/INSERT/UPDATE mirati, MAI DELETE su nessuna
--     tabella di questa migration (decisione 12). Nessuna policy RLS
--     corrispondente: l'accesso è governato esclusivamente da questi GRANT
--     più i trigger di provenance/immutabilità già esistenti.

-- Provisioning organizzativo (bootstrap di una nuova organization/sede/
-- integrazione, incluso il primo owner — nessun utente umano potrebbe
-- soddisfare has_org_role su un'organization che non ha ancora membri).
GRANT SELECT, INSERT, UPDATE ON core.organizations TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.locations TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.source_systems TO service_role;
GRANT SELECT, INSERT ON core.user_organization_roles TO service_role;

-- user_profiles: SELECT+INSERT, per un futuro flusso di provisioning
-- backend-driven al signup (PENDING DECISION sul meccanismo esatto, vedi
-- 4.11 — questo grant esiste già perché è comunque necessario a
-- qualunque implementazione scelta in seguito). Nessun UPDATE: la
-- correzione di un profilo esistente resta un'operazione dell'utente
-- stesso (authenticated), non del backend.
GRANT SELECT, INSERT ON core.user_profiles TO service_role;

-- Lettura di riferimento per la normalizzazione (nessuna scrittura: sono
-- dati configurati da umani, non generati dalla pipeline).
GRANT SELECT ON core.units_of_measure TO service_role;
GRANT SELECT ON core.tax_rates TO service_role;
GRANT SELECT ON core.payment_methods TO service_role;
GRANT SELECT ON core.management_rules TO service_role;
GRANT SELECT ON core.party_roles TO service_role;

-- Mapping generati/corretti dalla pipeline di ingestion.
GRANT SELECT, INSERT, UPDATE ON core.parties TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.products TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.product_external_refs TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.supplier_product_refs TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.payment_method_external_refs TO service_role;

-- Normalizzazione CORE vendite/acquisti (INSERT/UPDATE per applicare
-- revisioni, mai DELETE: la strategia è sempre supersede/reversal).
GRANT SELECT, INSERT, UPDATE ON core.sales_documents TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.sales_lines TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.sale_payments TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.purchase_documents TO service_role;
GRANT SELECT, INSERT, UPDATE ON core.purchase_lines TO service_role;

-- Append-only puro: solo SELECT+INSERT, MAI UPDATE (il trigger lo
-- bloccherebbe comunque, ma il grant riflette l'uso legittimo).
GRANT SELECT, INSERT ON core.rule_classification_links TO service_role;
GRANT SELECT, INSERT ON core.product_purchase_prices TO service_role;

-- RAW: SELECT/INSERT/UPDATE (requisito 6), MAI DELETE. UPDATE limitato di
-- fatto ai campi di processing dal trigger di immutabilità di 003_raw_ops,
-- indipendentemente da questo grant.
GRANT SELECT, INSERT, UPDATE ON raw.ingest_events TO service_role;

-- OPS: bookkeeping tecnico (sync_runs/integration_cursors) pienamente
-- read/write per service_role; mapping_queue INSERT (nuove voci) oltre a
-- SELECT/UPDATE (auto-risoluzione); entity_raw_links/audit_log solo
-- SELECT+INSERT (append-only, MAI UPDATE).
GRANT SELECT, INSERT, UPDATE ON ops.sync_runs TO service_role;
GRANT SELECT, INSERT, UPDATE ON ops.integration_cursors TO service_role;
GRANT SELECT, INSERT, UPDATE ON ops.mapping_queue TO service_role;
GRANT SELECT, INSERT ON ops.entity_raw_links TO service_role;
GRANT SELECT, INSERT ON ops.audit_log TO service_role;

-- --- anon: zero grant, esplicito e totale (decisione 9). Nessun GRANT
--     concesso sopra; il REVOKE ALL FROM PUBLIC + l'assenza di qualunque
--     GRANT TO anon già garantiscono zero accesso, ma lo rendiamo
--     verificabile senza ambiguità:
REVOKE ALL ON ALL TABLES IN SCHEMA core FROM anon;
REVOKE ALL ON ALL TABLES IN SCHEMA raw  FROM anon;
REVOKE ALL ON ALL TABLES IN SCHEMA ops  FROM anon;
REVOKE ALL ON SCHEMA core FROM anon;
REVOKE ALL ON SCHEMA raw  FROM anon;
REVOKE ALL ON SCHEMA ops  FROM anon;

COMMIT;

-- =============================================================================
-- FORCE ROW LEVEL SECURITY — verifica richiesta prima di una futura attivazione
-- =============================================================================
-- FORCE_RLS_STATUS = PENDING_REAL_DB_VERIFICATION
--
-- Questa migration NON esegue alcun ALTER TABLE ... FORCE ROW LEVEL SECURITY.
-- Determinato con certezza (fonti PostgreSQL/Supabase, vedi Revisione 2
-- sezione E): BYPASSRLS ha precedenza assoluta su FORCE — un ruolo con
-- BYPASSRLS non è mai vincolato da FORCE. service_role ha BYPASSRLS
-- (confermato), quindi FORCE è comunque irrilevante per lui. Resta aperto
-- se il ruolo `postgres` (tipicamente usato per applicare le migration su
-- Supabase) possieda anch'esso BYPASSRLS: da questo ambiente sandbox (solo
-- PostgreSQL locale puro, nessun accesso al progetto Supabase reale) non è
-- verificabile, e non è stato inventato un risultato.
--
-- Query di verifica da eseguire sul progetto Supabase REALE prima di
-- un'eventuale migration futura che attivi FORCE sulle tabelle candidate
-- (raw.ingest_events, ops.audit_log, ops.entity_raw_links,
-- core.product_purchase_prices, core.rule_classification_links,
-- core.user_organization_roles):
--
--   SELECT rolname, rolsuper, rolbypassrls
--   FROM pg_roles
--   WHERE rolname IN ('postgres', 'service_role', 'authenticated', 'anon', 'supabase_admin');
--
-- Se postgres.rolbypassrls = false: FORCE su quelle 6 tabelle è
-- effettivamente protettiva contro un accesso diretto come table owner, da
-- attivare in una migration successiva con test dedicato.
-- Se postgres.rolbypassrls = true: FORCE non aggiungerebbe protezione
-- reale; da rivalutare con un ruolo tecnico dedicato senza BYPASSRLS prima
-- di considerare FORCE "protezione effettiva".
-- =============================================================================
