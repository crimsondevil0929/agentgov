--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15 (Debian 16.15-1.pgdg13+2)
-- Dumped by pg_dump version 16.15 (Debian 16.15-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: fixture; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA fixture;


--
-- Name: append_only(); Type: FUNCTION; Schema: fixture; Owner: -
--

CREATE FUNCTION fixture.append_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
            BEGIN
                RAISE EXCEPTION 'agentgov: ledger entries are append-only; % refused', TG_OP
                    USING ERRCODE = 'integrity_constraint_violation';
            END
            $$;


--
-- Name: claim(bytea, uuid, uuid, text, text, text); Type: FUNCTION; Schema: fixture; Owner: -
--

CREATE FUNCTION fixture.claim(p_token bytea, p_claim uuid, p_hold uuid, p_scope text, p_amount text, p_memo text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
            DECLARE
                expected bytea;
            BEGIN
                SELECT sha256(j.k || convert_to(pg_current_xact_id()::text, 'UTF8'))
                  INTO expected FROM "fixture"."join_key" AS j;
                IF expected IS NULL OR p_token IS DISTINCT FROM expected THEN
                    RAISE EXCEPTION 'agentgov: no governor of this ledger joined this transaction'
                        USING ERRCODE = 'insufficient_privilege';
                END IF;
                INSERT INTO "fixture"."claims" (claim_id, hold_id, scope_id, amount, memo)
                VALUES (p_claim, p_hold, p_scope, p_amount, p_memo);
            END
            $$;


--
-- Name: extend_chain(); Type: FUNCTION; Schema: fixture; Owner: -
--

CREATE FUNCTION fixture.extend_chain() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
            BEGIN
                IF NEW.sequence = 1 THEN
                    IF NEW.prev_hash <> '0000000000000000000000000000000000000000000000000000000000000000' THEN
                        RAISE EXCEPTION 'agentgov: entry 1 does not link to the genesis hash'
                            USING ERRCODE = 'integrity_constraint_violation';
                    END IF;
                ELSIF NOT EXISTS (
                    SELECT 1 FROM "fixture"."entries" AS e
                    WHERE e.sequence = NEW.sequence - 1 AND e.entry_hash = NEW.prev_hash
                ) THEN
                    RAISE EXCEPTION 'agentgov: entry % does not extend the committed chain',
                        NEW.sequence
                        USING ERRCODE = 'integrity_constraint_violation',
                              HINT = 'a writer must hold the ledger writer lock and build on '
                                     'the committed head';
                END IF;
                RETURN NEW;
            END
            $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: claims; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.claims (
    seq bigint NOT NULL,
    claim_id uuid NOT NULL,
    hold_id uuid,
    scope_id text NOT NULL,
    amount text NOT NULL,
    memo text NOT NULL,
    claimed_by xid8 DEFAULT pg_current_xact_id() NOT NULL,
    claimed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: claims_seq_seq; Type: SEQUENCE; Schema: fixture; Owner: -
--

ALTER TABLE fixture.claims ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME fixture.claims_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: control_events; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.control_events (
    id bigint NOT NULL,
    event_id uuid NOT NULL,
    "timestamp" text NOT NULL,
    event_type text NOT NULL,
    scope_id text NOT NULL,
    reason text NOT NULL,
    ledger_head_hash text NOT NULL,
    entry_id uuid
);


--
-- Name: control_events_id_seq; Type: SEQUENCE; Schema: fixture; Owner: -
--

ALTER TABLE fixture.control_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME fixture.control_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: entries; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.entries (
    sequence bigint NOT NULL,
    entry_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    "timestamp" text NOT NULL,
    entry_type text NOT NULL,
    direction text NOT NULL,
    scope_id text NOT NULL,
    counterparty_id text,
    amount text NOT NULL,
    balance_after text NOT NULL,
    prev_hash text NOT NULL,
    entry_hash text NOT NULL,
    memo text DEFAULT ''::text NOT NULL,
    version text NOT NULL,
    ref uuid,
    CONSTRAINT entries_sequence_check CHECK ((sequence > 0))
);


--
-- Name: join_key; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.join_key (
    singleton boolean DEFAULT true NOT NULL,
    k bytea NOT NULL,
    CONSTRAINT join_key_k_check CHECK ((length(k) >= 32)),
    CONSTRAINT join_key_singleton_check CHECK (singleton)
);


--
-- Name: nodes; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.nodes (
    scope_id text NOT NULL,
    parent_id text,
    depth integer NOT NULL,
    allocated text NOT NULL,
    created_at text NOT NULL
);


--
-- Name: open_authorizations; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.open_authorizations (
    authorization_id uuid NOT NULL,
    scope_id text NOT NULL,
    amount text NOT NULL,
    opened_at text NOT NULL,
    entry_id uuid NOT NULL
);


--
-- Name: schema_meta; Type: TABLE; Schema: fixture; Owner: -
--

CREATE TABLE fixture.schema_meta (
    key text NOT NULL,
    value text NOT NULL
);


--
-- Data for Name: claims; Type: TABLE DATA; Schema: fixture; Owner: -
--



--
-- Data for Name: control_events; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (1, '006e6038-e22e-47e8-99a9-de128b4dd852', '2026-10-11T07:43:10.860515Z', 'circuit_tripped', 'writer', 'operator halt', 'a6ef0db0f805a8f16d318c11cb3a96bc27f2527db2e1784756f2a944fd357c2f', '006e6038-e22e-47e8-99a9-de128b4dd852');
INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (2, 'cfaa97da-4d63-4db0-abb6-407c2ff7800a', '2026-10-11T07:43:10.867872Z', 'circuit_reset', 'writer', 'operator reset', '0df48a2ada4d1701c32c840ccb3642b95779a9d211671252f5591f672709f227', 'cfaa97da-4d63-4db0-abb6-407c2ff7800a');
INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (3, 'a9122909-5366-4a8d-85c8-25c59ca3d84c', '2026-10-11T07:43:10.872518Z', 'circuit_tripped', 'writer', 'halted again', 'e2ef8fd6f973e62048ea4a4d8efd828dd6ba6c9f1b8506c979bbca625f836aec', 'a9122909-5366-4a8d-85c8-25c59ca3d84c');


--
-- Data for Name: entries; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.entries VALUES (1, '2d1e73cc-ba62-4762-ade2-852bbf3d32ff', 'adca147c-2282-4435-be54-5c261ca32b04', '2026-10-11T07:43:10.810112Z', 'funding', 'CR', 'orchestrator', NULL, '10.00000000', '10.00000000', '0000000000000000000000000000000000000000000000000000000000000000', '374317d7d00a95f3a5a74f4f3059a495494304666a67eee6b2665cf14304323d', 'root envelope issued', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (2, 'a0da57e8-9c32-4756-8396-27238936ffed', '5b0f2bd6-35f9-4e14-a189-69f8d5632877', '2026-10-11T07:43:10.813875Z', 'allocation', 'DR', 'orchestrator', 'researcher', '2.50000000', '7.50000000', '374317d7d00a95f3a5a74f4f3059a495494304666a67eee6b2665cf14304323d', '4b71292d30876cbc77a4eca9f3add119460d3ae3639560f7f047a8e7d0c3e6e5', 'sub-budget delegated to researcher', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (3, 'f10143b3-deee-475c-a3db-f925582eb249', '5b0f2bd6-35f9-4e14-a189-69f8d5632877', '2026-10-11T07:43:10.813875Z', 'allocation', 'CR', 'researcher', 'orchestrator', '2.50000000', '2.50000000', '4b71292d30876cbc77a4eca9f3add119460d3ae3639560f7f047a8e7d0c3e6e5', '20ec8f5fab8dfdcf628bf0667c8944c7222b12a88120e088faa582d02987f1e5', 'sub-budget delegated to researcher', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (4, '6a2d64c8-57ba-4c19-bec5-d6611583ac3b', 'fcfefb57-63d9-4f0a-b3a7-5c0c21b6509f', '2026-10-11T07:43:10.817820Z', 'allocation', 'DR', 'orchestrator', 'writer', '1.00000000', '6.50000000', '20ec8f5fab8dfdcf628bf0667c8944c7222b12a88120e088faa582d02987f1e5', '73f39f8193a8eacca8216da9a7a7805b7c4edfa6577c740eb8c056229cc00087', 'sub-budget delegated to writer', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (5, '8c265e83-01bc-48fb-8dee-51eae98a88ca', 'fcfefb57-63d9-4f0a-b3a7-5c0c21b6509f', '2026-10-11T07:43:10.817820Z', 'allocation', 'CR', 'writer', 'orchestrator', '1.00000000', '1.00000000', '73f39f8193a8eacca8216da9a7a7805b7c4edfa6577c740eb8c056229cc00087', 'ac7ab43203c07c3890a19bf02aba8ba95b6db5d55c591c45564214e1d1149be0', 'sub-budget delegated to writer', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (6, '99ddf056-af1b-4cb9-9aad-5ac2c85eebf5', '0e47a455-646d-47dd-b180-105cb03e3dbd', '2026-10-11T07:43:10.821858Z', 'hold', 'DR', 'researcher', NULL, '0.40000000', '2.10000000', 'ac7ab43203c07c3890a19bf02aba8ba95b6db5d55c591c45564214e1d1149be0', '332e64be9b7b4757014821251566b0508e54cd81f5762dabfaa248c67a53278a', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (7, 'd64fd018-5ada-48b5-ac77-252838c6dc1f', '26cd192e-04f6-42ac-b7ec-2316af137759', '2026-10-11T07:43:10.827737Z', 'hold_void', 'CR', 'researcher', NULL, '0.40000000', '2.50000000', '332e64be9b7b4757014821251566b0508e54cd81f5762dabfaa248c67a53278a', '9c13f7a0625d060c825ca14485a65418527ab32eb26fc0d61018135d65c7da9f', 'authorization captured', 'AGOV2', '99ddf056-af1b-4cb9-9aad-5ac2c85eebf5');
INSERT INTO fixture.entries VALUES (8, '4a285857-84bf-46b3-8435-227c6c1b85af', '26cd192e-04f6-42ac-b7ec-2316af137759', '2026-10-11T07:43:10.827737Z', 'spend', 'DR', 'researcher', NULL, '0.31000000', '2.19000000', '9c13f7a0625d060c825ca14485a65418527ab32eb26fc0d61018135d65c7da9f', '6423c0256b4d3a5ee001106a4507218c3b0aceb3209a2d65e9cf5ef371015ca1', 'settled call cost', 'AGOV2', '99ddf056-af1b-4cb9-9aad-5ac2c85eebf5');
INSERT INTO fixture.entries VALUES (9, 'cfb0538d-af9a-441e-8aa0-500e6de22a99', '31b16c63-25fa-4bf3-a7a5-1ad436e5b09a', '2026-10-11T07:43:10.830331Z', 'hold', 'DR', 'writer', NULL, '0.25000000', '0.75000000', '6423c0256b4d3a5ee001106a4507218c3b0aceb3209a2d65e9cf5ef371015ca1', '624db0791fdef176a267da4f577bd92477a5e4c061c761a037f38b5c96fbe3ce', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (10, '30a04f01-d23a-4d07-8cbc-8f6d1ccf179c', '491aacbe-dcc9-493e-8df8-05917f651ffa', '2026-10-11T07:43:10.831082Z', 'hold_void', 'CR', 'writer', NULL, '0.25000000', '1.00000000', '624db0791fdef176a267da4f577bd92477a5e4c061c761a037f38b5c96fbe3ce', 'fc10270c473d45c69b9f42d3e20a0d2b0781d66e289d06ac59db916bc80bc96e', 'authorization captured', 'AGOV2', 'cfb0538d-af9a-441e-8aa0-500e6de22a99');
INSERT INTO fixture.entries VALUES (11, '9e81b92d-d28b-4a2b-a3a5-54b05342113a', '491aacbe-dcc9-493e-8df8-05917f651ffa', '2026-10-11T07:43:10.831082Z', 'spend', 'DR', 'writer', NULL, '0.25000000', '0.75000000', 'fc10270c473d45c69b9f42d3e20a0d2b0781d66e289d06ac59db916bc80bc96e', '1fa7406a80b19e4af129ac66b910ff5cb171effc33f9b1d2704cec2f2dc10159', 'settled call cost', 'AGOV2', 'cfb0538d-af9a-441e-8aa0-500e6de22a99');
INSERT INTO fixture.entries VALUES (12, 'f6ac6619-b50d-4ec7-bf03-db3e65f48bec', 'e349e727-b43c-4eb8-854d-43163182f484', '2026-10-11T07:43:10.834666Z', 'reversal', 'CR', 'writer', NULL, '0.05000000', '0.80000000', '1fa7406a80b19e4af129ac66b910ff5cb171effc33f9b1d2704cec2f2dc10159', 'beb178a400d9b5212b7f771749c13b4a16365f980885a994efe672decb9cf3b1', 'vendor refund', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (13, 'bb84b4bd-4474-4e01-87cd-9bd832b579f5', 'b14456c0-a21a-4700-a1e0-34ec9fce298f', '2026-10-11T07:43:10.836539Z', 'hold', 'DR', 'researcher', NULL, '0.10000000', '2.09000000', 'beb178a400d9b5212b7f771749c13b4a16365f980885a994efe672decb9cf3b1', 'f6e7f3441c353ed343f0509b0a2cefe261be7f2b9710aed783d90845f6d80f6c', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (14, '7a0b3b89-e40f-4ac8-be1d-bae040f5d96d', 'e57cdffa-cf2d-4b64-a39b-6d017208a638', '2026-10-11T07:43:10.840969Z', 'hold', 'DR', 'writer', NULL, '0.10000000', '0.70000000', 'f6e7f3441c353ed343f0509b0a2cefe261be7f2b9710aed783d90845f6d80f6c', 'bab5bda77ee9cd8d7d8ee88c5f4093fe0717a9c16ae80ea5bb6d12cdd5cd4157', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (15, 'cb3f8108-cca0-4453-9469-2afb179c5801', '3dc78e36-3b36-4438-aa78-9a45888f67bd', '2026-10-11T07:43:10.846532Z', 'hold_void', 'CR', 'writer', NULL, '0.10000000', '0.80000000', 'bab5bda77ee9cd8d7d8ee88c5f4093fe0717a9c16ae80ea5bb6d12cdd5cd4157', '09b10371b99a083ceec7f0120b221471dbceb92020a31041a70764490f2aeed2', 'authorization voided', 'AGOV2', '7a0b3b89-e40f-4ac8-be1d-bae040f5d96d');
INSERT INTO fixture.entries VALUES (16, '57f9f6ce-4ecb-4fa3-bac2-075f2a507480', 'da07ae09-affb-47e4-87bc-e6b0bbd0ba19', '2026-10-11T07:43:10.850932Z', 'release', 'DR', 'writer', 'orchestrator', '0.20000000', '0.60000000', '09b10371b99a083ceec7f0120b221471dbceb92020a31041a70764490f2aeed2', '8c52e4abaf7d7a9f9547c5a659b55c82f069516eb6c10858c672e94b33b84f19', 'unused budget returned to orchestrator', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (17, '378fa9e4-69d3-47c7-b9be-dd6dc70b786a', 'da07ae09-affb-47e4-87bc-e6b0bbd0ba19', '2026-10-11T07:43:10.850932Z', 'release', 'CR', 'orchestrator', 'writer', '0.20000000', '6.70000000', '8c52e4abaf7d7a9f9547c5a659b55c82f069516eb6c10858c672e94b33b84f19', '1f852f66b66533e14b90c38a2998d25369bd63984c90a099c624ea92b49f08d1', 'unused budget returned to orchestrator', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (18, 'b3cb3e94-ee37-4f58-aa2f-527ae5f3deed', 'f62d3ae8-ff03-4de6-8f35-a957089114bd', '2026-10-11T07:43:10.854948Z', 'funding', 'CR', 'orchestrator', NULL, '5.00000000', '11.70000000', '1f852f66b66533e14b90c38a2998d25369bd63984c90a099c624ea92b49f08d1', 'a6ef0db0f805a8f16d318c11cb3a96bc27f2527db2e1784756f2a944fd357c2f', 'envelope topped up', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (19, '006e6038-e22e-47e8-99a9-de128b4dd852', '8a557b2d-7605-46de-a0c8-1143b6eb3ba6', '2026-10-11T07:43:10.860515Z', 'circuit_tripped', '--', 'writer', NULL, '0', '0.60000000', 'a6ef0db0f805a8f16d318c11cb3a96bc27f2527db2e1784756f2a944fd357c2f', '0df48a2ada4d1701c32c840ccb3642b95779a9d211671252f5591f672709f227', 'operator halt', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (20, 'cfaa97da-4d63-4db0-abb6-407c2ff7800a', '8de38cc4-492e-4a62-9667-37d90ad4d63e', '2026-10-11T07:43:10.867872Z', 'circuit_reset', '--', 'writer', NULL, '0', '0.60000000', '0df48a2ada4d1701c32c840ccb3642b95779a9d211671252f5591f672709f227', 'e2ef8fd6f973e62048ea4a4d8efd828dd6ba6c9f1b8506c979bbca625f836aec', 'operator reset', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (21, 'a9122909-5366-4a8d-85c8-25c59ca3d84c', '4c9eeedf-7678-4fb6-a46e-003c5b66340c', '2026-10-11T07:43:10.872518Z', 'circuit_tripped', '--', 'writer', NULL, '0', '0.60000000', 'e2ef8fd6f973e62048ea4a4d8efd828dd6ba6c9f1b8506c979bbca625f836aec', '56dd02ca03fcebf188d956a53c1e9a65a4946d08b1e204b2e5585d1916c0777b', 'halted again', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (22, 'cb772b19-6022-471e-a498-496a6b14020b', '1a836caf-4d18-4831-a499-5ca8bc132d62', '2026-10-11T07:43:10.882105Z', 'anchor', '--', 'orchestrator', NULL, '0', '11.70000000', '56dd02ca03fcebf188d956a53c1e9a65a4946d08b1e204b2e5585d1916c0777b', '6e91c5781e8210ca7af93488b5d6831b3561890fe86c8b66bf80b032df81ddfc', 'escrow head 9f2c', 'AGOV2', NULL);


--
-- Data for Name: join_key; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.join_key VALUES (true, '\x3bb9429da00b1cf6f285c2f96b3d26002f0ed9298144f17b7647649a0897de10');


--
-- Data for Name: nodes; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.nodes VALUES ('researcher', 'orchestrator', 1, '2.50000000', '2026-10-11T07:43:10.813875Z');
INSERT INTO fixture.nodes VALUES ('writer', 'orchestrator', 1, '1.00000000', '2026-10-11T07:43:10.817820Z');
INSERT INTO fixture.nodes VALUES ('orchestrator', NULL, 0, '15.00000000', '2026-10-11T07:43:10.810112Z');


--
-- Data for Name: open_authorizations; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.open_authorizations VALUES ('bb84b4bd-4474-4e01-87cd-9bd832b579f5', 'researcher', '0.10000000', '2026-10-11T07:43:10.836539Z', 'bb84b4bd-4474-4e01-87cd-9bd832b579f5');


--
-- Data for Name: schema_meta; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.schema_meta VALUES ('schema_version', 'pg1');


--
-- Name: claims_seq_seq; Type: SEQUENCE SET; Schema: fixture; Owner: -
--

SELECT pg_catalog.setval('fixture.claims_seq_seq', 1, false);


--
-- Name: control_events_id_seq; Type: SEQUENCE SET; Schema: fixture; Owner: -
--

SELECT pg_catalog.setval('fixture.control_events_id_seq', 3, true);


--
-- Name: claims claims_hold_id_key; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.claims
    ADD CONSTRAINT claims_hold_id_key UNIQUE (hold_id);


--
-- Name: claims claims_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.claims
    ADD CONSTRAINT claims_pkey PRIMARY KEY (claim_id);


--
-- Name: claims claims_seq_key; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.claims
    ADD CONSTRAINT claims_seq_key UNIQUE (seq);


--
-- Name: control_events control_events_event_id_key; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.control_events
    ADD CONSTRAINT control_events_event_id_key UNIQUE (event_id);


--
-- Name: control_events control_events_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.control_events
    ADD CONSTRAINT control_events_pkey PRIMARY KEY (id);


--
-- Name: entries entries_entry_id_key; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.entries
    ADD CONSTRAINT entries_entry_id_key UNIQUE (entry_id);


--
-- Name: entries entries_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.entries
    ADD CONSTRAINT entries_pkey PRIMARY KEY (sequence);


--
-- Name: join_key join_key_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.join_key
    ADD CONSTRAINT join_key_pkey PRIMARY KEY (singleton);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (scope_id);


--
-- Name: open_authorizations open_authorizations_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.open_authorizations
    ADD CONSTRAINT open_authorizations_pkey PRIMARY KEY (authorization_id);


--
-- Name: schema_meta schema_meta_pkey; Type: CONSTRAINT; Schema: fixture; Owner: -
--

ALTER TABLE ONLY fixture.schema_meta
    ADD CONSTRAINT schema_meta_pkey PRIMARY KEY (key);


--
-- Name: entries append_only; Type: TRIGGER; Schema: fixture; Owner: -
--

CREATE TRIGGER append_only BEFORE DELETE OR UPDATE ON fixture.entries FOR EACH ROW EXECUTE FUNCTION fixture.append_only();

ALTER TABLE fixture.entries ENABLE ALWAYS TRIGGER append_only;


--
-- Name: entries append_only_truncate; Type: TRIGGER; Schema: fixture; Owner: -
--

CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON fixture.entries FOR EACH STATEMENT EXECUTE FUNCTION fixture.append_only();

ALTER TABLE fixture.entries ENABLE ALWAYS TRIGGER append_only_truncate;


--
-- Name: entries extend_chain; Type: TRIGGER; Schema: fixture; Owner: -
--

CREATE TRIGGER extend_chain BEFORE INSERT ON fixture.entries FOR EACH ROW EXECUTE FUNCTION fixture.extend_chain();

ALTER TABLE fixture.entries ENABLE ALWAYS TRIGGER extend_chain;


--
-- PostgreSQL database dump complete
--


