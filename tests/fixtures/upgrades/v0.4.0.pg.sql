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

INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (1, '69ef6152-8172-4e93-ad96-cbfc78b4b888', '2026-10-11T07:43:12.060716Z', 'circuit_tripped', 'writer', 'operator halt', 'a8b0ed1658259336025aa43c21654e5bcc9ef50606f93a490767da8bdd59a7c4', '69ef6152-8172-4e93-ad96-cbfc78b4b888');
INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (2, '3ee0fde9-da42-4d24-9907-4a03b1442bd8', '2026-10-11T07:43:12.063844Z', 'circuit_reset', 'writer', 'operator reset', 'b7d3deb0ef99b2d20fe522701c80fca91625a9309d8d54823e1639cda17cf1d8', '3ee0fde9-da42-4d24-9907-4a03b1442bd8');
INSERT INTO fixture.control_events OVERRIDING SYSTEM VALUE VALUES (3, '8627c0e6-1cca-4541-8f3c-690ac9a9d9ab', '2026-10-11T07:43:12.065788Z', 'circuit_tripped', 'writer', 'halted again', 'f4b74cbe0865d308f376e98d2221be0cb09d0c0e9a361a3103232d50f9d96c96', '8627c0e6-1cca-4541-8f3c-690ac9a9d9ab');


--
-- Data for Name: entries; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.entries VALUES (1, 'd0952831-6052-4c21-9ee2-6ff63adef3f6', '4ddafc55-0695-43f6-8f0e-099a44c0fc38', '2026-10-11T07:43:12.028147Z', 'funding', 'CR', 'orchestrator', NULL, '10.00000000', '10.00000000', '0000000000000000000000000000000000000000000000000000000000000000', '2ebbc84b8f45007f2945fe20a345c84088345a4e22b550891d76cc9951b7f3b9', 'root envelope issued', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (2, 'e77cca46-529c-4ce5-ade4-52d2abf05800', '138ec5b3-66bf-46d2-8a97-a11d882404ab', '2026-10-11T07:43:12.032910Z', 'allocation', 'DR', 'orchestrator', 'researcher', '2.50000000', '7.50000000', '2ebbc84b8f45007f2945fe20a345c84088345a4e22b550891d76cc9951b7f3b9', 'f1fee371eb3a04e536f57ae6bc76e2550981e98b5fe534bfd09073d6582b474f', 'sub-budget delegated to researcher', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (3, '3330de8e-3d0b-47c9-a42d-fff55ee7e3d8', '138ec5b3-66bf-46d2-8a97-a11d882404ab', '2026-10-11T07:43:12.032910Z', 'allocation', 'CR', 'researcher', 'orchestrator', '2.50000000', '2.50000000', 'f1fee371eb3a04e536f57ae6bc76e2550981e98b5fe534bfd09073d6582b474f', '135a9887ccb71aa8b50e2d6bed12ca375b1bcd5ea6a466f9f8118a0ec7f2cd34', 'sub-budget delegated to researcher', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (4, '2f7b6aae-8939-47b4-a376-e1b3bf0e98dd', '48b3940a-5b28-4d94-9543-7068006e63e2', '2026-10-11T07:43:12.036758Z', 'allocation', 'DR', 'orchestrator', 'writer', '1.00000000', '6.50000000', '135a9887ccb71aa8b50e2d6bed12ca375b1bcd5ea6a466f9f8118a0ec7f2cd34', '171f824dcae0fea74826f5d56205795ed80170e48375eb1e7ab801f322a49d89', 'sub-budget delegated to writer', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (5, '0d763976-cd28-4962-b235-e2c9f02e3d91', '48b3940a-5b28-4d94-9543-7068006e63e2', '2026-10-11T07:43:12.036758Z', 'allocation', 'CR', 'writer', 'orchestrator', '1.00000000', '1.00000000', '171f824dcae0fea74826f5d56205795ed80170e48375eb1e7ab801f322a49d89', 'db04abb8f99522f95f183804aa2b71268f3db1908c6469c1ac01787a09b8ac84', 'sub-budget delegated to writer', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (6, '82308cbe-4fb9-4a97-838b-95cabd9db8ae', 'f28fa798-b06e-4f0e-b9a4-f016c880e010', '2026-10-11T07:43:12.039483Z', 'hold', 'DR', 'researcher', NULL, '0.40000000', '2.10000000', 'db04abb8f99522f95f183804aa2b71268f3db1908c6469c1ac01787a09b8ac84', '217d895ba079286189affadbbf3035249e5363ff99f097f69889efa7419309ca', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (7, 'd3ec6bb4-1436-4b03-8c58-b6351922f5e7', 'd27cc216-074b-498f-bab8-2bedb699894f', '2026-10-11T07:43:12.042469Z', 'hold_void', 'CR', 'researcher', NULL, '0.40000000', '2.50000000', '217d895ba079286189affadbbf3035249e5363ff99f097f69889efa7419309ca', '422d4020ca1f967d604721139ebc674ec1ece38119bbd6a5b07ea2f003e3e102', 'authorization captured', 'AGOV2', '82308cbe-4fb9-4a97-838b-95cabd9db8ae');
INSERT INTO fixture.entries VALUES (8, '9127db81-8254-4986-adc1-82ec62d1bc9a', 'd27cc216-074b-498f-bab8-2bedb699894f', '2026-10-11T07:43:12.042469Z', 'spend', 'DR', 'researcher', NULL, '0.31000000', '2.19000000', '422d4020ca1f967d604721139ebc674ec1ece38119bbd6a5b07ea2f003e3e102', '109d8d381c214ed3141602c1368c5fdd1f82806f5e558eb022123f16efd4bd51', 'settled call cost', 'AGOV2', '82308cbe-4fb9-4a97-838b-95cabd9db8ae');
INSERT INTO fixture.entries VALUES (9, 'd783f084-aa46-406c-91b9-a1b077daf45b', '03411cb0-7a24-4f45-b8e1-ac884153c0e9', '2026-10-11T07:43:12.045590Z', 'hold', 'DR', 'writer', NULL, '0.25000000', '0.75000000', '109d8d381c214ed3141602c1368c5fdd1f82806f5e558eb022123f16efd4bd51', 'b485112ccf93a90300d6b8765b2f5e75d48c187421ac2cd81f8f8840d435faf4', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (10, '733f0b9b-8c92-484e-bddc-ab64e5002cc7', 'f8545ade-444b-44e0-b543-85b8c104bb91', '2026-10-11T07:43:12.046755Z', 'hold_void', 'CR', 'writer', NULL, '0.25000000', '1.00000000', 'b485112ccf93a90300d6b8765b2f5e75d48c187421ac2cd81f8f8840d435faf4', '40b25930b19f163bcf7cfefaefabf420b1f3532eb17af2b988afce7c4baaef6d', 'authorization captured', 'AGOV2', 'd783f084-aa46-406c-91b9-a1b077daf45b');
INSERT INTO fixture.entries VALUES (11, 'b40ffa6c-a337-4912-8ef5-176cba927308', 'f8545ade-444b-44e0-b543-85b8c104bb91', '2026-10-11T07:43:12.046755Z', 'spend', 'DR', 'writer', NULL, '0.25000000', '0.75000000', '40b25930b19f163bcf7cfefaefabf420b1f3532eb17af2b988afce7c4baaef6d', '16173596adfc655ae0799393dc0d68b59fba55111a87d62f62dfb0d22390f235', 'settled call cost', 'AGOV2', 'd783f084-aa46-406c-91b9-a1b077daf45b');
INSERT INTO fixture.entries VALUES (12, '83cd0160-2765-48bf-a6f8-55f6b2294071', '2092c32b-441f-41e3-99a3-3a61df9d8e74', '2026-10-11T07:43:12.049281Z', 'reversal', 'CR', 'writer', NULL, '0.05000000', '0.80000000', '16173596adfc655ae0799393dc0d68b59fba55111a87d62f62dfb0d22390f235', '424bd94b4da75cd5aab6c97c56ba294060036bc1e1cfb6dcf202e1b870d77d22', 'vendor refund', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (13, '800968ce-cf77-440d-90c9-e73da823314c', '1a728a17-1be8-4bd7-aaf4-9e41be200fb4', '2026-10-11T07:43:12.051131Z', 'hold', 'DR', 'researcher', NULL, '0.10000000', '2.09000000', '424bd94b4da75cd5aab6c97c56ba294060036bc1e1cfb6dcf202e1b870d77d22', 'd19b6e0e42a52fd134ec12972861b0874ab83301f2681afcd9b31bbdc6af3165', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (14, '0395c276-470b-4284-9c19-41c8298ee9a8', 'c6b4d634-e35c-453e-a9d7-97a466e82f7b', '2026-10-11T07:43:12.053015Z', 'hold', 'DR', 'writer', NULL, '0.10000000', '0.70000000', 'd19b6e0e42a52fd134ec12972861b0874ab83301f2681afcd9b31bbdc6af3165', '7aba5b4442380421482000a204685a34877640daebb2d8f4f7920c3c89cc7e0e', 'authorization hold', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (15, '092bc009-42da-47f8-9be1-bde01e97a361', '8b875dec-e54f-4860-990e-83130ec04a49', '2026-10-11T07:43:12.055141Z', 'hold_void', 'CR', 'writer', NULL, '0.10000000', '0.80000000', '7aba5b4442380421482000a204685a34877640daebb2d8f4f7920c3c89cc7e0e', '146dd5fa79372a31d7192814fdb65185564dc71043c74fbd2ffc80bfea2c6213', 'authorization voided', 'AGOV2', '0395c276-470b-4284-9c19-41c8298ee9a8');
INSERT INTO fixture.entries VALUES (16, 'b396abe0-27a2-4b97-b1d9-b4f2a0675838', 'e1585b54-5e0e-48e1-b3e4-3d23d5bfa3b4', '2026-10-11T07:43:12.057456Z', 'release', 'DR', 'writer', 'orchestrator', '0.20000000', '0.60000000', '146dd5fa79372a31d7192814fdb65185564dc71043c74fbd2ffc80bfea2c6213', 'c3399a9ae32cbc8c47f7064abc55c90c6704baf6d391843321301adbe7532d3f', 'unused budget returned to orchestrator', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (17, '0e134245-cc55-4b0a-b27a-bb8f9bfdd817', 'e1585b54-5e0e-48e1-b3e4-3d23d5bfa3b4', '2026-10-11T07:43:12.057456Z', 'release', 'CR', 'orchestrator', 'writer', '0.20000000', '6.70000000', 'c3399a9ae32cbc8c47f7064abc55c90c6704baf6d391843321301adbe7532d3f', '3301512dbee6693ed1b0389f679d3aa26188fe872ea6ac507474035b3206c294', 'unused budget returned to orchestrator', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (18, 'e4bb168c-4f5f-42f6-941a-431cf81e9f13', '84158b52-e737-4c52-8c78-eb320eee2ed4', '2026-10-11T07:43:12.058814Z', 'funding', 'CR', 'orchestrator', NULL, '5.00000000', '11.70000000', '3301512dbee6693ed1b0389f679d3aa26188fe872ea6ac507474035b3206c294', 'a8b0ed1658259336025aa43c21654e5bcc9ef50606f93a490767da8bdd59a7c4', 'envelope topped up', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (19, '69ef6152-8172-4e93-ad96-cbfc78b4b888', '519d393d-5b5f-4838-ba0e-176f921191a3', '2026-10-11T07:43:12.060716Z', 'circuit_tripped', '--', 'writer', NULL, '0', '0.60000000', 'a8b0ed1658259336025aa43c21654e5bcc9ef50606f93a490767da8bdd59a7c4', 'b7d3deb0ef99b2d20fe522701c80fca91625a9309d8d54823e1639cda17cf1d8', 'operator halt', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (20, '3ee0fde9-da42-4d24-9907-4a03b1442bd8', 'e6ad0567-e30a-4689-9665-25ed56c58d53', '2026-10-11T07:43:12.063844Z', 'circuit_reset', '--', 'writer', NULL, '0', '0.60000000', 'b7d3deb0ef99b2d20fe522701c80fca91625a9309d8d54823e1639cda17cf1d8', 'f4b74cbe0865d308f376e98d2221be0cb09d0c0e9a361a3103232d50f9d96c96', 'operator reset', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (21, '8627c0e6-1cca-4541-8f3c-690ac9a9d9ab', 'f8ca8ab3-c8e5-4311-9f36-7ea39d5f01c7', '2026-10-11T07:43:12.065788Z', 'circuit_tripped', '--', 'writer', NULL, '0', '0.60000000', 'f4b74cbe0865d308f376e98d2221be0cb09d0c0e9a361a3103232d50f9d96c96', 'f3be7cc1864985ff4aa2ce1fb44525647c7230fd0895a05d291c1c38859d2a22', 'halted again', 'AGOV2', NULL);
INSERT INTO fixture.entries VALUES (22, 'c1f6e504-8170-40e6-a68a-47f791189930', '17319869-7ae0-43dd-afdb-68f748f250b3', '2026-10-11T07:43:12.068138Z', 'anchor', '--', 'orchestrator', NULL, '0', '11.70000000', 'f3be7cc1864985ff4aa2ce1fb44525647c7230fd0895a05d291c1c38859d2a22', '41f0b23eb830791f4e58b5a22f1882672aab5fdd53583b1454d68addb5c393f8', 'escrow head 9f2c', 'AGOV2', NULL);


--
-- Data for Name: join_key; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.join_key VALUES (true, '\xfa35bbc5d4262fa9bfa526533290c85d1f5470ac8f815f2a67836fee024d450f');


--
-- Data for Name: nodes; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.nodes VALUES ('researcher', 'orchestrator', 1, '2.50000000', '2026-10-11T07:43:12.032910Z');
INSERT INTO fixture.nodes VALUES ('writer', 'orchestrator', 1, '1.00000000', '2026-10-11T07:43:12.036758Z');
INSERT INTO fixture.nodes VALUES ('orchestrator', NULL, 0, '15.00000000', '2026-10-11T07:43:12.028147Z');


--
-- Data for Name: open_authorizations; Type: TABLE DATA; Schema: fixture; Owner: -
--

INSERT INTO fixture.open_authorizations VALUES ('800968ce-cf77-440d-90c9-e73da823314c', 'researcher', '0.10000000', '2026-10-11T07:43:12.051131Z', '800968ce-cf77-440d-90c9-e73da823314c');


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


