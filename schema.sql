--
-- PostgreSQL database dump
--

\restrict qFfbEXJjjOh763IW0g4tyHJVBqzqr5rbsh4HsvDeMhkOaFC8TU9K3n7TFjmUTBN

-- Dumped from database version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)
-- Dumped by pg_dump version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ip_reputation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_reputation (
    id bigint NOT NULL,
    ip_address inet NOT NULL,
    score integer DEFAULT 0 NOT NULL,
    events_count integer DEFAULT 0 NOT NULL,
    last_seen timestamp with time zone,
    risk_level text,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: ip_reputation_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ip_reputation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ip_reputation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ip_reputation_id_seq OWNED BY public.ip_reputation.id;


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip inet NOT NULL,
    dst_ip inet,
    service text,
    session text,
    event_type text NOT NULL,
    details jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: security_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_events_id_seq OWNED BY public.security_events.id;


--
-- Name: threat_intel; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_intel (
    id bigint NOT NULL,
    ip_address inet NOT NULL,
    score integer NOT NULL,
    reason text,
    confidence double precision,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: threat_intel_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_intel_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_intel_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_intel_id_seq OWNED BY public.threat_intel.id;


--
-- Name: ip_reputation id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_reputation ALTER COLUMN id SET DEFAULT nextval('public.ip_reputation_id_seq'::regclass);


--
-- Name: security_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events ALTER COLUMN id SET DEFAULT nextval('public.security_events_id_seq'::regclass);


--
-- Name: threat_intel id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel ALTER COLUMN id SET DEFAULT nextval('public.threat_intel_id_seq'::regclass);


--
-- Name: ip_reputation ip_reputation_ip_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_reputation
    ADD CONSTRAINT ip_reputation_ip_address_key UNIQUE (ip_address);


--
-- Name: ip_reputation ip_reputation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_reputation
    ADD CONSTRAINT ip_reputation_pkey PRIMARY KEY (id);


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);


--
-- Name: threat_intel threat_intel_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel
    ADD CONSTRAINT threat_intel_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict qFfbEXJjjOh763IW0g4tyHJVBqzqr5rbsh4HsvDeMhkOaFC8TU9K3n7TFjmUTBN
