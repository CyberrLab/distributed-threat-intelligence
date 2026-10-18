# Behavior-Based Distributed Threat Intelligence and Automated Response Framework Using Distributed Honeypots

## Overview

This project explores centralized behavioral correlation of security events collected from distributed honeypots. It analyzes attacker activity, assigns IP reputation scores, exposes threat intelligence through an API, and supports automated temporary firewall blocking on a protected server.

## Architecture

Distributed Cowrie Honeypots
        |
        v
Central Collector (FastAPI)
        |
        v
PostgreSQL Database
        |
        v
Behavioral Correlation and Risk Scoring
        |
        v
Threat Intelligence API
        |
        v
Response Agent
        |
        v
nftables Firewall

## Technologies

- Cowrie honeypot
- Python
- FastAPI
- PostgreSQL
- Linux / Ubuntu
- nftables
- VirtualBox

## Main Features

- Collect events from multiple honeypots.
- Normalize and forward events to a central API.
- Correlate attacker activity across multiple targets.
- Calculate risk scores and store IP reputation.
- Provide threat intelligence through an API.
- Apply temporary firewall blocks on a protected server.

## Research Objective

Evaluate whether centralized behavioral correlation across multiple honeypots can improve threat identification compared with independent, per-server detection.

## Project Status

Core components have been implemented and tested in a controlled virtual lab. Further testing and evaluation are ongoing.

## Disclaimer

This project is intended for authorized cybersecurity education and controlled laboratory testing only.
