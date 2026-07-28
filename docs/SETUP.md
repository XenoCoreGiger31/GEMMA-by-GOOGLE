# Autonomous Security Agent - Setup Guide

## Prerequisites

- Kali Linux
- LM Studio installed
- Gemma 4-12B model loaded in LM Studio
- Python 3.10+
- Suricata IDS
- IPTables firewall

## Step 1: Firewall Configuration

sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

## Step 2: Suricata IDS

sudo systemctl start suricata
sudo systemctl enable suricata

## Step 3: LM Studio

Load Gemma 4-12B in LM Studio and start its local server (default:
`http://localhost:1234`). If the server runs on another host or port, point
the agent at it with `HALO_MODEL_URL`, e.g.:

    export HALO_MODEL_URL="http://198.51.100.10:1234/v1/chat/completions"

## Step 4: Configure Engagement Authorization

    cp engagement.example.yaml engagement.yaml

Edit `engagement.yaml` — fill in `authorization` and `scope_targets`. The
agent refuses to start without both (see [`engagement.py`](../engagement.py),
HALO's safety spine). `engagement.yaml` is gitignored — it names real
authorized targets and must never be committed.

## Step 5: Run Agent

python agent_loop.py
