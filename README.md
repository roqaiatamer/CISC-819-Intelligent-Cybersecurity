# AI Cyber Warfare Simulation 
### Autonomous Cyber Battlefield Simulator — DVWA Integration

---

## Project Structure

```
ai_cyberwar/
├── config/
│   └── settings.py              # All config loaded from .env
├── environment/
│   ├── dvwa_session.py          # DVWA auth, session, CSRF handling
│   ├── attack_modules.py        # Real attack payloads against DVWA
│   ├── defend_modules.py        # WAF rules, IP block, honeypot, etc.
│   └── cyber_env.py             # RL environment (state, step, reward)
├── agents/
│   ├── q_agent.py               # Base Q-Learning (Bellman equation)
│   ├── attacker_agent.py        # Red-team AI with recon-first strategy
│   └── defender_agent.py        # Blue-team AI with threat escalation
├── forensics/
│   └── forensics.py             # Event logging, pattern detection, reporting
├── dashboard/
│   ├── server.py                # Flask server for live dashboard
│   └── index.html               # Real-time web dashboard
├── utils/
│   └── logger.py                # Centralised logging
├── models/                      # Saved Q-tables (auto-created)
├── logs/                        # battle.jsonl + system.log (auto-created)
├── reports/                     # forensics_report.json (auto-created)
├── train.py                     # ← MAIN ENTRY POINT
├── .env.example                 # Copy to .env and configure
└── requirements.txt
```

---

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 2. Start DVWA (Docker — recommended)

```bash
# Pull and run DVWA
docker run -d \
  --name dvwa \
  -p 80:80 \
  vulnerables/web-dvwa

# Wait ~10 seconds, then open browser:
# http://localhost/dvwa/setup.php
# Click "Create / Reset Database"
```

**Default DVWA credentials:**
- Username: `admin`
- Password: `password`

> If you prefer XAMPP or a VM, just update `DVWA_URL` in `.env`.

---

## 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```env
DVWA_URL=http://localhost/dvwa
DVWA_USERNAME=admin
DVWA_PASSWORD=password
DVWA_SECURITY_LEVEL=low        # Start with low for best attack success
MAX_EPISODES=300
```

---

## 4. Run the Simulation

```bash
# Full training (300 episodes by default)
python train.py

# Custom episode count
python train.py --episodes 500

# Quiet mode (episode summaries only)
python train.py --episodes 200 --quiet

# Resume from saved models
python train.py --resume

# Evaluation only (no learning, greedy agents)
python train.py --eval
```

---

## 5. View Live Dashboard

In a **second terminal**, while training is running:

```bash
python dashboard/server.py
```

Open browser: **http://localhost:8080**

The dashboard polls every 3 seconds and shows:
- Live battle timeline with attack payloads + evidence
- Attacker / defender win rates and reward curves
- Attack success rates per vulnerability type
- Defense block rates per strategy
- Detected multi-step attack chains
- Forensic recommendations

---

## Attack Modules (8 real DVWA attacks)

| Action | DVWA Page | Payload |
|--------|-----------|---------|
| `sqli_union` | `/vulnerabilities/sqli/` | `1' UNION SELECT user(),database()-- -` |
| `sqli_boolean_blind` | `/vulnerabilities/sqli/` | `1' AND 1=1-- -` vs `1' AND 1=2-- -` |
| `xss_reflected` | `/vulnerabilities/xss_r/` | `<script>alert('XSS')</script>` |
| `xss_stored` | `/vulnerabilities/xss_s/` | Persisted script in guestbook |
| `cmd_injection` | `/vulnerabilities/exec/` | `127.0.0.1; id` |
| `file_inclusion` | `/vulnerabilities/fi/` | `../../../../etc/passwd` |
| `brute_force` | `/vulnerabilities/brute/` | Credential list (7 pairs) |
| `csrf_probe` | `/vulnerabilities/csrf/` | Token-less password change |

---

## Defense Modules (8 countermeasures)

| Action | Method |
|--------|--------|
| `allow` | Passive observation only |
| `block_ip` | Firewall-style IP block simulation |
| `rate_limit` | 1.5s throttle on requests |
| `honeypot_redirect` | Isolates attacker in decoy session |
| `waf_rule_sqli` | Pattern-matches SQLi payloads |
| `waf_rule_xss` | Pattern-matches XSS payloads |
| `reset_session` | Clears + renews DVWA session |
| `alert_only` | IDS-style logging without blocking |

---

## RL Configuration

```
State vector (10 features):
  [0] successful_attacks      (normalised)
  [1] failed_attacks          (normalised)
  [2] blocked_by_defender     (normalised)
  [3] session_resets          (normalised)
  [4] waf_triggers            (normalised)
  [5] ip_blocked              (binary)
  [6] in_honeypot             (binary)
  [7] rate_limited            (binary)
  [8] step_fraction           (0–1)
  [9] last_attack_success     (binary)

Bellman update:
  Q(s,a) ← Q(s,a) + α · [r + γ · max Q(s',·) − Q(s,a)]
  α = 0.1   γ = 0.95   ε_start = 1.0   ε_min = 0.05
```

---

## Output Files

| File | Contents |
|------|----------|
| `logs/battle.jsonl` | Every battle event (real-time, one JSON per line) |
| `logs/system.log` | System events, errors, warnings |
| `reports/forensics_report.json` | Full forensic analysis + recommendations |
| `models/AttackerAgent.json` | Saved Q-table (attacker) |
| `models/DefenderAgent.json` | Saved Q-table (defender) |

---

## Security Notice

> **This system is for educational and research use only.**
> Run exclusively against DVWA on your own local machine.
> Never target systems you don't own or have explicit permission to test.
> DVWA is intentionally vulnerable — never expose it to a public network.

---

## Increasing DVWA Security Level

After training on `low`, increase the challenge:

```env
DVWA_SECURITY_LEVEL=medium   # WAF-like input filtering
DVWA_SECURITY_LEVEL=high     # Stronger protections — attacker must adapt
```

This forces the RL agents to discover new strategies over more episodes.
