# CyberSasi AI — Intelligent Network Intrusion Detection & Auto-Response System

**Full Project Name:** CyberSasi AI: An AI-Powered Network Intrusion Detection and Automated Response System for Institutions

**Author:** [Your Full Name]
**Program:** Bachelor of Science in Information and Computer Network (ICN)
**Institution:** Mbeya University of Science and Technology (MUST)
**Academic Year:** 2025/2026 — Final Year Project (I & II)

---

## 1. Project Overview

CyberSasi AI is a lightweight, AI-driven Network Intrusion Detection and Prevention System (NIDPS) designed for small-to-medium organizations in Tanzania — schools, hospitals, SACCOS, local banks, and SMEs — that cannot afford enterprise-grade security solutions such as Microsoft Defender for Endpoint or Cisco Secure Network Analytics.

The system captures live network traffic, uses a machine learning model to detect anomalies and known attack patterns (e.g., port scans, DDoS, brute-force attempts), automatically responds by blocking malicious IPs or isolating affected devices, and logs all events for forensic investigation through a real-time web dashboard.

---

## 2. Objectives

- Capture and analyze real-time network traffic
- Detect intrusions and anomalies using machine learning
- Automatically respond to threats (block IP, isolate device)
- Provide a real-time monitoring dashboard
- Maintain forensic logs for incident investigation and reporting

---

## 3. Technology Stack

| Component                | Technology                          |
|---------------------------|--------------------------------------|
| Packet Capture             | Python, Scapy, Suricata             |
| Machine Learning           | Python, scikit-learn, Pandas, NumPy |
| Backend API                | Python (FastAPI)                    |
| Frontend Dashboard         | React.js, Tailwind CSS, Chart.js    |
| Database                   | PostgreSQL                          |
| Auto-Response / Firewall   | iptables / Python automation scripts|
| Deployment                 | Docker, Docker Compose              |
| Forensic Logging           | Python, JSON/PostgreSQL logs        |

**Primary Language:** Python (core system, ML, automation)
**Secondary Language:** JavaScript / React (dashboard frontend)

---

## 4. Repository Structure

```
CyberSasi-AI/
├── README.md
├── requirements.txt
├── docker-compose.yml
├── .env.example
├── .gitignore
│
├── src/
│   ├── capture/              # Packet sniffing & traffic capture modules
│   │   └── packet_sniffer.py
│   │
│   ├── ml_model/             # ML training, evaluation, and inference
│   │   ├── train_model.py
│   │   ├── predict.py
│   │   └── feature_extraction.py
│   │
│   ├── response/             # Auto-response / mitigation actions
│   │   └── auto_block.py
│   │
│   ├── forensics/            # Logging & incident reporting
│   │   └── log_manager.py
│   │
│   └── dashboard/
│       ├── backend/          # FastAPI app, routes, database models
│       │   ├── main.py
│       │   ├── models.py
│       │   └── routes/
│       └── frontend/         # React dashboard (UI)
│           ├── src/
│           └── public/
│
├── data/
│   ├── raw/                  # Raw captured traffic / datasets (e.g., CICIDS2017)
│   ├── processed/            # Cleaned & feature-engineered data
│   └── models/               # Saved trained ML models (.pkl)
│
├── notebooks/                # Jupyter notebooks for EDA & model experiments
│
├── docs/                      # Proposal, diagrams, reports, presentation slides
│
├── tests/                      # Unit and integration tests
│
├── configs/                    # Configuration files (YAML/JSON)
│
└── scripts/                     # Setup, deployment, and utility scripts
```

---

## 5. How It Works (High-Level Flow)

1. **Capture** — `packet_sniffer.py` captures live network packets from a monitored interface.
2. **Feature Extraction** — Raw packets are converted into numerical features (packet size, flow duration, protocol type, etc.).
3. **Detection** — The trained ML model (`predict.py`) classifies traffic as *normal* or *malicious*.
4. **Response** — If malicious, `auto_block.py` triggers a firewall rule to block the source IP or isolate the device.
5. **Logging** — `log_manager.py` records the event with timestamp, source, and action taken.
6. **Visualization** — The React dashboard displays live alerts, traffic statistics, and historical logs via the FastAPI backend.

---

## 6. Setup Instructions (Draft)

```bash
# Clone repository
git clone https://github.com/<your-username>/CyberSasi-AI.git
cd CyberSasi-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run with Docker
docker-compose up --build
```

---

## 7. Significance to Society

CyberSasi AI addresses a real cybersecurity gap in Tanzania by offering an affordable, locally adaptable intrusion detection solution for institutions that are frequent targets of cyberattacks but lack resources for commercial security tools. It supports national cybersecurity goals under TCRA regulations and the Cybercrimes Act, and demonstrates practical, in-demand skills in network security, AI/ML, and cloud-native development.

---

## 8. One-Month Project Plan (Weekdays Only)

This plan covers 4 working weeks (Monday–Friday, 20 working days), with weekends skipped for rest/buffer.

### Week 1 — Setup, Research & Data Preparation

| Day | Task |
|-----|------|
| Day 1 (Mon) | Repository setup, environment setup (Python venv, Docker), install dependencies from `requirements.txt` |
| Day 2 (Tue) | Research and download a network traffic dataset (e.g., CICIDS2017 or NSL-KDD) into `data/raw/` |
| Day 3 (Wed) | Explore dataset in `notebooks/` (Jupyter EDA): understand features, attack labels, class distribution |
| Day 4 (Thu) | Data cleaning and preprocessing — handle missing values, encode categorical features, normalize numeric features |
| Day 5 (Fri) | Build `feature_extraction.py` — define final feature set; save processed dataset to `data/processed/` |

### Week 2 — Machine Learning Model Development

| Day | Task |
|-----|------|
| Day 6 (Mon) | Split data into train/test sets; build baseline model (e.g., Logistic Regression / Decision Tree) in `train_model.py` |
| Day 7 (Tue) | Train and evaluate Random Forest / Gradient Boosting model; compare accuracy, precision, recall, F1-score |
| Day 8 (Wed) | Hyperparameter tuning (GridSearchCV) and model selection; save best model to `data/models/` as `.pkl` |
| Day 9 (Thu) | Build `predict.py` — load saved model and create a function to classify new traffic samples (normal/malicious) |
| Day 10 (Fri) | Write unit tests for feature extraction and prediction in `tests/`; document model performance in `docs/` |

### Week 3 — Packet Capture, Auto-Response & Backend

| Day | Task |
|-----|------|
| Day 11 (Mon) | Build `packet_sniffer.py` using Scapy — capture live traffic and extract relevant fields |
| Day 12 (Tue) | Connect packet sniffer output to `feature_extraction.py` and `predict.py` for real-time classification |
| Day 13 (Wed) | Build `auto_block.py` — implement IP blocking logic using iptables/firewall rules (test in safe/lab environment) |
| Day 14 (Thu) | Build `log_manager.py` — log detected events (timestamp, source IP, action, severity) to PostgreSQL/JSON |
| Day 15 (Fri) | Set up FastAPI backend (`main.py`, `models.py`, routes) — create endpoints for alerts, logs, and statistics |

### Week 4 — Dashboard, Integration, Testing & Documentation

| Day | Task |
|-----|------|
| Day 16 (Mon) | Build React dashboard skeleton — layout, navigation, connect to FastAPI backend |
| Day 17 (Tue) | Build dashboard components: live alerts table, traffic statistics charts (Chart.js) |
| Day 18 (Wed) | Full system integration test — run sniffer + model + auto-response + dashboard together in lab/Packet Tracer/GNS3 environment |
| Day 19 (Thu) | Bug fixing, performance tuning, finalize Docker setup (`docker-compose.yml`) for one-command deployment |
| Day 20 (Fri) | Finalize documentation (`docs/`), write final report/proposal sections, prepare presentation slides and demo script |

---

## 9. License

This project is developed for academic purposes as part of the Final Year Project (IT 8354 / IT 8362) requirements for the BSc in Information and Computer Network program.
