# 🛡️ AI-Driven Real-Time Cyber Threat Detection & Alert System

---

# 📌 Overview

AI-Driven Real-Time Cyber Threat Detection & Alert System is an intelligent cybersecurity monitoring platform that detects suspicious activities in real time using Machine Learning, Socket.IO live alerts, MongoDB logging, and blockchain-based tamper-proof hashing.

The system analyzes telemetry data, classifies cyber threats using an AI engine, stores threat logs securely, and displays live alerts on an interactive SOC dashboard.

---

# ✨ Features

- 🔍 Real-time cyber threat detection
- 🤖 AI-powered threat classification using RandomForestClassifier
- 📡 Live telemetry monitoring
- ⚡ Instant Socket.IO alerts
- 📊 Interactive React SOC Dashboard
- 🌍 Threat visualization and statistics
- 🔐 SHA-256 blockchain-based tamper-proof logging
- 🗄️ MongoDB threat storage
- 🧪 Telemetry attack simulator for testing
- 📈 Real-time charts and analytics

---

# 🛠️ Tech Stack

## Frontend
- React.js
- CSS
- Socket.IO Client
- Chart.js / Recharts

## Backend
- Node.js
- Express.js
- Socket.IO
- MongoDB + Mongoose

## AI Engine
- Python
- Flask
- Scikit-Learn
- RandomForestClassifier

## Security & Logging
- SHA-256 Blockchain Logging

---

# 📁 Project Structure

```bash
cyber-threat-system/
├── backend/                  
│   ├── server.js             
│   ├── models/Threat.js      
│   ├── controllers/
│   │   ├── threatController.js
│   │   └── statsController.js
│   ├── routes/
│   │   ├── threatRoutes.js
│   │   └── statsRoutes.js
│   ├── .env
│   └── package.json
│
├── ai-engine/                
│   ├── ai_server.py          
│   └── requirements.txt
│
├── blockchain/               
│   └── blockchain.js
│
├── telemetry-simulator/      
│   └── telemetry_simulator.py
│
└── frontend/                 
    ├── public/index.html
    ├── package.json
    └── src/
        ├── App.js
        ├── App.css
        ├── index.js
        ├── pages/Dashboard.js
        └── components/
            ├── StatCards.js
            ├── ThreatTable.js
            ├── ThreatCharts.js
            ├── LiveAlerts.js
            ├── ThreatMap.js
            └── TestPanel.js
```

---

# ⚙️ Setup & Installation

## 📋 Prerequisites

Make sure you have installed:

- Node.js v18+
- Python 3.9+
- MongoDB

---

# 🔧 Step 1: Start MongoDB

```bash
mongod
```

---

# 🤖 Step 2: Start AI Engine

```bash
cd ai-engine
pip install -r requirements.txt
python ai_server.py
```

Runs on:

```bash
http://127.0.0.1:7000
```

---

# ⚙️ Step 3: Start Backend

```bash
cd backend
npm install
node server.js
```

Runs on:

```bash
http://localhost:5000
```

---

# 🌐 Step 4: Start Frontend

```bash
cd frontend
npm install
npm start
```

Opens:

```bash
http://localhost:3000
```

---

# 🧪 Testing the System

## ✅ Option A: Dashboard Test Panel

Open:

```bash
http://localhost:3000
```

Use the **"Send Test Telemetry"** panel.

---

## ✅ Option B: PowerShell / Curl

### Windows PowerShell

```powershell
Invoke-RestMethod -Uri http://localhost:5000/api/telemetry `
  -Method POST `
  -Body '{"ip":"45.33.32.156","action":"port_scan"}' `
  -ContentType "application/json"
```

### Linux / macOS

```bash
curl -X POST http://localhost:5000/api/telemetry \
  -H "Content-Type: application/json" \
  -d '{"ip":"45.33.32.156","action":"malware_activity"}'
```

---

## ✅ Option C: Telemetry Simulator

```bash
cd telemetry-simulator
python telemetry_simulator.py 30 1
```

This sends:
- 30 telemetry events
- 1 second apart

---

# 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|-----------|-------------|
| POST | `/api/telemetry` | Submit new telemetry |
| GET | `/api/threats` | Get all threat logs |
| GET | `/api/threats/:id` | Get single threat |
| GET | `/api/stats` | Get dashboard statistics |

---

# 🤖 AI Engine Endpoints

| Method | Endpoint | Description |
|--------|-----------|-------------|
| POST | `/analyze` | Analyze telemetry event |
| GET | `/health` | Health check |
| GET | `/model-info` | ML model details |

---

# 🎯 Threat Severity Levels

| Action Type | Expected Severity |
|-------------|------------------|
| login_attempt | LOW / MEDIUM |
| file_access | LOW / MEDIUM |
| port_scan | HIGH |
| malware_activity | HIGH |
| brute_force | HIGH |
| ddos | HIGH |

---

# 🏗️ System Architecture

```bash
Telemetry Source
      ↓ (POST /api/telemetry)

Node.js Backend (port 5000)
      ↓ (POST /analyze)

Python AI Engine (port 7000)
      ↓ AI Classification

MongoDB Database
      ↓

Socket.IO Live Events
      ↓

React SOC Dashboard
```

---

# 🔗 Blockchain Logging

Each threat log is secured using SHA-256 hashing:

```bash
hash = SHA256(ip + action + severity + timestamp)
```

This makes every log entry:
- Tamper-evident
- Secure
- Traceable

The generated hash is stored in MongoDB and displayed in the dashboard.

---

# 📸 Dashboard Modules

- 📊 Threat Statistics Cards
- 📈 Live Threat Charts
- 🚨 Real-Time Alerts
- 🌍 Threat Map
- 📋 Threat Logs Table
- 🧪 Test Telemetry Panel

---

# 🔥 Future Enhancements

- Docker deployment
- Kubernetes scaling
- JWT Authentication
- Advanced ML models
- Threat intelligence integration
- Cloud deployment monitoring
- SIEM integration

---

# 👨‍💻 Author

## Neeladri Yogendra
- Full Stack Developer
- AI & Cybersecurity Enthusiast

---

# ⭐ Support

If you like this project:

- ⭐ Star the repository
- 🍴 Fork the project
- 📢 Share with others

---

# 📜 License

This project is licensed under the MIT License.
