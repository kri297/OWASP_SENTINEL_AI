# 🛡️ OWASP Sentinel AI

### Intelligent Web Vulnerability Scanner & Attack-Path Analyzer

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-22+-339933?style=for-the-badge&logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge&logo=owasp&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Backend-000000?style=for-the-badge&logo=flask&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)

---

**OWASP Sentinel AI** is a comprehensive, AI-powered web vulnerability scanner that combines automated security testing with intelligent analysis. It scans web applications for common vulnerabilities, maps attack paths across related findings, and generates professional security assessment reports — all through an intuitive React dashboard.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-Vector Vulnerability Scanning** | Detects SQL Injection, Cross-Site Scripting (XSS), security header misconfigurations, CSRF vulnerabilities, and more |
| 🤖 **AI-Powered Analysis** | Leverages Google Gemini AI for intelligent vulnerability assessment with automatic rule-based fallback |
| 🕸️ **Attack Path Analysis** | Connects related vulnerabilities into attack chains, revealing how attackers could escalate access |
| 📊 **Interactive Dashboard** | Real-time statistics, severity distribution charts, and scan history tracking |
| 📄 **Professional PDF Reports** | Downloadable, branded security assessment reports with executive summaries and remediation guidance |
| 🌐 **Web Crawler** | Automatic discovery of pages, forms, and input fields across the target application |
| 🎯 **OWASP Top 10 Coverage** | Comprehensive checks mapped to the OWASP Top 10 vulnerability categories |

---

## 📸 Screenshots

> **Screenshots coming soon!**
>
> The dashboard includes:
> - **Home Dashboard** — Overview of scan statistics and severity breakdown
> - **Scanner View** — Configure and launch vulnerability scans
> - **Results Panel** — Detailed vulnerability findings with severity ratings
> - **Attack Path Visualizer** — Interactive graph of connected vulnerabilities
> - **PDF Reports** — Professional, downloadable security assessment reports

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                 React Frontend                   │
│  ┌──────────┬───────────┬───────────┬─────────┐ │
│  │Dashboard │  Scanner  │  Results  │ Reports │ │
│  └────┬─────┴─────┬─────┴─────┬─────┴────┬────┘ │
│       └───────────┴───────────┴──────────┘       │
│                    REST API                       │
├─────────────────────────────────────────────────┤
│                 Flask Backend                    │
│  ┌──────────┬───────────┬───────────┬─────────┐ │
│  │ Scanner  │ AI Analyzer│Attack Path│Reporter │ │
│  │ Engine   │ (Gemini)  │ Analyzer  │(PDF Gen)│ │
│  └──────────┴───────────┴───────────┴─────────┘ │
│  ┌──────────────────────────────────────────────┐│
│  │            SQLite Database                   ││
│  └──────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

**Data Flow:**
1. User configures a scan via the React frontend
2. Frontend sends scan request to the Flask REST API
3. Scanner Engine crawls the target and runs vulnerability checks
4. AI Analyzer (Gemini or rule-based) assesses and prioritizes findings
5. Attack Path Analyzer maps relationships between vulnerabilities
6. Results are stored in SQLite and displayed on the dashboard
7. PDF Reporter generates downloadable security assessment reports

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11+, Flask, SQLAlchemy, ReportLab |
| **Frontend** | React 19, Vite, Tailwind CSS v4, Recharts |
| **AI Engine** | Google Gemini API (optional, with rule-based fallback) |
| **Database** | SQLite |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** — [Download](https://www.python.org/downloads/)
- **Node.js 22+** — [Download](https://nodejs.org/)
- **Git** — [Download](https://git-scm.com/)

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/owasp-sentinel-ai.git
cd owasp-sentinel-ai
```

#### 2. Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The backend server will start at **http://localhost:5000**.

#### 3. Frontend Setup (New Terminal)

```bash
cd frontend
npm install
npm run dev
```

The frontend dev server will start at **http://localhost:5173**.

#### 4. Open the Application

Navigate to **http://localhost:5173** in your browser.

#### 5. (Optional) Enable AI-Powered Analysis

1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Copy `.env.example` to `.env` in the project root:
   ```bash
   cp .env.example .env
   ```
3. Add your API key to `.env`:
   ```
   GEMINI_API_KEY=your-api-key-here
   ```
4. Restart the backend server

> **Note:** Without a Gemini API key, the system will use rule-based analysis. All scanning features work without AI — the AI integration provides enhanced analysis and remediation suggestions.

### Quick Start (Windows)

Use the included startup scripts to launch both servers at once:

```bash
# Batch file
start.bat

# PowerShell
.\start.ps1
```

---

## 📁 Project Structure

```
owasp-sentinel-ai/
├── backend/
│   ├── app.py                  # Flask application entry point
│   ├── requirements.txt        # Python dependencies
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── vulnerability_scanner.py  # Core scanning engine
│   │   ├── ai_analyzer.py           # Gemini AI integration
│   │   ├── attack_path_analyzer.py  # Attack chain mapping
│   │   └── report_generator.py      # PDF report generation
│   ├── models/
│   │   └── database.py         # SQLAlchemy models
│   └── instance/
│       └── sentinel.db         # SQLite database (auto-created)
├── frontend/
│   ├── package.json            # Node.js dependencies
│   ├── vite.config.js          # Vite configuration
│   ├── tailwind.config.js      # Tailwind CSS configuration
│   ├── src/
│   │   ├── App.jsx             # Root React component
│   │   ├── main.jsx            # Application entry point
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Page-level components
│   │   └── services/           # API service layer
│   └── public/                 # Static assets
├── .env.example                # Environment variable template
├── .gitignore                  # Git ignore rules
├── start.bat                   # Windows batch startup script
├── start.ps1                   # PowerShell startup script
├── LICENSE                     # MIT License
└── README.md                   # This file
```

---

## 🎯 OWASP Top 10 Coverage

| # | OWASP Category | Checks Performed | Status |
|---|---------------|-------------------|--------|
| A01 | **Broken Access Control** | Directory traversal, insecure direct object references | ✅ |
| A02 | **Cryptographic Failures** | SSL/TLS configuration, insecure data exposure | ✅ |
| A03 | **Injection** | SQL Injection, XSS, command injection detection | ✅ |
| A04 | **Insecure Design** | Architecture-level vulnerability patterns | ✅ |
| A05 | **Security Misconfiguration** | Security headers, default configs, verbose errors | ✅ |
| A06 | **Vulnerable Components** | Outdated library detection, known CVE checks | ✅ |
| A07 | **Authentication Failures** | Weak authentication patterns, session management | ✅ |
| A08 | **Data Integrity Failures** | CSRF detection, insecure deserialization patterns | ✅ |
| A09 | **Logging & Monitoring Failures** | Information leakage, debug mode detection | ✅ |
| A10 | **Server-Side Request Forgery** | SSRF vulnerability pattern detection | ✅ |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new vulnerability scan |
| `GET` | `/api/scan/<id>` | Get scan status and results |
| `GET` | `/api/scans` | List all scans |
| `DELETE` | `/api/scan/<id>` | Delete a scan and its results |
| `GET` | `/api/scan/<id>/vulnerabilities` | Get vulnerabilities for a scan |
| `GET` | `/api/scan/<id>/attack-paths` | Get attack path analysis |
| `GET` | `/api/scan/<id>/report` | Download PDF report |
| `GET` | `/api/stats` | Get dashboard statistics |

---

## ⚠️ Ethical Use Disclaimer

> **🚨 IMPORTANT: This tool is for educational purposes and authorized security testing only.**
>
> - You **MUST** have explicit, written authorization before scanning any web application
> - **Unauthorized scanning of systems you do not own is illegal** and may violate laws such as the Computer Fraud and Abuse Act (CFAA) and similar legislation worldwide
> - Always obtain proper permission from the system owner before conducting any security assessment
> - The developers of OWASP Sentinel AI assume **no liability** for misuse of this tool
> - Use responsibly and ethically — help make the web safer, not more vulnerable

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow PEP 8 for Python code
- Use ESLint and Prettier for JavaScript/React code
- Write meaningful commit messages
- Add tests for new features
- Update documentation as needed

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 OWASP Sentinel AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- **[OWASP Foundation](https://owasp.org/)** — For the Top 10 vulnerability classification and security best practices
- **[Google Gemini AI](https://ai.google.dev/)** — For powering the intelligent vulnerability analysis engine
- **[Flask](https://flask.palletsprojects.com/)** — Lightweight Python web framework
- **[React](https://react.dev/)** — Frontend UI library
- **[Vite](https://vitejs.dev/)** — Next-generation frontend build tool
- **[Tailwind CSS](https://tailwindcss.com/)** — Utility-first CSS framework
- **[Recharts](https://recharts.org/)** — Composable charting library for React
- **[ReportLab](https://www.reportlab.com/)** — PDF generation library for Python

---

<p align="center">
  Made with ❤️ for a safer web
</p>
