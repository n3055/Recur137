# Recur137: A Multi-Layered Web3 Security Analysis Suite

**Recur137 is an integrated suite of advanced security tools designed for the comprehensive analysis and simulation of Web3 ecosystems. Moving beyond single-contract auditing, this project provides a holistic security verification platform, featuring a static smart contract analyzer, a real-time token behavior monitor, and a novel Web3 architecture simulator.**

This project is developed as part of an M.Tech in Cybersecurity, with the core goal of identifying and mitigating complex, multi-component vulnerabilities that traditional tools often miss.

## The Problem
Security in the blockchain space is often siloed. Audits focus on individual smart contracts, while token analysis is detached from the underlying code. The most devastating exploits, however, arise from flawed interactions between multiple contracts, protocols, and off-chain components. There is a critical need for a tool that can model and analyze the *entire system architecture* for emergent security threats.

## Our Solution
Recur137 tackles this challenge by providing three integrated modules:

1.  **Smart Contract Analyzer:** A powerful static analysis engine to detect common vulnerabilities (like re-entrancy, integer overflows, and access control issues) directly from Solidity/Vyper source code.
2.  **Token Analyzer:** An on-chain analysis tool designed to identify malicious token behaviors, such as honeypots, rug pulls, and suspicious transfer logic, by analyzing transaction patterns and contract code.
3.  **Web3 Architecture Simulator:** The flagship feature of this project. A "Cisco Packet Tracer for Web3" that allows developers and security auditors to model, visualize, and simulate entire decentralized application architectures. Test how your contracts, oracles, and bridges interact under various conditions and adversarial scenarios *before* deployment.

## Features at a Glance

| Feature                      | Description                                                                                                                              | Status      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| **Smart Contract Analyzer** | Static analysis (SAST) for Solidity & Vyper. Detects a wide range of common vulnerabilities and generates detailed reports.              | In Progress |
| **Token Analyzer** | Analyzes token contracts for scam characteristics (e.g., honeypot code, high fees, disabled selling) using on-chain data.                | In Progress |
| **Architecture Simulator** | Model complex multi-contract systems. Simulate transaction flows and test for emergent, architectural-level vulnerabilities.               | Core Focus  |
| **Vulnerability Reporting** | Generates clear, actionable reports with vulnerability descriptions, severity levels, and remediation guidance.                          | Planned     |
| **Attack Simulation** | Within the simulator, launch pre-defined attack scenarios (e.g., flash loan attacks, cross-chain exploits) against your modeled architecture. | Planned     |

## The Architecture Simulator: "A Packet Tracer for Web3"
The heart of Recur137 is the architecture simulator. This tool provides a visual and interactive environment to:

* **Model Components:** Drag-and-drop nodes representing smart contracts, Externally Owned Accounts (EOAs), oracles, bridges, and liquidity pools.
* **Define Interactions:** Configure the relationships and function calls between these components to replicate your application's logic.
* **Run Simulations:** Simulate a series of transactions and observe the state changes across the entire system.
* **Identify Architectural Flaws:** Discover vulnerabilities that are invisible at the single-contract level, such as unsafe cross-protocol interactions, economic exploits, or cascading failures.

## Tech Stack
* **Backend:** Django
* **Smart Contract Analysis:** Slither, Mythril, Intel, EthScanner and some custom analysis scripts
* **On-Chain Data:** Web3.py, Ethers.js, The Graph Protocol
* **Simulator Frontend:** HTML/CSS 
* **Database:** SQLite
# Getting Started

This section will guide you through setting up and running the **Recur137** suite locally.

## Prerequisites

- Python 3.9+ installed and available on `PATH`.

## Installation & Running

1. **Clone the repository**

```bash
git clone https://github.com/n3055/Recur137.git
cd Recur137
```

2. **Create and activate a virtual environment**

**Windows (PowerShell)**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows (cmd.exe)**

```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**macOS / Linux**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

5. **Run database migrations**

```bash
python manage.py makemigrations
python manage.py migrate
```

7. **Start the development server**

```bash
python manage.py runserver 
```

8. **Open the web interface**

Visit `http://127.0.0.1:8000` or `http://localhost:8000` in your browser.




## Research & Publication
This project serves as the foundation for M.Tech thesis research in cybersecurity. The primary research contribution is the development of a formal methodology and a practical framework for simulating Web3 architectures to identify security vulnerabilities. The goal is to publish these findings in a peer-reviewed cybersecurity conference or journal.



## License
This project is licensed under the MIT License 
