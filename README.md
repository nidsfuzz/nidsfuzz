
# 🛡️ NIDSFuzz

**Fuzzing Framework for Network Intrusion Detection Systems (NIDS)**  
> Automated environment for discovering rule enforcement inconsistencies in **Snort2**, **Snort3**, and **Suricata**.  

![architecture](https://img.shields.io/badge/Framework-Docker--Compose-blue?style=for-the-badge)  
![python](https://img.shields.io/badge/Python-%3E%3D3.11-green?style=for-the-badge&logo=python)  

---

## 📦 Prerequisites

- Python **≥ 3.11**
- Docker & Docker Compose

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🌐 Network Topology

```text
+----------------+        +------------------+        +-------------------+
| NIDS Initiator | <----> | Gateway & Mirror | <----> | Tunable Responder |
+----------------+        +------------------+        +-------------------+
                             /     |      \ 
                            +      +       +
                   +--------+  +--------+  +----------+  
                   | Snort3 |  | Snort2 |  | Suricata | 
                   +--------+  +--------+  +----------+
                           (Promiscuous Mode)
```

---

## 🚀 Quick Start

### 1️⃣ Prepare Rules
Move your rules into the benchmark folder:

```bash
./benchmark/rules/
```

Update rule configuration in:

```text
docker-compose/variables.env
```

- `SNORT2_RULE_FILE=...`
- `SNORT3_RULE_FILE=...`

---

### 2️⃣ Start Fuzzing

Run fuzzing with:

```bash
bash ./benchmark/start.sh --fuzzing
```

> ⚠️ **Note:** The **biggest bottleneck** during setup may be your **network speed**.

---

### 3️⃣ Stop & Collect Logs

Stop fuzzing and gather results:

```bash
bash ./benchmark/clean.sh --fuzzing
```

This will:
- Save all generated logs (`alerts`, `packets`, discrepancies, etc.)
- Clean up all containers, networks, and volumes.

---

### 4️⃣ Replay Abnormal Cases

You can reproduce abnormal cases:

```bash
bash ./benchmark/start.sh --replay -packets fuzzing-results/initiator/log
bash ./benchmark/clean.sh --replay
```

---

## 📂 Output Structure

After running `clean.sh`, results are organized like this:

```text
fuzzing-results/
│
├── initiator/
│   └── log/
│       ├── fuzzing.log
│       ├── discrepancies.txt
│       └── packets.bin
│
├── responder/
│   └── log/
│       └── server.log
│ 
├── snort2/
│   └── log/
│       └── snort2.log
│
├── snort3/
│   └── log/
│       └── snort3.log
│
├── suricata/
│   └── log/
│       ├── eve.json
│       ├── fast.log
│       ├── stats.log
│       └── suricata.log
```

---

## ✨ Features

- 🔍 **Rule Coverage Testing** across Snort2, Snort3, Suricata  
- 🔄 **Replay Engine** for reproducing inconsistencies  
- 📊 **Structured Logging** for fuzzing & detection outcomes  
- 🐳 **Dockerized Environment** with automated orchestration  

---

## 📖 Documentation

For advanced usage and research methodology, please refer to the [Wiki](#).

---

## 🤝 Contributing

Contributions are welcome!  
Feel free to submit issues or PRs to improve **NIDSFuzz**.  

---

