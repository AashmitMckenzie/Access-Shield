# CyberShield: AI-Powered Broken Access Control Detection and Mitigation

🚨 **Broken Access Control (BAC)** is consistently ranked as the #1 web application vulnerability by OWASP. This project introduces **CyberShield**, a machine learning-based detection and mitigation framework tailored for real-time identification of BAC vulnerabilities.

## 📌 Project Highlights

- 📁 **Custom Dataset**: First-of-its-kind extensive dataset capturing real and simulated BAC behaviors.
- 🤖 **ML Pipeline**: Logistic Regression, Random Forest, Gradient Boosting, XGBoost models implemented.
- 🧠 **Behavioral Analysis**: User profiling and resource access patterns simulated across DVWA, Juice Shop, and WebGoat.
- 📊 **Results**: 
  - Random Forest: 90.5% accuracy, 0.8627 F1-score
  - XGBoost: AUC of 0.9556
- 🧪 **Data-Driven Simulation**: BAC attacks simulated in Dockerized environments with live endpoint access and JWT manipulation.

## 📚 Research Paper

📄 Published: *CyberShield: AI Powered Broken Access Control Detection and Mitigation*  
🔗 Dataset Hosted: [Mendeley Data Repository](https://data.mendeley.com/drafts/vvr4w36bn6) 

## ⚙️ Setup Instructions

1. **Clone the repo**:

   ```bash
   git clone https://github.com/<your-username>/CyberShield-BAC.git
   cd CyberShield-BAC
   ```

2. **Install requirements**:

    install required modules and packages
   
4. **Run attack simulation**:

   follow the steps in -> instructions to run the script.txt
   
   ```bash
   python bac_attack_automation.py
   ```

5. **Preprocess data for ML**:

   ```bash
   python get_ml_processed_features.py
   ```

6. **Train models**:
   Open `model_training.ipynb` or `adv_model_training.ipynb` in Jupyter Notebook or VS Code.

## 🧪 Features Engineered

* **Time Encoding**: Hour/day cyclic encoding
* **Geolocation Encoding**: Continent & Country one-hot
* **Device Fingerprinting**: MD5-based simulated fingerprints
* **Role-Based Access Patterns**: JWT manipulation to simulate unauthorized role escalation
* **Endpoint Behavior**: Benign vs Malicious classification with expected access outcome

## 🧠 Machine Learning Models

| Model               | Accuracy | F1-Score | AUC        |
| ------------------- | -------- | -------- | ---------- |
| Logistic Regression | 86.2%    | 0.825    | 0.91       |
| Random Forest       | 90.5%    | 0.8627   | 0.94       |
| XGBoost             | 89.8%    | 0.854    | **0.9556** |
| Gradient Boosting   | 89.1%    | 0.848    | 0.94       |

## 🧪 Test Environment

* **OS**: Kali Linux (Debian)
* **Targets**: DVWA (8081), WebGoat (8080), Juice Shop (3000)
* **Python**: v3.8+
* **Multi-threading**: Simulated concurrent users and attackers

## 📊 Dataset Overview

* 📦 Format: `.csv` (request features), `.json` (user behaviors, resource patterns)
* 🧬 Samples: 1 million (can be increased based on need) annotated entries
* 🔍 Features: `hour_of_day`, `geo_country`, `role`, `endpoint`, `access_expected`, `attack_detected`, etc.

## 📎 Citation

If you use this work, please cite:

> Aashmit McKenzie, Malay Doshi, Gauri Deodghare, Ranjeet Bidwe, Sonali Kothari, *CyberShield: AI Powered Broken Access Control Detection and Mitigation*, Journal of Information Security, 2025.

## 🧑‍💻 Authors

* **Aashmit McKenzie** (Lead)
* **Malay Doshi** (Lead)
* **Gauri Deodghare** (Lead)
* Prof. Ranjeet Bidwe (Mentor)
* Dr. Sonali Kothari (Mentor)---


> 🔐 *CyberShield empowers the next generation of web security through data-driven BAC detection.*

```

Let me know if you'd like this styled with badges, links, or auto-generated documentation.
```
