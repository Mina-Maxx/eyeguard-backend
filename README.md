# 🛡️ EyeGuard Backend

EyeGuard هو **خادم FastAPI** لعمل Enrichment على الـ Indicators of Compromise (IOCs)  
(IP addresses, File hashes, URLs) باستخدام مصادر Threat Intel زي:

- [VirusTotal](https://virustotal.com/)  
- [AbuseIPDB](https://abuseipdb.com/)  
- [AlienVault OTX](https://otx.alienvault.com/)  
- Local dataset (قواعد خاصة بيك)

---

## ⚙️ المتطلبات

- Python 3.10+
- pip
- حسابات مجانية / API keys للمصادر اللي هتستخدمها (VT, AbuseIPDB, OTX)

---

## 📥 التنصيب

```bash
git clone https://github.com/USERNAME/eyeguard-backend.git
cd eyeguard-backend
pip install -r requirements.txt
