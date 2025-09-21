# 🛡️ EyeGuard

EyeGuard هو مشروع مفتوح المصدر بيعمل **Threat Intelligence Enrichment + Automation** على مؤشرات زي:

* IP Addresses
* Domains
* File Hashes

بيعتمد على:

* [VirusTotal](https://www.virustotal.com)
* [AbuseIPDB](https://www.abuseipdb.com)
* [AlienVault OTX](https://otx.alienvault.com)

وبيجمع الـ raw responses منهم + يطبّق **قواعد أوتوميشن** (Blocking / Alerting / Tagging).

---

## 🚀 التشغيل

### 1) نزّل المكتبات المطلوبة

```bash
pip install -r requirements.txt
```

### 2) حط الـ API Keys في الـ environment

```bash
export VT_API_KEY="your_vt_key"
export ABUSEIPDB_KEY="your_abuseipdb_key"
export OTX_KEY="your_otx_key"
```

### 3) (اختياري) ضبط الـ Rate Limits

```bash
export VT_RATE_SECONDS=15.5
export ABUSE_RATE_SECONDS=1.5
export OTX_RATE_SECONDS=1.5
```

### 4) (اختياري) Webhook للتنبيهات

```bash
export DASHBOARD_WEBHOOK_URL="https://your-webhook.site/endpoint"
```

### 5) (اختياري) تفعيل الـ Blocking (iptables)

⚠️ **خطير**: هيحظر IP فعليًا.

```bash
export EG_ENABLE_BLOCKING=1
```

### 6) شغّل السيرفر

```bash
uvicorn service:app --reload --port 8000
```

---

## ⚙️ إضافة ملف قواعد الأوتوميشن

EyeGuard بيستعمل ملف خارجي اسمه:

```
data/local/automation_rules.json
```

لو الملف مش موجود، أنشئه يدويًا:

```bash
mkdir -p data/local
nano data/local/automation_rules.json
```

### 📜 مثال لملف Rules:

```json
[
  {
    "name": "Block if VT malicious >= 5",
    "type": "ip",
    "vt_min_malicious": 5,
    "actions": [
      {"name": "block_ip"},
      {"name": "tag_local", "label": "blocked-vt", "score": 100},
      {"name": "webhook"}
    ]
  },
  {
    "name": "Alert when AbuseIPDB >= 90",
    "type": "ip",
    "abuse_min_score": 90,
    "actions": [
      {"name": "webhook"},
      {"name": "tag_local", "label": "high-abuse", "score": 90}
    ]
  }
]
```

### ✏️ وصف القواعد:

* **Block if VT malicious >= 5**  → أي IP عليه ≥ 5 محركات VT malicious → Block + Tag + Alert.
* **Alert when AbuseIPDB >= 90**  → أي IP واخد Abuse Score ≥ 90 → Alert + Tag.

### 🔄 تحميل القواعد بعد التعديل

```bash
curl -X POST http://127.0.0.1:8000/automation/reload
curl http://127.0.0.1:8000/automation/rules
```

---

## 🔍 أمثلة للاستعلامات

### 1) Query IP

```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"type":"ip","value":"8.8.8.8","providers":["vt","abuse","otx"],"force_refresh":false}' | jq .
```

### 2) Query Domain

```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"type":"domain","value":"example.com","providers":["vt","otx"],"force_refresh":false}' | jq .
```

### 3) Query File Hash (MD5/SHA1/SHA256)

```bash
curl -X POST http://127.0.0.1:8000/query \
  -H "Content-Type: application/json" \
  -d '{"type":"file","value":"44d88612fea8a8f36de82e1278abb02f","providers":["vt"],"force_refresh":false}' | jq .
```

### 4) Alerts

```bash
curl http://127.0.0.1:8000/alerts | jq .
```

Stream Alerts:

```bash
curl http://127.0.0.1:8000/alerts/stream
```

---

## 📂 مخرجات مهمة

* **data/local/indicators.csv** → المؤشرات المتعلّمة محليًا (tag\_local).
* **data/local/alerts.jsonl** → كل التنبيهات كـ JSON lines.
* **raw\_sources** → الردود الخام من الـ APIs.

---

## 📑 ملخص الـ Conditions والـ Actions

### 🟦 Conditions المدعومة

| الحقل              | الوصف                                                   |
| ------------------ | ------------------------------------------------------- |
| `type`             | نوع المؤشّر (`ip`, `domain`, `file`)                    |
| `min_threat_score` | الحد الأدنى من التقييم المركب (0-100)                   |
| `vt_min_malicious` | عدد المحركات اللي قالت malicious في VirusTotal          |
| `abuse_min_score`  | أقل قيمة مقبولة لـ AbuseIPDB Confidence Score           |
| `otx_min_pulses`   | عدد الـ Pulses في OTX                                   |
| `include_cidrs`    | قائمة Subnets، القاعدة تنطبق فقط على الـ IPs اللي جواها |

### 🟩 Actions المدعومة

| الفعل       | الوصف                                                           |
| ----------- | --------------------------------------------------------------- |
| `block_ip`  | حظر الـ IP محليًا باستخدام iptables (لو `EG_ENABLE_BLOCKING=1`) |
| `webhook`   | يبعث النتيجة لعنوان Webhook (من متغير بيئة أو URL في الـ rule)  |
| `tag_local` | يضيف المؤشّر في ملف `indicators.csv` بعلامة وScore              |

---

## 📝 ملاحظات أمان

* متحطّش الـ API Keys في الكود أو الريبو العام → استعمل `.env` + `.gitignore`.
* فعل blocking بحذر جدًا (يفضّل في لاب/VM).
* EyeGuard معمولة للتعلّم والـ DFIR / SOC labs، مش production-ready 100%.
