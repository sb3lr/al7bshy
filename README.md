# 🛡️ Unified Security Scanner

منصة متكاملة للفحص الأمني الذكي والآمن

<div align="center">

![Cyber Security](https://img.shields.io/badge/Cyber-Security-0f0?style=for-the-badge\&logo=security\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.13-0f0?style=for-the-badge\&logo=python\&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3-0f0?style=for-the-badge\&logo=flask\&logoColor=white)
![WebSocket](https://img.shields.io/badge/WebSocket-RealTime-0f0?style=for-the-badge\&logo=socket.io\&logoColor=white)

منصة فحص أمني تكشف 4 أنواع رئيسية من الثغرات بواجهة حديثة وتحديث لحظي.

</div>

---

## 📋 المحتويات

* 🎯 نظرة عامة
* ✨ المميزات
* 🔧 التثبيت
* 🚀 التشغيل
* 🎮 استخدام الواجهة
* 🔍 الماسحات المتاحة
* 📊 نتائج الفحص
* 📁 هيكل المشروع
* ⚙️ التقنيات
* ⚠️ ملاحظات أمنية
* 📈 أمثلة
* 🔮 التطوير المستقبلي
* 📄 الرخصة

---

## 🎯 نظرة عامة

**Unified Security Scanner** منصة فحص ويب مبنية بـ **Python + Flask**.
تكتشف الأنواع التالية:

* XSS
* SQL Injection
* IDOR
* CSRF

تستخدم حملات ذكية غير مدمرة، وتعرض النتائج مباشرة عبر WebSocket مع واجهة Cyberpunk.

---

## ✨ المميزات

### 🔐 ماسحات قوية

* **XSS**: أكثر من 10 حملات
* **SQLi**: كشف الخطأ – المنطقي – المؤقت
* **IDOR**: تحليل الـ IDs وتجاوز الوصول
* **CSRF**: تحليل التوكنات والكوكيز

### 🎨 واجهة حديثة

* Cyberpunk style
* عرض تقدم الفحص Live
* تقارير منظمة وخطورة واضحة

### ⚡ أداء

* فحص متزامن
* تأخير ذكي بين الطلبات
* تحليل دقيق + مستويات ثقة

### 🛡️ أمان

* حملات غير مدمرة
* منع الروابط المحلية
* تحذيرات واضحة

---

## 🔧 التثبيت

### المتطلبات

* Python 3.8+
* pip

### الخطوات

```bash
git clone https://github.com/sb3lr/al7bshy.git
cd al7bshy
pip install -r requirements.txt
```

تأكد من التثبيت:

```bash
python --version
pip list | grep Flask
```

---

## 🚀 التشغيل

### تشغيل سريع

```bash
python run.py
```

### تشغيل متقدم

```bash
python app.py --port 8080
python app.py --host 0.0.0.0
python app.py --debug false
```

عند النجاح يظهر:

```
🛡️   UNIFIED SECURITY SCANNER PLATFORM v2.0
Web Interface: http://127.0.0.1:5000
API Base URL: http://127.0.0.1:5000/api
WebSocket: ws://127.0.0.1:5000
```

---

## 🎮 استخدام الواجهة

1. افتح:

```
http://localhost:5000
```

2. أدخل الرابط المراد فحصه
3. اختر وضع الفحص:

   * 🟢 Normal
   * 🟡 Passive
   * 🔴 Aggressive
4. اضغط START وراقب النتائج Live.

---

## 🔍 الماسحات المتاحة

### 1. XSS

* Reflected / Stored / DOM
* كشف onerror/onload/scripts
* 10+ بايلود ذكي

### 2. SQL Injection

* Boolean – Error – Time
* MySQL / PostgreSQL / MSSQL / Oracle

### 3. IDOR

* التلاعب بالـ IDs
* اكتشاف الوصول غير المصرح

### 4. CSRF

* تحليل توكن
* SameSite / HttpOnly / Secure

---

## 📊 نتائج الفحص

### مستويات الخطورة

* 🔴 **CRITICAL** (>0.8)
* 🟡 **HIGH** (>0.7)
* 🟠 **MEDIUM** (>0.5)
* 🟢 **LOW** (<0.5)

### مثال

```json
{
  "type": "SQL Injection",
  "confidence": 0.9,
  "risk": "high",
  "issue": "SQL error detected",
  "location": "search.php?test=query",
  "recommendation": "Use parameterized queries"
}
```

---

## 📁 هيكل المشروع

```
security-scanner/
│ app.py
│ run.py
│ requirements.txt
│ README.md
│
├─ core/
│   config.py
│   scanner_base.py
│
├─ scanners/
│   xss_scanner.py
│   sqli_scanner.py
│   idor_scanner.py
│   csrf_scanner.py
│
└─ templates/
    index.html
```

---

## ⚙️ التقنيات

### Backend

* Flask
* Flask-SocketIO
* Requests
* BeautifulSoup4
* Flask-CORS

### Frontend

* HTML5, CSS3 Cyberpunk
* JS ES6 + WebSocket
* Socket.IO client

### Security

* Safe payloads
* Intelligent delays
* Exception handling

---

## ⚠️ ملاحظات أمنية

### ممنوع:

* فحص مواقع بدون إذن
* أي استخدام تخريبي
* استهداف أنظمة حقيقية بدون تصريح

### مسموح:

* مواقع تدريب
* مواقعك
* التعليم والبحث

### مواقع تدريب آمنة:

```
http://testphp.vulnweb.com
https://juice-shop.herokuapp.com
http://zero.webappsecurity.com
```

---

## 📈 أمثلة

### موقع: testphp.vulnweb.com

```
XSS: 6
SQLi: 5
IDOR: 1
CSRF: 2
الخطورة: HIGH
```

### موقع: juice-shop

```
XSS: 0
SQLi: 0
IDOR: 0
CSRF: 1 (تحذير كوكيز)
الخطورة: LOW
```

---

## 🔮 التطوير القادم

* ماسح RFI/LFI
* ماسح XXE
* ماسح SSRF
* تقارير PDF
* واجهة إدارة
* API كاملة

## 📄 الرخصة

MIT License
للاستخدام التعليمي والبحثي فقط.
المطور غير مسؤول عن أي إساءة استخدام.

---

<div align="center">
⭐ إذا أعجبك المشروع لا تنسَ النجمة  
"الأمن مسؤولية جماعية"
</div>
