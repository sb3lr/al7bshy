"""
app.py
المنصة الرئيسية للفحص الأمني (نسخة متزامنة) - مصحح
"""

import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from core.config import config
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.idor_scanner import IDORScanner
from scanners.csrf_scanner import CSRFScanner

# إعداد السجل
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# تعطيل تحذيرات SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إنشاء تطبيق Flask
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = config.secret_key
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# بيانات الجلسة
scan_results = {}
active_scans = {}
scan_sockets = {}  # لتخزين socket لكل scan

class UnifiedSecurityScanner:
    """ماسح أمني موحد"""
    
    def __init__(self, target_url: str, scan_id: str):
        self.target_url = target_url
        self.scan_id = scan_id
        self.results = {
            "scan_id": scan_id,
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_duration": 0,
            "vulnerabilities": [],
            "statistics": {
                "total_checks": 0,
                "vulnerabilities_found": 0,
                "scanners_used": 4,
                "requests_made": 0
            },
            "scanners": {
                "xss": {"status": "pending", "vulnerabilities": 0, "warnings": 0},
                "sqli": {"status": "pending", "vulnerabilities": 0, "warnings": 0},
                "idor": {"status": "pending", "vulnerabilities": 0, "warnings": 0},
                "csrf": {"status": "pending", "vulnerabilities": 0, "warnings": 0}
            },
            "summary": {}
        }
        self.start_time = time.time()
        self.scanners_completed = 0
    
    def scan_all_vulnerabilities(self):
        """فحص شامل لجميع الثغرات"""
        logger.info(f"🚀 Starting comprehensive security scan for {self.target_url}")
        
        self._update_progress("Initializing scanners...")
        
        # تشغيل الماسحات بالتتابع
        scanners = [
            ("xss", "XSS", XSSScanner, self._scan_xss),
            ("sqli", "SQL Injection", SQLiScanner, self._scan_sqli),
            ("idor", "IDOR", IDORScanner, self._scan_idor),
            ("csrf", "CSRF", CSRFScanner, self._scan_csrf)
        ]
        
        for scanner_key, scanner_name, scanner_class, scan_func in scanners:
            try:
                logger.info(f"🔍 Running {scanner_name} scanner...")
                
                self.results["scanners"][scanner_key]["status"] = "running"
                self._update_progress(f"Running {scanner_name} scan...")
                
                scanner_results = scan_func(scanner_class)
                self._process_scanner_results(scanner_key, scanner_name, scanner_results)
                
                self.results["scanners"][scanner_key]["status"] = "completed"
                self.scanners_completed += 1
                self._update_progress(f"{scanner_name} completed")
                
                time.sleep(1)  # تأخير قصير
                
            except Exception as e:
                logger.error(f"❌ {scanner_name} scanner error: {e}")
                self.results["scanners"][scanner_key]["status"] = "failed"
                self.results["scanners"][scanner_key]["error"] = str(e)
                self.scanners_completed += 1
        
        self.results["scan_duration"] = time.time() - self.start_time
        self._generate_summary()
        
        logger.info(f"✅ Scan completed in {self.results['scan_duration']:.2f} seconds")
        logger.info(f"📊 Found {self.results['statistics']['vulnerabilities_found']} vulnerabilities")
        
        return self.results
    
    def _scan_xss(self, scanner_class):
        scanner = scanner_class(self.target_url, {
            'timeout': 30,
            'random_delay': True,
            'max_requests': 50
        })
        scanner.initialize()
        results = scanner.scan()
        scanner.close()
        return results
    
    def _scan_sqli(self, scanner_class):
        scanner = scanner_class(self.target_url, {
            'timeout': 30,
            'random_delay': True,
            'allow_time_based': False
        })
        scanner.initialize()
        results = scanner.scan()
        scanner.close()
        return results
    
    def _scan_idor(self, scanner_class):
        scanner = scanner_class(self.target_url, {
            'timeout': 30,
            'random_delay': True,
            'max_requests': 40
        })
        scanner.initialize()
        results = scanner.scan()
        scanner.close()
        return results
    
    def _scan_csrf(self, scanner_class):
        scanner = scanner_class(self.target_url, {
            'timeout': 30,
            'random_delay': False
        })
        scanner.initialize()
        results = scanner.scan()
        scanner.close()
        return results
    
    def _process_scanner_results(self, scanner_key: str, scanner_name: str, results: Dict):
        if not results:
            return
        
        if "statistics" in results:
            self.results["statistics"]["requests_made"] += results["statistics"].get("requests_made", 0)
            self.results["statistics"]["total_checks"] += results["statistics"].get("total_tested", 0)
        
        if "vulnerabilities" in results:
            vulnerabilities_added = 0
            for vuln in results["vulnerabilities"]:
                vuln["scanner"] = scanner_name
                self.results["vulnerabilities"].append(vuln)
                vulnerabilities_added += 1
            
            self.results["statistics"]["vulnerabilities_found"] += vulnerabilities_added
            self.results["scanners"][scanner_key]["vulnerabilities"] = vulnerabilities_added
        
        if "warnings" in results:
            warnings_added = 0
            for warning in results["warnings"]:
                warning["type"] = "warning"
                warning["scanner"] = scanner_name
                self.results["vulnerabilities"].append(warning)
                warnings_added += 1
            
            self.results["scanners"][scanner_key]["warnings"] = warnings_added
    
    def _generate_summary(self):
        vuln_analysis = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
        
        for vuln in self.results["vulnerabilities"]:
            risk = vuln.get("risk", "low").lower()
            confidence = vuln.get("confidence", 0)
            
            if risk == "critical" and confidence > 0.8:
                vuln_analysis["critical_count"] += 1
            elif risk == "high" and confidence > 0.7:
                vuln_analysis["high_count"] += 1
            elif risk == "medium" and confidence > 0.5:
                vuln_analysis["medium_count"] += 1
            else:
                vuln_analysis["low_count"] += 1
        
        total_risk_score = (
            vuln_analysis["critical_count"] * 4 +
            vuln_analysis["high_count"] * 3 +
            vuln_analysis["medium_count"] * 2 +
            vuln_analysis["low_count"] * 1
        )
        
        if vuln_analysis["critical_count"] > 0:
            overall_risk = "CRITICAL"
        elif total_risk_score > 5:
            overall_risk = "HIGH"
        elif total_risk_score > 2:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        self.results["summary"] = {
            "total_vulnerabilities": self.results["statistics"]["vulnerabilities_found"],
            "critical_vulnerabilities": vuln_analysis["critical_count"],
            "high_vulnerabilities": vuln_analysis["high_count"],
            "medium_vulnerabilities": vuln_analysis["medium_count"],
            "low_vulnerabilities": vuln_analysis["low_count"],
            "overall_risk_level": overall_risk,
            "scanners_completed": self.scanners_completed,
            "total_scanners": 4,
            "scan_efficiency": f"{self.results['scan_duration']:.2f} seconds"
        }
    
    def _update_progress(self, message: str):
        """تحديث تقدم الفحص - نسخة آمنة"""
        progress_percentage = (self.scanners_completed / 4) * 100
        
        # إرسال تحديث عبر WebSocket في سياق التطبيق
        try:
            # استخدام socketio في سياق التطبيق
            with app.app_context():
                socketio.emit('scan_progress', {
                    'scan_id': self.scan_id,
                    'target': self.target_url,
                    'progress': progress_percentage,
                    'completed_scanners': self.scanners_completed,
                    'total_scanners': 4,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            logger.debug(f"WebSocket emit error: {e}")

# ==================== Flask Routes ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({"error": "Target URL is required"}), 400
    
    target_url = data['target'].strip()
    
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        return jsonify({"error": "URL must start with http:// or https://"}), 400
    
    local_indicators = ['localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.']
    if any(indicator in target_url for indicator in local_indicators):
        return jsonify({"error": "Scanning local addresses is not allowed"}), 400
    
    scan_id = f"scan_{int(time.time())}_{hash(target_url) % 10000:04d}"
    
    def run_scan():
        """تشغيل الفحص في thread"""
        try:
            scanner = UnifiedSecurityScanner(target_url, scan_id)
            results = scanner.scan_all_vulnerabilities()
            scan_results[scan_id] = results
            
            # إرسال النتائج عبر WebSocket في سياق التطبيق
            with app.app_context():
                socketio.emit('scan_complete', {
                    'scan_id': scan_id,
                    'target': target_url,
                    'results': results,
                    'summary': results['summary'],
                    'timestamp': datetime.now().isoformat()
                })
            
            logger.info(f"✅ Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"❌ Scan {scan_id} failed: {e}")
            
            scan_results[scan_id] = {
                "error": str(e),
                "status": "failed",
                "timestamp": datetime.now().isoformat()
            }
            
            # إرسال الخطأ عبر WebSocket في سياق التطبيق
            try:
                with app.app_context():
                    socketio.emit('scan_error', {
                        'scan_id': scan_id,
                        'target': target_url,
                        'error': str(e)
                    })
            except Exception as ws_error:
                logger.error(f"WebSocket error: {ws_error}")
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    active_scans[scan_id] = {
        "target": target_url,
        "started_at": datetime.now().isoformat(),
        "status": "running",
        "scanners": ["XSS", "SQLi", "IDOR", "CSRF"]
    }
    
    return jsonify({
        "scan_id": scan_id,
        "message": "Security scan started successfully",
        "target": target_url,
        "status": "running",
        "scanners": ["XSS", "SQL Injection", "IDOR", "CSRF"],
        "estimated_time": "1-3 minutes"
    })

@app.route('/api/results/<scan_id>', methods=['GET'])
def api_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({"error": "Scan results not found"}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        "status": "online",
        "version": "2.0.0",
        "platform": "Unified Security Scanner",
        "active_scans": len(active_scans),
        "completed_scans": len(scan_results),
        "scanners_available": ["XSS", "SQL Injection", "IDOR", "CSRF"],
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/quick-check', methods=['POST'])
def api_quick_check():
    """فحص سريع - أضف هذا الطريق"""
    data = request.json
    if not data or 'target' not in data:
        return jsonify({"error": "Target URL is required"}), 400
    
    target_url = data['target']
    
    try:
        import requests
        
        response = requests.get(
            target_url, 
            timeout=10,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        html = response.text if response.status_code == 200 else ""
        
        results = {
            "reachable": response.status_code == 200,
            "status_code": response.status_code,
            "content_length": len(html),
            "has_forms": "form" in html.lower() if html else False,
            "has_inputs": "input" in html.lower() if html else False,
            "status": "success" if response.status_code == 200 else f"failed ({response.status_code})"
        }
        
    except Exception as e:
        results = {
            "reachable": False,
            "error": str(e),
            "status": "error"
        }
    
    return jsonify({
        "target": target_url,
        "quick_check": results,
        "message": "Quick check completed",
        "recommendation": "Proceed with full scan" if results.get("reachable") else "Check target URL"
    })

@app.route('/api/scanners', methods=['GET'])
def api_scanners():
    """معلومات الماسحات"""
    return jsonify({
        "scanners": {
            "xss": {
                "name": "XSS Scanner",
                "description": "Detects Cross-Site Scripting vulnerabilities",
                "techniques": ["Reflected XSS", "Stored XSS", "DOM XSS"],
                "payloads_count": "10+ smart payloads",
                "risk_level": "High"
            },
            "sqli": {
                "name": "SQL Injection Scanner",
                "description": "Detects SQL Injection vulnerabilities",
                "techniques": ["Error-based", "Boolean-based", "Time-based"],
                "payloads_count": "7+ safe payloads",
                "risk_level": "Critical"
            },
            "idor": {
                "name": "IDOR Scanner",
                "description": "Detects Insecure Direct Object References",
                "techniques": ["Parameter manipulation", "Path traversal"],
                "test_cases": "Pattern detection",
                "risk_level": "High"
            },
            "csrf": {
                "name": "CSRF Scanner",
                "description": "Detects Cross-Site Request Forgery vulnerabilities",
                "techniques": ["Token analysis", "Cookie security"],
                "test_cases": "Form analysis",
                "risk_level": "Medium"
            }
        }
    })

# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    logger.info(f"🔗 Client connected: {request.sid}")
    emit('connected', {
        'message': 'Connected to Unified Security Scanner',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('start_scan')
def handle_start_scan(data):
    """بدء فحص عبر WebSocket"""
    target = data.get('target')
    if not target:
        emit('error', {'message': 'Target URL is required'})
        return
    
    scan_id = f"scan_{int(time.time())}_{hash(target) % 10000:04d}"
    
    def run_ws_scan():
        """تشغيل الفحص لـ WebSocket"""
        try:
            scanner = UnifiedSecurityScanner(target, scan_id)
            results = scanner.scan_all_vulnerabilities()
            scan_results[scan_id] = results
            
            # إرسال النتائج
            socketio.emit('scan_complete', {
                'scan_id': scan_id,
                'target': target,
                'results': results,
                'summary': results['summary']
            })
        except Exception as e:
            # إرسال الخطأ
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'target': target,
                'error': str(e)
            })
    
    thread = threading.Thread(target=run_ws_scan)
    thread.daemon = True
    thread.start()
    
    active_scans[scan_id] = {
        "target": target,
        "started_at": datetime.now().isoformat(),
        "status": "running"
    }
    
    emit('scan_started', {
        'scan_id': scan_id,
        'message': 'Security scan started successfully',
        'scanners': ['XSS', 'SQL Injection', 'IDOR', 'CSRF']
    })

@socketio.on('get_scan_status')
def handle_get_scan_status(data):
    """الحصول على حالة الفحص"""
    scan_id = data.get('scan_id')
    if not scan_id:
        emit('error', {'message': 'Scan ID is required'})
        return
    
    if scan_id in scan_results:
        results = scan_results[scan_id]
        emit('scan_status', {
            'scan_id': scan_id,
            'status': 'completed',
            'results': results.get('summary', {}),
            'vulnerabilities_found': results.get('statistics', {}).get('vulnerabilities_found', 0)
        })
    elif scan_id in active_scans:
        emit('scan_status', {
            'scan_id': scan_id,
            'status': 'running',
            'started_at': active_scans[scan_id]['started_at']
        })
    else:
        emit('error', {'message': 'Scan not found'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"🔌 Client disconnected: {request.sid}")

@app.route('/health')
def health():
    """فحص صحة الخادم"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

def run_server():
    """تشغيل الخادم"""
    print("\n" + "="*70)
    print("🛡️   UNIFIED SECURITY SCANNER PLATFORM v2.0")
    print("="*70)
    print(f"\n🚀 Starting platform...")
    print(f"🌐 Web Interface: http://{config.host}:{config.port}")
    print(f"🔗 API Base URL: http://{config.host}:{config.port}/api")
    print(f"⚡ WebSocket: ws://{config.host}:{config.port}")
    print("\n" + "="*70)
    print("🎯 AVAILABLE SCANNERS:")
    print("  • XSS Scanner - Smart payloads")
    print("  • SQL Injection Scanner - Safe payloads")
    print("  • IDOR Scanner - ID manipulation detection")
    print("  • CSRF Scanner - Token and cookie analysis")
    print("\n" + "="*70)
    print("⚠️  LEGAL USE ONLY - Test only authorized websites")
    print("💡 Test site: http://testphp.vulnweb.com")
    print("="*70 + "\n")
    
    try:
        socketio.run(
            app,
            host=config.host,
            port=config.port,
            debug=config.debug,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Shutdown requested by user")
        print("👋 Goodbye!")

if __name__ == '__main__':
    run_server()