"""
scanners/sqli_scanner.py
ماسح SQL Injection (نسخة متزامنة مبسطة)
"""

import re
import time
import random
from typing import Dict, List
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from core.scanner_base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class SQLiScanner(BaseScanner):
    """ماسح ثغرات SQL Injection"""
    
    def __init__(self, target_url: str, config: Dict = None):
        super().__init__(target_url, config)
        
        # حملات SQL Injection
        self.payloads = [
            {"payload": "'", "type": "single_quote", "risk": "low"},
            {"payload": "\"", "type": "double_quote", "risk": "low"},
            {"payload": "' OR '1'='1", "type": "boolean_true", "risk": "medium"},
            {"payload": "' OR 1=1--", "type": "comment", "risk": "medium"},
            {"payload": "'; SELECT SLEEP(2)--", "type": "time_based", "risk": "high"},
            {"payload": "' UNION SELECT NULL--", "type": "union", "risk": "medium"},
            {"payload": "' AND 1=2--", "type": "boolean_false", "risk": "medium"},
        ]
        
        # أنماط أخطاء SQL
        self.error_patterns = {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"MySQLSyntaxErrorException",
                r"Warning: mysql",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"PG::SyntaxError",
            ],
            'mssql': [
                r"Microsoft SQL Native Client",
                r"Incorrect syntax near",
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle error",
            ],
            'generic': [
                r"SQL syntax.*MySQL",
                r"Warning.*sql",
                r"Division by zero",
            ]
        }
    
    def scan(self) -> Dict:
        """تنفيذ فحص SQL Injection"""
        logger.info(f"Starting SQLi scan for {self.target_url}")
        
        try:
            self.initialize()
            
            # جلب الصفحة الرئيسية
            main_page = self.fetch_page(self.target_url)
            if not main_page:
                self.add_warning("Could not fetch main page")
                return self.get_results()
            
            # استخراج النماذج
            input_points = self.extract_input_points(main_page)
            self.add_info(f"Found {len(input_points['forms'])} forms")
            
            # فحص النماذج
            for form in input_points['forms'][:3]:
                self._test_form(form)
            
            # فحص بارامترات URL
            parsed = urlparse(self.target_url)
            if parsed.query:
                self._test_url_parameters(parsed)
            
        except Exception as e:
            logger.error(f"SQLi scan error: {e}")
            self.add_warning(f"Scan error: {str(e)}")
        finally:
            self.close()
        
        return self.get_results()
    
    def _test_form(self, form: Dict):
        """اختبار نموذج لثغرات SQLi"""
        for payload in self.payloads[:5]:  # أول 5 حملات
            try:
                # بناء بيانات النموذج
                form_data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button']:
                        form_data[inp['name']] = payload['payload']
                
                # بناء URL
                action_url = urljoin(self.target_url, form['action'])
                if not action_url:
                    action_url = self.target_url
                
                # إرسال الطلب
                start_time = time.time()
                
                if form['method'] == 'post':
                    response = self.post_form(action_url, form_data)
                else:
                    from urllib.parse import urlencode
                    query = urlencode(form_data)
                    test_url = f"{action_url}?{query}"
                    response = self.fetch_page(test_url)
                
                response_time = time.time() - start_time
                
                # تحليل الاستجابة
                if response:
                    self._analyze_response(response, response_time, payload, form['action'])
                
                self.delay()
                
            except Exception as e:
                logger.debug(f"Form test error: {e}")
    
    def _test_url_parameters(self, parsed):
        """اختبار بارامترات URL"""
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param_name in list(params.keys())[:3]:
            for payload in self.payloads[:5]:
                try:
                    # بناء URL مع البايلود
                    test_params = params.copy()
                    test_params[param_name] = [payload['payload']]
                    
                    from urllib.parse import urlencode
                    new_query = urlencode(test_params, doseq=True)
                    test_url = f"{base_url}?{new_query}"
                    
                    start_time = time.time()
                    response = self.fetch_page(test_url)
                    response_time = time.time() - start_time
                    
                    if response:
                        self._analyze_response(response, response_time, payload, f"param: {param_name}")
                    
                    self.delay()
                    
                except Exception as e:
                    logger.debug(f"Parameter test error: {e}")
    
    def _analyze_response(self, response: str, response_time: float, payload: Dict, context: str):
        """تحليل الاستجابة"""
        # البحث عن أخطاء SQL
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    self.add_vulnerability('SQL Injection', {
                        'issue': f'SQL Error detected (DB: {db_type})',
                        'confidence': 0.9,
                        'risk': 'high',
                        'evidence': f"Pattern: {pattern[:50]}...",
                        'location': context,
                        'payload': payload['payload'],
                        'db_type': db_type
                    })
                    return
        
        # تحليل Time-based SQLi
        if payload['type'] == 'time_based' and response_time > 2.0:
            self.add_vulnerability('SQL Injection (Time-based)', {
                'issue': 'Potential time-based SQL injection',
                'confidence': 0.7,
                'risk': 'high',
                'evidence': f"Response delay: {response_time:.2f}s",
                'location': context,
                'payload': payload['payload']
            })
        
        # تحليل Boolean-based
        if 'OR 1=1' in payload['payload']:
            # يمكن إضافة منطق لتحليل الاختلافات في الاستجابة
            self.add_info(f"Boolean test sent to {context}")