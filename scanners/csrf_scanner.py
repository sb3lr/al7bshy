"""
scanners/csrf_scanner.py
ماسح CSRF (Cross-Site Request Forgery) - نسخة محسنة
"""

import re
import time
from typing import Dict, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.scanner_base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class CSRFScanner(BaseScanner):
    """ماسح ثغرات CSRF متقدم"""
    
    def __init__(self, target_url: str, config: Dict = None):
        super().__init__(target_url, config)
        
    def scan(self) -> Dict:
        """تنفيذ فحص CSRF شامل"""
        logger.info(f"Starting CSRF scan for {self.target_url}")
        
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
            
            # فحص النماذج لثغرات CSRF
            csrf_forms_found = 0
            for form in input_points['forms']:
                if self._analyze_form_csrf(form, main_page):
                    csrf_forms_found += 1
            
            # فحص أمان cookies فقط إذا وجدنا نماذج
            if csrf_forms_found > 0:
                self._check_cookies_security()
            
            # فحص CORS إذا كان الموقع يدعم AJAX
            self._check_cors_headers()
            
        except Exception as e:
            logger.error(f"CSRF scan error: {e}")
            self.add_warning(f"Scan error: {str(e)}")
        finally:
            self.close()
        
        return self.get_results()
    
    def _analyze_form_csrf(self, form: Dict, html: str) -> bool:
        """تحليل نموذج للكشف عن CSRF"""
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        
        # فقط نماذج POST مهمة لفحص CSRF
        if form_method != 'post':
            self.add_info(f"Form {form_action} uses GET method - less critical for CSRF")
            return False
        
        is_critical_form = self._is_critical_form(form, html)
        
        # البحث عن CSRF tokens في النموذج
        csrf_tokens = []
        for inp in form['inputs']:
            input_name = inp['name'].lower() if inp.get('name') else ''
            
            # البحث عن tokens CSRF
            csrf_keywords = ['csrf', 'token', 'nonce', 'authenticity', '_token', 'anticsrf']
            if any(keyword in input_name for keyword in csrf_keywords):
                token_value = inp.get('value', '')
                csrf_tokens.append({
                    'name': inp['name'],
                    'type': inp['type'],
                    'value_length': len(token_value) if token_value else 0,
                    'is_hidden': inp['type'] == 'hidden'
                })
        
        # تحليل النتائج
        if csrf_tokens:
            self.add_info(f"Form {form_action} has {len(csrf_tokens)} CSRF token(s)")
            
            # تحقق من قوة tokens
            strong_tokens = 0
            for token in csrf_tokens:
                if token['value_length'] >= 16 and token['is_hidden']:
                    strong_tokens += 1
                elif token['value_length'] < 10:
                    self.add_warning(f"Weak CSRF token found: {token['name']} (length: {token['value_length']})")
            
            if strong_tokens == 0 and is_critical_form:
                self.add_vulnerability('CSRF', {
                    'issue': 'Weak or missing CSRF protection in critical form',
                    'confidence': 0.7,
                    'risk': 'medium',
                    'evidence': f"Form {form_action} has weak CSRF tokens",
                    'location': form_action,
                    'recommendation': 'Implement strong CSRF tokens (min 16 chars, hidden)'
                })
                return True
                
        else:
            # إذا لم توجد tokens CSRF في نموذج حرج
            if is_critical_form:
                self.add_vulnerability('CSRF', {
                    'issue': 'Missing CSRF protection in critical form',
                    'confidence': 0.8,
                    'risk': 'medium',
                    'evidence': f"No CSRF token found in form: {form_action}",
                    'location': form_action,
                    'recommendation': 'Add CSRF token to form'
                })
                return True
            else:
                self.add_info(f"Form {form_action} has no CSRF token (non-critical form)")
        
        return False
    
    def _is_critical_form(self, form: Dict, html: str) -> bool:
        """تحديد إذا كان النموذج حرجاً (يحتوي على عمليات مهمة)"""
        form_action = form.get('action', '').lower()
        form_html = str(form).lower() if hasattr(form, '__str__') else ''
        
        # قائمة بالعمليات الحرجة
        critical_keywords = [
            'login', 'logout', 'register', 'signup', 'signin',
            'password', 'changepass', 'resetpass',
            'delete', 'remove', 'update', 'edit', 'save',
            'transfer', 'pay', 'purchase', 'buy', 'order',
            'admin', 'moderator', 'privilege',
            'email', 'profile', 'account', 'settings'
        ]
        
        # التحقق من action URL
        if any(keyword in form_action for keyword in critical_keywords):
            return True
        
        # التحقق من حقول النموذج
        for inp in form['inputs']:
            input_name = inp.get('name', '').lower()
            input_type = inp.get('type', '').lower()
            
            if input_type == 'password':
                return True
            
            if any(keyword in input_name for keyword in ['password', 'pass', 'pwd', 'secret', 'token']):
                return True
        
        # التحقق من السياق في HTML
        soup = BeautifulSoup(html, 'html.parser')
        form_element = soup.find('form', {'action': form.get('action', '')})
        if form_element:
            form_text = form_element.get_text().lower()
            if any(keyword in form_text for keyword in ['login', 'sign in', 'register', 'password']):
                return True
        
        return False
    
    def _check_cookies_security(self):
        """فحص أمان cookies - نسخة محسنة"""
        try:
            # إرسال طلب للحصول على cookies
            response = self.session.get(self.target_url)
            cookies = self.session.cookies
            
            if not cookies:
                self.add_info("No cookies found")
                return
            
            security_issues = []
            warning_issues = []
            
            for cookie in cookies:
                cookie_name = cookie.name
                cookie_dict = cookie.__dict__
                
                # تجاهل cookies التتبع غير الحرجة
                non_critical_cookies = ['__utma', '__utmb', '__utmc', '__utmz', '_ga', '_gid']
                if any(nc in cookie_name.lower() for nc in non_critical_cookies):
                    continue
                
                # التحقق من Secure flag (فقط لـ HTTPS)
                if self.target_url.startswith('https://'):
                    if not cookie_dict.get('secure', False):
                        security_issues.append(f"Cookie '{cookie_name}' missing Secure flag on HTTPS site")
                
                # التحقق من HttpOnly flag
                if not cookie_dict.get('httponly', False):
                    # إذا كان الـ cookie يحمل بيانات حساسة
                    sensitive_names = ['session', 'auth', 'login', 'token', 'jwt', 'access', 'refresh']
                    cookie_lower = cookie_name.lower()
                    
                    if any(sensitive in cookie_lower for sensitive in sensitive_names):
                        security_issues.append(f"Sensitive cookie '{cookie_name}' missing HttpOnly flag")
                    else:
                        warning_issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag")
                
                # التحقق من SameSite attribute
                samesite = cookie_dict.get('samesite', '').lower()
                if not samesite:
                    warning_issues.append(f"Cookie '{cookie_name}' missing SameSite attribute")
                elif samesite == 'none':
                    # SameSite=None يجب أن يكون مع Secure
                    if self.target_url.startswith('https://') and not cookie_dict.get('secure', False):
                        security_issues.append(f"Cookie '{cookie_name}' has SameSite=None without Secure flag")
            
            # تسجيل النتائج
            if security_issues:
                self.add_vulnerability('Cookie Security', {
                    'issue': 'Insecure cookie configuration',
                    'confidence': 0.7,
                    'risk': 'low',  # جعلها low بدلاً من medium
                    'evidence': '; '.join(security_issues[:3]),
                    'location': 'Cookies',
                    'recommendation': 'Set Secure, HttpOnly, and SameSite=Strict/Lax flags for sensitive cookies'
                })
            
            if warning_issues:
                self.add_warning('Cookie Security Warning', {
                    'message': 'Non-critical cookie security issues detected',
                    'details': {'issues': warning_issues[:2]},
                    'recommendation': 'Consider improving cookie security settings for better protection'
                })
            
            # إضافة معلومات عن عدد cookies
            self.add_info(f"Analyzed {len(list(cookies))} cookies for security")
            
        except Exception as e:
            logger.debug(f"Cookie check error: {e}")
            self.add_info("Could not analyze cookies due to connection issue")
    
    def _check_cors_headers(self):
        """فحص CORS headers"""
        try:
            # إرسال طلب OPTIONS لفحص CORS
            test_headers = {
                'Origin': 'https://evil-attacker.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-Requested-With'
            }
            
            response = self.session.options(
                self.target_url,
                headers=test_headers,
                timeout=10
            )
            
            # التحقق من headers
            headers = response.headers
            
            # التحقق من Access-Control-Allow-Origin
            allow_origin = headers.get('Access-Control-Allow-Origin', '')
            if allow_origin == '*':
                self.add_warning('CORS Policy Warning', {
                    'message': 'CORS policy allows any origin (*)',
                    'risk': 'medium',
                    'recommendation': 'Restrict CORS to specific domains'
                })
            elif 'evil-attacker.com' in allow_origin:
                self.add_vulnerability('CORS Misconfiguration', {
                    'issue': 'CORS policy allows arbitrary origins',
                    'confidence': 0.6,
                    'risk': 'medium',
                    'evidence': f"Access-Control-Allow-Origin: {allow_origin}",
                    'recommendation': 'Implement proper CORS origin validation'
                })
            
            # التحقق من Access-Control-Allow-Credentials
            allow_credentials = headers.get('Access-Control-Allow-Credentials', '')
            if allow_credentials.lower() == 'true' and allow_origin == '*':
                self.add_vulnerability('CORS Misconfiguration', {
                    'issue': 'CORS allows credentials with wildcard origin',
                    'confidence': 0.8,
                    'risk': 'high',
                    'evidence': 'Allow-Credentials: true with wildcard origin',
                    'recommendation': 'Never use Allow-Credentials: true with wildcard origin'
                })
                
        except Exception as e:
            logger.debug(f"CORS check error: {e}")
    
    def _test_form_submission(self, form: Dict):
        """اختبار إرسال نموذج بدون token"""
        try:
            form_action = urljoin(self.target_url, form['action'])
            
            # بناء بيانات اختبارية
            test_data = {}
            for inp in form['inputs']:
                if inp['type'] not in ['submit', 'button']:
                    test_data[inp['name']] = 'test_value'
            
            # إرسال طلب بدون referer header (محاكاة هجوم CSRF)
            test_headers = {
                'Referer': 'https://evil-site.com/attack.html'
            }
            
            response = self.session.post(
                form_action,
                data=test_data,
                headers=test_headers,
                timeout=15
            )
            
            # تحليل الاستجابة
            if response.status_code == 200:
                success_indicators = ['success', 'updated', 'changed', 'thank you', 'completed']
                response_text = response.text.lower()
                
                if any(indicator in response_text for indicator in success_indicators):
                    self.add_info(f"Form {form['action']} accepted submission (possible CSRF)")
            
        except Exception as e:
            logger.debug(f"Form submission test error: {e}")