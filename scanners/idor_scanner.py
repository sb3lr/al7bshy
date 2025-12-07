"""
scanners/idor_scanner.py
ماسح IDOR (Insecure Direct Object References)
"""

import re
import time
from typing import Dict, List
from urllib.parse import urljoin, urlparse
from core.scanner_base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class IDORScanner(BaseScanner):
    """ماسح ثغرات IDOR"""
    
    def __init__(self, target_url: str, config: Dict = None):
        super().__init__(target_url, config)
        
    def scan(self) -> Dict:
        """تنفيذ فحص IDOR"""
        logger.info(f"Starting IDOR scan for {self.target_url}")
        
        try:
            self.initialize()
            
            # جلب الصفحة الرئيسية
            main_page = self.fetch_page(self.target_url)
            if not main_page:
                self.add_warning("Could not fetch main page")
                return self.get_results()
            
            # البحث عن أنماط IDOR في الصفحة
            self._scan_for_idor_patterns(main_page)
            
            # فحص الروابط المتوقعة
            self._test_common_idor_patterns()
            
        except Exception as e:
            logger.error(f"IDOR scan error: {e}")
            self.add_warning(f"Scan error: {str(e)}")
        finally:
            self.close()
        
        return self.get_results()
    
    def _scan_for_idor_patterns(self, html: str):
        """البحث عن أنماط IDOR في HTML"""
        # أنماط شائعة لمعرفات
        patterns = [
            r'id=(\d+)',
            r'user=(\d+)',
            r'uid=(\d+)',
            r'account=(\d+)',
            r'file=(\d+)',
            r'doc=(\d+)',
            r'order=(\d+)',
            r'invoice=(\d+)',
            r'token=([a-zA-Z0-9]{8,})',
            r'session=([a-zA-Z0-9]{16,})',
        ]
        
        found_ids = []
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match not in found_ids:
                    found_ids.append(match)
                    self.add_info(f"Found potential ID: {pattern.split('=')[0]}={match}")
        
        # إذا وجدنا معرفات، نقوم باختبارها
        if found_ids:
            self._test_idor_access(found_ids[:3])  # أول 3 معرفات فقط
    
    def _test_common_idor_patterns(self):
        """اختبار أنماط IDOR شائعة"""
        common_patterns = [
            f"{self.target_url}/user/1",
            f"{self.target_url}/profile/1",
            f"{self.target_url}/account/1",
            f"{self.target_url}/file/1",
            f"{self.target_url}/download/1",
            f"{self.target_url}/api/user/1",
            f"{self.target_url}/api/profile/1",
        ]
        
        for pattern in common_patterns:
            try:
                response = self.fetch_page(pattern)
                if response and response.status_code == 200:
                    # التحقق من أن الصفحة ليست صفحة خطأ
                    if not self._is_error_page(response):
                        self.add_vulnerability('IDOR', {
                            'issue': 'Potential IDOR vulnerability',
                            'confidence': 0.6,
                            'risk': 'medium',
                            'evidence': f"Accessible URL: {pattern}",
                            'location': 'Direct object reference'
                        })
                
                self.delay()
                
            except Exception as e:
                logger.debug(f"IDOR pattern test error: {e}")
    
    def _test_idor_access(self, ids: List[str]):
        """اختبار الوصول باستخدام معرفات مختلفة"""
        # اختبار الزيادة/النقصان
        for id_val in ids:
            if id_val.isdigit():
                test_id = int(id_val)
                
                # اختبار ID+1
                next_id = test_id + 1
                prev_id = test_id - 1 if test_id > 1 else None
                
                # بناء URL للاختبار
                base_url = self.target_url.rstrip('/')
                
                # محاولة أنماط مختلفة
                test_patterns = [
                    f"{base_url}?id={next_id}",
                    f"{base_url}/user/{next_id}",
                    f"{base_url}/profile/{next_id}",
                ]
                
                if prev_id:
                    test_patterns.append(f"{base_url}?id={prev_id}")
                
                for test_url in test_patterns[:2]:  # أول اختبارين فقط
                    try:
                        original_response = self.fetch_page(f"{base_url}?id={id_val}")
                        test_response = self.fetch_page(test_url)
                        
                        if test_response and original_response:
                            # مقارنة الاستجابات
                            if test_response.status_code == 200 and not self._is_error_page(test_response):
                                # إذا كانت الاستجابات مختلفة بشكل ملحوظ
                                if len(test_response) > 100 and len(test_response) != len(original_response):
                                    self.add_vulnerability('IDOR', {
                                        'issue': 'Potential IDOR via ID manipulation',
                                        'confidence': 0.7,
                                        'risk': 'high',
                                        'evidence': f"Accessed {test_url} with modified ID",
                                        'location': 'ID parameter manipulation'
                                    })
                                    break
                        
                        self.delay()
                        
                    except Exception as e:
                        logger.debug(f"IDOR access test error: {e}")
    
    def _is_error_page(self, response) -> bool:
        """التحقق من إذا كانت الصفحة صفحة خطأ"""
        if isinstance(response, str):
            html = response.lower()
        else:
            html = response.text.lower() if hasattr(response, 'text') else str(response).lower()
        
        error_indicators = [
            'error',
            'not found',
            '404',
            'forbidden',
            'access denied',
            'invalid',
            'unauthorized'
        ]
        
        return any(indicator in html for indicator in error_indicators)