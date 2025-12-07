"""
core/scanner_base.py
الفئة الأساسية للماسحات باستخدام requests (نسخة متزامنة)
"""

import time
import random
import requests
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class BaseScanner:
    """الفئة الأساسية لجميع الماسحات باستخدام requests"""
    
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.session = None
        self.results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'statistics': {
                'requests_made': 0,
                'total_tested': 0
            }
        }
        self.timeout = self.config.get('timeout', 30)
        self.delay_range = self.config.get('delay_range', (1, 3))
        self.random_delay = self.config.get('random_delay', True)
        
    def initialize(self):
        """تهيئة جلسة HTTP باستخدام requests"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # تعطيل تحذيرات SSL لأغراض الاختبار
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        logger.info(f"Scanner initialized for {self.target_url}")
        
    def fetch_page(self, url: str) -> Optional[str]:
        """جلب صفحة من الويب"""
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                allow_redirects=True
            )
            
            self.results['statistics']['requests_made'] += 1
            
            if response.status_code == 200:
                # تحديد الترميز
                if response.encoding is None:
                    response.encoding = 'utf-8'
                return response.text
            else:
                logger.debug(f"Failed to fetch {url}: Status {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            return None
    
    def fetch_with_headers(self, url: str, headers: Dict = None) -> Optional[str]:
        """جلب صفحة مع headers مخصصة"""
        try:
            current_headers = self.session.headers.copy()
            if headers:
                current_headers.update(headers)
                
            response = self.session.get(
                url,
                headers=current_headers,
                timeout=self.timeout
            )
            
            self.results['statistics']['requests_made'] += 1
            
            if response.status_code == 200:
                if response.encoding is None:
                    response.encoding = 'utf-8'
                return response.text
            return None
        except Exception as e:
            logger.debug(f"Error with custom headers: {e}")
            return None
    
    def post_form(self, url: str, data: Dict, headers: Dict = None) -> Optional[str]:
        """إرسال نموذج POST"""
        try:
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
            
            self.results['statistics']['requests_made'] += 1
            
            if response.status_code == 200:
                if response.encoding is None:
                    response.encoding = 'utf-8'
                return response.text
            return None
        except Exception as e:
            logger.debug(f"Error posting form: {e}")
            return None
    
    def delay(self):
        """تأخير عشوائي بين الطلبات"""
        if self.random_delay:
            delay = random.uniform(*self.delay_range)
            time.sleep(delay)
    
    def add_vulnerability(self, vuln_type: str, details: Dict):
        """إضافة ثغرة إلى النتائج"""
        vulnerability = {
            'type': vuln_type,
            'timestamp': time.time(),
            'confidence': details.get('confidence', 0.5),
            'risk': details.get('risk', 'medium'),
            'issue': details.get('issue', 'Unknown vulnerability'),
            'evidence': details.get('evidence', ''),
            'details': details
        }
        
        self.results['vulnerabilities'].append(vulnerability)
        self.results['statistics']['total_tested'] += 1
        
        logger.warning(f"Vulnerability found: {vuln_type} - {details.get('issue', 'Unknown')}")
    
    def add_warning(self, message: str, details: Dict = None):
        """إضافة تحذير"""
        warning = {
            'message': message,
            'details': details or {},
            'timestamp': time.time()
        }
        
        self.results['warnings'].append(warning)
        logger.info(f"Warning: {message}")
    
    def add_info(self, message: str):
        """إضافة معلومة"""
        info = {
            'message': message,
            'timestamp': time.time()
        }
        
        self.results['info'].append(info)
        logger.debug(f"Info: {message}")
    
    def get_results(self) -> Dict:
        """الحصول على النتائج"""
        return self.results
    
    def close(self):
        """إغلاق الجلسة"""
        if self.session:
            self.session.close()
            self.session = None
    
    def extract_input_points(self, html: str) -> Dict:
        """استخراج نقاط الإدخال من HTML"""
        if not html:
            return {'forms': [], 'inputs': [], 'links': []}
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            input_points = {
                'forms': [],
                'inputs': [],
                'links': []
            }
            
            # استخراج النماذج
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'enctype': form.get('enctype', ''),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    if input_name:
                        input_data = {
                            'name': input_name,
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', ''),
                            'id': input_tag.get('id', '')
                        }
                        form_data['inputs'].append(input_data)
                
                input_points['forms'].append(form_data)
            
            # استخراج الروابط
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(self.target_url, href)
                input_points['links'].append({
                    'url': full_url,
                    'text': link.text.strip()[:50],
                    'has_params': '?' in href
                })
            
            return input_points
            
        except Exception as e:
            logger.error(f"Error extracting input points: {e}")
            return {'forms': [], 'inputs': [], 'links': []}