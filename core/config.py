"""
core/config.py
إعدادات المنصة المعدلة
"""

class PlatformConfig:
    """تخزين إعدادات المنصة"""
    
    def __init__(self): 
        self.debug = True  # غيره إلى False للإنتاج
        self.host = "127.0.0.1"
        self.port = 5000
        self.secret_key = "unified-security-scanner-2024"
        self.max_concurrent_scans = 3
        self.request_timeout = 30
        self.scan_timeout = 300

config = PlatformConfig()