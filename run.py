"""
run.py
ملف التشغيل الرئيسي مع فحص الأخطاء
"""

import sys
import traceback
import os

def check_python_syntax():
    """فحص بناء جملة Python في الملفات"""
    print("🔍 Checking Python syntax...")
    
    files_to_check = [
        'app.py',
        'core/config.py',
        'core/scanner_base.py',
        'scanners/xss_scanner.py',
        'scanners/sqli_scanner.py',
        'scanners/idor_scanner.py',
        'scanners/csrf_scanner.py'
    ]
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                # محاولة تحليل الملف
                compile(content, file_path, 'exec')
                print(f"  ✓ {file_path}")
            except SyntaxError as e:
                print(f"  ✗ {file_path} - SyntaxError: {e}")
                return False
            except Exception as e:
                print(f"  ? {file_path} - Error: {e}")
        else:
            print(f"  ✗ {file_path} - File not found")
    
    return True

def check_imports():
    """فحص الاستيرادات"""
    print("\n🔍 Checking imports...")
    
    try:
        # محاولة استيراد التطبيق
        from app import run_server
        print("  ✓ Successfully imported from app.py")
        return run_server
    except ImportError as e:
        print(f"  ✗ ImportError from app.py: {e}")
    
    try:
        # محاولة باسم آخر
        from cyber_platform import run_server
        print("  ✓ Successfully imported from cyber_platform.py")
        return run_server
    except ImportError as e:
        print(f"  ✗ ImportError from cyber_platform.py: {e}")
    
    return None

def main():
    """الدالة الرئيسية"""
    print("=" * 60)
    print("🛡️   UNIFIED SECURITY SCANNER - STARTUP CHECK")
    print("=" * 60)
    
    # فحص بناء الجملة أولاً
    if not check_python_syntax():
        print("\n❌ Syntax errors found. Please fix them first.")
        return
    
    # فحص الاستيرادات
    run_server_func = check_imports()
    
    if not run_server_func:
        print("\n❌ Could not import the application.")
        print("\n📁 Listing directory contents:")
        for item in os.listdir('.'):
            print(f"  {item}")
        
        print("\n📁 Core directory:")
        if os.path.exists('core'):
            for item in os.listdir('core'):
                print(f"  core/{item}")
        
        print("\n📁 Scanners directory:")
        if os.path.exists('scanners'):
            for item in os.listdir('scanners'):
                print(f"  scanners/{item}")
        
        print("\n🔧 Please check your files and try again.")
        return
    
    # تشغيل الخادم
    print("\n" + "=" * 60)
    print("🚀 Starting Unified Security Scanner...")
    print("=" * 60)
    print("🌐 Web Interface: http://localhost:5000")
    print("🔍 Enter a target URL to scan for vulnerabilities")
    print("   Example: http://testphp.vulnweb.com")
    print("🛑 Press CTRL+C to stop the server")
    print("=" * 60 + "\n")
    
    try:
        run_server_func()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        traceback.print_exc()

if __name__ == '__main__':
    main()