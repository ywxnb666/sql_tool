import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
import sys
import os
import glob
from io import StringIO

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pikachu_scanner import PikachuSQLiScanner

class TextRedirector:
    """用于将控制台输出重定向到Tkinter文本控件"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
    
    def write(self, string):
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)  # 自动滚动到底部
        self.text_widget.configure(state='disabled')
    
    def flush(self):
        pass  # 刷新方法，保持与文件接口兼容

class SQLInjectionGUITool:
    """SQL注入工具的GUI界面类"""
    
    def __init__(self, root):
        """
        初始化GUI界面
        
        参数:
            root: Tkinter主窗口实例
        """
        self.root = root
        self.root.title("SQL注入自动化扫描工具")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # 设置中文字体
        self.font_config = ("SimHei", 10)
        
        # 保存原始的stdout
        self.original_stdout = sys.stdout
        
        # 扫描线程
        self.scanner_thread = None
        
        # 虽然不再使用单独的变化窗口，但为了保持兼容性，仍需初始化
        self.changes_window = None
        
        # 创建UI组件
        self.create_widgets()
        
        # 配置布局
        self.setup_layout()
    
    def create_widgets(self):
        """创建所有UI组件"""
        # 顶部配置区域
        self.config_frame = ttk.LabelFrame(self.root, text="配置")
        
        # URL标签和输入框
        self.url_label = ttk.Label(self.config_frame, text="目标URL:", font=self.font_config)
        self.url_var = tk.StringVar(value="")  # 移除默认地址，用户输入完整URL
        self.url_entry = ttk.Entry(self.config_frame, textvariable=self.url_var, width=40, font=self.font_config)
        
        # 添加灰色默认提示
        self.default_url = "http://192.168.232.128/pikachu/vul/sqli/sqli_search.php"
        self._add_placeholder()
        
        # 按钮
        self.test_conn_btn = ttk.Button(self.config_frame, text="测试连接", command=self.test_connection)
        self.scan_btn = ttk.Button(self.config_frame, text="开始扫描", command=self.start_scan)
        self.clear_btn = ttk.Button(self.config_frame, text="清空结果", command=self.clear_results)
        self.show_changes_btn = ttk.Button(self.config_frame, text="显示网站变化", command=self.toggle_changes_window)
        self.load_results_btn = ttk.Button(self.config_frame, text="加载最新结果", command=self.load_latest_results)
        
        # 进度条和状态标签
        self.progress_frame = ttk.Frame(self.root)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, mode='determinate')
        self.progress_label = ttk.Label(self.progress_frame, text="准备就绪", font=self.font_config)
        
        # 创建一个分隔的容器，用于放置扫描结果和网站变化输出
        self.content_frame = ttk.Frame(self.root)
        
        # 扫描结果显示区域
        self.result_frame = ttk.LabelFrame(self.content_frame, text="扫描结果")
        self.result_text = scrolledtext.ScrolledText(self.result_frame, wrap=tk.WORD, state='disabled', font=self.font_config)
        
        # 网站变化输出区域
        self.changes_frame = ttk.LabelFrame(self.content_frame, text="网站动态变化输出")
        self.changes_text = scrolledtext.ScrolledText(self.changes_frame, wrap=tk.WORD, state='disabled', font=self.font_config)
        
        # 页面变化信息容器
        self.page_changes = []
        
        # 初始化网站变化输出区域的样式
        self._init_changes_styles()
    
    def _init_changes_styles(self):
        """初始化网站变化输出区域的样式"""
        # 配置文本控件样式
        self.changes_text.tag_config('difference', foreground='green')
        self.changes_text.tag_config('label', foreground='blue')
        self.changes_text.tag_config('separator', foreground='gray')
        self.changes_text.tag_config('error', foreground='red', background='#ffeeee')
    
    def _add_placeholder(self):
        """为URL输入框添加灰色默认提示"""
        # 设置初始placeholder
        self.url_entry.insert(0, self.default_url)
        self.url_entry.config(foreground='grey')
        
        # 绑定焦点事件
        self.url_entry.bind('<FocusIn>', self._on_url_entry_focus_in)
        self.url_entry.bind('<FocusOut>', self._on_url_entry_focus_out)
    
    def _on_url_entry_focus_in(self, event):
        """当URL输入框获得焦点时"""
        if self.url_entry.get() == self.default_url:
            self.url_entry.delete(0, tk.END)
            self.url_entry.config(foreground='black')
    
    def _on_url_entry_focus_out(self, event):
        """当URL输入框失去焦点时"""
        if not self.url_entry.get():
            self.url_entry.insert(0, self.default_url)
            self.url_entry.config(foreground='grey')
        
    def setup_layout(self):
        """设置UI布局"""
        # 使用网格布局
        self.config_frame.pack(fill=tk.X, padx=10, pady=5)
        self.url_label.grid(row=0, column=0, padx=5, pady=10, sticky=tk.W)
        self.url_entry.grid(row=0, column=1, padx=5, pady=10, sticky=tk.EW)
        self.test_conn_btn.grid(row=0, column=2, padx=5, pady=10)
        self.scan_btn.grid(row=0, column=3, padx=5, pady=10)
        self.clear_btn.grid(row=0, column=4, padx=5, pady=10)
        # 移除显示网站变化按钮，因为我们现在在同一窗口显示
        # self.show_changes_btn.grid(row=0, column=5, padx=5, pady=10)
        self.load_results_btn.grid(row=0, column=5, padx=5, pady=10)
        
        # 设置列权重，使URL输入框能够拉伸
        self.config_frame.grid_columnconfigure(1, weight=1)
        
        # 进度条
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar.pack(fill=tk.X)
        self.progress_label.pack(side=tk.RIGHT, padx=5)
        
        # 主内容区域 - 放置扫描结果和网站变化输出
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 扫描结果区域（左侧）
        self.result_frame.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 5))
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 网站变化输出区域（右侧）
        self.changes_frame.grid(row=0, column=1, sticky=tk.NSEW, padx=(5, 0))
        self.changes_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设置行和列权重，使两个区域能够均匀拉伸
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1)
    
    def update_output(self, message):
        """更新GUI输出"""
        self.result_text.configure(state='normal')
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)
        self.result_text.configure(state='disabled')
    
    def update_page_changes(self, changes):
        """更新页面变化信息，支持新的关键差异格式"""
        # 直接存储变化信息（现在从sqli_scanner直接获取格式化的IO记录）
        self.page_changes.append(changes)
        # 直接显示变化，因为我们现在在同一窗口显示
        self._display_changes(changes)
    
    def _display_changes(self, changes):
        """显示页面变化信息，在主窗口的右侧区域显示"""
        try:
            # 确保changes_text已初始化
            if not hasattr(self, 'changes_text'):
                return
                
            self.changes_text.configure(state='normal')
            
            # 提取关键信息
            output_info = changes.get('output', {})
            input_info = changes.get('input', {})
            
            # 获取内容预览
            content_preview = output_info.get('content_preview', '').strip()
            
            # 无条件显示任何内容，确保窗口不为空
            if not content_preview:
                content_preview = "[无内容] 未获取到内容预览"
            
            # 如果已有内容，添加更清晰的分隔线
            current_content = self.changes_text.get(1.0, tk.END).strip()
            if current_content:
                self.changes_text.insert(tk.END, "\n" + "-" * 50 + "\n\n", "separator")
            
            # 显示时间戳
            timestamp = changes.get('timestamp', '')
            if timestamp:
                self.changes_text.insert(tk.END, f"[时间]: {timestamp}\n", "label")
            
            # 显示URL信息（与文件输出保持一致）
            url = input_info.get('url', '')
            if url:
                self.changes_text.insert(tk.END, f"[URL]: {url}\n", "label")
            
            # 显示方法信息
            method = input_info.get('method', 'GET').upper()
            self.changes_text.insert(tk.END, f"[方法]: {method}\n", "label")
            
            # 显示参数或数据信息
            if input_info.get('params'):
                params = input_info.get('params')
                self.changes_text.insert(tk.END, f"[参数]: {params}\n", "label")
            elif input_info.get('data'):
                data = input_info.get('data')
                self.changes_text.insert(tk.END, f"[数据]: {data}\n", "label")
            
            # 提取测试参数（用于更简洁的显示）
            test_param = ""
            if input_info.get('params'):
                params = input_info.get('params')
                # 找出主要测试参数（排除submit）
                for k, v in params.items():
                    if k.lower() != 'submit':
                        test_param = f"{k}={v}"
                        break
                if not test_param and params:
                    k, v = list(params.items())[0]
                    test_param = f"{k}={v}"
            elif input_info.get('data'):
                data = input_info.get('data')
                if data:
                    k, v = list(data.items())[0]
                    test_param = f"{k}={v}"
            
            # 智能格式化差异内容
            formatted_changes = self._format_changes_content(content_preview)
            
            # 插入差异内容，使用绿色样式
            self.changes_text.insert(tk.END, formatted_changes + "\n", "difference")
            
            # 显示状态码信息，不再限制特定格式
            if 'status_code' in output_info:
                status_info = f"[状态码]: {output_info.get('status_code')}\n"
                self.changes_text.insert(tk.END, status_info, "label")
            
            # 滚动到底部
            self.changes_text.see(tk.END)
            self.changes_text.configure(state='disabled')
            
        except Exception as e:
            # 错误情况下简单处理
            try:
                self.changes_text.configure(state='normal')
                self.changes_text.insert(tk.END, f"[错误] 显示变化时出错: {str(e)}\n", "error")
                self.changes_text.configure(state='disabled')
            except:
                pass
    
    def _format_changes_content(self, content):
        """智能格式化变化内容，改善可读性"""
        if not content:
            return ""
            
        # 分割并处理每一行
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            # 清理空白
            line = line.strip()
            if not line:
                continue
            
            # 智能识别和格式化键值对格式
            if ':' in line or '=' in line:
                # 尝试为键值对添加适当的缩进
                if any(key in line.lower() for key in ['your uid', 'your email', 'password', 'username', 'id']):
                    # 这看起来是重要的用户信息，保持原样或增强格式
                    formatted_lines.append(line)
                else:
                    # 尝试识别键和值并添加缩进
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        formatted_lines.append(f"  {key}: {value}")
                    elif '=' in line and ' ' not in line.split('=')[0]:
                        key, value = line.split('=', 1)
                        formatted_lines.append(f"  {key}={value}")
                    else:
                        formatted_lines.append(line)
            else:
                # 检查是否包含邮箱、哈希值等特殊格式
                import re
                if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', line):
                    formatted_lines.append(f"  {line}")  # 邮箱地址添加缩进
                elif re.search(r'\b[0-9a-f]{32,}\b', line, re.IGNORECASE):
                    formatted_lines.append(f"  {line}")  # 哈希值添加缩进
                else:
                    formatted_lines.append(line)
        
        # 重新组合成文本
        return '\n'.join(formatted_lines)
    
    def find_latest_files(self):
        """找到scan_results目录中最新的两个文件"""
        scan_results_dir = os.path.join(os.getcwd(), 'scan_results')
        
        if not os.path.exists(scan_results_dir):
            return None, None
        
        # 查找所有txt文件
        txt_files = glob.glob(os.path.join(scan_results_dir, '*.txt'))
        
        if not txt_files:
            return None, None
        
        # 按修改时间排序，最新的在前
        txt_files.sort(key=os.path.getmtime, reverse=True)
        
        # 分离两种类型的文件
        scan_results_files = [f for f in txt_files if 'scan_results' in os.path.basename(f)]
        dynamic_output_files = [f for f in txt_files if 'dynamic_output' in os.path.basename(f)]
        
        latest_scan_results = scan_results_files[0] if scan_results_files else None
        latest_dynamic_output = dynamic_output_files[0] if dynamic_output_files else None
        
        return latest_scan_results, latest_dynamic_output
    
    def load_results_from_files(self):
        """从文件加载最新结果并更新GUI，确保内容完全一致"""
        try:
            scan_results_file, dynamic_output_file = self.find_latest_files()
            
            # 加载扫描结果
            if scan_results_file and os.path.exists(scan_results_file):
                with open(scan_results_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.result_text.configure(state='normal')
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, content)
                self.result_text.configure(state='disabled')
            
            # 加载动态输出
            if dynamic_output_file and os.path.exists(dynamic_output_file):
                with open(dynamic_output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.changes_text.configure(state='normal')
                self.changes_text.delete(1.0, tk.END)
                self.changes_text.insert(tk.END, content)
                self.changes_text.configure(state='disabled')
                
        except Exception as e:
            messagebox.showerror("错误", f"加载结果文件时出错: {str(e)}")
    
    def load_latest_results(self):
        """加载最新结果按钮的回调函数"""
        self.load_results_from_files()
    
    def toggle_changes_window(self):
        """切换变化窗口的显示/隐藏状态（现在只是显示一个提示）"""
        messagebox.showinfo("提示", "网站变化输出现在直接显示在主窗口的右侧区域。")
    
    def _create_changes_window(self):
        """创建变化显示窗口（不再需要，因为我们现在在同一窗口显示，但保留方法以保持兼容性）"""
        # 显示一个提示信息，说明变化现在显示在主窗口中
        messagebox.showinfo("提示", "网站变化输出现在直接显示在主窗口的右侧区域。")
    
    def _clear_changes(self):
        """清空变化窗口内容"""
        if self.changes_text:
            self.changes_text.configure(state='normal')
            self.changes_text.delete(1.0, tk.END)
            self.changes_text.configure(state='disabled')
        self.page_changes = []
    
    def test_connection(self):
        """测试连接按钮的回调函数"""
        url = self.url_var.get().strip()
        if not url:
            # 使用默认URL
            url = "http://192.168.232.128/pikachu/vul/sqli/sqli_search.php"
            self.update_output(f"未输入URL，使用默认URL: {url}\n")
        
        # 禁用按钮
        self.test_conn_btn.config(state=tk.DISABLED)
        self.scan_btn.config(state=tk.DISABLED)
        
        # 在线程中测试连接
        def conn_task():
            try:
                # 重定向输出
                sys.stdout = TextRedirector(self.result_text)
                
                scanner = PikachuSQLiScanner(url, self.update_output, self.update_progress, self.update_page_changes, enable_file_output=True)
                scanner.test_connection()
            finally:
                # 恢复输出
                sys.stdout = self.original_stdout
                
                # 恢复按钮状态
                self.root.after(0, lambda: self.test_conn_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
        
        # 启动测试连接线程
        conn_thread = threading.Thread(target=conn_task)
        conn_thread.daemon = True
        conn_thread.start()
    
    def update_progress(self, value, status=None):
        """
        更新进度条和状态信息
        
        参数:
            value: 进度值(0-100)
            status: 状态消息
        """
        # 使用线程安全的方式更新UI
        def update_ui():
            if value is not None:
                self.progress_var.set(value)
            if status:
                self.progress_label.config(text=status)
        
        self.root.after(0, update_ui)
    
    def start_scan(self):
        """开始扫描按钮的回调函数"""
        url = self.url_var.get().strip()
        if not url:
            # 使用默认URL
            url = "http://192.168.232.128/pikachu/vul/sqli/sqli_search.php"
            self.update_output(f"未输入URL，使用默认URL: {url}\n")
        
        # 检查是否有正在运行的扫描
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("信息", "扫描已在进行中，请等待完成")
            return
        
        # 禁用按钮，重置进度条
        self.scan_btn.config(state=tk.DISABLED)
        self.test_conn_btn.config(state=tk.DISABLED)
        self.clear_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.progress_label.config(text="开始扫描")
        
        # 清空变化记录
        self.page_changes = []
        if self.changes_window and self.changes_text:
            self._clear_changes()
        
        # 在线程中执行扫描，避免界面卡顿
        def scan_task():
            try:
                # 重定向标准输出到GUI
                sys.stdout = TextRedirector(self.result_text)
                
                # 创建扫描器实例，传入进度回调和页面变化回调
                scanner = PikachuSQLiScanner(url, self.update_output, self.update_progress, self.update_page_changes, enable_file_output=True)
                scanner.run_complete_scan()
            finally:
                # 恢复标准输出
                sys.stdout = self.original_stdout
                
                # 恢复按钮状态
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.test_conn_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.clear_btn.config(state=tk.NORMAL))
        
        # 启动扫描线程
        self.scanner_thread = threading.Thread(target=scan_task)
        self.scanner_thread.daemon = True
        self.scanner_thread.start()
    
    def clear_results(self):
        """清空结果按钮的回调函数"""
        # 清空扫描结果窗口
        self.result_text.configure(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.configure(state='disabled')
        
        # 清空网站变化输出窗口
        self.changes_text.configure(state='normal')
        self.changes_text.delete(1.0, tk.END)
        self.changes_text.configure(state='disabled')
        
        # 重置进度条和状态
        self.progress_var.set(0)
        self.progress_label.config(text="准备就绪")
        # 清空变化记录
        self.page_changes = []

def run_gui():
    """运行GUI应用的主函数"""
    root = tk.Tk()
    app = SQLInjectionGUITool(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()