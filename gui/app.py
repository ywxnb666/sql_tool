import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
import sys
from io import StringIO
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
        self.url_label = ttk.Label(self.config_frame, text="靶场URL:", font=self.font_config)
        self.url_var = tk.StringVar(value="http://192.168.232.128/pikachu")  # 默认地址
        self.url_entry = ttk.Entry(self.config_frame, textvariable=self.url_var, width=40, font=self.font_config)
        
        # 按钮
        self.test_conn_btn = ttk.Button(self.config_frame, text="测试连接", command=self.test_connection)
        self.scan_btn = ttk.Button(self.config_frame, text="开始扫描", command=self.start_scan)
        self.clear_btn = ttk.Button(self.config_frame, text="清空结果", command=self.clear_results)
        self.show_changes_btn = ttk.Button(self.config_frame, text="显示网站变化", command=self.toggle_changes_window)
        
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
        # 关键差异样式 - 使用明亮的绿色，加粗，白色背景
        self.changes_text.tag_config("difference", foreground="#00AA00", background="#FFFFFF", 
                                   font=("SimHei", 10, "bold"))
        
        # 标签样式 - 使用蓝色
        self.changes_text.tag_config("label", foreground="#0000FF", font=("SimHei", 10, "bold"))
        
        # 错误样式 - 使用红色
        self.changes_text.tag_config("error", foreground="#FF0000", font=("SimHei", 10, "bold"))
        
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
            if not output_info:
                self.changes_text.configure(state='disabled')
                return
            
            # 获取内容预览
            content_preview = output_info.get('content_preview', '').strip()
            
            # 无条件显示任何内容，确保窗口不为空
            if not content_preview:
                content_preview = "[无内容] 未获取到内容预览"
                # 继续显示，不返回
            
            # 如果已有内容，添加分隔线
            current_content = self.changes_text.get(1.0, tk.END).strip()
            if current_content:
                self.changes_text.insert(tk.END, "=" * 30 + "\n")
            
            # 只显示测试参数和关键差异，不显示其他无关信息
            input_info = changes.get('input', {})
            if input_info:
                # 提取测试参数
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
                
                if test_param:
                    method = input_info.get('method', 'GET').upper()
                    self.changes_text.insert(tk.END, f"[测试]: {method} {test_param}\n")
            
            # 显示时间戳
            timestamp = changes.get('timestamp', '')
            if timestamp:
                self.changes_text.insert(tk.END, f"[时间]: {timestamp}\n")
            
            # 插入差异内容，使用绿色样式
            self.changes_text.insert(tk.END, content_preview + "\n", "difference")
            
            # 显示状态码信息，不再限制特定格式
            if 'status_code' in output_info:
                status_info = f"[状态码]: {output_info.get('status_code')}\n"
                self.changes_text.insert(tk.END, status_info)
            
            # 滚动到底部
            self.changes_text.see(tk.END)
            self.changes_text.configure(state='disabled')
            
        except Exception as e:
            # 错误情况下简单处理
            try:
                self.changes_text.configure(state='normal')
                self.changes_text.configure(state='disabled')
            except:
                pass
    
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
            messagebox.showerror("错误", "请输入靶场URL")
            return
        
        # 禁用按钮
        self.test_conn_btn.config(state=tk.DISABLED)
        self.scan_btn.config(state=tk.DISABLED)
        
        # 在线程中测试连接
        def conn_task():
            try:
                # 重定向输出
                sys.stdout = TextRedirector(self.result_text)
                
                scanner = PikachuSQLiScanner(url, self.update_output, self.update_progress, self.update_page_changes)
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
            messagebox.showerror("错误", "请输入靶场URL")
            return
        
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
                scanner = PikachuSQLiScanner(url, self.update_output, self.update_progress, self.update_page_changes)
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
        self.result_text.configure(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.configure(state='disabled')
        # 重置进度条和状态
        self.progress_var.set(0)
        self.progress_label.config(text="准备就绪")
        # 清空变化记录
        self.page_changes = []
        if self.changes_window and self.changes_text:
            self._clear_changes()

def run_gui():
    """运行GUI应用的主函数"""
    root = tk.Tk()
    app = SQLInjectionGUITool(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()