import argparse
import re
from core.pikachu_scanner import PikachuSQLiScanner
from core.sqli_scanner import SQLInjectionScanner
from gui.app import run_gui

def main():
    """主函数，提供命令行参数解析和运行方式选择"""
    parser = argparse.ArgumentParser(description='SQL注入自动化扫描工具')
    parser.add_argument('--url', type=str, help='Pikachu靶场URL')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('--no-file-output', action='store_true', help='禁用文件输出')
    parser.add_argument('--test', type=str, help='测试特定URL的SQL注入')
    
    args = parser.parse_args()
    
    if args.gui:
        # 启动GUI模式
        run_gui()
    elif args.test:
        # 测试模式
        test_url = args.test
        print(f"测试模式 - 测试URL: {test_url}")
        
        # 在测试模式下也启用文件输出
        enable_file_output = not args.no_file_output
        
        # 提取URL和参数信息
        match = re.search(r'(.*)\?(.*)=(.*)', test_url)
        if match:
            base_url = match.group(1)
            param_name = match.group(2)
            
            # 创建扫描器并测试
            scanner = SQLInjectionScanner(base_url, enable_file_output=enable_file_output)
            print(f"[*] 正在测试 {base_url} 的 {param_name} 参数...")
            
            # 发送测试请求
            response = scanner.send_request(test_url)
            if response:
                print(f"[+] 请求成功，状态码: {response.status_code}")
                is_vul, db_type = scanner.is_vulnerable(response)
                if is_vul:
                    print(f"[!] 检测到SQL注入漏洞！数据库类型: {db_type}")
                else:
                    print("[-] 未检测到明显的SQL注入漏洞")
        else:
            print("[!] 无效的测试URL格式，请使用: http://example.com/page.php?param=value")
    else:
        # 命令行模式
        url = args.url
        if not url:
            # 如果没有提供URL，使用默认值
            url = "http://192.168.232.128/pikachu"
            print(f"未提供URL，使用默认值: {url}")
        
        # 在命令行模式下默认启用文件输出，除非明确禁用
        enable_file_output = not args.no_file_output
        
        # 运行扫描
        scanner = PikachuSQLiScanner(url, enable_file_output=enable_file_output)
        scanner.run_complete_scan()

if __name__ == "__main__":
    main()