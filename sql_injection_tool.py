import argparse
from core.pikachu_scanner import PikachuSQLiScanner
from gui.app import run_gui

def main():
    """主函数，提供命令行参数解析和运行方式选择"""
    parser = argparse.ArgumentParser(description='SQL注入自动化扫描工具')
    parser.add_argument('--url', type=str, help='Pikachu靶场URL')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    
    args = parser.parse_args()
    
    if args.gui:
        # 启动GUI模式
        run_gui()
    else:
        # 命令行模式
        url = args.url
        if not url:
            # 如果没有提供URL，使用默认值
            url = "http://192.168.232.128/pikachu"
            print(f"未提供URL，使用默认值: {url}")
        
        # 运行扫描
        scanner = PikachuSQLiScanner(url)
        scanner.run_complete_scan()

if __name__ == "__main__":
    main()