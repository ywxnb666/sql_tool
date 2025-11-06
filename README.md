# SQL注入扫描工具

## 项目介绍

这是一个功能强大的SQL注入漏洞扫描工具，专门设计用于自动检测和利用Web应用中的SQL注入漏洞。该工具支持多种靶场环境（如DVWA和Pikachu），能够自动识别注入类型、检测漏洞并提取敏感数据。

## 功能特点

### 漏洞检测
- 支持多种SQL注入类型检测（数字型、字符型、XX型等）
- 自动识别HTTP请求方法（GET/POST）
- 智能判断数据库错误信息
- 基于响应比较的盲注检测

### 数据提取
- 自动检测查询字段数量
- 使用UNION查询技术提取数据
- 提取数据库基础信息（版本、当前数据库名等）
- 提取数据库表名和表结构
- 提取敏感用户数据（用户名、密码等）

### 靶场支持
- **DVWA靶场**：自动登录功能，支持不同安全级别
- **Pikachu靶场**：自动识别注入点和类型
- 可扩展支持更多靶场环境

### 用户界面
- 简洁直观的图形用户界面
- 实时扫描进度显示
- 详细的扫描结果输出
- 支持扫描过程中取消操作

## 技术架构

### 核心模块
- **core/sqli_scanner.py**：基础SQL注入扫描功能，包含漏洞检测和数据提取的核心逻辑
- **core/dvwa_scanner.py**：DVWA靶场专用扫描器，处理登录和安全级别设置
- **core/pikachu_scanner.py**：Pikachu靶场专用扫描器，处理特定的注入点识别

### GUI模块
- **gui/app.py**：图形用户界面实现，处理用户交互和结果展示

### 入口文件
- **sql_injection_tool.py**：应用程序主入口

## 安装说明

### 环境要求
- Python 3.8 或更高版本
- Windows 操作系统

### 安装步骤

1. **克隆项目**
   ```bash
   git clone https://github.com/username/sql-injection-tool.git
   cd sql-injection-tool
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

   依赖说明：
   - requests>=2.25.1：HTTP请求处理
   - beautifulsoup4>=4.9.3：HTML解析
   - urllib3>=1.26.5：URL处理
   - lxml>=4.6.3：XML/HTML解析器

## 使用方法

### 启动应用

```bash
python ./sql_injection_tool.py --gui
```

### 基本使用流程

1. **输入目标URL**
   - 在URL输入框中输入目标网站地址
   - 默认值为DVWA靶场地址：http://192.168.232.128/dvwa/

2. **选择靶场类型**
   - 工具会根据URL自动识别靶场类型
   - 对于DVWA靶场，可选择安全级别（Low/Medium/High）

3. **测试连接**
   - 点击"测试连接"按钮验证与目标网站的连接状态

4. **开始扫描**
   - 点击"开始扫描"按钮启动SQL注入扫描过程
   - 扫描进度会实时显示在进度条中

5. **查看结果**
   - 扫描结果会实时显示在下方的结果区域
   - 包括漏洞发现、数据库信息和提取的数据

## 支持的靶场

### DVWA (Damn Vulnerable Web Application)
- 支持自动登录
- 可配置安全级别（Low/Medium/High）
- 主要检测SQL Injection模块

### Pikachu 靶场
- 自动识别不同类型的注入点
- 支持多种注入模式测试

## 安全声明

本工具仅用于合法的安全测试和教育目的。使用者必须遵守相关法律法规，未经授权不得在生产环境或非授权系统上使用。使用本工具造成的任何后果，由使用者自行承担。

## 开发说明

### 项目结构
```
sql_software/
├── core/
│   ├── sqli_scanner.py    # 基础SQL注入扫描功能
│   ├── dvwa_scanner.py    # DVWA靶场专用扫描器
│   └── pikachu_scanner.py # Pikachu靶场专用扫描器
├── gui/
│   └── app.py             # 图形用户界面
├── requirements.txt       # 项目依赖
├── sql_injection_tool.py  # 应用入口
├── .gitignore             # Git忽略配置
└── README.md              # 项目说明文档
```

### 扩展开发
- 可以通过继承`SQLInjectionScanner`类添加新的靶场支持
- 在`gui/app.py`中添加新的靶场配置选项
- 更新`requirements.txt`以添加新的依赖

## 故障排除

### 常见问题

1. **连接失败**
   - 检查目标网站是否可访问
   - 确认URL格式正确
   - 检查网络设置和防火墙配置

2. **登录失败（DVWA）**
   - 确认用户名和密码正确
   - 检查DVWA靶场是否正常运行

3. **扫描无结果**
   - 确认目标存在SQL注入漏洞
   - 尝试调整靶场安全级别

## 许可证

本项目采用MIT许可证。详情请查看LICENSE文件。

## 贡献指南

欢迎提交Issue和Pull Request。在贡献代码前，请确保代码符合项目的编码规范。

## 联系方式

如有问题或建议，请通过以下方式联系：
- Email: [ywxnb666@sjtu.edu.cn]

---

**免责声明**：本工具仅供学习和授权测试使用，严禁用于非法用途。使用本工具造成的任何后果，由使用者自行承担。