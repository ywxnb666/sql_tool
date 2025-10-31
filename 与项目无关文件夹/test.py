import re

text = """username：1uid:admin email is: e10adc3949ba59abbe56e057f20f883eusername：1uid:pikachu email is: 670b14728ad9902aecba32e22fa4f6bdusername：1uid:test email is: e99a18c428cb38d5f260853678922e03"""

pattern = r'username：(.*?)uid:(.*?) email is: (.*?)(?=user|\Z)'

# 使用 re.findall 进行匹配
results = re.findall(pattern, text)

# 打印匹配结果
print(results)