import os
from dotenv import load_dotenv

# 加载 .env 文件中的变量
load_dotenv()

class Config:
    # 从系统环境变量中读取 API Key，如果没有则报错
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
    BASE_URL = "https://api.deepseek.com"

    @classmethod
    def validate(cls):
        if not cls.DEEPSEEK_API_KEY:
            raise ValueError("错误: 未在 .env 文件中找到 DEEPSEEK_API_KEY")
        print("[+] 环境配置验证通过")

if __name__ == "__main__":
    Config.validate()