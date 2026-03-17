from httpx import get
from langchain.agents import create_agent
from dotenv import load_dotenv
from tools import ALL_TOOLS
from utils.logger import agent_logger
from loguru import logger

load_dotenv()


agent = create_agent(
    model="deepseek-chat",
    tools=ALL_TOOLS,
    system_prompt="你是一个渗透测试助手，可以执行各种渗透测试任务。请",
)

# 运行代理
response = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": "确定一下目标192.168.43.1的端口开放情况和运行服务的版本",
            }
        ]
    }
)

print("--- 完整返回 ---")
print(response)

# 只获取最后的结果
print("\n--- 最终答案 ---")
# 注意：根据 create_agent 的具体实现，结果可能在 'output' 或 'messages' 的最后一个元素
if "output" in response:
    print(response["output"])
else:
    # 针对这类高阶 Agent，通常最后一条消息就是答案
    print(response["messages"][-1].content)
