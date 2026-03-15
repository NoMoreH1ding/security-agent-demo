from langchain.agents import create_agent
from langchain_deepseek import ChatDeepSeek
from langchain_core.prompts import PromptTemplate
from dotenv import load_dotenv

load_dotenv() # 载入虚拟环境

# 1. 定义模型
agent = create_agent(
    model="deepseek-chat",
    tools=[],
    system_prompt="",
    
    )


# 2. 这里的重构重点：直接定义满足 ReAct 协议的 Prompt
# 在 v1.x 中，手动定义 Prompt 往往比从 hub 下载更稳定且易于调试环境
prompt = PromptTemplate.from_template("...") 

# 3. 创建 Agent
agent = create_react_agent(llm, [nmap_version_scanner], prompt)

# 4. 执行器
agent_executor = AgentExecutor(
    agent=agent, 
    tools=[nmap_version_scanner], 
    verbose=True,
    handle_parsing_errors=True # 极其重要：处理模型输出的小毛病
)