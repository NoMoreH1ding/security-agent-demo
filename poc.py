from core.brain import PentestBrain
from core.executor import CommandExecutor
from utils.config import Config
from loguru import logger

def main():
    # 初始化
    Config.validate()
    brain = PentestBrain()
    executor = CommandExecutor()
    
    print("=== AI-PTA 自动化渗透助手 PoC ===")
    
    # 模拟一个典型的渗透意图
    user_query = "查看一下当前登录的用户是谁"
    
    # 第一步：思考 (Brain)
    try:
        action = brain.think(user_query)
        print(f"\n[🧠 AI 决策]: {action.thought}")
        print(f"[🛠️ 预执行]: {action.command} {' '.join(action.args)}")
        
        # 第二步：执行 (Executor)
        # 在真实的渗透场景中，这里通常会有一个 input() 让用户确认是否执行
        confirm = input("\n是否确认执行该命令? (y/n): ")
        if confirm.lower() == 'y':
            output = executor.execute(action)
            
            print(f"\n[📡 执行结果]:\n{output}")
            
            # 第三步：反馈 (反馈给 AI 进行下一步分析，这一步目前可以先手动查看)
            # 进阶：可以将 output 再次传给 brain.think() 生成报告
        else:
            print("[!] 用户取消执行。")

    except Exception as e:
        logger.error(f"流程中断: {e}")

if __name__ == "__main__":
    main()