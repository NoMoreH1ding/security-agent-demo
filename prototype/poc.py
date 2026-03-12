from core.brain import PentestBrain
from core.executor import CommandExecutor
from utils.config import Config
from utils.logger import SimpleLogger 
from utils.parser import NmapXMLParser
from loguru import logger

def main():
    # 1. 初始化日志系统（单次对话隔离模式）
    # 程序一启动就生成 logs/YYYYMMDD_HHMMSS 文件夹
    agent_logger = SimpleLogger()
    logger.info("=== AI-PTA 自动化渗透助手 PoC 系统启动 ===")
    
    # 2. 环境校验与组件初始化
    try:
        Config.validate()
        brain = PentestBrain()
        executor = CommandExecutor()
        logger.debug("系统组件初始化成功")
    except Exception as e:
        logger.error(f"初始化失败: {e}")
        return

    # 3. 模拟渗透意图
    user_query = "利用nmap -sS -sV -O -Pn -n --top-ports 100 -oX - 的参数扫描192.168.43.1"
    logger.info(f"收到用户指令: {user_query}")
    
    # 第一步：思考 (Brain)
    try:
        # 在这里记录 AI 交互的 Trace
        action = brain.think(user_query)
        
        # 记录到 ai_trace.log，方便复盘 Prompt
        agent_logger.log_ai_trace(user_query, f"Thought: {action.thought}\nCommand: {action.command} {' '.join(action.args)}")
        
        logger.info(f"AI 决策完成: {action.thought}")
        logger.warning(f"拟执行命令: {action.command} {' '.join(action.args)}")
        
        # 第二步：执行确认 (人机交互)
        #confirm = input("\n[⚠️ 确认] 是否确认执行该命令? (y/n): ")
        #if confirm.lower() == 'y':
        if 1:
            logger.info("用户确认执行，启动流式执行器...")nu
            
            # 在执行器内部，你之前已经添加了 logger.info(line)
            # 这里的 output 会包含所有流式输出的汇总
            output = executor.execute(action)
            
            # 将最终结果摘要存入系统日志
            logger.success("命令执行完毕，正在归档扫描结果")
            logger.info(f"{output}") # TODO:仅作调试用，后续需将其更改为提取过的简报内容
            
            # 第三步：反馈 (目前为演示逻辑，打印结果)
            # 以后可以将这里的 output 传给 agent_logger.log_ai_trace 记录分析过程
            print(f"\n[📡 执行结果如下]:\n{output}...") 
            output_json = NmapXMLParser.parse_from_string(output)
            nmap_md = NmapXMLParser.to_markdown(output_json)
            report = brain.analyze(nmap_md)
            agent_logger.log_ai_trace(nmap_md, report)
            
        else:
            logger.warning("用户取消执行。")

    except Exception as e:
        # 这里会记录到 system.log，包含详细的堆栈信息
        logger.exception(f"流程异常中断: {e}")

if __name__ == "__main__":
    main()