from typing import List, Sequence
from langchain_core.messages import BaseMessage, ToolMessage, HumanMessage, AIMessage, SystemMessage

def summarize_messages(messages: Sequence[BaseMessage]) -> List[BaseMessage]:
    """
    对消息历史进行优化：
    1. 保留 Parser 转换后的 Markdown 表格。
    2. 仅对超过 2500 字符的超长消息进行截断。
    3. 确保 LLM 能够看到工具执行的核心摘要。
    """
    optimized_messages = []
    
    for i, msg in enumerate(messages):
        # 始终保留最近的 3 条消息和所有的 HumanMessage/SystemMessage
        if i >= len(messages) - 3 or isinstance(msg, (HumanMessage, SystemMessage)):
            optimized_messages.append(msg)
            continue
            
        if isinstance(msg, ToolMessage):
            content = str(msg.content)
            # 如果包含表格（Parser 的特征），给予更高的保留配额
            limit = 2500 if "|" in content and "---" in content else 500
            
            if len(content) > limit:
                summary = f"\n... (内容过长，已保留前 {limit} 字符) ...\n"
                msg.content = content[:limit] + summary
            optimized_messages.append(msg)
        else:
            optimized_messages.append(msg)
            
    return optimized_messages
