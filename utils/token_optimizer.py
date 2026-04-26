from typing import List, Sequence, Optional
import functools
import time
import logging
from langchain_core.messages import BaseMessage, ToolMessage, HumanMessage, AIMessage, SystemMessage

logger = logging.getLogger(__name__)

# 简单字符到token的估算（4字符 ≈ 1 token）
def estimate_tokens(text: str) -> int:
    """估算文本的token数量"""
    return len(text) // 4 + 1

def count_message_tokens(msg: BaseMessage) -> int:
    """估算单条消息的token数量"""
    content = ""
    if hasattr(msg, 'content') and msg.content:
        content = str(msg.content)
    # 对于AIMessage with tool_calls，还需要估算tool_calls部分
    if isinstance(msg, AIMessage) and msg.tool_calls:
        tool_calls_str = str(msg.tool_calls)
        content += tool_calls_str
    return estimate_tokens(content)

def summarize_messages(messages: Sequence[BaseMessage], max_tokens: int = 20000) -> List[BaseMessage]:
    """
    对消息历史进行优化，保持总token数在max_tokens以内。
    策略：
    1. 始终保留第一条HumanMessage（用户原始请求）和所有SystemMessage
    2. 保留最近3条完整对话（AIMessage+ToolMessage对）
    3. 截断过长的ToolMessage内容
    4. 如果仍超限，逐步丢弃中间的历史消息
    """
    if not messages:
        return []
    
    # 第一步：识别关键消息（必须保留的）
    essential_indices = []
    for i, msg in enumerate(messages):
        if isinstance(msg, SystemMessage):
            essential_indices.append(i)
        elif isinstance(msg, HumanMessage) and i == 0:  # 第一条用户消息
            essential_indices.append(i)
    
    # 第二步：识别最近 10 个完整对话对（增加记忆深度，防止循环）
    recent_pairs = []
    i = len(messages) - 1
    while i >= 0 and len(recent_pairs) < 10:
        if isinstance(messages[i], ToolMessage):
            # 向前找配对的AIMessage
            for j in range(i-1, max(-1, i-3), -1):
                if isinstance(messages[j], AIMessage) and messages[j].tool_calls:
                    # 找到一对
                    if j not in essential_indices:
                        essential_indices.append(j)
                    if i not in essential_indices:
                        essential_indices.append(i)
                    recent_pairs.append((j, i))
                    i = j - 1  # 跳过这对，继续向前
                    break
            else:
                i -= 1
        else:
            i -= 1
    
    # 第三步：构建保留的消息列表（按原始顺序）
    kept_indices = sorted(set(essential_indices))
    kept_messages = [messages[i] for i in kept_indices]
    
    # 第四步：截断过长的ToolMessage内容
    for i, msg in enumerate(kept_messages):
        if isinstance(msg, ToolMessage):
            content = str(msg.content)
            # 表格类消息保留更多内容
            limit = 3000 if "|" in content and "---" in content else 800
            if len(content) > limit:
                kept_messages[i].content = content[:limit] + f"\n... (已截断至 {limit} 字符) ...\n"
    
    # 第五步：检查token总数，如果超限则逐步丢弃中间历史
    total_tokens = sum(count_message_tokens(msg) for msg in kept_messages)
    if total_tokens <= max_tokens:
        return kept_messages
    
    # 超限处理：优先丢弃非essential的中间消息
    logger.warning(f"消息历史token数超标 ({total_tokens} > {max_tokens})，开始丢弃中间历史")
    
    # 只保留第一条和最后两条（如果可能）
    if len(kept_messages) <= 3:
        # 如果只有3条或更少，强制截断内容
        for msg in kept_messages:
            if isinstance(msg, ToolMessage):
                content = str(msg.content)
                if len(content) > 500:
                    msg.content = content[:500] + f"\n... (强制截断) ...\n"
        return kept_messages
    
    # 保留：第一条 + 最后两条
    final_messages = [kept_messages[0]] + kept_messages[-2:]
    return final_messages

def filter_legal_messages(messages: Sequence[BaseMessage]) -> List[BaseMessage]:
    """
    确保消息序列符合 API 规范：
    1. AI(tool_calls) 必须紧跟 ToolMessage。
    2. 过滤掉不完整的对。
    """
    legal = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        
        # 如果是带有 tool_calls 的 AIMessage
        if isinstance(msg, AIMessage) and msg.tool_calls:
            # 检查后面是否跟着 ToolMessage
            if i + 1 < len(messages) and isinstance(messages[i+1], ToolMessage):
                # 成对保留
                legal.append(msg)
                legal.append(messages[i+1])
                i += 2
            else:
                # 孤立的 tool_calls，跳过以避免报错
                i += 1
        elif isinstance(msg, ToolMessage):
            # 孤立的 ToolMessage（前面没有 AI 呼应），跳过
            i += 1
        else:
            # 普通消息，保留
            legal.append(msg)
            i += 1
    return legal

def retry_on_api_error(max_retries: int = 3, initial_delay: float = 1.0):
    """
    装饰器：在API调用失败时进行指数退避重试。
    主要处理token超限、网络超时等临时性错误。
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    error_msg = str(e).lower()
                    
                    # 检查是否可重试的错误
                    is_retryable = False
                    if "timeout" in error_msg or "connection" in error_msg:
                        is_retryable = True
                        logger.warning(f"API连接错误 (尝试 {attempt+1}/{max_retries}): {e}")
                    elif "bad request" in error_msg or "400" in error_msg:
                        # 可能是token超限，重试可能无效，但可以尝试一次
                        if attempt == 0:
                            logger.warning(f"API请求错误 (尝试 {attempt+1}/{max_retries}): {e}")
                            is_retryable = True
                        else:
                            logger.error(f"API请求错误持续，放弃重试: {e}")
                            break
                    elif "rate limit" in error_msg or "429" in error_msg:
                        is_retryable = True
                        logger.warning(f"API速率限制 (尝试 {attempt+1}/{max_retries}): {e}")
                    else:
                        logger.error(f"API不可重试错误: {e}")
                        break
                    
                    if not is_retryable or attempt == max_retries - 1:
                        break
                    
                    time.sleep(delay)
                    delay *= 2  # 指数退避
            
            # 所有重试都失败，抛出最后一个异常
            raise last_exception
        return wrapper
    return decorator
