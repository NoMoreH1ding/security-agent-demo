from typing import Any, Dict, List, Optional
from uuid import UUID
import re
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from utils.logger import agent_logger


class AgentTraceCallbackHandler(BaseCallbackHandler):
    """
    符合 LangChain 标准的同步回调处理器。
    """

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> Any:
        # 从 Prompt 中尝试识别当前阶段（Recon/Analysis）
        prompt = prompts[0]
        role = "LLM"
        if "侦察专家" in prompt:
            role = "LLM-RECON"
        elif "安全分析师" in prompt:
            role = "LLM-ANALYSIS"
        elif "安全审计员" in prompt:
            role = "LLM-REPORTING"
            
        # 我们不再记录庞大的历史上下文 Prompt，只记录一个开始标记，节省日志空间
        agent_logger.log_ai_trace(role=role, content="[Starting LLM Inference...]", title="NODE START")

    def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> Any:
        # 获取 AI 的响应正文
        res_text = response.generations[0][0].text
        # 我们根据内容动态判断角色（这里可以进一步优化）
        agent_logger.log_ai_trace(role="AI-RESPONSE", content=res_text)

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, *, run_id: UUID, **kwargs: Any
    ) -> Any:
        tool_name = serialized.get("name", "Unknown Tool")
        agent_logger.log_ai_trace(
            role="TOOL-CALL", content=f"Args: {input_str}", title=f"Action: {tool_name}"
        )

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> Any:
        # 如果输出是 Markdown 表格，我们可以直接记录
        agent_logger.log_ai_trace(role="TOOL-RESULT", content=str(output))

    def on_tool_error(
        self, error: BaseException, *, run_id: UUID, **kwargs: Any
    ) -> Any:
        agent_logger.log_ai_trace(
            role="TOOL-ERROR", content=f"Error: {str(error)}"
        )
