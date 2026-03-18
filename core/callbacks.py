from typing import Any, Dict, List, Optional
from uuid import UUID
from langchain_core.callbacks import BaseCallbackHandler  # 现代导入路径
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
        # 使用 prompts[0] 获取当前的输入
        agent_logger.log_ai_trace(prompt=prompts[0], response="[Thinking...]")

    def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> Any:
        # 现代提取 Response 的方式
        res_text = response.generations[0][0].text
        agent_logger.log_ai_trace(prompt=None, response=res_text)

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, *, run_id: UUID, **kwargs: Any
    ) -> Any:
        # serialized['name'] 是获取工具名最稳妥的方式
        tool_name = serialized.get("name", "Unknown Tool")
        agent_logger.log_ai_trace(
            prompt=f">>> 执行工具: {tool_name}", response=f"参数: {input_str}"
        )

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> Any:
        # 将工具结果记录回 ai_trace
        agent_logger.log_ai_trace(prompt="<<< 工具返回结果", response=str(output))

    def on_tool_error(
        self, error: BaseException, *, run_id: UUID, **kwargs: Any
    ) -> Any:
        # 捕捉执行异常
        agent_logger.log_ai_trace(
            prompt="!!! 工具运行报错", response=f"详细错误: {str(error)}"
        )
