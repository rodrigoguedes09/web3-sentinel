"""
Base Agent class for all Sentinela agents.

Provides common functionality for LLM interaction, structured output parsing,
and state management.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from pydantic import BaseModel

from sentinela.core.config import ModelProvider, Settings, get_settings
from sentinela.core.state import AgentState

# Type variable for structured output types
T = TypeVar("T", bound=BaseModel)


class BaseAgent(ABC, Generic[T]):
    """
    Abstract base class for all Sentinela agents.
    
    Provides:
    - LLM initialization with provider abstraction
    - Structured output parsing via Pydantic models
    - Common state access patterns
    - Error handling and logging
    
    Type Parameters:
        T: The Pydantic model type for structured outputs
    """

    def __init__(
        self,
        settings: Settings | None = None,
        model_override: str | None = None,
    ) -> None:
        """
        Initialize the base agent.
        
        Args:
            settings: Application settings (uses default if not provided)
            model_override: Override the model specified in settings
        """
        self.settings = settings or get_settings()
        self._model_name = model_override or self.settings.primary_model
        self._llm: BaseChatModel | None = None

    @property
    def name(self) -> str:
        """Agent name for logging and identification."""
        return self.__class__.__name__

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt defining the agent's role and capabilities."""
        ...

    @property
    @abstractmethod
    def output_schema(self) -> type[T]:
        """Pydantic model class for structured output parsing."""
        ...

    def get_llm(self) -> BaseChatModel:
        """
        Get or initialize the LLM instance.
        
        Returns:
            Configured LangChain chat model
        """
        if self._llm is None:
            self._llm = self._create_llm()
        return self._llm

    def _create_llm(self) -> BaseChatModel:
        """
        Create an LLM instance based on model name.
        
        Returns:
            Configured LangChain chat model
        """
        # Check if Azure OpenAI is configured
        if self.settings.azure_openai_endpoint and self.settings.azure_openai_api_key:
            return AzureChatOpenAI(
                azure_endpoint=self.settings.azure_openai_endpoint,
                azure_deployment=self.settings.azure_openai_deployment_name,
                api_version=self.settings.azure_openai_api_version,
                api_key=self.settings.azure_openai_api_key,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
            )
        
        model_name = self._model_name.lower()

        if "gpt" in model_name or "o1" in model_name:
            return ChatOpenAI(
                model=self._model_name,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
                api_key=self.settings.openai_api_key,
            )
        elif "claude" in model_name:
            return ChatAnthropic(
                model=self._model_name,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
                api_key=self.settings.anthropic_api_key,
            )
        else:
            # Default to OpenAI
            return ChatOpenAI(
                model=self._model_name,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
                api_key=self.settings.openai_api_key,
            )

    def get_structured_llm(self) -> BaseChatModel:
        """
        Get LLM configured for structured output.
        
        For Azure OpenAI models that don't support json_schema,
        uses json_object mode with manual parsing.
        
        Returns:
            LLM with structured output schema bound
        """
        llm = self.get_llm()
        
        # Check if using Azure OpenAI
        if self.settings.azure_openai_endpoint and self.settings.azure_openai_api_key:
            # Azure models may not support json_schema, use method='json_mode'
            try:
                return llm.with_structured_output(
                    self.output_schema,
                    method="json_mode",
                    include_raw=False
                )
            except Exception:
                # Fallback to default method
                return llm.with_structured_output(self.output_schema)
        
        # Standard OpenAI/Anthropic with json_schema support
        return llm.with_structured_output(self.output_schema)

    @abstractmethod
    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute the agent's primary function.
        
        Args:
            state: Current pipeline state
            
        Returns:
            Updated pipeline state
        """
        ...

    async def invoke_with_structure(
        self,
        user_message: str,
        context: dict[str, Any] | None = None,
    ) -> T:
        """
        Invoke the LLM with structured output parsing.
        
        Args:
            user_message: The user/task message to process
            context: Additional context to include in the prompt
            
        Returns:
            Parsed Pydantic model instance
        """
        structured_llm = self.get_structured_llm()

        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=self._format_message(user_message, context)),
        ]

        response = await structured_llm.ainvoke(messages)
        return response  # type: ignore

    def _format_message(
        self,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """
        Format a message with optional context.
        
        Args:
            message: Base message content
            context: Additional context to append
            
        Returns:
            Formatted message string
        """
        if not context:
            return message

        context_str = "\n\n---\nAdditional Context:\n"
        for key, value in context.items():
            context_str += f"\n## {key}:\n{value}\n"

        return message + context_str
