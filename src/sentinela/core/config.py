"""
Configuration management for Sentinela Web3.

Uses Pydantic Settings for environment-based configuration with validation.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ModelProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Configure via .env file or environment variables.
    All paths are resolved relative to the project root.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==========================================================================
    # LLM Configuration
    # ==========================================================================
    openai_api_key: str = Field(default="", description="OpenAI API key")
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    
    # Azure OpenAI Configuration
    azure_openai_endpoint: str = Field(default="", description="Azure OpenAI endpoint URL")
    azure_openai_api_key: str = Field(default="", description="Azure OpenAI API key")
    azure_openai_deployment_name: str = Field(default="", description="Azure OpenAI deployment name")
    azure_openai_model_name: str = Field(default="", description="Azure OpenAI model name")
    azure_openai_api_version: str = Field(default="2024-08-01-preview", description="Azure OpenAI API version")
    
    primary_model: str = Field(
        default="gpt-4o",
        description="Primary LLM model for agent reasoning",
    )
    fallback_model: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Fallback model if primary fails",
    )
    
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description="LLM temperature for deterministic outputs",
    )
    max_tokens: int = Field(
        default=4096,
        ge=256,
        le=128000,
        description="Maximum tokens per LLM response",
    )

    # ==========================================================================
    # Tool Paths
    # ==========================================================================
    slither_path: str = Field(
        default="slither",
        description="Path to Slither executable",
    )
    forge_path: str = Field(
        default="forge",
        description="Path to Forge executable",
    )
    anvil_path: str = Field(
        default="anvil",
        description="Path to Anvil executable",
    )

    # ==========================================================================
    # Blockchain Configuration
    # ==========================================================================
    mainnet_rpc_url: str = Field(default="", description="Ethereum mainnet RPC URL")
    sepolia_rpc_url: str = Field(default="", description="Sepolia testnet RPC URL")
    etherscan_api_key: str = Field(default="", description="Etherscan API key")

    # ==========================================================================
    # ChromaDB Configuration
    # ==========================================================================
    chroma_persist_dir: Path = Field(
        default=Path("./data/vector_db"),
        description="ChromaDB persistence directory",
    )
    chroma_collection_name: str = Field(
        default="hack_postmortems",
        description="Collection name for hack post-mortems",
    )

    # ==========================================================================
    # Agent Configuration
    # ==========================================================================
    max_reflection_loops: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum reflection iterations for error correction",
    )
    exploit_timeout_seconds: int = Field(
        default=120,
        ge=10,
        le=600,
        description="Timeout for exploit test execution",
    )
    max_hypotheses_per_run: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum hypotheses to generate per audit",
    )

    # ==========================================================================
    # Sandbox Configuration
    # ==========================================================================
    anvil_port: int = Field(
        default=8545,
        ge=1024,
        le=65535,
        description="Anvil local node port",
    )
    anvil_block_time: int = Field(
        default=1,
        ge=0,
        le=60,
        description="Anvil block time in seconds (0 for auto-mining)",
    )

    # ==========================================================================
    # Logging Configuration
    # ==========================================================================
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Application log level",
    )

    # ==========================================================================
    # Path Configuration
    # ==========================================================================
    project_root: Path = Field(
        default_factory=lambda: Path(__file__).parent.parent.parent.parent.parent,
        description="Project root directory",
    )
    contracts_dir: Path = Field(
        default=Path("contracts"),
        description="Contracts directory relative to project root",
    )
    output_dir: Path = Field(
        default=Path("output"),
        description="Output directory for reports",
    )

    @field_validator("chroma_persist_dir", "project_root", "contracts_dir", "output_dir")
    @classmethod
    def resolve_path(cls, v: Path) -> Path:
        """Resolve paths to absolute paths."""
        if not v.is_absolute():
            return Path.cwd() / v
        return v

    def get_primary_provider(self) -> ModelProvider:
        """Determine the primary model provider from model name."""
        if "gpt" in self.primary_model.lower() or "o1" in self.primary_model.lower():
            return ModelProvider.OPENAI
        elif "claude" in self.primary_model.lower():
            return ModelProvider.ANTHROPIC
        return ModelProvider.OPENAI

    def validate_api_keys(self) -> None:
        """Validate that required API keys are present."""
        provider = self.get_primary_provider()
        if provider == ModelProvider.OPENAI and not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenAI models")
        if provider == ModelProvider.ANTHROPIC and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for Anthropic models")

    def get_contracts_path(self) -> Path:
        """Get absolute path to contracts directory."""
        return self.project_root / self.contracts_dir

    def get_test_path(self) -> Path:
        """Get absolute path to test directory."""
        return self.get_contracts_path() / "test"

    def get_output_path(self) -> Path:
        """Get absolute path to output directory."""
        path = self.project_root / self.output_dir
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Returns:
        Singleton Settings instance loaded from environment.
    """
    return Settings()
