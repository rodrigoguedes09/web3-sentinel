"""
Intelligent Query Cache

Caches blockchain queries and LLM results to improve performance
and reduce costs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CacheEntry(BaseModel):
    """Cache entry with metadata."""

    key: str = Field(..., description="Cache key")
    value: Any = Field(..., description="Cached value")
    created_at: float = Field(..., description="Creation timestamp")
    ttl_seconds: int = Field(..., description="Time to live")
    hit_count: int = Field(default=0, description="Number of cache hits")
    size_bytes: int = Field(..., description="Entry size in bytes")


class QueryCache:
    """
    Intelligent cache for blockchain queries and LLM results.
    
    Features:
    - TTL-based expiration
    - Size-based eviction (LRU)
    - Query deduplication
    - Statistics tracking
    """

    def __init__(
        self,
        cache_dir: Path | str = "./data/cache",
        ttl_seconds: int = 3600,
        max_size_mb: int = 100,
    ):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory for cache storage
            ttl_seconds: Default TTL for entries
            max_size_mb: Maximum cache size in MB
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.ttl_seconds = ttl_seconds
        self.max_size_bytes = max_size_mb * 1024 * 1024

        # In-memory index
        self.index: dict[str, CacheEntry] = {}
        self._load_index()

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_saved_time": 0.0,
        }

    def _load_index(self) -> None:
        """Load cache index from disk."""
        index_file = self.cache_dir / "index.json"
        if index_file.exists():
            try:
                with open(index_file, "r") as f:
                    data = json.load(f)
                    for key, entry_data in data.items():
                        self.index[key] = CacheEntry(**entry_data)
                logger.info(f"Loaded {len(self.index)} cache entries")
            except Exception as e:
                logger.warning(f"Failed to load cache index: {e}")

    def _save_index(self) -> None:
        """Save cache index to disk."""
        index_file = self.cache_dir / "index.json"
        try:
            data = {key: entry.model_dump() for key, entry in self.index.items()}
            with open(index_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache index: {e}")

    def _generate_key(self, query_type: str, **params: Any) -> str:
        """
        Generate cache key from query parameters.
        
        Args:
            query_type: Type of query (e.g., 'rpc_balance', 'llm_response')
            **params: Query parameters
            
        Returns:
            Cache key hash
        """
        # Sort params for consistent hashing
        sorted_params = json.dumps(params, sort_keys=True)
        content = f"{query_type}:{sorted_params}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, query_type: str, **params: Any) -> Any | None:
        """
        Get cached value.
        
        Args:
            query_type: Type of query
            **params: Query parameters
            
        Returns:
            Cached value or None if not found/expired
        """
        key = self._generate_key(query_type, **params)

        if key not in self.index:
            self.stats["misses"] += 1
            return None

        entry = self.index[key]

        # Check expiration
        age = time.time() - entry.created_at
        if age > entry.ttl_seconds:
            self._evict(key)
            self.stats["misses"] += 1
            return None

        # Update hit count
        entry.hit_count += 1
        self.stats["hits"] += 1
        
        # Estimate saved time (assuming 200ms for RPC, 2s for LLM)
        saved_time = 2.0 if "llm" in query_type else 0.2
        self.stats["total_saved_time"] += saved_time

        logger.debug(f"Cache hit: {query_type} (age: {age:.1f}s)")
        return entry.value

    def set(
        self,
        value: Any,
        query_type: str,
        ttl_seconds: int | None = None,
        **params: Any,
    ) -> None:
        """
        Set cache value.
        
        Args:
            value: Value to cache
            query_type: Type of query
            ttl_seconds: Custom TTL (overrides default)
            **params: Query parameters
        """
        key = self._generate_key(query_type, **params)
        ttl = ttl_seconds or self.ttl_seconds

        # Estimate size
        size_bytes = len(json.dumps(value).encode())

        # Check if we need to evict
        self._ensure_space(size_bytes)

        # Create entry
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            ttl_seconds=ttl,
            size_bytes=size_bytes,
        )

        self.index[key] = entry
        self._save_index()

        logger.debug(f"Cached: {query_type} ({size_bytes} bytes, TTL: {ttl}s)")

    def _ensure_space(self, needed_bytes: int) -> None:
        """Evict entries if needed to make space."""
        current_size = sum(e.size_bytes for e in self.index.values())

        if current_size + needed_bytes <= self.max_size_bytes:
            return

        # Sort by hit count (LRU-like)
        sorted_entries = sorted(
            self.index.items(),
            key=lambda x: (x[1].hit_count, x[1].created_at),
        )

        # Evict until we have space
        for key, entry in sorted_entries:
            if current_size + needed_bytes <= self.max_size_bytes:
                break

            self._evict(key)
            current_size -= entry.size_bytes

    def _evict(self, key: str) -> None:
        """Evict cache entry."""
        if key in self.index:
            del self.index[key]
            self.stats["evictions"] += 1
            self._save_index()

    def invalidate(self, query_type: str, **params: Any) -> None:
        """Invalidate specific cache entry."""
        key = self._generate_key(query_type, **params)
        self._evict(key)

    def clear(self) -> None:
        """Clear entire cache."""
        self.index.clear()
        self._save_index()
        logger.info("Cache cleared")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (
            self.stats["hits"] / total_requests if total_requests > 0 else 0.0
        )

        total_size = sum(e.size_bytes for e in self.index.values())
        size_mb = total_size / (1024 * 1024)

        return {
            "entries": len(self.index),
            "size_mb": round(size_mb, 2),
            "max_size_mb": self.max_size_bytes / (1024 * 1024),
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": round(hit_rate * 100, 1),
            "evictions": self.stats["evictions"],
            "saved_time_seconds": round(self.stats["total_saved_time"], 1),
        }


class BlockchainQueryCache:
    """
    Specialized cache for blockchain queries with smart invalidation.
    
    Automatically invalidates cache when new blocks are detected.
    """

    def __init__(self, base_cache: QueryCache):
        """Initialize with base cache."""
        self.cache = base_cache
        self.last_block: dict[str, int] = {}  # network -> block number

    async def get_balance(
        self,
        address: str,
        network: str,
        current_block: int,
    ) -> int | None:
        """Get cached balance or None."""
        # Invalidate if block changed
        if self.last_block.get(network, 0) < current_block:
            self.cache.invalidate(
                "rpc_balance",
                address=address,
                network=network,
            )
            self.last_block[network] = current_block

        return self.cache.get(
            "rpc_balance",
            address=address,
            network=network,
            block=current_block,
        )

    async def set_balance(
        self,
        address: str,
        network: str,
        current_block: int,
        balance: int,
    ) -> None:
        """Cache balance."""
        self.cache.set(
            balance,
            "rpc_balance",
            address=address,
            network=network,
            block=current_block,
            ttl_seconds=60,  # Short TTL for balances
        )

    async def get_contract_code(
        self,
        address: str,
        network: str,
    ) -> str | None:
        """Get cached contract code (immutable, long TTL)."""
        return self.cache.get(
            "rpc_code",
            address=address,
            network=network,
        )

    async def set_contract_code(
        self,
        address: str,
        network: str,
        code: str,
    ) -> None:
        """Cache contract code."""
        self.cache.set(
            code,
            "rpc_code",
            address=address,
            network=network,
            ttl_seconds=86400,  # Long TTL - code is immutable
        )

    async def get_bytecode(
        self,
        address: str,
        network: str,
    ) -> bytes | None:
        """Get cached bytecode (immutable, long TTL)."""
        return self.cache.get(
            "rpc_bytecode",
            address=address,
            network=network,
        )

    async def set_bytecode(
        self,
        address: str,
        network: str,
        bytecode: bytes,
    ) -> None:
        """Cache bytecode."""
        # Convert HexBytes to hex string for JSON serialization
        if hasattr(bytecode, 'hex'):
            bytecode_str = bytecode.hex()
        else:
            bytecode_str = bytecode.hex() if isinstance(bytecode, bytes) else bytecode
            
        self.cache.set(
            bytecode_str,
            "rpc_bytecode",
            address=address,
            network=network,
            ttl_seconds=86400,  # Long TTL - bytecode is immutable
        )


class LLMResponseCache:
    """Cache for LLM responses to reduce API costs."""

    def __init__(self, base_cache: QueryCache):
        """Initialize with base cache."""
        self.cache = base_cache

    def get_response(
        self,
        prompt: str,
        model: str,
        temperature: float,
    ) -> str | None:
        """Get cached LLM response."""
        return self.cache.get(
            "llm_response",
            prompt=prompt,
            model=model,
            temperature=temperature,
        )

    def set_response(
        self,
        prompt: str,
        model: str,
        temperature: float,
        response: str,
    ) -> None:
        """Cache LLM response."""
        # Only cache deterministic responses
        if temperature < 0.3:
            self.cache.set(
                response,
                "llm_response",
                prompt=prompt,
                model=model,
                temperature=temperature,
                ttl_seconds=3600,
            )
