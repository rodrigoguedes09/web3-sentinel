# Sentinela Web3 Tests

This directory contains the Python test suite for Sentinela Web3.

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=sentinela --cov-report=html

# Run specific test file
pytest tests/test_core.py

# Run with verbose output
pytest -v

# Run only unit tests (no integration)
pytest -m "not integration"
```

## Test Structure

- `test_core.py` - Tests for core state and type definitions
- `test_integrations.py` - Tests for Slither and Foundry integrations
- `test_agents.py` - Tests for agent implementations (TODO)
- `test_orchestrator.py` - Tests for LangGraph workflow (TODO)
- `test_rag.py` - Tests for RAG retrieval (TODO)

## Markers

- `@pytest.mark.integration` - Tests requiring external tools (Slither, Forge)
- `@pytest.mark.slow` - Long-running tests
- `@pytest.mark.asyncio` - Async tests
