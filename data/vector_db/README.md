# Vector DB Data

This directory stores the ChromaDB persistent data for the RAG system.

**Note:** This directory is auto-generated and should be in `.gitignore`.

## Contents

When initialized, this directory will contain:
- `chroma.sqlite3` - SQLite database for ChromaDB metadata
- `*.bin` - Embedding vectors
- `index/` - Index files

## Regenerating

If you need to regenerate the database:

```bash
# Delete existing data
rm -rf data/vector_db/*

# Reinitialize
sentinela init-rag
```
