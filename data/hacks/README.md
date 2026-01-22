# Hack Post-Mortem Data

This directory contains historical hack post-mortem documents for the RAG database.

## Supported Formats

1. **JSON** - Array of hack objects
2. **YAML** - List of hack documents
3. **Markdown** - Single hack with YAML frontmatter

## JSON Format

```json
[
  {
    "name": "Hack Name",
    "date": "2024-01-01",
    "loss_amount": "$1M",
    "vulnerability_type": "reentrancy",
    "summary": "Brief summary of the attack",
    "attack_vector": "Step by step attack description",
    "affected_contracts": ["0x..."],
    "references": ["https://..."]
  }
]
```

## YAML Format

```yaml
- name: Hack Name
  date: 2024-01-01
  loss_amount: $1M
  vulnerability_type: reentrancy
  summary: Brief summary
  attack_vector: |
    1. First step
    2. Second step
```

## Markdown Format

```markdown
---
name: Hack Name
date: 2024-01-01
vulnerability_type: reentrancy
loss_amount: $1M
---

# Detailed Analysis

Full markdown content here...
```

## Loading Data

```bash
# Load default hacks
sentinela init-rag

# Load from this directory
sentinela init-rag --data-dir ./data/hacks
```

## Data Sources

Consider adding post-mortems from:
- [Rekt News](https://rekt.news)
- [DeFi Llama Hacks](https://defillama.com/hacks)
- [SlowMist Hacked](https://hacked.slowmist.io)
- Protocol-specific disclosures
