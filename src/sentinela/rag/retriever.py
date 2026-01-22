"""
RAG Retriever for Historical Hack Post-Mortems

Uses ChromaDB for vector storage and semantic search over
documented smart contract exploits and vulnerabilities.
"""

from __future__ import annotations

import logging
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings

from sentinela.core.config import Settings, get_settings


logger = logging.getLogger(__name__)


class HackRetriever:
    """
    Retrieves relevant historical hacks from the vector database.
    
    Features:
    - Semantic search over hack post-mortems
    - Filtering by vulnerability type, date, impact
    - Caching for performance
    - Automatic embedding generation
    """

    def __init__(
        self,
        settings: Settings | None = None,
        collection_name: str | None = None,
    ) -> None:
        """
        Initialize HackRetriever.
        
        Args:
            settings: Application settings
            collection_name: ChromaDB collection name
        """
        self.settings = settings or get_settings()
        self.collection_name = collection_name or self.settings.chroma_collection_name
        self._client: chromadb.Client | None = None
        self._collection: chromadb.Collection | None = None

    @property
    def client(self) -> chromadb.Client:
        """Get or create ChromaDB client."""
        if self._client is None:
            self._client = chromadb.PersistentClient(
                path=str(self.settings.chroma_persist_dir),
                settings=ChromaSettings(anonymized_telemetry=False),
            )
        return self._client

    @property
    def collection(self) -> chromadb.Collection:
        """Get or create the hack post-mortems collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "Smart contract hack post-mortem analysis"},
            )
        return self._collection

    async def retrieve(
        self,
        query: str,
        k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve relevant hacks based on semantic similarity.
        
        Args:
            query: Search query (contract patterns, vulnerability types, etc.)
            k: Number of results to return
            filter_metadata: Optional metadata filters
            
        Returns:
            List of relevant hack documents with metadata
        """
        try:
            # Check if collection has documents
            if self.collection.count() == 0:
                logger.warning("Hack database is empty. Run the loader to populate it.")
                return self._get_default_hacks()

            # Query the collection
            results = self.collection.query(
                query_texts=[query],
                n_results=k,
                where=filter_metadata,
                include=["documents", "metadatas", "distances"],
            )

            # Format results
            documents = []
            if results["documents"] and results["metadatas"]:
                for doc, metadata, distance in zip(
                    results["documents"][0],
                    results["metadatas"][0],
                    results["distances"][0] if results["distances"] else [0] * len(results["documents"][0]),
                ):
                    documents.append({
                        "content": doc,
                        "similarity_score": 1 - distance,  # Convert distance to similarity
                        **metadata,
                    })

            return documents

        except Exception as e:
            logger.error(f"Error retrieving from vector DB: {e}")
            return self._get_default_hacks()

    def _get_default_hacks(self) -> list[dict[str, Any]]:
        """
        Return a set of well-known hacks as fallback.
        
        These are used when the vector database is empty or unavailable.
        """
        return [
            {
                "name": "The DAO Hack",
                "date": "2016-06-17",
                "loss_amount": "$60M",
                "vulnerability_type": "reentrancy",
                "summary": "Classic reentrancy attack exploiting recursive calls before state update.",
                "attack_vector": "1. Call withdraw function 2. Receive callback calls withdraw again 3. Drain funds before balance update",
                "content": "The DAO hack exploited a reentrancy vulnerability where the attacker's fallback function recursively called withdraw before the victim's balance was updated.",
            },
            {
                "name": "Parity Wallet Freeze",
                "date": "2017-11-06",
                "loss_amount": "$150M frozen",
                "vulnerability_type": "access_control",
                "summary": "Unprotected initialization function allowed anyone to become owner and self-destruct.",
                "attack_vector": "1. Call unprotected initWallet 2. Become owner 3. Call kill to destroy library",
                "content": "The Parity multi-sig wallet used a library contract with an unprotected initialization function. An attacker called initWallet to become owner, then destroyed the library, freezing all dependent wallets.",
            },
            {
                "name": "bZx Flash Loan Attack",
                "date": "2020-02-15",
                "loss_amount": "$350K",
                "vulnerability_type": "flash_loan",
                "summary": "Flash loan used to manipulate oracle prices and profit from arbitrage.",
                "attack_vector": "1. Flash loan large amount 2. Manipulate price oracle 3. Execute profitable trade 4. Repay loan",
                "content": "The attacker used a flash loan to manipulate the price oracle used by bZx, then executed trades at the manipulated price before the loan had to be repaid.",
            },
            {
                "name": "Cream Finance Hack",
                "date": "2021-10-27",
                "loss_amount": "$130M",
                "vulnerability_type": "oracle_manipulation",
                "summary": "Price oracle manipulation through flash loans to drain lending pools.",
                "attack_vector": "1. Flash loan collateral tokens 2. Inflate collateral price 3. Borrow against inflated collateral 4. Never repay",
                "content": "Attackers manipulated the price oracles for collateral tokens using flash loans, allowing them to borrow far more than their collateral was actually worth.",
            },
            {
                "name": "Ronin Bridge Hack",
                "date": "2022-03-23",
                "loss_amount": "$620M",
                "vulnerability_type": "access_control",
                "summary": "Compromised validator keys allowed unauthorized bridge withdrawals.",
                "attack_vector": "1. Compromise 5 of 9 validator keys 2. Sign fraudulent withdrawal 3. Extract bridge funds",
                "content": "The Ronin bridge required 5 of 9 validators to sign withdrawals. Attackers compromised enough keys to approve unauthorized transfers, draining the bridge of ETH and USDC.",
            },
        ]

    async def add_document(
        self,
        document: str,
        metadata: dict[str, Any],
        doc_id: str | None = None,
    ) -> str:
        """
        Add a new hack post-mortem to the database.
        
        Args:
            document: The document content
            metadata: Document metadata (name, date, vulnerability_type, etc.)
            doc_id: Optional document ID (auto-generated if not provided)
            
        Returns:
            Document ID
        """
        import uuid

        doc_id = doc_id or str(uuid.uuid4())

        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id],
        )

        logger.info(f"Added document {doc_id} to hack database")
        return doc_id

    async def get_stats(self) -> dict[str, Any]:
        """Get statistics about the hack database."""
        count = self.collection.count()
        return {
            "total_documents": count,
            "collection_name": self.collection_name,
            "persist_directory": str(self.settings.chroma_persist_dir),
        }
