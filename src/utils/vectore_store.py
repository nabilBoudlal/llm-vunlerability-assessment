"""
Vector Store Manager — ChromaDB with metadata filtering support.
"""
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

class VectorStoreManager:

    def __init__(self, model_name="nomic-embed-text", db_path="vector_db"):
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.db_path    = db_path
        self.db         = None

    def initialize_db(self, documents: list):
        """Create DB from plain text list (no metadata)."""
        self.db = Chroma.from_texts(
            texts=documents,
            embedding=self.embeddings,
            persist_directory=self.db_path
        )
        print(f"--- Vector DB initialised with {len(documents)} entries ---")

    def initialize_db_with_metadata(self, texts: list, metadatas: list):
        """Create DB from texts + metadata dicts."""
        self.db = Chroma.from_texts(
            texts=texts,
            embedding=self.embeddings,
            metadatas=metadatas,
            persist_directory=self.db_path
        )
        print(f"--- Vector DB initialised with {len(texts)} entries (with metadata) ---")

    def add_texts_with_metadata(self, texts: list, metadatas: list):
        """Add more texts to an existing DB."""
        if self.db is None:
            self.initialize_db_with_metadata(texts, metadatas)
        else:
            self.db.add_texts(texts=texts, metadatas=metadatas)

    def search_context(self, query: str, k: int = 5) -> str:
        """Unfiltered similarity search."""
        if not self.db:
            self.db = Chroma(
                persist_directory=self.db_path,
                embedding_function=self.embeddings
            )
        results = self.db.similarity_search(query, k=k)
        return "\n".join([doc.page_content for doc in results])

    def search_context_filtered(self, query: str, port: str, k: int = 5) -> str:
        """
        Similarity search filtered by port metadata.
        Returns only CVEs indexed for that specific port/service.
        """
        if not self.db:
            return ""
        try:
            results = self.db.similarity_search(
                query,
                k=k,
                filter={"port": port}
            )
            return "\n".join([doc.page_content for doc in results])
        except Exception:
            # ChromaDB may not have any docs for this port
            return ""