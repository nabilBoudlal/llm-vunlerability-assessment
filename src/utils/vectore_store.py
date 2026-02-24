"""
Vector Store Manager for RAG integration.
"""
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

class VectorStoreManager:
    
    def __init__(self, model_name="nomic-embed-text", db_path="vector_db"):
        # Use Ollama for generating embeddings
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.db_path = db_path
        self.db = None

    def initialize_db(self, documents):
        """Creates a local vector database from CVE descriptions."""
        self.db = Chroma.from_texts(
            texts=documents, 
            embedding=self.embeddings, 
            persist_directory=self.db_path
        )
        print(f"--- Vector Database initialized with {len(documents)} entries ---")

    def search_context(self, query, k=3):
        """Retrieves the most relevant security context from the local DB."""
        if not self.db:
            # Load existing database if not already in memory
            self.db = Chroma(persist_directory=self.db_path, embedding_function=self.embeddings)
        
        results = self.db.similarity_search(query, k=k)
        return "\n".join([doc.page_content for doc in results])