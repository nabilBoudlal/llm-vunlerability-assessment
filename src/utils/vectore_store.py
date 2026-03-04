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

    def initialize_db(self, documents, metadatas):
        """Crea il DB associando ogni documento al suo servizio specifico."""
        self.db = Chroma.from_texts(
            texts=documents,
            metadatas=metadatas, # Aggiungiamo i metadati
            embedding=self.embeddings,
            persist_directory=self.db_path
        )

    def search_context(self, query, service_name, k=5):
        """Cerca solo i documenti che appartengono al servizio richiesto."""
        if not self.db:
            self.db = Chroma(persist_directory=self.db_path, embedding_function=self.embeddings)
        
        # Applichiamo un filtro basato sul metadato 'service'
        results = self.db.similarity_search(
            query, 
            k=k, 
            filter={"service": service_name.lower()}
        )
        return "\n".join([doc.page_content for doc in results])