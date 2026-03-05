"""
Vector Store Manager for RAG integration.

Key improvements over previous version:
- initialize_db() now accepts optional metadatas list so each document
  is tagged with its source service (e.g. {"service": "apache", "type": "cve"}).
  This enables filtered retrieval and prevents cross-service CVE leakage.
- search_context() accepts an optional service_name parameter.
  When provided it performs a metadata-filtered similarity search so only
  documents tagged for that service are considered.
  If the filtered search returns fewer than min_results documents it falls
  back to an unfiltered search — this prevents Apache (or any other service)
  from silently returning zero results just because the metadata tag does
  not exactly match the indexed token.
- Both paths log a warning when context is unexpectedly empty, making
  silent retrieval failures visible during evaluation runs.
"""

from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma


class VectorStoreManager:

    def __init__(self, model_name: str = "nomic-embed-text", db_path: str = "vector_db"):
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.db_path    = db_path
        self.db         = None

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize_db(self, documents: list[str], metadatas: list[dict] | None = None):
        """
        Creates (or recreates) the local vector database.

        Parameters
        ----------
        documents : list of str
            Plain-text entries to embed and store (CVE descriptions, policy alerts, …).
        metadatas : list of dict, optional
            One metadata dict per document.  Recommended keys:
              - "service" : base token of the source software (e.g. "apache", "proftpd")
              - "type"    : "cve" | "policy"
            When omitted every document gets an empty metadata dict.
        """
        if metadatas is None:
            metadatas = [{} for _ in documents]

        if len(metadatas) != len(documents):
            raise ValueError(
                f"metadatas length ({len(metadatas)}) must match "
                f"documents length ({len(documents)})."
            )

        self.db = Chroma.from_texts(
            texts=documents,
            embedding=self.embeddings,
            metadatas=metadatas,
            persist_directory=self.db_path
        )
        print(f"--- Vector DB initialised with {len(documents)} entries ---")

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def search_context(
        self,
        query:        str,
        service_name: str | None = None,
        k:            int        = 5,
        min_results:  int        = 2
    ) -> str:
        """
        Retrieves the most relevant context for a given query.

        Strategy
        --------
        1. If *service_name* is provided, attempt a metadata-filtered search
           restricted to documents whose "service" field matches that token.
        2. If the filtered search returns fewer than *min_results* documents
           (e.g. because the metadata token did not match anything indexed),
           fall back to an unfiltered similarity search over the whole DB.
           A warning is printed so silent failures are visible in logs.
        3. If no DB is loaded, attempt to load from disk before searching.

        Parameters
        ----------
        query        : the natural-language search string
        service_name : base token to filter by (e.g. "apache", "proftpd")
        k            : number of documents to retrieve
        min_results  : minimum acceptable filtered results before fallback
        """
        if not self.db:
            self.db = Chroma(
                persist_directory=self.db_path,
                embedding_function=self.embeddings
            )

        results = []

        # --- Attempt 1: metadata-filtered search ---
        if service_name:
            # langchain_chroma uses flat dict syntax: {"key": "value"}
            # NOT the ChromaDB-native {"key": {"$eq": "value"}} form.
            filter_expr = {"service": service_name.lower()}
            try:
                results = self.db.similarity_search(query, k=k, filter=filter_expr)
            except Exception as e:
                print(f"[!] Filtered search failed for service='{service_name}': {e}")
                results = []

            if len(results) < min_results:
                print(
                    f"[!] Filtered search for '{service_name}' returned only "
                    f"{len(results)} result(s) — falling back to unfiltered search."
                )
                results = []  # clear so we fall through to attempt 2

        # --- Attempt 2: unfiltered fallback ---
        if not results:
            try:
                results = self.db.similarity_search(query, k=k)
            except Exception as e:
                print(f"[!] Unfiltered search failed: {e}")
                results = []

        if not results:
            print(f"[!] No context found for query: '{query}'")
            return "No relevant context found in the knowledge base."

        return "\n".join([doc.page_content for doc in results])