"""DEMO — a RAG ingestion pipeline that poisons its own retrieval index.

Two unsafe patterns AgentFirewall flags: writing untrusted user content into a
shared vector store, and indexing attacker-controllable web pages without review.
"""
from langchain_community.document_loaders import WebBaseLoader
from langchain_community.vectorstores import Chroma

store = Chroma(collection_name="shared_kb")


def index_user_note(request):
    # Untrusted: any user's note goes straight into the shared knowledge base,
    # so it becomes retrieved context for every other user.
    store.add_texts([request.json["note"]])


def crawl_and_index(url):
    # Attacker-controlled page -> indexed without validation (RAG poisoning).
    docs = WebBaseLoader(url).load()
    store.add_documents(docs)
