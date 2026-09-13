import json
import pytest
from flask import Flask
from pydantic import ValidationError
from langchain_core.embeddings import Embeddings
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_core.runnables import RunnableLambda
from rag.models import Event, Feedback
from rag.pipeline import Pipeline, build_index, providers
from rag.storage import Repository
from rag.api import create_blueprint
from rag.evaluation import traffic_metrics, candidate_metrics


class KeywordEmbeddings(Embeddings):
    """Deterministic vectors for plumbing tests, not quality benchmarks."""
    def embed_documents(self, texts):
        return [self.embed_query(text) for text in texts]
    def embed_query(self, text):
        return [1.0, float('SQLI' in text), float('XSS' in text)]


def event(**changes):
    return Event(application='shop', endpoint='/search', attack_type='SQLI', **changes)


def pipeline(output=None, docs=None):
    store = InMemoryVectorStore(KeywordEmbeddings())
    if docs is None:
        docs = [Document(page_content='SQLI rule reference', metadata={
            'chunk_id': 'known', 'application': 'shop', 'version': 'current',
            'source': 'https://example.com/rules', 'title': 'SQLI'})]
    if docs:
        store.add_documents(docs)
    answer = output or {'decision': 'RECOMMEND', 'rule_type': 'SQLI',
                        'rationale': 'Test SQLI in Count mode.', 'citation_ids': ['known']}
    return Pipeline(store, RunnableLambda(lambda _: json.dumps(answer)))


def test_real_langchain_chain_and_vector_retrieval():
    result = pipeline().recommend(event())
    assert result['decision'] == 'RECOMMEND'
    assert result['citation_ids'] == ['known']
    assert result['evidence'][0]['score'] > .99
    assert result['deployment_mode'] == 'COUNT_CANDIDATE_ONLY'


@pytest.mark.parametrize('application,version', [('other', 'current'), ('shop', 'old')])
def test_scope_excludes_other_apps_and_versions(application, version):
    result = pipeline().recommend(Event(application=application, version=version, endpoint='/search'))
    assert result['decision'] == 'NEEDS_REVIEW'
    assert not result['evidence']


def test_missing_evidence_never_calls_model():
    p = pipeline(docs=[])
    p.chain = RunnableLambda(lambda _: pytest.fail('Model must not be called'))
    assert p.recommend(event())['decision'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('citations', [[], ['invented']])
def test_invalid_citations_fail_closed(citations):
    p = pipeline({'decision': 'RECOMMEND', 'rule_type': 'SQLI', 'rationale': 'Test', 'citation_ids': citations})
    assert p.recommend(event())['decision'] == 'NEEDS_REVIEW'


def test_rate_requires_measured_window():
    p = pipeline({'decision': 'RECOMMEND', 'rule_type': 'RATE_LIMIT', 'rationale': 'Test', 'citation_ids': ['known']})
    assert p.recommend(event())['decision'] == 'NEEDS_REVIEW'


def test_baseline_does_not_retrieve():
    p = pipeline({'decision': 'RECOMMEND', 'rule_type': 'SQLI', 'rationale': 'Test'})
    p.store.similarity_search_with_score = lambda *a, **k: pytest.fail('Baseline retrieved evidence')
    assert not p.recommend(event(), mode='baseline')['evidence']


def test_ingestion_persistence_and_embedding_identity(tmp_path, monkeypatch):
    corpus = tmp_path/'knowledge'
    corpus.mkdir()
    (corpus/'rules.json').write_text(json.dumps([{'text': 'SQLI evidence', 'title': 'Rule',
        'source': 'https://example.com', 'application': '*', 'version': '*'}]))
    target = tmp_path/'index.json'
    assert build_index(corpus, target, KeywordEmbeddings(), 'test-model') == 1
    monkeypatch.setenv('RAG_INDEX_PATH', str(target))
    monkeypatch.setenv('RAG_EMBEDDING_MODEL', 'test-model')
    monkeypatch.setenv('RAG_MODEL_ID', 'test-chat')
    monkeypatch.setattr('rag.pipeline.providers', lambda: (KeywordEmbeddings(), RunnableLambda(lambda _: '{}')))
    restored = Pipeline.configured()
    assert len(restored.store.store) == 1
    assert restored.store.similarity_search('SQLI')[0].page_content == 'SQLI evidence'
    monkeypatch.setenv('RAG_EMBEDDING_MODEL', 'changed')
    with pytest.raises(RuntimeError, match='rebuild'):
        Pipeline.configured()


def test_reviews_survive_restart_and_do_not_double_count(tmp_path):
    path = tmp_path/'reviews.sqlite3'
    repo = Repository(path)
    result = pipeline().recommend(event())
    repo.save(result)
    app = Flask(__name__)
    app.register_blueprint(create_blueprint(lambda: pipeline(), Repository(path)))
    client = app.test_client()
    url = '/api/rag/recommendations/'+result['id']+'/feedback'
    review = dict(decision='accepted', analyst='Tester', reason='Appropriate for testing')
    assert client.post(url, json=review).status_code == 201
    assert client.post(url, json=review).status_code == 409
    metrics = client.get('/api/rag/metrics').json
    assert metrics['rag']['reviewed'] == 1
    assert metrics['rag']['acceptance_rate'] == 1
    assert metrics['baseline']['acceptance_rate'] is None
    assert client.get('/api/rag/recommendations').json['recommendations'][0]['feedback_decision'] == 'accepted'


def test_api_input_validation_and_provider_failure(tmp_path):
    app = Flask(__name__)
    p = pipeline()
    app.register_blueprint(create_blueprint(lambda: p, Repository(tmp_path/'db')))
    client = app.test_client()
    assert client.post('/api/rag/recommendations', json=event().model_dump()).status_code == 201
    bad = event().model_dump() | {'headers': {'Authorization': 'secret'}}
    assert client.post('/api/rag/recommendations', json=bad).status_code == 400
    assert client.post('/api/rag/recommendations', json={'x': 'a'*17000}).status_code == 413
    p.chain = RunnableLambda(lambda _: 'not valid JSON')
    response = client.post('/api/rag/recommendations', json=event().model_dump())
    assert response.status_code == 503
    assert 'Traceback' not in response.json['error']


def test_endpoint_rejects_query_secrets():
    with pytest.raises(ValidationError):
        Event(application='shop', endpoint='/search?token=secret')


def test_metrics_keep_denominators_and_uncertainty():
    rows = [{'id': str(i), 'label': 'benign', 'would_block': False} for i in range(500)]
    rows += [{'id': 'attack', 'label': 'malicious', 'would_block': True}]
    metrics = traffic_metrics(rows)
    assert metrics['benign_requests'] == 500
    assert metrics['false_positive_rate'] == 0
    assert metrics['attack_recall'] == 1
    assert metrics['supports_below_one_percent_at_95pct']
    assert not traffic_metrics(rows[:10])['supports_below_one_percent_at_95pct']
    assert traffic_metrics([])['false_positive_rate'] is None
    with pytest.raises(ValueError):
        traffic_metrics(rows + rows)
    with pytest.raises(ValueError):
        traffic_metrics([{'id': 'a', 'label': 'benign', 'would_block': 'false'}])
    assert 'false_positive_rate' not in candidate_metrics([])


def test_bedrock_providers_construct_without_network(monkeypatch):
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'test')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'test')
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('RAG_MODEL_ID', 'anthropic.claude-sonnet-4-20250514-v1:0')
    embeddings, llm = providers()
    assert embeddings.model_id == 'amazon.titan-embed-text-v2:0'
    assert llm.model_id == 'anthropic.claude-sonnet-4-20250514-v1:0'


def test_existing_dashboard_registers_rag_without_waf_writes(monkeypatch, tmp_path):
    import importlib
    import sys
    from unittest.mock import MagicMock
    monkeypatch.setenv('USE_S3_LOGS', 'false')
    monkeypatch.setenv('RAG_DB_PATH', str(tmp_path/'dashboard.sqlite3'))
    client = MagicMock()
    monkeypatch.setattr('boto3.client', lambda *a, **kw: client)
    sys.modules.pop('api_server', None)
    server = importlib.import_module('api_server')
    response = server.app.test_client().get('/api/rag/recommendations')
    assert response.status_code == 200
    assert response.json == {'recommendations': []}
    client.update_web_acl.assert_not_called()
