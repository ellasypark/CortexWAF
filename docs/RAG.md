# LangChain RAG recommendations

The optional RAG feature retrieves curated WAF guidance with LangChain cosine vector search, generates a structured Bedrock recommendation, validates citation IDs, and records analyst reviews in SQLite. The dashboard has a dedicated recommendations panel. Outputs are rule-family candidates for Count-mode testing, not executable WAF statements. Neither generation nor acceptance calls AWS WAF or sends notifications.

## Run

Requires Python 3.10+ and AWS credentials configured through your usual AWS profile or workload role. Do not put credentials in the repository. The existing dashboard API still requires its original AWS configuration.

From the repository root:

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export AWS_REGION=ap-northeast-2
export RAG_MODEL_ID='YOUR_ENABLED_BEDROCK_MODEL_OR_INFERENCE_PROFILE_ID'
export RAG_EMBEDDING_MODEL='amazon.titan-embed-text-v2:0'
python -m rag.cli ingest
export RAG_ENABLED=true
python api_server.py
```

In another terminal, run `npm install` and `npm start` from `frontend/`. The new panel lets you enter an application, route, detection type, and optional measured request count/window. Use route templates, not user identifiers. Raw headers, request bodies, and query strings are not accepted. Other text fields must also be free of secrets.

For a standalone RAG API without initializing the legacy S3/WAF clients, use `python -m rag.cli serve`. This binds to localhost on port 5000. It supports only `/api/rag` routes. The dashboard's other routes need the full API.

Provider calls incur your normal Bedrock charges. The account needs access to both the embedding model and chosen chat model in the configured region. No model is silently selected. A missing index, disabled service, malformed model output, or provider error is shown as unavailable rather than a fabricated recommendation.

Optional paths: `RAG_INDEX_PATH` (default `data/rag/index.json`) and `RAG_DB_PATH` (default `data/rag/reviews.sqlite3`). Both resolve relative to the process working directory; run from the repository root. Restart the API after rebuilding the index. Keep these files outside version control.

## Knowledge

`knowledge/waf_rules.json` contains four short, manually curated notes with AWS source links, not a comprehensive copy of AWS documentation. Add application-specific records to JSON lists in that directory:

```json
[
  {
    "title": "Search endpoint contract",
    "source": "https://your-internal-docs.example/search",
    "application": "my-app",
    "version": "current",
    "text": "Curated, accurate details about the endpoint and expected legitimate input."
  }
]
```

Replace the example with a real source and actual application behavior. Ingestion splits text into overlapping chunks, computes Bedrock embeddings, and saves vectors with their embedding-model identity in one atomically replaced JSON index. Application and version filters run before selecting the top four chunks. `*` means globally applicable guidance. A cosine threshold of 0.25 is an initial engineering setting, not a calibrated quality guarantee. Tune it on development cases, then freeze it for held-out evaluation.

The current implementation uses LangChain's in-memory vector store with persisted JSON for small corpora. It performs exact cosine search, not approximate nearest-neighbor search. Large corpora will need a dedicated vector database. The index is operator-controlled and contains document text; protect it accordingly.

Missing relevant evidence causes abstention. Unknown citation IDs or uncited RAG recommendations are rejected. Citation validation verifies membership in the retrieved context; it does not prove that the cited passage logically supports every claim. Reviewers still need to evaluate relevance and correctness. The prompt treats retrieved content as untrusted data. Only operator-curated documents enter the index; accepting a recommendation does not automatically add it to the corpus.

## Review and API

- `GET /api/rag/status`: enabled/indexed status (not a live Bedrock health check).
- `POST /api/rag/recommendations`: event summary; returns a persisted result.
- `GET /api/rag/recommendations`: latest 50 results and their review status.
- `POST /api/rag/recommendations/<id>/feedback`: `decision` (`accepted` or `rejected`), `analyst`, and `reason`. One review per recommendation; duplicates return 409.
- `GET /api/rag/metrics`: descriptive acceptance counts for RAG and baseline; unmeasured rates are null.

Only `RECOMMEND` results can receive acceptance feedback. `NEEDS_REVIEW` is an abstention and is not counted as an accepted rule. Reviewer names are self-reported: this inherits the prototype's lack of user authentication. Run locally or behind your authenticated internal gateway. It is not a multi-tenant review service.

## Measure improvements honestly

Create a held-out JSON list of cases containing `id`, an independently assigned `label` (`benign` or `malicious`), and an `event` matching the API schema. Do not index evaluation cases, their labels, or answers. Use both attack and legitimate-traffic cases representative of your application.

```json
[
  {
    "id": "replace-with-real-case-id",
    "label": "benign",
    "event": {
      "application": "my-app",
      "version": "current",
      "endpoint": "/forum/post",
      "method": "POST",
      "attack_type": "XSS"
    }
  }
]
```

This example demonstrates the format, not evaluation evidence.

```sh
python -m rag.cli evaluate held-out-cases.json --output comparison.json
```

This invokes the same model with and without retrieval, alternates execution order, and saves both outputs for review. It is a no-retrieval ablation, not a comparison to the legacy event classifier. Each output records model ID, index hash, retrieval threshold, mode, and case ID. The report measures benign-case recommendation rate, malicious-case recommendation rate, and abstention. These are **not** traffic false-positive rates. A model that abstains everywhere should not be described as an improvement simply because it makes no false recommendations.

Have analysts review both cohorts with a consistent rubric; use blinded review outside the current panel if you need an unbiased comparison, since the panel identifies the mode. Acceptance is accepted / reviewed recommendations. The metrics endpoint aggregates saved cohorts; for a controlled study use a separate `RAG_DB_PATH` per run. Account for different recommendation/abstention counts. No existing 60% baseline or 85% result is assumed.

Traffic false-positive rate requires actual candidate outcomes from replay or Count-mode observation, independently labeled as benign or malicious:

```json
[
  {"id": "request-1", "label": "benign", "would_block": false},
  {"id": "request-2", "label": "malicious", "would_block": true}
]
```

```sh
python -m rag.cli traffic-metrics labeled-traffic.json
```

The tool reports false positives / all benign requests, attack recall, sample sizes, and the upper endpoint of a 95% Wilson interval. Missing denominators return null. The tool does not replay traffic or generate labels itself. Small or unrepresentative samples do not establish production performance; correlated requests can also invalidate simple binomial uncertainty assumptions. Keep raw evidence and the evaluated candidate configuration alongside results.

## Validation and current limits

```sh
pip install pytest
python -m pytest tests/test_rag.py -q
cd frontend
CI=true npm test -- --watchAll=false --runInBand RagRecommendations.test.js
npm run build
```

Backend tests execute real LangChain retrieval/chaining with deterministic test embeddings and mocked generation, plus persistence, validation, provider construction, and metrics checks. These are integration correctness tests, not model-quality benchmarks. Existing legacy tests require AWS or local traffic files and are not part of this isolated suite.

Live Bedrock generation, real analyst acceptance, and deployed traffic FPR must be evaluated in your configured AWS environment. No 60%→85% improvement or <1% FPR has been established. Automatic S3-to-RAG ingestion, executable rule generation, authentication, automatic feedback ingestion, and WAF deployment are outside this initial feature.

References: [LangChain Bedrock integration](https://docs.langchain.com/oss/python/integrations/chat/bedrock), [LangChain vector stores](https://docs.langchain.com/oss/python/integrations/vectorstores), [AWS WAF testing guidance](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html).
