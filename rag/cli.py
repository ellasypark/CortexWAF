import argparse
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from .models import Event
from .storage import Repository
from .evaluation import traffic_metrics, candidate_metrics


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description='CortexWAF retrieval and evaluation')
    commands = parser.add_subparsers(dest='command', required=True)
    ingest = commands.add_parser('ingest')
    ingest.add_argument('--corpus', default='knowledge')
    evaluate = commands.add_parser('evaluate')
    evaluate.add_argument('cases', help='JSON list: id, label (benign/malicious), event')
    evaluate.add_argument('--output', required=True)
    traffic = commands.add_parser('traffic-metrics')
    traffic.add_argument('observations', help='JSON list of independently labeled Count-mode or replay outcomes')
    serve = commands.add_parser('serve')
    serve.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    if args.command == 'serve':
        from flask import Flask
        from .api import create_blueprint
        app = Flask(__name__)
        app.register_blueprint(create_blueprint())
        app.run(host='127.0.0.1', port=args.port)
    elif args.command == 'ingest':
        from .pipeline import build_index, providers
        embeddings, _ = providers()
        count = build_index(args.corpus, os.getenv('RAG_INDEX_PATH', 'data/rag/index.json'),
                            embeddings, os.getenv('RAG_EMBEDDING_MODEL', 'amazon.titan-embed-text-v2:0'))
        print(json.dumps({'indexed_chunks': count}))
    elif args.command == 'traffic-metrics':
        print(json.dumps(traffic_metrics(json.loads(Path(args.observations).read_text())), indent=2))
    else:
        from .pipeline import Pipeline
        cases = json.loads(Path(args.cases).read_text())
        if not isinstance(cases, list) or not cases:
            raise ValueError('Evaluation requires a nonempty list of independently labeled cases')
        seen = set()
        # Validate the whole dataset before any model calls.
        for case in cases:
            if not isinstance(case.get('id'), str) or not case['id'] or case['id'] in seen:
                raise ValueError('Case IDs must be unique nonempty strings')
            seen.add(case['id'])
            if case.get('label') not in ('benign', 'malicious'):
                raise ValueError('Labels must be benign or malicious')
            Event.model_validate(case['event'])
        pipeline = Pipeline.configured()
        repository = Repository(os.getenv('RAG_DB_PATH', 'data/rag/reviews.sqlite3'))
        results = {mode: [] for mode in ('baseline', 'rag')}
        for position, case in enumerate(cases):
            # Alternate order to reduce a systematic ordering effect.
            for mode in (('baseline', 'rag') if position % 2 == 0 else ('rag', 'baseline')):
                result = pipeline.recommend(Event.model_validate(case['event']), mode=mode)
                result['evaluation_case_id'] = case['id']
                repository.save(result)
                results[mode].append(dict(result, label=case['label']))
        output = {'comparison': 'Same-model no-retrieval ablation; not the legacy classifier',
                  'metrics': {m: candidate_metrics(r) for m, r in results.items()}, 'results': results}
        Path(args.output).write_text(json.dumps(output, indent=2))
        print(json.dumps(output['metrics'], indent=2))


if __name__ == '__main__':
    main()
