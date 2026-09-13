import os
import sqlite3
from threading import Lock
from flask import Blueprint, jsonify, request, current_app
from pydantic import ValidationError
from .models import Event, Feedback
from .storage import Repository


def create_blueprint(pipeline_factory=None, repository=None):
    api = Blueprint('rag', __name__, url_prefix='/api/rag')
    pipeline = None
    lock = Lock()

    def repo():
        return repository or Repository(os.getenv('RAG_DB_PATH', 'data/rag/reviews.sqlite3'))

    def enabled():
        return pipeline_factory is not None or os.getenv('RAG_ENABLED', '').lower() == 'true'

    @api.before_request
    def validate_size():
        if request.content_length and request.content_length > 16384:
            return jsonify(error='Request exceeds 16 KB'), 413

    @api.get('/status')
    def status():
        return jsonify(enabled=enabled(), indexed=os.path.isfile(os.getenv('RAG_INDEX_PATH', 'data/rag/index.json')))

    @api.get('/recommendations')
    def recent():
        return jsonify(recommendations=repo().recent())

    @api.get('/metrics')
    def metrics():
        return jsonify(repo().metrics())

    @api.post('/recommendations')
    def recommend():
        nonlocal pipeline
        if not enabled():
            return jsonify(error='Set RAG_ENABLED=true after configuring Bedrock and building the index'), 503
        try:
            event = Event.model_validate(request.get_json())
        except ValidationError:
            return jsonify(error='Invalid event summary; check the documented fields and use an endpoint without a query string'), 400
        try:
            with lock:
                if pipeline is None:
                    if pipeline_factory:
                        pipeline = pipeline_factory()
                    else:
                        from .pipeline import Pipeline
                        pipeline = Pipeline.configured()
                result = pipeline.recommend(event)
            repo().save(result)
            return jsonify(result), 201
        except Exception:
            current_app.logger.exception('RAG recommendation failed')
            return jsonify(error='Recommendation unavailable. Check index, model access, and server configuration.'), 503

    @api.post('/recommendations/<recommendation_id>/feedback')
    def review(recommendation_id):
        try:
            feedback = Feedback.model_validate(request.get_json())
            repo().review(recommendation_id, feedback)
            return jsonify(saved=True), 201
        except ValidationError:
            return jsonify(error='Provide decision, analyst, and reason'), 400
        except KeyError:
            return jsonify(error='Recommendation not found'), 404
        except sqlite3.IntegrityError:
            return jsonify(error='This recommendation has already been reviewed'), 409
        except ValueError as error:
            return jsonify(error=str(error)), 400

    return api
