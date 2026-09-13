import json
from contextlib import contextmanager
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class Repository:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feedback (
                    recommendation_id TEXT PRIMARY KEY REFERENCES recommendations(id),
                    decision TEXT NOT NULL, analyst TEXT NOT NULL, reason TEXT NOT NULL,
                    created_at TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, result):
        with self.connect() as db:
            db.execute('INSERT INTO recommendations VALUES (?, ?)', (result['id'], json.dumps(result)))

    def recent(self):
        with self.connect() as db:
            rows = db.execute('''SELECT r.payload, f.decision AS feedback_decision
                FROM recommendations r LEFT JOIN feedback f ON r.id=f.recommendation_id
                ORDER BY r.rowid DESC LIMIT 50''').fetchall()
        return [dict(json.loads(row['payload']), feedback_decision=row['feedback_decision']) for row in rows]

    def review(self, recommendation_id, feedback):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM recommendations WHERE id=?', (recommendation_id,)).fetchone()
            if row is None:
                raise KeyError(recommendation_id)
            if json.loads(row['payload'])['decision'] != 'RECOMMEND':
                raise ValueError('Only rule recommendations can be accepted or rejected')
            # One review per recommendation prevents repeated clicks inflating acceptance.
            db.execute('INSERT INTO feedback VALUES (?, ?, ?, ?, ?)', (
                recommendation_id, feedback.decision, feedback.analyst, feedback.reason,
                datetime.now(timezone.utc).isoformat()))

    def metrics(self):
        with self.connect() as db:
            rows = db.execute('''SELECT r.payload, f.decision AS feedback_decision
                FROM recommendations r LEFT JOIN feedback f ON r.id=f.recommendation_id''').fetchall()
        result = {}
        for mode in ('baseline', 'rag'):
            subset = [r for r in rows if json.loads(r['payload'])['mode'] == mode
                      and json.loads(r['payload'])['decision'] == 'RECOMMEND']
            reviewed = [r for r in subset if r['feedback_decision'] is not None]
            accepted = sum(r['feedback_decision'] == 'accepted' for r in reviewed)
            result[mode] = {'recommendations': len(subset), 'reviewed': len(reviewed),
                            'accepted': accepted,
                            'acceptance_rate': accepted / len(reviewed) if reviewed else None}
        return result
