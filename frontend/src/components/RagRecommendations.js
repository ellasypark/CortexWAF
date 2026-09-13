import React, { useEffect, useState } from 'react';
import axios from 'axios';
import './RagRecommendations.css';

const initialEvent = {
  application: 'my-app', version: 'current', endpoint: '/search',
  method: 'GET', attack_type: 'SQLI'
};

export default function RagRecommendations() {
  const [event, setEvent] = useState(initialEvent);
  const [items, setItems] = useState([]);
  const [status, setStatus] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [analyst, setAnalyst] = useState('');
  const [reasons, setReasons] = useState({});

  async function refresh() {
    const [s, r, m] = await Promise.all([
      axios.get('/api/rag/status'), axios.get('/api/rag/recommendations'), axios.get('/api/rag/metrics')
    ]);
    setStatus(s.data); setItems(r.data.recommendations); setMetrics(m.data);
  }
  useEffect(() => { refresh().catch(() => setError('Unable to load recommendations. Check the API connection.')); }, []);

  async function generate(e) {
    e.preventDefault(); setError(''); setBusy(true);
    try {
      await axios.post('/api/rag/recommendations', event);
      await refresh();
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to generate a recommendation.');
    } finally { setBusy(false); }
  }
  async function review(id, decision) {
    setError(''); setBusy(true);
    try {
      await axios.post(`/api/rag/recommendations/${id}/feedback`, { decision, analyst, reason: reasons[id] || '' });
      await refresh();
    } catch (err) { setError(err.response?.data?.error || 'Unable to save review.'); }
    finally { setBusy(false); }
  }

  return <section className="rag-panel" aria-labelledby="rag-title">
    <h2 id="rag-title">Evidence-backed rule recommendations</h2>
    <p>Review suggested rule families and their sources. Accepting saves your review; it does not change AWS WAF.</p>
    {status && (!status.enabled || !status.indexed) && <p className="rag-notice">Setup needed: configure Bedrock, build the knowledge index, and enable RAG. See docs/RAG.md.</p>}
    <form onSubmit={generate}>
      <label htmlFor="rag-event">Application</label>
      <input id="rag-event" value={event.application} onChange={e => setEvent({ ...event, application: e.target.value })} required maxLength={100} />
      <label htmlFor="rag-endpoint">Endpoint path (omit personal data and query parameters)</label>
      <input id="rag-endpoint" value={event.endpoint} onChange={e => setEvent({ ...event, endpoint: e.target.value })} required maxLength={300} />
      <div className="rag-fields">
        <label>Application version<input value={event.version} onChange={e => setEvent({ ...event, version: e.target.value })} required maxLength={100} /></label>
        <label>Method<select value={event.method} onChange={e => setEvent({ ...event, method: e.target.value })}>{['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map(m => <option key={m}>{m}</option>)}</select></label>
        <label>Detection type<select value={event.attack_type} onChange={e => setEvent({ ...event, attack_type: e.target.value })}>{['SQLI', 'XSS', 'RATE_LIMIT', 'IP_REPUTATION', 'UNKNOWN'].map(t => <option key={t}>{t}</option>)}</select></label>
        <label>Observed requests (optional)<input type="number" min="0" value={event.request_count ?? ''} onChange={e => setEvent({ ...event, request_count: e.target.value === '' ? null : Number(e.target.value) })} /></label>
        <label>Observation window in seconds (optional)<input type="number" min="1" value={event.time_window_seconds ?? ''} onChange={e => setEvent({ ...event, time_window_seconds: e.target.value === '' ? null : Number(e.target.value) })} /></label>
      </div>
      <button disabled={busy || !status?.enabled || !status?.indexed} type="submit">{busy ? 'Working…' : 'Recommend a rule'}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    <label htmlFor="rag-analyst">Reviewer name</label>
    <input id="rag-analyst" value={analyst} maxLength={100} onChange={e => setAnalyst(e.target.value)} placeholder="Your name" />
    {metrics && <div className="rag-metrics">{['baseline', 'rag'].map(mode => <span key={mode}>
      {mode === 'rag' ? 'RAG' : 'No-retrieval baseline'} acceptance: {metrics[mode].acceptance_rate === null ? 'Not measured' : `${(metrics[mode].acceptance_rate * 100).toFixed(1)}%`}
      {' '}({metrics[mode].accepted}/{metrics[mode].reviewed} reviewed)
    </span>)}</div>}
    {!items.length && <p>No recommendations yet. Submit an event summary to begin.</p>}
    {items.map(item => <article className="rag-card" key={item.id}>
      <h3>{item.rule_type === 'NONE' ? item.decision.replaceAll('_', ' ') : `${item.rule_type} · Count-mode candidate`}</h3>
      <small>{item.event.application} · {item.event.endpoint} · {item.mode} · {new Date(item.created_at).toLocaleString()}</small>
      <p>{item.rationale}</p>
      {!!item.missing_context.length && <p>Context needed: {item.missing_context.join('; ')}</p>}
      <details><summary>Retrieved evidence ({item.evidence.length})</summary>
        {item.evidence.map(source => <div className="rag-source" key={source.chunk_id}>
          <a href={source.source} target="_blank" rel="noreferrer">{source.title}</a>
          {item.citation_ids.includes(source.chunk_id) && <strong> · Cited</strong>}
          <p>{source.text}</p>
        </div>)}
      </details>
      {item.feedback_decision ? <p>Review saved: {item.feedback_decision}</p> : item.decision === 'RECOMMEND' && <div className="rag-review">
        <label htmlFor={`reason-${item.id}`}>Review reason</label>
        <input id={`reason-${item.id}`} value={reasons[item.id] || ''} maxLength={1000} onChange={e => setReasons({ ...reasons, [item.id]: e.target.value })} />
        <button disabled={busy || !analyst.trim() || !reasons[item.id]?.trim()} onClick={() => review(item.id, 'accepted')}>Accept for testing</button>
        <button disabled={busy || !analyst.trim() || !reasons[item.id]?.trim()} onClick={() => review(item.id, 'rejected')}>Reject</button>
      </div>}
    </article>)}
  </section>;
}
