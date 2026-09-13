import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { Simulate } from 'react-dom/test-utils';
import axios from 'axios';
import RagRecommendations from './RagRecommendations';

jest.mock('axios');
global.IS_REACT_ACT_ENVIRONMENT = true;
let container, root;
const metrics = { baseline: { accepted: 0, reviewed: 0, acceptance_rate: null }, rag: { accepted: 0, reviewed: 0, acceptance_rate: null } };
function responses(enabled = true, items = []) {
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/status') ? { enabled, indexed: enabled } : url.endsWith('/metrics') ? metrics : { recommendations: items } }));
}
beforeEach(() => { jest.clearAllMocks(); container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });

test('setup state disables model requests and does not invent acceptance', async () => {
  responses(false);
  await act(async () => root.render(<RagRecommendations />));
  expect(container.textContent).toContain('Not measured');
  expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(axios.post).not.toHaveBeenCalled();
});

test('submits a summary and shows API failures', async () => {
  responses(); axios.post.mockRejectedValue({ response: { data: { error: 'Model unavailable' } } });
  await act(async () => root.render(<RagRecommendations />));
  await act(async () => Simulate.submit(container.querySelector('form')));
  expect(axios.post).toHaveBeenCalledWith('/api/rag/recommendations', expect.objectContaining({ application: 'my-app', attack_type: 'SQLI' }));
  expect(container.querySelector('[role="alert"]').textContent).toBe('Model unavailable');
});

test('review records feedback without calling WAF apply routes', async () => {
  responses(true, [{ id: 'one', decision: 'RECOMMEND', rule_type: 'SQLI', mode: 'rag', created_at: new Date().toISOString(), event: { application: 'shop', endpoint: '/search' }, rationale: 'Count candidate', missing_context: [], evidence: [], citation_ids: [] }]);
  axios.post.mockResolvedValue({ data: { saved: true } });
  await act(async () => root.render(<RagRecommendations />));
  await act(async () => {
    Simulate.change(container.querySelector('#rag-analyst'), { target: { value: 'Tester' } });
    Simulate.change(container.querySelector('#reason-one'), { target: { value: 'Ready for testing' } });
  });
  const accept = [...container.querySelectorAll('button')].find(b => b.textContent === 'Accept for testing');
  await act(async () => Simulate.click(accept));
  expect(axios.post).toHaveBeenCalledTimes(1);
  expect(axios.post).toHaveBeenCalledWith('/api/rag/recommendations/one/feedback', { analyst: 'Tester', reason: 'Ready for testing', decision: 'accepted' });
});
