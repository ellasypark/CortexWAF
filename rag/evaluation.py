"""Metrics retain denominators and distinguish candidate errors from traffic FPR."""
import math


def fraction(numerator, denominator):
    return numerator / denominator if denominator else None


def wilson_upper(errors, total):
    if not total:
        return None
    z = 1.959963984540054
    p = errors / total
    return (p + z*z/(2*total) + z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))) / (1+z*z/total)


def traffic_metrics(rows):
    seen = set()
    for row in rows:
        if not isinstance(row.get('id'), str) or not row['id'] or row['id'] in seen:
            raise ValueError('Traffic IDs must be unique nonempty strings')
        seen.add(row['id'])
        if row.get('label') not in ('benign', 'malicious') or type(row.get('would_block')) is not bool:
            raise ValueError('Traffic rows require a benign/malicious label and boolean would_block')
    benign = [r for r in rows if r['label'] == 'benign']
    malicious = [r for r in rows if r['label'] == 'malicious']
    fp = sum(r['would_block'] for r in benign)
    tp = sum(r['would_block'] for r in malicious)
    upper = wilson_upper(fp, len(benign))
    return {'benign_requests': len(benign), 'malicious_requests': len(malicious),
            'false_positives': fp, 'true_positives': tp,
            'false_positive_rate': fraction(fp, len(benign)),
            'attack_recall': fraction(tp, len(malicious)),
            'fpr_95pct_wilson_upper': upper,
            'supports_below_one_percent_at_95pct': upper is not None and upper < .01}


def candidate_metrics(rows):
    benign = [r for r in rows if r['label'] == 'benign']
    malicious = [r for r in rows if r['label'] == 'malicious']
    return {'cases': len(rows), 'benign_cases': len(benign), 'malicious_cases': len(malicious),
            'recommendation_rate_on_benign_cases': fraction(sum(r['decision'] == 'RECOMMEND' for r in benign), len(benign)),
            'recommendation_rate_on_malicious_cases': fraction(sum(r['decision'] == 'RECOMMEND' for r in malicious), len(malicious)),
            'abstention_rate': fraction(sum(r['decision'] == 'NEEDS_REVIEW' for r in rows), len(rows)),
            'note': 'Candidate-level metrics are not deployed WAF traffic false-positive rates or analyst acceptance.'}
