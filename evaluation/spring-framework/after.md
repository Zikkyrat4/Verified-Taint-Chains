# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 8 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 15 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2022-22965/CachedIntrospectionResults.java
_CVE:_ CVE-2022-22965

- TP: 0 / 1
- FP (matched patterns): 8
- FN: 1
- Unclassified: 15
- Pipeline metrics: {'sources_found': 17, 'sinks_found': 18, 'sanitizers_found': 0, 'chains_found': 29, 'chains_verified': 23, 'verification_rate': 0.7931034482758621, 'explanations_generated': 23, 'graph_nodes': 445, 'graph_edges': 131}

#### False Positives (matched FP patterns)
- `beanClass` -> `pd` [type=ssrf, conf=0.85] — Internal iteration variables
- `beanClass` -> `results` [type=other, conf=0.90] — Internal cache mutations
- `beanClass` -> `beanInfo` [type=other, conf=0.88] — Internal iteration variables
- `beanClass` -> `pd` [type=xss, conf=0.90] — Internal iteration variables
- `beanClass` -> `existingPd` [type=xss, conf=0.90] — Internal iteration variables
- `beanClass` -> `pd` [type=other, conf=0.93] — Internal iteration variables
- `beanClass` -> `existing` [type=deserialization, conf=0.97] — Internal iteration variables
- `classLoader` -> `results` [type=other, conf=0.90] — Internal cache mutations

#### False Negatives (expected TPs not found)
- TP-1: `beanClass` -> `beanInfo` (Constructor beanClass parameter (request-derived via data binding) -> getBeanInfo(beanClass) -> Introspector.getBeanInfo, exposing classLoader/protectionDomain getters that can be reached via property paths like class.module.classLoader.URLs[0])

#### Unclassified chains
- `pd` (line 361) -> `existingPd` (line 320) [type=xss, conf=0.90]
- `pd` (line 361) -> `existing` (line 370) [type=deserialization, conf=0.97]
- `classLoader` (line 143) -> `existing` (line 370) [type=deserialization, conf=0.97]
- `candidate` (line 219) -> `classLoaderToCheck` (line 225) [type=other, conf=0.90]
- `name` (line 346) -> `pd` (line 361) [type=ssrf, conf=0.82]
- `name` (line 346) -> `pd` (line 320) [type=xss, conf=0.88]
- `name` (line 346) -> `existingPd` (line 320) [type=xss, conf=0.88]
- `name` (line 346) -> `pd` (line 348) [type=other, conf=0.90]
- `name` (line 346) -> `existing` (line 370) [type=deserialization, conf=0.95]
- `propertyDescriptors` (line 355) -> `pd` (line 361) [type=ssrf, conf=0.82]
- `propertyDescriptors` (line 355) -> `pd` (line 320) [type=xss, conf=0.88]
- `propertyDescriptors` (line 355) -> `existingPd` (line 320) [type=xss, conf=0.88]
- `propertyDescriptors` (line 355) -> `pd` (line 348) [type=other, conf=0.90]
- `propertyDescriptors` (line 355) -> `existing` (line 370) [type=deserialization, conf=0.95]
- `td` (line 370) -> `existing` (line 370) [type=deserialization, conf=0.97]
