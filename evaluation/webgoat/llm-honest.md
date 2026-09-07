# VTC Evaluation Report

## Analysis configuration

- Backend: `llm`
- LLM analysis mode: `targeted`
- Provider: `openai`
- Model: `glm-5.3-flash`
- Minimum confidence: `0.6`
- Verification: `both`
- Pathfinder: `astar`
- Joern: `True`
- LLM graph enrichment: `False`
- Stage 1 cache reads: `True`

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 7 |
| Files failed | 0 |
| True positives | 4 / 4 expected |
| Known false positives | 5 |
| False negatives | 0 |
| Other unmatched findings | 15 |
| Precision (all unmatched findings are FP) | 16.67% |
| Precision on known labels only (diagnostic) | 44.44% |
| Recall | 100.00% |
| F1 | 0.2857 |

## Per-file breakdown

### pathtraversal/ProfileUploadBase.java

- TP: 2 / 2
- FP (matched patterns): 3
- FN: 0
- Unclassified: 11
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `fullName` (line 41) -> `uploadedFile` (line 53) [type=path_traversal, conf=1.00] == expected TP-1 (ProfileUpload.uploadFileHandler(@RequestParam fullName) -> super.execute(file, fullName, username) -> new File(uploadDirectory, fullName) assigned to `uploadedFile`. Cross-file: @RequestParam source in subclass, sink in inherited base method. Sink variable is the File assignment target `uploadedFile` (the variable the detector's data-flow graph terminates on); cross-file taint is carried by the parameter pass-through bridge ProfileUpload:fullName -> ProfileUploadBase:fullName -> uploadedFile.)
- `file` (line 39) -> `uploadedFile` (line 53) [type=path_traversal, conf=1.00] == expected TP-2 (ProfileUploadRemoveUserInput.uploadFileHandler -> super.execute(file, file.getOriginalFilename(), username) -> new File(uploadDirectory, fullName). The tainted name is passed INLINE as file.getOriginalFilename() (no named `fullName` variable) into a differently-named base parameter. Detecting this needs positional argument binding (file -> fullName), i.e. real inter-procedural analysis the name-matching bridge does not perform. expected_realistic=false: kept as a documented hard case, excluded from recall.)

#### False Positives (matched FP patterns)
- `username` -> `profilePictureDirectory` [type=path_traversal, conf=0.88] — @CurrentUsername — server-authenticated identity, not user-controlled in dangerous way
- `username` -> `uploadedFile` [type=path_traversal, conf=0.95] — @CurrentUsername — server-authenticated identity, not user-controlled in dangerous way
- `username` -> `uploadDirectory` [type=path_traversal, conf=0.90] — @CurrentUsername — server-authenticated identity, not user-controlled in dangerous way

#### Unclassified chains
- `fullName` (line 44) -> `uploadedFile` (line 53) [type=path_traversal, conf=1.00]
- `fullName` (line 41) -> `uploadedFile` (line 53) [type=path_traversal, conf=1.00]
- `username` (line 42) -> `uploadedFile` (line 53) [type=path_traversal, conf=0.85]
- `username` (line 42) -> `uploadDirectory` (line 74) [type=path_traversal, conf=0.80]
- `username` (line 42) -> `profilePictureDirectory` (line 103) [type=path_traversal, conf=0.75]
- `username` (line 40) -> `uploadedFile` (line 53) [type=path_traversal, conf=0.85]
- `username` (line 40) -> `uploadDirectory` (line 74) [type=path_traversal, conf=0.80]
- `username` (line 40) -> `profilePictureDirectory` (line 103) [type=path_traversal, conf=0.75]
- `username` (line 66) -> `uploadedFile` (line 53) [type=path_traversal, conf=0.85]
- `username` (line 66) -> `uploadDirectory` (line 74) [type=path_traversal, conf=0.80]
- `username` (line 66) -> `profilePictureDirectory` (line 103) [type=path_traversal, conf=0.75]

### pathtraversal/ProfileUpload.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadFix.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadRemoveUserInput.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadRetrieval.java

- TP: 1 / 1
- FP (matched patterns): 0
- FN: 0
- Unclassified: 2
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `id` (line 99) -> `catPicture` (line 100) [type=path_traversal, conf=1.00] == expected TP-3 (request.getParameter("id") -> new File(catPicturesDirectory, id + ".jpg") assigned to `catPicture` -> FileCopyUtils.copyToByteArray. Single-file flow inside the project-mode fixture. Sink variable is `catPicture` (the File built from the tainted `id`): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

#### Unclassified chains
- `webGoatHomeDirectory` (line 53) -> `catPicturesDirectory` (line 54) [type=path_traversal, conf=0.72]
- `request` (line 92) -> `catPicture` (line 100) [type=path_traversal, conf=1.00]

### pathtraversal/ProfileZipSlip.java

- TP: 1 / 1
- FP (matched patterns): 2
- FN: 0
- Unclassified: 2
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `e` (line 78) -> `f` (line 79) [type=path_traversal, conf=0.95] == expected TP-4 (Enumerated ZipEntry e (attacker-controlled archive) -> new File(tmpZipDirectory, e.getName()) assigned to `f` -> Files.copy(is, f.toPath()). Classic Zip Slip. Sink variable is `f` (the File built from the tainted entry name): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

#### False Positives (matched FP patterns)
- `username` -> `uploadedZipFile` [type=path_traversal, conf=0.82] — @CurrentUsername — server-authenticated
- `username` -> `f` [type=path_traversal, conf=0.82] — @CurrentUsername — server-authenticated

#### Unclassified chains
- `file` (line 66) -> `uploadedZipFile` (line 72) [type=path_traversal, conf=0.95]
- `file` (line 66) -> `f` (line 79) [type=path_traversal, conf=0.95]

### pathtraversal/PathTraversal.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 10, 'sanitizers_found': 2, 'chains_found': 24, 'chains_verified': 24, 'verification_rate': 1.0, 'explanations_generated': 23, 'graph_nodes': 639, 'graph_edges': 61, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}
