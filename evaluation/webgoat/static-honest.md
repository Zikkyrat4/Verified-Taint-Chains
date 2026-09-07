# VTC Evaluation Report

## Analysis configuration

- Backend: `static`
- LLM analysis mode: `n/a`
- Provider: `n/a`
- Model: `n/a`
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
| True positives | 3 / 4 expected |
| Known false positives | 1 |
| False negatives | 1 |
| Other unmatched findings | 3 |
| Precision (all unmatched findings are FP) | 42.86% |
| Precision on known labels only (diagnostic) | 75.00% |
| Recall | 75.00% |
| F1 | 0.5455 |

## Per-file breakdown

### pathtraversal/ProfileUploadBase.java

- TP: 2 / 2
- FP (matched patterns): 0
- FN: 0
- Unclassified: 3
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `fullName` (line 41) -> `uploadedFile` (line 51) [type=path_traversal, conf=0.91] == expected TP-1 (ProfileUpload.uploadFileHandler(@RequestParam fullName) -> super.execute(file, fullName, username) -> new File(uploadDirectory, fullName) assigned to `uploadedFile`. Cross-file: @RequestParam source in subclass, sink in inherited base method. Sink variable is the File assignment target `uploadedFile` (the variable the detector's data-flow graph terminates on); cross-file taint is carried by the parameter pass-through bridge ProfileUpload:fullName -> ProfileUploadBase:fullName -> uploadedFile.)
- `file` (line 39) -> `uploadedFile` (line 51) [type=path_traversal, conf=0.91] == expected TP-2 (ProfileUploadRemoveUserInput.uploadFileHandler -> super.execute(file, file.getOriginalFilename(), username) -> new File(uploadDirectory, fullName). The tainted name is passed INLINE as file.getOriginalFilename() (no named `fullName` variable) into a differently-named base parameter. Detecting this needs positional argument binding (file -> fullName), i.e. real inter-procedural analysis the name-matching bridge does not perform. expected_realistic=false: kept as a documented hard case, excluded from recall.)

#### Unclassified chains
- `username` (line 66) -> `uploadedFile` (line 51) [type=path_traversal, conf=0.81]
- `username` (line 66) -> `uploadDirectory` (line 70) [type=path_traversal, conf=0.81]
- `username` (line 66) -> `profilePictureDirectory` (line 103) [type=path_traversal, conf=0.81]

### pathtraversal/ProfileUpload.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadFix.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadRemoveUserInput.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

### pathtraversal/ProfileUploadRetrieval.java

- TP: 1 / 1
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `id` (line 99) -> `catPicture` (line 100) [type=path_traversal, conf=0.88] == expected TP-3 (request.getParameter("id") -> new File(catPicturesDirectory, id + ".jpg") assigned to `catPicture` -> FileCopyUtils.copyToByteArray. Single-file flow inside the project-mode fixture. Sink variable is `catPicture` (the File built from the tainted `id`): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/ProfileZipSlip.java

- TP: 0 / 1
- FP (matched patterns): 1
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Positives (matched FP patterns)
- `username` -> `f` [type=path_traversal, conf=0.81] — @CurrentUsername — server-authenticated

#### False Negatives (expected TPs not found)
- TP-4: `e` -> `f` (Enumerated ZipEntry e (attacker-controlled archive) -> new File(tmpZipDirectory, e.getName()) assigned to `f` -> Files.copy(is, f.toPath()). Classic Zip Slip. Sink variable is `f` (the File built from the tainted entry name): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/PathTraversal.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 5, 'sanitizers_found': 6, 'chains_found': 8, 'chains_verified': 7, 'verification_rate': 0.875, 'explanations_generated': 7, 'graph_nodes': 638, 'graph_edges': 57, 'extraction_complete': True, 'extraction_errors': {}, 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}
