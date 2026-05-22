# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 7 |
| Files failed | 0 |
| True positives | 1 / 3 expected |
| False positives | 5 (matched FP patterns) |
| False negatives | 2 |
| Unclassified | 3 |
| Precision (TP / TP+FP) | 16.67% |
| Precision strict (TP / TP+FP+Uncl) | 11.11% |
| Recall | 33.33% |
| F1 | 0.2222 |

## Per-file breakdown

### pathtraversal/ProfileUploadBase.java

- TP: 1 / 1
- FP (matched patterns): 2
- FN: 0
- Unclassified: 2
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

#### True Positives matched
- `fullName` (line 43) -> `uploadedFile` (line 55) [type=path_traversal, conf=0.91] == expected TP-1 (ProfileUpload.uploadFileHandler(@RequestParam fullName) -> super.execute(file, fullName, username) -> new File(uploadDirectory, fullName) assigned to `uploadedFile`. Cross-file: @RequestParam source in subclass, sink in inherited base method. Sink variable is the File assignment target `uploadedFile` (the variable the detector's data-flow graph terminates on); cross-file taint is carried by the parameter pass-through bridge ProfileUpload:fullName -> ProfileUploadBase:fullName -> uploadedFile.)

#### False Positives (matched FP patterns)
- `username` -> `uploadedFile` [type=path_traversal, conf=0.83] — @CurrentUsername — server-authenticated identity, not user-controlled in dangerous way
- `username` -> `uploadedFile` [type=path_traversal, conf=0.89] — @CurrentUsername — server-authenticated identity, not user-controlled in dangerous way

#### Unclassified chains
- `fullName` (line 44) -> `uploadedFile` (line 55) [type=path_traversal, conf=0.94]
- `fullName` (line 43) -> `uploadedFile` (line 55) [type=path_traversal, conf=0.91]

### pathtraversal/ProfileUpload.java

- TP: 0 / 0
- FP (matched patterns): 1
- FN: 0
- Unclassified: 1
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

#### False Positives (matched FP patterns)
- `username` -> `username` [type=path_traversal, conf=0.82] — @CurrentUsername — server-authenticated

#### Unclassified chains
- `fullName` (line 43) -> `fullName` (line 43) [type=path_traversal, conf=0.82]

### pathtraversal/ProfileUploadFix.java

- TP: 0 / 0
- FP (matched patterns): 2
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

#### False Positives (matched FP patterns)
- `fullName` -> `fullName` [type=path_traversal, conf=0.88] — Fix variant applies fullName.replace("../", "") before delegating — sanitized
- `username` -> `username` [type=path_traversal, conf=0.78] — @CurrentUsername — server-authenticated

### pathtraversal/ProfileUploadRemoveUserInput.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

### pathtraversal/ProfileUploadRetrieval.java

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

#### False Negatives (expected TPs not found)
- TP-3: `id` -> `catPicture` (request.getParameter("id") -> new File(catPicturesDirectory, id + ".jpg") assigned to `catPicture` -> FileCopyUtils.copyToByteArray. Single-file flow inside the project-mode fixture. Sink variable is `catPicture` (the File built from the tainted `id`): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/ProfileZipSlip.java

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}

#### False Negatives (expected TPs not found)
- TP-4: `e` -> `f` (Enumerated ZipEntry e (attacker-controlled archive) -> new File(tmpZipDirectory, e.getName()) assigned to `f` -> Files.copy(is, f.toPath()). Classic Zip Slip. Sink variable is `f` (the File built from the tainted entry name): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/PathTraversal.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 21, 'sanitizers_found': 9, 'chains_found': 39, 'chains_verified': 9, 'verification_rate': 0.23076923076923078, 'explanations_generated': 9, 'graph_nodes': 640, 'graph_edges': 219}
