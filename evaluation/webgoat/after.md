# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 7 |
| Files failed | 0 |
| True positives | 0 / 3 expected |
| False positives | 1 (matched FP patterns) |
| False negatives | 3 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### pathtraversal/ProfileUploadBase.java

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

#### False Negatives (expected TPs not found)
- TP-1: `fullName` -> `uploadedFile` (ProfileUpload.uploadFileHandler(@RequestParam fullName) -> super.execute(file, fullName, username) -> new File(uploadDirectory, fullName) assigned to `uploadedFile`. Cross-file: @RequestParam source in subclass, sink in inherited base method. Sink variable is the File assignment target `uploadedFile` (the variable the detector's data-flow graph terminates on); cross-file taint is carried by the parameter pass-through bridge ProfileUpload:fullName -> ProfileUploadBase:fullName -> uploadedFile.)

### pathtraversal/ProfileUpload.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

### pathtraversal/ProfileUploadFix.java

- TP: 0 / 0
- FP (matched patterns): 1
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

#### False Positives (matched FP patterns)
- `fullName` -> `fullName` [type=path_traversal, conf=0.90] — Fix variant applies fullName.replace("../", "") before delegating — sanitized

### pathtraversal/ProfileUploadRemoveUserInput.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

### pathtraversal/ProfileUploadRetrieval.java

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

#### False Negatives (expected TPs not found)
- TP-3: `id` -> `catPicture` (request.getParameter("id") -> new File(catPicturesDirectory, id + ".jpg") assigned to `catPicture` -> FileCopyUtils.copyToByteArray. Single-file flow inside the project-mode fixture. Sink variable is `catPicture` (the File built from the tainted `id`): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/ProfileZipSlip.java

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}

#### False Negatives (expected TPs not found)
- TP-4: `e` -> `f` (Enumerated ZipEntry e (attacker-controlled archive) -> new File(tmpZipDirectory, e.getName()) assigned to `f` -> Files.copy(is, f.toPath()). Classic Zip Slip. Sink variable is `f` (the File built from the tainted entry name): source and sink must be distinct nodes, otherwise the detector's self-loop filter discards the single-node path.)

### pathtraversal/PathTraversal.java

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 10, 'sanitizers_found': 9, 'chains_found': 14, 'chains_verified': 1, 'verification_rate': 0.07142857142857142, 'explanations_generated': 1, 'graph_nodes': 640, 'graph_edges': 191}
