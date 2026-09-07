"""Regression tests for file- and variable-sensitive sanitizer matching."""

from src.core.models import CodeLocation, Sink, Source, VulnerabilityType
from src.stage1_llm_inference.sanitizer_detector import StaticSanitizerDetector
from src.stage2_path_discovery.astar_search import AStarPathFinder


def _endpoints(source_file: str):
    source = Source(
        location=CodeLocation(file_path=source_file, line_number=1),
        variable_name="fullName", type="user_input", confidence=0.9,
        code_snippet="String fullName",
    )
    sink = Sink(
        location=CodeLocation(file_path="Base.java", line_number=20),
        variable_name="uploadedFile", type="file_path", confidence=0.9,
        code_snippet="File uploadedFile = new File(dir, fullName);",
        vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
    )
    return source, sink


def test_path_replacement_is_bound_to_receiver_variable() -> None:
    sanitizers = StaticSanitizerDetector().detect(
        'return execute(fullName.replace("../", ""));', "Fix.java"
    )

    assert len(sanitizers) == 1
    assert sanitizers[0].variable_name == "fullName"


def test_sanitizer_from_sibling_file_does_not_suppress_chain() -> None:
    sanitizer = StaticSanitizerDetector().detect(
        'return execute(fullName.replace("../", ""));', "Fix.java"
    )
    source, sink = _endpoints("Vulnerable.java")

    chain = AStarPathFinder._create_chain_from_path(
        source, sink, ["Vulnerable.java:fullName", "Base.java:uploadedFile"], sanitizer
    )

    assert chain.sanitizers_on_path == []


def test_sanitizer_on_source_file_is_attached_to_its_chain() -> None:
    sanitizer = StaticSanitizerDetector().detect(
        'return execute(fullName.replace("../", ""));', "Fix.java"
    )
    source, sink = _endpoints("Fix.java")

    chain = AStarPathFinder._create_chain_from_path(
        source, sink, ["Fix.java:fullName", "Base.java:uploadedFile"], sanitizer
    )

    assert chain.sanitizers_on_path == sanitizer


def test_file_existence_check_is_not_a_path_sanitizer() -> None:
    sanitizers = StaticSanitizerDetector().detect(
        "if (catPicture.exists()) { return catPicture; }", "Retrieval.java"
    )

    assert sanitizers == []


def test_canonicalization_alone_cannot_reject_path_chain() -> None:
    sanitizers = StaticSanitizerDetector().detect(
        "String path = file.getCanonicalPath();", "Upload.java"
    )

    assert len(sanitizers) == 1
    assert sanitizers[0].effectiveness < 0.9
