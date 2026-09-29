from pathlib import Path

from src.stage1_llm_inference.project_context import (
    ProjectContextIndex,
    strip_java_comments,
)


def test_strip_java_comments_preserves_literals_and_line_numbers() -> None:
    code = '''
class Example {
    String url = "https://example.test/a//b"; // safe label must disappear
    char slash = '/'; /* vulnerable
                         label must disappear */
    String text = """text block // content /* content */""";
}
'''

    stripped = strip_java_comments(code)

    assert "safe label" not in stripped
    assert "vulnerable" not in stripped
    assert '"https://example.test/a//b"' in stripped
    assert "char slash = '/';" in stripped
    assert '"""text block // content /* content */"""' in stripped
    assert stripped.count("\n") == code.count("\n")


def test_context_resolves_called_helper_and_removes_comments(tmp_path: Path) -> None:
    helper = tmp_path / "SafeHelper.java"
    helper.write_text(
        """
public class SafeHelper {
    // Ground-truth-like comments must not be shown to the model.
    public String value() { return "bar"; }
}
""",
        encoding="utf-8",
    )
    target = """
class Target {
    void run() {
        SafeHelper helper = new SafeHelper();
        String value = helper.value();
        Runtime.getRuntime().exec(value);
    }
}
"""

    index = ProjectContextIndex.from_files([str(helper)])
    context = index.context_for(target)

    assert "SafeHelper.value" in context
    assert 'return "bar"' in context
    assert "Ground-truth-like" not in context
    assert index.proven_constant_calls_for(target) == {"helper.value"}


def test_context_does_not_guess_ambiguous_untyped_call(tmp_path: Path) -> None:
    files = []
    for class_name in ("First", "Second", "Third"):
        path = tmp_path / f"{class_name}.java"
        path.write_text(
            f'class {class_name} {{ String get() {{ return "{class_name}"; }} }}',
            encoding="utf-8",
        )
        files.append(str(path))

    context = ProjectContextIndex.from_files(files).context_for(
        "class Target { String run(Unknown value) { return value.get(); } }"
    )

    assert context == ""


def test_context_resolves_this_qualified_field_receiver(tmp_path: Path) -> None:
    helper = tmp_path / "SafeHelper.java"
    helper.write_text(
        'class SafeHelper { String value() { return "fixed"; } }',
        encoding="utf-8",
    )
    target = """class Target {
    private SafeHelper helper = new SafeHelper();
    String run() { return this.helper.value(); }
}
"""

    index = ProjectContextIndex.from_files([str(helper)])

    assert "SafeHelper.value" in index.context_for(target)
    assert index.proven_constant_calls_for(target) == {"this.helper.value"}
