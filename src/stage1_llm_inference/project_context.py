"""Bounded source context for resolving calls into project-local methods."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from src.stage1_llm_inference.ast_parser import JavaASTParser


def strip_java_comments(code: str) -> str:
    """Remove Java comments while preserving literals and line numbers."""
    token = re.compile(
        r'("""(?:\\.|(?!""").)*"""|"(?:\\.|[^"\\])*"|'
        r"'(?:\\.|[^'\\])*')|(/\*.*?\*/|//[^\n]*)",
        re.DOTALL,
    )

    def replace(match: re.Match[str]) -> str:
        if match.group(1) is not None:
            return match.group(1)
        return "\n" * match.group(0).count("\n")

    return token.sub(replace, code)


@dataclass(frozen=True)
class MethodDefinition:
    """A project-local method body that may explain a call in another file."""

    path: str
    class_name: str
    name: str
    body: str


class ProjectContextIndex:
    """Resolve a small transitive slice of project methods for an LLM prompt.

    This is intentionally an analysis aid rather than a taint rule database.
    It exposes implementations that a human or compiler could resolve from the
    project, without classifying them as safe, tainted, sources, or sinks.
    """

    def __init__(
        self,
        definitions: dict[str, list[MethodDefinition]],
        *,
        max_chars: int = 12_000,
        max_depth: int = 2,
    ) -> None:
        self.definitions = definitions
        self.max_chars = max_chars
        self.max_depth = max_depth
        self.parser = JavaASTParser()

    @classmethod
    def from_files(
        cls,
        paths: Iterable[str],
        *,
        max_chars: int = 12_000,
        max_depth: int = 2,
    ) -> ProjectContextIndex:
        parser = JavaASTParser()
        definitions: dict[str, list[MethodDefinition]] = {}
        for raw_path in sorted(set(paths)):
            path = Path(raw_path)
            try:
                code = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for method in parser.extract_functions(code):
                name = str(method.get("name") or "")
                body = str(method.get("body") or "")
                if not name or not body:
                    continue
                definitions.setdefault(name, []).append(
                    MethodDefinition(
                        path=str(path),
                        class_name=str(method.get("class_name") or path.stem),
                        name=name,
                        body=body,
                    )
                )
        return cls(definitions, max_chars=max_chars, max_depth=max_depth)

    def context_for(self, source_code: str, *, source_path: str = "") -> str:
        """Return deterministic implementations reachable from ``source_code``."""
        selected: list[MethodDefinition] = []
        selected_keys: set[tuple[str, str, str]] = set()
        frontier = [(source_code, 0)]

        while frontier:
            code, depth = frontier.pop(0)
            if depth >= self.max_depth:
                continue
            variable_types = self._variable_types(code)
            for call in self.parser.extract_method_calls(code):
                candidates = self._resolve_call(
                    str(call.get("name") or ""),
                    str(call.get("receiver") or ""),
                    variable_types,
                    source_path=source_path,
                )
                for definition in candidates:
                    key = (definition.path, definition.class_name, definition.name)
                    if key in selected_keys:
                        continue
                    selected_keys.add(key)
                    selected.append(definition)
                    frontier.append((definition.body, depth + 1))

        if not selected:
            return ""

        chunks: list[str] = []
        used = 0
        for definition in sorted(
            selected, key=lambda item: (item.class_name, item.name, item.path)
        ):
            body = strip_java_comments(definition.body).strip()
            if not body:
                continue
            chunk = (
                f"// {definition.class_name}.{definition.name} "
                f"({Path(definition.path).name})\n{body}"
            )
            projected = used + len(chunk) + 2
            if projected > self.max_chars:
                break
            chunks.append(chunk)
            used = projected
        return "\n\n".join(chunks)

    def proven_constant_calls_for(
        self, source_code: str, *, source_path: str = ""
    ) -> set[str]:
        """Return call expressions whose resolved methods return constants only."""
        variable_types = self._variable_types(source_code)
        proven: set[str] = set()
        for call in self.parser.extract_method_calls(source_code):
            name = str(call.get("name") or "")
            receiver = str(call.get("receiver") or "")
            if not name or not receiver:
                continue
            candidates = self._resolve_call(
                name, receiver, variable_types, source_path=source_path
            )
            if candidates and all(
                self._returns_only_constants(item.body) for item in candidates
            ):
                proven.add(f"{receiver}.{name}")
        return proven

    def _resolve_call(
        self,
        name: str,
        receiver: str,
        variable_types: dict[str, str],
        *,
        source_path: str,
    ) -> list[MethodDefinition]:
        candidates = [
            item for item in self.definitions.get(name, [])
            if item.path != source_path
        ]
        if not candidates:
            return []

        root_receiver = receiver.split(".", 1)[0]
        leaf_receiver = receiver.rsplit(".", 1)[-1]
        expected_class = (
            variable_types.get(root_receiver)
            or variable_types.get(leaf_receiver)
        )
        if expected_class is None and receiver:
            expected_class = receiver.rsplit(".", 1)[-1]
        if expected_class:
            typed = [
                item for item in candidates
                if item.class_name == expected_class
                or item.class_name.endswith("." + expected_class)
            ]
            if typed:
                return typed[:3]
            if receiver:
                return []

        # Ambiguous common names such as get()/set() add noise rather than
        # useful context. Unique and narrowly overloaded project methods are
        # safe to expose without guessing a target.
        return candidates if len(candidates) <= 2 else []

    @staticmethod
    def _variable_types(code: str) -> dict[str, str]:
        result: dict[str, str] = {}
        pattern = re.compile(
            r"(?:^|[;(,{])\s*"
            r"(?:(?:public|protected|private|static|final|volatile|transient)\s+)*"
            r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:<[^;=()]+>)?(?:\[\])?)"
            r"\s+([A-Za-z_$][\w$]*)\s*(?==|[,;)])",
            re.MULTILINE,
        )
        for match in pattern.finditer(code):
            raw_type, variable = match.groups()
            base_type = re.sub(r"<.*>", "", raw_type).removesuffix("[]")
            result[variable] = base_type.rsplit(".", 1)[-1]
        return result

    @classmethod
    def _returns_only_constants(cls, body: str) -> bool:
        code = strip_java_comments(body)
        returns = re.findall(r"\breturn\s+(.+?);", code, re.DOTALL)
        if not returns:
            return False
        literal = re.compile(
            r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
            r"-?\d+(?:\.\d+)?(?:[dDfFlL])?|true|false|null)"
        )
        for expression in returns:
            remainder = literal.sub("", expression)
            remainder = re.sub(r"[\s+\-*/%()?:!<>=&|.^~]", "", remainder)
            if remainder:
                return False
        return True
