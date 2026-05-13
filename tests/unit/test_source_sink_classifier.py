"""Unit tests for source/sink category classifier."""

import pytest

from src.core.models import (
    CodeLocation,
    Source,
    Sink,
    SourceCategory,
    SinkCategory,
    VulnerabilityType,
)
from src.core.source_sink_classifier import classify_source, classify_sink


def _make_source(code_snippet: str = "", source_type: str = "unknown") -> Source:
    """Helper to create a Source with minimal required fields."""
    return Source(
        location=CodeLocation(file_path="Test.java", line_number=1),
        variable_name="var",
        type=source_type,
        confidence=0.8,
        code_snippet=code_snippet,
    )


def _make_sink(code_snippet: str = "", sink_type: str = "unknown") -> Sink:
    """Helper to create a Sink with minimal required fields."""
    return Sink(
        location=CodeLocation(file_path="Test.java", line_number=1),
        variable_name="var",
        type=sink_type,
        confidence=0.8,
        code_snippet=code_snippet,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
    )


# ============================================================================
# SOURCE CLASSIFICATION TESTS
# ============================================================================


class TestClassifySourceUserInput:
    def test_get_parameter(self) -> None:
        src = _make_source('String name = request.getParameter("name");')
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_get_header(self) -> None:
        src = _make_source('String auth = request.getHeader("Authorization");')
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_request_param_annotation(self) -> None:
        src = _make_source("@RequestParam String username")
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_path_variable_annotation(self) -> None:
        src = _make_source("@PathVariable Long id")
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_request_body_annotation(self) -> None:
        src = _make_source("@RequestBody UserDTO body")
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_get_cookies(self) -> None:
        src = _make_source("Cookie[] cookies = request.getCookies();")
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_get_input_stream(self) -> None:
        src = _make_source("InputStream is = request.getInputStream();")
        assert classify_source(src) == SourceCategory.USER_INPUT


class TestClassifySourceSessionData:
    def test_get_attribute(self) -> None:
        src = _make_source('Object val = session.getAttribute("user");')
        assert classify_source(src) == SourceCategory.SESSION_DATA

    def test_get_auth_note(self) -> None:
        src = _make_source('String note = authSession.getAuthNote("attempt");')
        assert classify_source(src) == SourceCategory.SESSION_DATA

    def test_get_authenticated_user(self) -> None:
        src = _make_source("UserModel user = session.getAuthenticatedUser();")
        assert classify_source(src) == SourceCategory.SESSION_DATA

    def test_get_principal(self) -> None:
        src = _make_source("Principal p = ctx.getPrincipal();")
        assert classify_source(src) == SourceCategory.SESSION_DATA

    def test_get_session(self) -> None:
        src = _make_source("HttpSession session = request.getSession();")
        assert classify_source(src) == SourceCategory.SESSION_DATA


class TestClassifySourceExternalData:
    def test_file_reader(self) -> None:
        src = _make_source("FileReader fr = new FileReader(path);")
        assert classify_source(src) == SourceCategory.EXTERNAL_DATA

    def test_buffered_reader(self) -> None:
        src = _make_source("BufferedReader br = new BufferedReader(reader);")
        assert classify_source(src) == SourceCategory.EXTERNAL_DATA

    def test_read_object(self) -> None:
        src = _make_source("Object obj = ois.readObject();")
        assert classify_source(src) == SourceCategory.EXTERNAL_DATA


class TestClassifySourceDatabase:
    def test_result_set(self) -> None:
        src = _make_source("ResultSet rs = stmt.executeQuery(sql);")
        assert classify_source(src) == SourceCategory.DATABASE

    def test_get_string(self) -> None:
        src = _make_source('String name = rs.getString("name");')
        assert classify_source(src) == SourceCategory.DATABASE


class TestClassifySourceInternalApi:
    def test_generic_getter(self) -> None:
        src = _make_source("RealmModel realm = context.getRealm();")
        assert classify_source(src) == SourceCategory.INTERNAL_API

    def test_framework_config(self) -> None:
        src = _make_source("Config config = provider.getConfig();")
        assert classify_source(src) == SourceCategory.INTERNAL_API

    def test_empty_snippet(self) -> None:
        src = _make_source("")
        assert classify_source(src) == SourceCategory.INTERNAL_API


class TestClassifySourceFromTypeField:
    def test_type_user_input(self) -> None:
        src = _make_source("", source_type="user_input")
        assert classify_source(src) == SourceCategory.USER_INPUT

    def test_type_file_read(self) -> None:
        src = _make_source("", source_type="file_read")
        assert classify_source(src) == SourceCategory.EXTERNAL_DATA

    def test_type_session_attribute(self) -> None:
        src = _make_source("", source_type="session_attribute")
        assert classify_source(src) == SourceCategory.SESSION_DATA

    def test_type_database_query(self) -> None:
        src = _make_source("", source_type="database_result")
        assert classify_source(src) == SourceCategory.DATABASE

    def test_type_http_request(self) -> None:
        src = _make_source("", source_type="http_request_parameter")
        assert classify_source(src) == SourceCategory.USER_INPUT


# ============================================================================
# SINK CLASSIFICATION TESTS
# ============================================================================


class TestClassifySinkDirectExecution:
    def test_execute_query(self) -> None:
        sink = _make_sink("ResultSet rs = stmt.executeQuery(sql);")
        assert classify_sink(sink) == SinkCategory.DIRECT_EXECUTION

    def test_execute_update(self) -> None:
        sink = _make_sink("int rows = stmt.executeUpdate(sql);")
        assert classify_sink(sink) == SinkCategory.DIRECT_EXECUTION

    def test_runtime_exec(self) -> None:
        sink = _make_sink("Process p = Runtime.getRuntime().exec(cmd);")
        assert classify_sink(sink) == SinkCategory.DIRECT_EXECUTION

    def test_create_query(self) -> None:
        sink = _make_sink('Query q = em.createQuery("SELECT ...");')
        assert classify_sink(sink) == SinkCategory.DIRECT_EXECUTION

    def test_process_builder(self) -> None:
        sink = _make_sink("ProcessBuilder pb = new ProcessBuilder(cmd);")
        assert classify_sink(sink) == SinkCategory.DIRECT_EXECUTION


class TestClassifySinkOutputRendering:
    def test_writer_write(self) -> None:
        sink = _make_sink("response.getWriter().write(data);")
        assert classify_sink(sink) == SinkCategory.OUTPUT_RENDERING

    def test_println(self) -> None:
        sink = _make_sink("out.println(userInput);")
        assert classify_sink(sink) == SinkCategory.OUTPUT_RENDERING

    def test_send_redirect(self) -> None:
        sink = _make_sink("response.sendRedirect(url);")
        assert classify_sink(sink) == SinkCategory.OUTPUT_RENDERING

    def test_send_error(self) -> None:
        sink = _make_sink("response.sendError(404, msg);")
        assert classify_sink(sink) == SinkCategory.OUTPUT_RENDERING


class TestClassifySinkResourceAccess:
    def test_new_file(self) -> None:
        sink = _make_sink("File f = new File(path);")
        assert classify_sink(sink) == SinkCategory.RESOURCE_ACCESS

    def test_new_url(self) -> None:
        sink = _make_sink("URL u = new URL(urlStr);")
        assert classify_sink(sink) == SinkCategory.RESOURCE_ACCESS

    def test_file_writer(self) -> None:
        sink = _make_sink("FileWriter fw = new FileWriter(path);")
        assert classify_sink(sink) == SinkCategory.RESOURCE_ACCESS

    def test_document_builder(self) -> None:
        sink = _make_sink("DocumentBuilder db = factory.newDocumentBuilder();")
        assert classify_sink(sink) == SinkCategory.RESOURCE_ACCESS


class TestClassifySinkDataStorage:
    def test_set_attribute(self) -> None:
        sink = _make_sink('session.setAttribute("user", user);')
        assert classify_sink(sink) == SinkCategory.DATA_STORAGE

    def test_set_auth_note(self) -> None:
        sink = _make_sink('authSession.setAuthNote("key", value);')
        assert classify_sink(sink) == SinkCategory.DATA_STORAGE

    def test_persist(self) -> None:
        sink = _make_sink("em.persist(entity);")
        assert classify_sink(sink) == SinkCategory.DATA_STORAGE

    def test_save(self) -> None:
        sink = _make_sink("repo.save(entity);")
        assert classify_sink(sink) == SinkCategory.DATA_STORAGE


class TestClassifySinkFrameworkApi:
    def test_constructor(self) -> None:
        sink = _make_sink("new AuthenticationFlow(session, flowId);")
        assert classify_sink(sink) == SinkCategory.FRAMEWORK_API

    def test_generic_setter(self) -> None:
        sink = _make_sink("context.setClient(client);")
        assert classify_sink(sink) == SinkCategory.FRAMEWORK_API

    def test_empty_snippet(self) -> None:
        sink = _make_sink("")
        assert classify_sink(sink) == SinkCategory.UNKNOWN
