"""Generates human-readable explanations for taint chains.

Enhanced with:
- Better prompt templates using vulnerability-specific templates
- Confidence scoring based on LLM + verification status
- Multiple output formats (Markdown, HTML, plain text)
"""

import json
from typing import Optional, Dict, List
from enum import Enum

from src.core.models import TaintChain, Explanation, VulnerabilityType, VerificationStatus
from src.core.exceptions import ParsingError, LLMError
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.stage4_explanation.templates import get_template, TEMPLATE_REGISTRY
from src.utils.logger import get_logger

logger = get_logger()


class OutputFormat(Enum):
    """Output format options for explanations."""
    MARKDOWN = "markdown"
    HTML = "html"
    PLAIN_TEXT = "plain_text"
    JSON = "json"


# CWE mapping for common vulnerability types
CWE_MAPPING = {
    VulnerabilityType.SQL_INJECTION: "CWE-89",
    VulnerabilityType.XSS: "CWE-79",
    VulnerabilityType.COMMAND_INJECTION: "CWE-78",
    VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
    VulnerabilityType.XXE: "CWE-611",
    VulnerabilityType.SSRF: "CWE-918",
}


# Severity mapping based on vulnerability type and context
SEVERITY_MAPPING = {
    VulnerabilityType.SQL_INJECTION: "CRITICAL",
    VulnerabilityType.COMMAND_INJECTION: "CRITICAL",
    VulnerabilityType.XXE: "HIGH",
    VulnerabilityType.SSRF: "HIGH",
    VulnerabilityType.XSS: "MEDIUM",
    VulnerabilityType.PATH_TRAVERSAL: "HIGH",
}


class ExplanationGenerator:
    """Generates human-readable explanations for taint chains.

    Enhanced version with:
    - Vulnerability-specific templates
    - Better LLM prompts with full context
    - Confidence scoring (LLM + verification)
    - Multiple output formats
    """

    def __init__(self, llm_client: SimpleLLMClient) -> None:
        """Initialize the explanation generator.

        Args:
            llm_client: SimpleLLMClient instance for LLM queries.
        """
        self.llm_client = llm_client
        logger.debug("Initialized ExplanationGenerator with enhanced templates")

    async def generate_explanation(
        self,
        chain: TaintChain,
        include_references: bool = True,
        include_attack_scenario: bool = True
    ) -> Explanation:
        """Generate explanation for a taint chain.

        Creates a comprehensive explanation including:
        - Why the code is vulnerable (with attack scenario)
        - Multiple fix strategies
        - Code examples
        - Severity level
        - CWE identifier
        - Confidence score
        - References (CWE, OWASP)

        Args:
            chain: TaintChain to explain.
            include_references: Include OWASP/CWE references in explanation.
            include_attack_scenario: Include attack scenario in explanation.

        Returns:
            Explanation object with detailed information.

        Raises:
            LLMError: If LLM explanation generation fails.
        """
        logger.info(f"Generating explanation for chain {chain.id}")

        # Build enhanced prompt using templates
        prompt = self._build_enhanced_prompt(
            chain,
            include_attack_scenario=include_attack_scenario
        )

        try:
            # Call LLM
            response = await self.llm_client.analyze_code(
                self._build_context_code(chain),
                prompt,
            )

            # Parse response
            explanation_data = self._parse_explanation_response(response, chain)

            # Create Explanation object
            explanation = Explanation(
                chain_id=chain.id,
                why_vulnerable=explanation_data["why_vulnerable"],
                how_to_fix=explanation_data["how_to_fix"],
                example_fix=explanation_data["example_fix"],
                severity=self.determine_severity(chain),
                cwe_id=self.map_to_cwe(chain.vulnerability_type),
            )

            logger.info(f"Generated explanation for chain {chain.id}")
            return explanation

        except (ParsingError, LLMError) as e:
            logger.error(f"Failed to generate explanation: {str(e)}")
            raise

    def determine_severity(self, chain: TaintChain) -> str:
        """Determine severity level for a vulnerability.

        Considers:
        - Base vulnerability type severity
        - Confidence score (LLM + verification)
        - Presence of sanitizers on path
        - Verification status

        Args:
            chain: TaintChain to evaluate.

        Returns:
            Severity level (LOW, MEDIUM, HIGH, CRITICAL).
        """
        # Base severity from vulnerability type
        severity = SEVERITY_MAPPING.get(chain.vulnerability_type, "MEDIUM")

        # Calculate overall confidence
        confidence = self.calculate_confidence(chain)

        # Adjust based on confidence
        if confidence < 0.6:
            # Low confidence reduces severity one level
            if severity == "CRITICAL":
                severity = "HIGH"
            elif severity == "HIGH":
                severity = "MEDIUM"
            elif severity == "MEDIUM":
                severity = "LOW"

        # Adjust based on verification status
        if chain.verification_status == VerificationStatus.FALSE:
            # Verified as FALSE -> likely false positive
            severity = "LOW"
        elif chain.verification_status == VerificationStatus.UNVERIFIABLE:
            # Couldn't verify -> reduce confidence
            if severity == "CRITICAL":
                severity = "HIGH"

        # Adjust based on sanitizers
        if chain.sanitizers_on_path:
            # Presence of sanitizers may reduce severity
            if severity == "CRITICAL":
                severity = "HIGH"
            elif severity == "HIGH":
                severity = "MEDIUM"

        logger.debug(
            f"Determined severity for {chain.id}: {severity} "
            f"(base: {SEVERITY_MAPPING.get(chain.vulnerability_type)}, "
            f"confidence: {confidence:.2f})"
        )

        return severity

    def calculate_confidence(self, chain: TaintChain) -> float:
        """Calculate overall confidence score for a vulnerability.

        Combines:
        1. LLM confidence (from source and sink detection)
        2. Verification status (from Stage 3)
        3. Path quality (penalises very short and same-variable chains)

        Args:
            chain: TaintChain to evaluate.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        # 1. LLM confidence (average of source and sink)
        llm_confidence = (chain.source.confidence + chain.sink.confidence) / 2.0

        # 2. Verification confidence
        verification_confidence = 0.5  # Default
        if chain.verification_status == VerificationStatus.VERIFIED:
            verification_confidence = 0.95
        elif chain.verification_status == VerificationStatus.FALSE:
            verification_confidence = 0.1
        elif chain.verification_status == VerificationStatus.UNVERIFIABLE:
            verification_confidence = 0.6

        # 3. Path quality score
        path_length = len(chain.path)
        # Longer paths = lower confidence
        path_confidence = max(0.5, 1.0 - (path_length - 2) * 0.05)

        # Penalty: same source and sink variable name (trivial/suspicious chain)
        if chain.source.variable_name == chain.sink.variable_name:
            path_confidence *= 0.5

        # Penalty: very short paths (2 nodes = source→sink with nothing in between)
        if path_length <= 2:
            path_confidence *= 0.8

        # Combined confidence (weighted average)
        # LLM: 40%, Verification: 50%, Path: 10%
        overall_confidence = (
            llm_confidence * 0.4 +
            verification_confidence * 0.5 +
            path_confidence * 0.1
        )

        logger.debug(
            f"Confidence for {chain.id}: {overall_confidence:.2f} "
            f"(LLM: {llm_confidence:.2f}, "
            f"Verification: {verification_confidence:.2f}, "
            f"Path: {path_confidence:.2f})"
        )

        return overall_confidence

    def map_to_cwe(self, vulnerability_type: VulnerabilityType) -> Optional[str]:
        """Map vulnerability type to CWE identifier.

        Args:
            vulnerability_type: VulnerabilityType enum value.

        Returns:
            CWE identifier (e.g., "CWE-89") or None if unmapped.
        """
        cwe = CWE_MAPPING.get(vulnerability_type)
        logger.debug(f"Mapped {vulnerability_type.value} to {cwe}")
        return cwe

    def _build_enhanced_prompt(
        self,
        chain: TaintChain,
        include_attack_scenario: bool = True
    ) -> str:
        """Build enhanced LLM prompt using vulnerability templates.

        Args:
            chain: TaintChain to explain.
            include_attack_scenario: Include attack scenario in prompt.

        Returns:
            Enhanced prompt string for LLM.
        """
        # Get vulnerability-specific template
        try:
            template = get_template(chain.vulnerability_type)
        except KeyError:
            # Fallback to basic prompt if no template
            return self._build_basic_prompt(chain)

        # Build data flow path string
        path_str = " -> ".join(node.variable_name for node in chain.path)

        # Build verification status context
        verification_context = ""
        if chain.verification_status:
            verification_context = f"\nVerification Status: {chain.verification_status.value}"
            if chain.verification_status == VerificationStatus.VERIFIED:
                verification_context += " (HIGH CONFIDENCE - Path verified by symbolic execution)"
            elif chain.verification_status == VerificationStatus.UNVERIFIABLE:
                verification_context += " (MEDIUM CONFIDENCE - Could not fully verify)"

        # Build sanitizer context
        sanitizer_context = ""
        if chain.sanitizers_on_path:
            sanitizer_names = ", ".join(s.variable_name for s in chain.sanitizers_on_path)
            sanitizer_context = f"\nSanitizers on path: {sanitizer_names} (may provide partial mitigation)"

        # Enhanced prompt with template context
        prompt = f"""Generate a detailed security explanation for this {template.name} vulnerability.

**Vulnerability Context:**
Type: {template.name} ({template.cwe_id})
OWASP Category: {template.owasp_category}
Default Severity: {template.severity_default}

**Data Flow Analysis:**
Data Flow Path: {path_str}
Source: {chain.source.variable_name} ({chain.source.type}) at line {chain.source.location.line_number}
Sink: {chain.sink.variable_name} ({chain.sink.type}) at line {chain.sink.location.line_number}
Source Confidence: {chain.source.confidence:.2f}
Sink Confidence: {chain.sink.confidence:.2f}{verification_context}{sanitizer_context}

**Vulnerability Description:**
{template.description}

"""

        if include_attack_scenario:
            prompt += f"""**Attack Scenario:**
{template.attack_scenario}

"""

        prompt += f"""**Common Pitfalls:**
"""
        for i, pitfall in enumerate(template.common_pitfalls, 1):
            prompt += f"{i}. {pitfall}\n"

        prompt += f"""
**Your Task:**
Analyze the specific data flow in this code and provide a JSON response with:

1. "why_vulnerable": Explain why THIS SPECIFIC data flow is dangerous (2-4 sentences).
   - Reference the actual variable names ({chain.source.variable_name}, {chain.sink.variable_name})
   - Explain the specific attack vector
   - Mention the confidence level if relevant

2. "how_to_fix": Describe how to fix THIS SPECIFIC vulnerability (2-4 sentences).
   - Recommend the most appropriate fix strategy from the {len(template.fix_strategies)} options below
   - Explain why this approach is best for this case
   - Mention any trade-offs

3. "example_fix": Provide a concrete code example showing the fix.
   - Use the actual variable names from the code
   - Show before/after or just the fixed version
   - Include comments explaining key changes

**Available Fix Strategies:**
"""

        for i, strategy in enumerate(template.fix_strategies, 1):
            prompt += f"""
{i}. {strategy['title']}
   {strategy['description']}
"""

        prompt += f"""
**Secure Coding Patterns:**
"""
        for i, pattern in enumerate(template.secure_patterns, 1):
            prompt += f"{i}. {pattern}\n"

        prompt += """
Return ONLY valid JSON with these three fields: why_vulnerable, how_to_fix, example_fix.
Do NOT include markdown code blocks or any other formatting.
"""

        return prompt

    def _build_basic_prompt(self, chain: TaintChain) -> str:
        """Build basic prompt (fallback when no template available).

        Args:
            chain: TaintChain to explain.

        Returns:
            Basic prompt string for LLM.
        """
        path_str = " -> ".join(node.variable_name for node in chain.path)

        prompt = f"""Generate a detailed security explanation for this taint chain vulnerability.

Vulnerability Type: {chain.vulnerability_type.value}
Data Flow: {path_str}
Source: {chain.source.variable_name} ({chain.source.type})
Sink: {chain.sink.variable_name} ({chain.sink.type})

Provide a JSON response with:
1. "why_vulnerable": Explain why this data flow is dangerous (2-3 sentences)
2. "how_to_fix": Describe how to fix the vulnerability (2-3 sentences)
3. "example_fix": Provide a code example showing the fix

Return ONLY valid JSON with these three fields."""

        return prompt

    def _build_context_code(self, chain: TaintChain) -> str:
        """Build code context from chain for LLM.

        Args:
            chain: TaintChain with code snippets.

        Returns:
            Code context string.
        """
        snippets = []

        # Add source context
        if chain.source.code_snippet:
            snippets.append(f"// Source ({chain.source.variable_name}):")
            snippets.append(chain.source.code_snippet)
            snippets.append("")

        # Add path nodes context
        for node in chain.path:
            if hasattr(node, 'code_snippet') and node.code_snippet:
                snippets.append(f"// Path node ({node.variable_name}):")
                snippets.append(node.code_snippet)
                snippets.append("")

        # Add sink context
        if chain.sink.code_snippet:
            snippets.append(f"// Sink ({chain.sink.variable_name}):")
            snippets.append(chain.sink.code_snippet)

        return "\n".join(snippets)

    def _parse_explanation_response(
        self, response: dict, chain: TaintChain
    ) -> dict:
        """Parse LLM response into explanation fields.

        Args:
            response: LLM response as dictionary.
            chain: TaintChain for context.

        Returns:
            Dictionary with explanation fields.

        Raises:
            ParsingError: If response format is invalid.
        """
        required_fields = ["why_vulnerable", "how_to_fix", "example_fix"]

        # Validate required fields
        for field in required_fields:
            if field not in response:
                logger.warning(f"Missing field in LLM response: {field}")
                raise ParsingError(f"Missing required field: {field}")

        return {
            "why_vulnerable": response.get("why_vulnerable", ""),
            "how_to_fix": response.get("how_to_fix", ""),
            "example_fix": response.get("example_fix", ""),
        }

    def generate_explanations_batch(
        self, chains: List[TaintChain]
    ) -> Dict[str, Explanation]:
        """Generate explanations for multiple chains (non-async wrapper).

        Args:
            chains: List of TaintChain objects.

        Returns:
            Dictionary mapping chain IDs to Explanation objects.
        """
        explanations: Dict[str, Explanation] = {}

        logger.info(f"Generating explanations for {len(chains)} chains")

        for chain in chains:
            try:
                # Create explanation using templates
                explanation = self._create_template_explanation(chain)
                explanations[chain.id] = explanation
                logger.debug(f"Created explanation for {chain.id}")

            except Exception as e:
                logger.warning(f"Failed to create explanation for {chain.id}: {str(e)}")
                continue

        logger.info(f"Generated {len(explanations)} explanations")
        return explanations

    def _create_template_explanation(self, chain: TaintChain) -> Explanation:
        """Create explanation using vulnerability templates.

        Enhanced version that uses detailed templates instead of simple strings.

        Args:
            chain: TaintChain to explain.

        Returns:
            Explanation object with template-based content.
        """
        try:
            template = get_template(chain.vulnerability_type)

            # Build why_vulnerable from template
            why_vulnerable = (
                f"This code is vulnerable to {template.name}. "
                f"The variable '{chain.source.variable_name}' contains untrusted input "
                f"that flows to '{chain.sink.variable_name}' without proper sanitization. "
                f"{template.description[:200]}..."
            )

            # Build how_to_fix from first fix strategy
            primary_fix = template.fix_strategies[0]
            how_to_fix = (
                f"{primary_fix['title']}: {primary_fix['description']} "
                f"Alternatively, consider: {template.fix_strategies[1]['title'] if len(template.fix_strategies) > 1 else 'input validation'}."
            )

            # Use example from template
            example_fix = primary_fix['code_example']

        except KeyError:
            # Fallback to simple explanation
            return self._create_default_explanation(chain)

        severity = self.determine_severity(chain)
        cwe = self.map_to_cwe(chain.vulnerability_type)

        return Explanation(
            chain_id=chain.id,
            why_vulnerable=why_vulnerable,
            how_to_fix=how_to_fix,
            example_fix=example_fix,
            severity=severity,
            cwe_id=cwe,
        )

    def _create_default_explanation(self, chain: TaintChain) -> Explanation:
        """Create a default explanation without template (fallback).

        Args:
            chain: TaintChain to explain.

        Returns:
            Explanation object with generated content.
        """
        vuln_type = chain.vulnerability_type.value
        source_var = chain.source.variable_name
        sink_var = chain.sink.variable_name

        # Default explanations by type
        why_vulnerable_templates = {
            "sql_injection": f"The variable '{source_var}' contains untrusted user input that flows directly into a SQL query without proper sanitization or parameterized queries.",
            "command_injection": f"User-controlled data '{source_var}' is passed to '{sink_var}' which executes system commands, allowing arbitrary command execution.",
            "xss": f"Untrusted user input '{source_var}' reaches the web output without proper encoding, allowing malicious scripts to be injected.",
            "path_traversal": f"User input '{source_var}' is used in file path operations without validation, allowing directory traversal attacks.",
            "xxe": f"External XML entity processing is enabled for data derived from untrusted source '{source_var}'.",
            "ssrf": f"User input '{source_var}' controls URLs in outbound requests, allowing Server-Side Request Forgery attacks.",
        }

        how_to_fix_templates = {
            "sql_injection": "Use parameterized queries or prepared statements to separate SQL code from data.",
            "command_injection": "Avoid executing system commands with user input. If necessary, use command whitelisting and proper escaping.",
            "xss": "Encode all user input before rendering in HTML. Use context-aware encoding (HTML, JS, URL encoding).",
            "path_traversal": "Validate and sanitize file paths. Use absolute paths and reject path traversal sequences like '../'.",
            "xxe": "Disable external entity processing in XML parsers. Use secure XML parser configurations.",
            "ssrf": "Validate and whitelist allowed URLs. Use blocklists for internal IP addresses.",
        }

        example_fix_templates = {
            "sql_injection": f"PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, {source_var});",
            "command_injection": f"String[] cmd = new String[]{{\"ls\", \"-l\", {source_var}}};\nRuntime.getRuntime().exec(cmd);",
            "xss": f"String encoded = HtmlUtils.htmlEscape({source_var});\nresponse.getWriter().println(encoded);",
            "path_traversal": f"Path path = Paths.get(\"/safe/dir\", {source_var});\nif (!path.normalize().startsWith(\"/safe/dir\")) throw new Exception(\"Path traversal\");",
            "xxe": "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\nfactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");",
            "ssrf": f"URL url = new URL({source_var});\nif (!ALLOWED_HOSTS.contains(url.getHost())) throw new Exception(\"Invalid host\");",
        }

        why_vulnerable = why_vulnerable_templates.get(
            vuln_type, f"Unsanitized data from '{source_var}' reaches dangerous operation '{sink_var}'."
        )
        how_to_fix = how_to_fix_templates.get(
            vuln_type, "Validate and sanitize all user inputs before use in dangerous operations."
        )
        example_fix = example_fix_templates.get(vuln_type, "Apply security best practices for your framework.")

        severity = self.determine_severity(chain)
        cwe = self.map_to_cwe(chain.vulnerability_type)

        return Explanation(
            chain_id=chain.id,
            why_vulnerable=why_vulnerable,
            how_to_fix=how_to_fix,
            example_fix=example_fix,
            severity=severity,
            cwe_id=cwe,
        )

    # ============================================================================
    # Multiple Output Formats
    # ============================================================================

    def format_explanation(
        self,
        explanation: Explanation,
        chain: TaintChain,
        output_format: OutputFormat = OutputFormat.MARKDOWN
    ) -> str:
        """Format explanation in specified output format.

        Args:
            explanation: Explanation object to format.
            chain: Associated TaintChain for context.
            output_format: Desired output format.

        Returns:
            Formatted explanation string.
        """
        if output_format == OutputFormat.MARKDOWN:
            return self._format_markdown(explanation, chain)
        elif output_format == OutputFormat.HTML:
            return self._format_html(explanation, chain)
        elif output_format == OutputFormat.PLAIN_TEXT:
            return self._format_plain_text(explanation, chain)
        elif output_format == OutputFormat.JSON:
            return self._format_json(explanation, chain)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _format_markdown(self, explanation: Explanation, chain: TaintChain) -> str:
        """Format explanation as Markdown.

        Args:
            explanation: Explanation to format.
            chain: Associated TaintChain.

        Returns:
            Markdown-formatted string.
        """
        confidence = self.calculate_confidence(chain)

        # Get template for references
        references = ""
        try:
            template = get_template(chain.vulnerability_type)
            refs = "\n".join(f"- {ref}" for ref in template.references)
            references = f"\n## References\n\n{refs}\n"
        except KeyError:
            pass

        md = f"""# {chain.vulnerability_type.value.replace('_', ' ').title()} Vulnerability

**Severity:** {explanation.severity}
**CWE:** {explanation.cwe_id or 'N/A'}
**Confidence:** {confidence:.0%}
**Status:** {chain.verification_status.value if chain.verification_status else 'Not verified'}

## Data Flow

```
{' -> '.join(node.variable_name for node in chain.path)}
```

**Source:** `{chain.source.variable_name}` ({chain.source.type}) at line {chain.source.location.line_number}
**Sink:** `{chain.sink.variable_name}` ({chain.sink.type}) at line {chain.sink.location.line_number}

## Why This Is Vulnerable

{explanation.why_vulnerable}

## How To Fix

{explanation.how_to_fix}

## Example Fix

```java
{explanation.example_fix}
```
{references}
---
*Generated by Verified Taint Chains Analyzer*
"""
        return md

    def _format_html(self, explanation: Explanation, chain: TaintChain) -> str:
        """Format explanation as HTML.

        Args:
            explanation: Explanation to format.
            chain: Associated TaintChain.

        Returns:
            HTML-formatted string.
        """
        confidence = self.calculate_confidence(chain)
        path = " &rarr; ".join(node.variable_name for node in chain.path)

        # Severity color
        severity_color = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
        }.get(explanation.severity, "#6c757d")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{chain.vulnerability_type.value.replace('_', ' ').title()} Vulnerability</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }}
        .header {{ border-bottom: 3px solid {severity_color}; padding-bottom: 10px; }}
        .severity {{ color: {severity_color}; font-weight: bold; }}
        .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .section {{ margin: 20px 0; }}
        .code {{ background: #f4f4f4; padding: 10px; border-left: 4px solid #007bff; font-family: monospace; overflow-x: auto; }}
        .path {{ background: #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{chain.vulnerability_type.value.replace('_', ' ').title()} Vulnerability</h1>
    </div>

    <div class="metadata">
        <p><strong>Severity:</strong> <span class="severity">{explanation.severity}</span></p>
        <p><strong>CWE:</strong> {explanation.cwe_id or 'N/A'}</p>
        <p><strong>Confidence:</strong> {confidence:.0%}</p>
        <p><strong>Status:</strong> {chain.verification_status.value if chain.verification_status else 'Not verified'}</p>
    </div>

    <div class="section">
        <h2>Data Flow</h2>
        <div class="path">{path}</div>
        <p><strong>Source:</strong> <code>{chain.source.variable_name}</code> ({chain.source.type}) at line {chain.source.location.line_number}</p>
        <p><strong>Sink:</strong> <code>{chain.sink.variable_name}</code> ({chain.sink.type}) at line {chain.sink.location.line_number}</p>
    </div>

    <div class="section">
        <h2>Why This Is Vulnerable</h2>
        <p>{explanation.why_vulnerable}</p>
    </div>

    <div class="section">
        <h2>How To Fix</h2>
        <p>{explanation.how_to_fix}</p>
    </div>

    <div class="section">
        <h2>Example Fix</h2>
        <pre class="code">{explanation.example_fix}</pre>
    </div>

    <hr>
    <p style="text-align: center; color: #6c757d;"><em>Generated by Verified Taint Chains Analyzer</em></p>
</body>
</html>
"""
        return html

    def _format_plain_text(self, explanation: Explanation, chain: TaintChain) -> str:
        """Format explanation as plain text.

        Args:
            explanation: Explanation to format.
            chain: Associated TaintChain.

        Returns:
            Plain text-formatted string.
        """
        confidence = self.calculate_confidence(chain)
        path = " -> ".join(node.variable_name for node in chain.path)

        text = f"""
{'=' * 70}
{chain.vulnerability_type.value.replace('_', ' ').upper()} VULNERABILITY
{'=' * 70}

SEVERITY: {explanation.severity}
CWE: {explanation.cwe_id or 'N/A'}
CONFIDENCE: {confidence:.0%}
STATUS: {chain.verification_status.value if chain.verification_status else 'Not verified'}

DATA FLOW:
{path}

Source: {chain.source.variable_name} ({chain.source.type}) at line {chain.source.location.line_number}
Sink: {chain.sink.variable_name} ({chain.sink.type}) at line {chain.sink.location.line_number}

WHY THIS IS VULNERABLE:
{explanation.why_vulnerable}

HOW TO FIX:
{explanation.how_to_fix}

EXAMPLE FIX:
{explanation.example_fix}

{'=' * 70}
Generated by Verified Taint Chains Analyzer
{'=' * 70}
"""
        return text

    def _format_json(self, explanation: Explanation, chain: TaintChain) -> str:
        """Format explanation as JSON.

        Args:
            explanation: Explanation to format.
            chain: Associated TaintChain.

        Returns:
            JSON-formatted string.
        """
        confidence = self.calculate_confidence(chain)

        data = {
            "vulnerability": {
                "type": chain.vulnerability_type.value,
                "severity": explanation.severity,
                "cwe_id": explanation.cwe_id,
                "confidence": confidence,
                "verification_status": chain.verification_status.value if chain.verification_status else None,
            },
            "data_flow": {
                "path": [node.variable_name for node in chain.path],
                "source": {
                    "variable": chain.source.variable_name,
                    "type": chain.source.type,
                    "location": {
                        "file": chain.source.location.file_path,
                        "line": chain.source.location.line_number,
                    },
                    "confidence": chain.source.confidence,
                },
                "sink": {
                    "variable": chain.sink.variable_name,
                    "type": chain.sink.type,
                    "location": {
                        "file": chain.sink.location.file_path,
                        "line": chain.sink.location.line_number,
                    },
                    "confidence": chain.sink.confidence,
                },
            },
            "explanation": {
                "why_vulnerable": explanation.why_vulnerable,
                "how_to_fix": explanation.how_to_fix,
                "example_fix": explanation.example_fix,
            },
        }

        return json.dumps(data, indent=2)
