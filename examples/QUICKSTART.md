# Quick Start Guide

## Running Analysis on the Vulnerable Example

### Step 1: Setup

```bash
# Navigate to project directory
cd verified-taint-chains

# Install dependencies
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### Step 2: Run Analysis

```bash
# Basic analysis
python -m src analyze --file examples/VulnerableExample.java

# With verbose output
python -m src analyze --file examples/VulnerableExample.java --verbose

# Custom output file
python -m src analyze --file examples/VulnerableExample.java --output reports/vuln_analysis.json
```

### Step 3: Review Results

```bash
# View the generated results
cat results.json

# Or with pretty printing
python -m json.tool results.json

# View with a text editor
nano results.json
```

## What to Expect

### Console Output

The tool will display:

```
🔍 Running security analysis...

✓ Results saved to results.json

Pipeline Analysis Results
========================
Source File: examples/VulnerableExample.java
Timestamp: 2024-01-29T10:30:45.123456

Chains Analysis:
  Total chains found: 4
  Chains verified: 4
  Verification rate: 100.0%

Metrics:
  sources_found: 4
  sinks_found: 4
  chains_found: 4
  chains_verified: 4
  verification_rate: 1.0
  explanations_generated: 4
  graph_nodes: 8
  graph_edges: 4

Explanations Generated: 4

📊 Analysis Metrics:
──────────────────────────────────────────────
  Sources Found.......................4
  Sinks Found..........................4
  Chains Found.........................4
  Chains Verified......................4
  Verification Rate...................100.0%
  Explanations Generated................4
  Graph Nodes...........................8
  Graph Edges...........................4
──────────────────────────────────────────────

⚠️  Found 4 verified vulnerable chain(s)!
```

### JSON Results

The `results.json` file contains:

```json
{
  "source_file": "examples/VulnerableExample.java",
  "total_chains": 4,
  "verified_chains": 4,
  "explanations": {
    "sql_injection_chain": {
      "severity": "CRITICAL",
      "cwe_id": "CWE-89",
      "why_vulnerable": "User input flows directly into SQL query..."
    },
    "command_injection_chain": {
      "severity": "CRITICAL",
      "cwe_id": "CWE-78",
      "why_vulnerable": "User input used in command execution..."
    },
    ...
  },
  "metrics": {
    "sources_found": 4,
    "sinks_found": 4,
    "chains_found": 4,
    "chains_verified": 4,
    ...
  },
  "timestamp": "2024-01-29T10:30:45.123456"
}
```

## Exploring Vulnerabilities

### View Configuration
```bash
python -m src config
```

### Get Help
```bash
python -m src --help
python -m src analyze --help
python -m src help-env
```

### View Version
```bash
python -m src version
```

## Understanding the Results

### Vulnerability Analysis

The tool identified 4 vulnerabilities in the example:

1. **SQL Injection** (Line 32)
   - Source: `userId` parameter
   - Sink: `stmt.executeQuery(query)`
   - Severity: CRITICAL
   - CWE: CWE-89

2. **Command Injection** (Line 43)
   - Source: `filename` parameter
   - Sink: `Runtime.getRuntime().exec()`
   - Severity: CRITICAL
   - CWE: CWE-78

3. **Cross-Site Scripting** (Line 54)
   - Source: `userComment` parameter
   - Sink: HTML output
   - Severity: MEDIUM
   - CWE: CWE-79

4. **Path Traversal** (Line 65)
   - Source: `filePath` parameter
   - Sink: `Files.readAllBytes()`
   - Severity: HIGH
   - CWE: CWE-22

### Data Flow Tracking

Each vulnerability shows:
- **Source**: Where untrusted data enters (HTTP parameters)
- **Path**: How data flows through the code
- **Sink**: Where dangerous operations occur
- **Verification**: Whether the path is actually reachable
- **Explanation**: How the vulnerability works and how to fix it

## Next Steps

### 1. Fix the Vulnerabilities
See the fixes in the README.md file to learn how to correct these issues.

### 2. Re-analyze Fixed Code
Create a corrected version and re-run the analysis to verify no vulnerabilities remain.

### 3. Test with Your Own Code
Create a test Java file with your own vulnerabilities and run the analysis.

### 4. Run the Test Suite
```bash
# Run all tests
pytest tests/ -v

# Run specific test suite
pytest tests/integration/test_pipeline_integration.py -v

# Run with coverage
pytest tests/ --cov=src
```

## Troubleshooting

### Missing OPENAI_API_KEY
```
❌ Configuration Error: OPENAI_API_KEY environment variable is required
```
**Solution**: Add your API key to `.env` file:
```
OPENAI_API_KEY=sk-your-key-here
```

### File Not Found
```
❌ File not found: examples/VulnerableExample.java
```
**Solution**: Make sure you're in the correct directory and the file path is correct.

### Too Many Requests (Rate Limited)
The tool will automatically retry with exponential backoff. If still failing:
- Wait a few minutes
- Check your OpenAI API quota
- Verify your API key is valid

### No Chains Found
If the analysis finds 0 chains:
- Lower the `MIN_CONFIDENCE` threshold in `.env`
- Check that the code has clear sources and sinks
- Enable verbose mode to see what was detected

## Advanced Usage

### Batch Analysis
```bash
# Analyze multiple files
for file in examples/*.java; do
  python -m src analyze --file "$file" --output "results_$(basename $file .java).json"
done
```

### Different Configuration
```bash
# Use different LLM model
export OPENAI_MODEL=gpt-4
python -m src analyze --file examples/VulnerableExample.java

# Lower confidence threshold
export MIN_CONFIDENCE=0.3
python -m src analyze --file examples/VulnerableExample.java

# Disable verification
export VERIFICATION_ENABLED=false
python -m src analyze --file examples/VulnerableExample.java
```

### Process Results
```python
import json

# Load and analyze results
with open('results.json') as f:
    results = json.load(f)

# Print vulnerabilities
for chain_id, explanation in results['explanations'].items():
    print(f"{chain_id}: {explanation['severity']}")
```

## Performance Tips

1. **Start Small**: Test on a single file first
2. **Enable Caching**: Use default configuration for better performance
3. **Adjust Thresholds**: Lower `MAX_PATH_LENGTH` for faster analysis
4. **Batch Processing**: Process multiple files in parallel
5. **Monitor API Usage**: Keep track of OpenAI API usage

## Getting Help

- Check the main README.md
- Review CLAUDE.md for architecture
- Run `python -m src --help` for CLI help
- Check `.env.example` for configuration options
- Review test files for usage examples
