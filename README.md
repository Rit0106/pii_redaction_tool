# PII Redaction Tool

A Python-based tool that detects and redacts Personally Identifiable Information (PII) from `.docx` documents, replacing each PII instance with a realistic fake alternative while maintaining document formatting.

## Approach

This tool uses a **hybrid multi-layer detection strategy** combining three complementary techniques:

### 1. Regex-Based Detection (`detectors.py → RegexDetector`)
Curated regular expression patterns detect **structured PII** with high precision:
- **Email addresses** — standard email format matching
- **Phone numbers** — Indian (+91), US, and international formats
- **Social Security Numbers** — US SSN format (XXX-XX-XXXX)
- **Credit card numbers** — Visa, MasterCard, AmEx, Discover, JCB (with and without separators)
- **IP addresses** — IPv4 and IPv6
- **Dates of birth** — DD/MM/YYYY, YYYY-MM-DD, and natural language formats (e.g., "January 15, 1990")
- **Indian identifiers** — Aadhaar (12-digit) and PAN numbers
- **Enrollment/roll numbers** — Academic ID patterns

### 2. NER-Based Detection (`detectors.py → NERDetector`)
spaCy's Named Entity Recognition model (`en_core_web_sm`) detects **unstructured PII**:
- **Person names** (PERSON → NAME)
- **Organizations** (ORG → ORGANIZATION)
- **Locations** (GPE/LOC/FAC → LOCATION)

A curated skip-list filters out technology names (React, Spring Boot, PostgreSQL) that NER may incorrectly flag as organizations.

### 3. Context-Aware Address Detection (`detectors.py → AddressDetector`)
Addresses are notoriously difficult for pure regex or NER. This detector combines:
- Street/road keywords (Road, Lane, Colony, Nagar, etc.)
- Indian PIN codes (6-digit patterns)
- State name matching
- JSON structure parsing for addresses in code samples

### Consistent Replacement (`replacer.py`)
The `ConsistentReplacer` ensures:
- The **same PII always maps to the same fake** (e.g., every occurrence of "Ritika Raj" becomes "John Doe")
- **Name-email consistency** — if "Ritika Raj" → "John Doe", then "ritika.raj@email.com" → "john.doe@example.com"
- **Format preservation** — phone number format, date format, separator style are maintained
- Uses the **Faker** library for realistic fake data generation

## Project Structure

```
pii-redaction-tool/
├── pii_redactor.py      # Main script — orchestrates detection + redaction
├── detectors.py         # All detection logic (Regex, NER, Address)
├── replacer.py          # Consistent fake replacement engine
├── evaluate.py          # Evaluation script with ground truth + metrics
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## Installation

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Usage

### Basic Redaction
```bash
python pii_redactor.py input_document.docx
```
Output: `input_document_redacted.docx`

### Custom Output Path
```bash
python pii_redactor.py input.docx --output redacted_output.docx
```

### With Detection Report
```bash
python pii_redactor.py input.docx --output redacted.docx --report
```

### Run Evaluation
```bash
python evaluate.py input_document.docx --output evaluation_report.md
```

## Tradeoffs & Design Decisions

| Decision | Rationale |
|:---------|:----------|
| **Hybrid approach** (regex + NER) instead of pure NER | Regex gives near-perfect precision on structured PII; NER handles the unstructured types that regex can't cover |
| **spaCy `en_core_web_sm`** instead of larger models | Smaller model is faster and sufficient for common name/org/location detection; can be upgraded to `en_core_web_lg` for better accuracy |
| **Skip-list for tech terms** | Prevents NER from flagging "Spring Boot", "React.js" etc. as organizations. Trade-off: may miss a real company named similarly |
| **Longest-first replacement** | Replaces longer PII strings first to prevent partial matches (e.g., "NIT Agartala" before "NIT") |
| **Conservative phone number matching** | Requires 7+ digits to avoid false positives on years, IDs, etc. |
| **Enrollment numbers treated as PII** | Academic enrollment numbers can identify individuals; explicitly detected and redacted |

## Known Limitations

1. **Abbreviations**: Short abbreviations (NIC, NIT) may not always be detected by NER as organizations
2. **Code samples**: URLs and hostnames in code snippets (e.g., `localhost:8081`) may or may not be treated as PII
3. **Cross-run PII**: When a name spans multiple formatting runs in the .docx, the replacement may lose inline formatting for that specific span
4. **Address detection**: Addresses not following standard patterns (no street keywords, no PIN code) may be missed
5. **False positives**: NER may flag some proper nouns (technology frameworks, project names) as organizations

## Extending to New PII Types

To add detection for a new PII type (e.g., passport numbers):

1. **Add a regex pattern** in `detectors.py → RegexDetector._build_patterns()`:
   ```python
   ("PASSPORT", re.compile(r'\b[A-Z]\d{7}\b'), 0.85),
   ```

2. **Add a replacement method** in `replacer.py → ConsistentReplacer`:
   ```python
   def _replace_passport(self, text: str) -> str:
       return f"X{random.randint(1000000, 9999999)}"
   ```

3. **Add the dispatch** in `replacer.py → _generate_replacement()`:
   ```python
   elif pii_type == "PASSPORT":
       return self._replace_passport(text)
   ```

4. **Add ground truth** entries in `evaluate.py` for evaluation.

## Evaluation

Run the evaluation to see precision/recall/F1 scores:
```bash
python evaluate.py input_document.docx
```

See `evaluation_report.md` for detailed results.
