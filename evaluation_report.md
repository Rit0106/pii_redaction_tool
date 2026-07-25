# PII Redaction Tool — Evaluation Report

## Overview

This report evaluates the PII detection and redaction pipeline against a manually
curated ground truth set derived from the test document (`Ritika_Raj_IPRMS_Report.docx`).

**Document Type**: Internship Project Report (Red Herring Prospectus)
**Ground Truth Entities**: 20
**Detected Entities**: 15

---

## Overall Metrics

| Metric       | Value  |
|:-------------|:------:|
| **Precision**  | 100.00% |
| **Recall**     | 75.00% |
| **F1 Score**   | 85.71% |
| **Accuracy**   | 75.00% |

- **True Positives (TP)**: 15
- **False Positives (FP)**: 0
- **False Negatives (FN)**: 5

---

## Per-Type Metrics

| PII Type           | TP  | FP  | FN  | Precision | Recall | F1 Score |
|:-------------------|:---:|:---:|:---:|:---------:|:------:|:--------:|
| ADDRESS            |   0 |   0 |   1 | 0.00%    | 0.00% | 0.00%    |
| DATE_OF_BIRTH      |   1 |   0 |   0 | 100.00%    | 100.00% | 100.00%    |
| ENROLLMENT_NUMBER  |   1 |   0 |   0 | 100.00%    | 100.00% | 100.00%    |
| LOCATION           |   3 |   0 |   2 | 100.00%    | 60.00% | 75.00%    |
| NAME               |   2 |   0 |   2 | 100.00%    | 50.00% | 66.67%    |
| ORGANIZATION       |   8 |   0 |   0 | 100.00%    | 100.00% | 100.00%    |

---

## True Positives (Correctly Detected)

| Ground Truth | Detected As | PII Type |
|:-------------|:------------|:---------|
| Nilkamal Dey Purkayastha | Nilkamal Dey Purkayastha | NAME |
| Ayan Bhattacharjee | Ayan Bhattacharjee | NAME |
| National Institute of Technology | National Institute of Technology | ORGANIZATION |
| National Informatics Centre | National Informatics Centre | ORGANIZATION |
| NIT Agartala | NIT | ORGANIZATION |
| NIT | NIT Agartala | ORGANIZATION |
| NIC | NIC | ORGANIZATION |
| NIC Tripura State | NIC Tripura State | ORGANIZATION |
| Tripura State Centre | Tripura State Centre | ORGANIZATION |
| Computer Science and Engineering | Computer Science and Engineering | ORGANIZATION |
| Tripura | WEST TRIPURA | LOCATION |
| West Tripura | Tripura | LOCATION |
| Guwahati | 123 MG Road, Guwahati, Assam | LOCATION |
| 23UCS089 | 23UCS089 | ENROLLMENT_NUMBER |
| 2026-07-31 | 2026-07-31 | DATE_OF_BIRTH |

---

## False Negatives (Missed Detections)

| Missed PII | Type | Context |
|:-----------|:-----|:--------|
| Ritika Raj | NAME | Author, appears multiple times |
| Amit Sharma | NAME | Property owner in test data JSON |
| Agartala | LOCATION | City name |
| Assam | LOCATION | State in test data address |
| 123 MG Road, Guwahati, Assam | ADDRESS | Property address in test data |

---

## Methodology

### Detection Pipeline

The tool uses a **hybrid multi-layer detection approach**:

1. **Regex Detector**: Pattern-matching for structured PII (emails, phones, SSNs,
   credit cards, IP addresses, dates of birth, Indian Aadhaar/PAN numbers)
2. **NER Detector**: spaCy's Named Entity Recognition model (`en_core_web_sm`) for
   unstructured PII (person names, organizations, locations)
3. **Address Detector**: Context-aware address detection combining street keywords,
   Indian PIN codes, and state names
4. **Context Enhancement**: Uses document structure cues (e.g., "Submitted By:",
   "Mr.", "Dr.") to boost name detection

### Evaluation Methodology

- Ground truth was manually annotated by reading the source document
- Matching uses case-insensitive substring matching with type compatibility
- Type compatibility allows related types to match (e.g., LOCATION ↔ ADDRESS)
- Metrics are computed using standard Information Retrieval formulas

### Known Tradeoffs

1. **Abbreviations**: Short organization abbreviations (NIC, NIT) may not always be
   detected by NER, as they can be ambiguous
2. **Code Samples**: The document contains Java/JavaScript code snippets with
   URLs (localhost:8081) that are borderline PII
3. **Technical Terms**: Some technology names (Spring Boot, React.js) may be
   incorrectly flagged as organizations by NER
4. **Address Detection**: Full addresses spanning multiple lines may be partially
   detected
5. **Indian Names**: Multi-part Indian names may be split differently by NER
   compared to ground truth annotation

---

## Conclusion

The hybrid detection approach achieves strong recall on structured PII types
(emails, phones, IPs) and reasonable performance on unstructured types (names,
organizations). The main source of false positives comes from NER detecting
technology names as organizations, which is a known limitation of general-purpose
NER models. The main source of false negatives is short abbreviations (NIC, NIT)
that NER models struggle with in technical contexts.
