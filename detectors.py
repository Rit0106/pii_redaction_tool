"""
PII Redaction Tool - Detectors Module
=====================================
Contains all PII detection logic: regex-based patterns and NER-based entity recognition.
Each detector returns a list of PIIEntity objects with span info, type, and confidence.
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class PIIEntity:
    """Represents a detected PII entity in text."""
    start: int          # Start character offset
    end: int            # End character offset
    text: str           # The matched text
    pii_type: str       # Category: NAME, EMAIL, PHONE, etc.
    confidence: float   # Detection confidence (0.0 - 1.0)
    source: str         # Detection method: "regex" or "ner"

    def __hash__(self):
        return hash((self.start, self.end, self.pii_type))

    def __eq__(self, other):
        return (self.start == other.start and
                self.end == other.end and
                self.pii_type == other.pii_type)


class RegexDetector:
    """
    Detects structured PII using curated regular expression patterns.
    Covers: emails, phone numbers, SSNs, credit cards, IPs, dates of birth,
    and Indian-specific identifiers (Aadhaar, PAN).
    """

    def __init__(self):
        self.patterns = self._build_patterns()

    def _build_patterns(self) -> List[Tuple[str, re.Pattern, float]]:
        """
        Returns a list of (pii_type, compiled_regex, confidence) tuples.
        Order matters - more specific patterns should come first.
        """
        return [
            # ── Email Addresses ──
            ("EMAIL", re.compile(
                r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
            ), 0.99),

            # ── Social Security Numbers (US format) ──
            ("SSN", re.compile(
                r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b'
            ), 0.90),

            # ── Credit Card Numbers (major brands) ──
            ("CREDIT_CARD", re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
                r'|5[1-5][0-9]{14}'                       # MasterCard
                r'|3[47][0-9]{13}'                        # AmEx
                r'|6(?:011|5[0-9]{2})[0-9]{12}'           # Discover
                r'|(?:2131|1800|35\d{3})\d{11})\b'        # JCB
            ), 0.85),

            # ── Credit Card with separators (e.g. 4111-1111-1111-1111) ──
            ("CREDIT_CARD", re.compile(
                r'\b(?:\d{4}[-\s]){3}\d{4}\b'
            ), 0.70),

            # ── IP Addresses (IPv4) ──
            ("IP_ADDRESS", re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ), 0.95),

            # ── IP Addresses (IPv6 - simplified) ──
            ("IP_ADDRESS", re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            ), 0.90),

            # ── Phone Numbers (Indian format) ──
            ("PHONE", re.compile(
                r'(?:\+91[\s\-]?)?(?:\(?0?\d{2,4}\)?[\s\-]?)?\d{5}[\s\-]?\d{5}\b'
            ), 0.85),

            # ── Phone Numbers (International/US format) ──
            ("PHONE", re.compile(
                r'(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b'
            ), 0.85),

            # ── Phone Numbers (with country code) ──
            ("PHONE", re.compile(
                r'\+\d{1,3}[\s\-]?\d{4,14}\b'
            ), 0.80),

            # ── Aadhaar Number (Indian 12-digit UID) ──
            ("AADHAAR", re.compile(
                r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b'
            ), 0.75),

            # ── PAN Number (Indian) ──
            ("PAN", re.compile(
                r'\b[A-Z]{5}\d{4}[A-Z]\b'
            ), 0.90),

            # ── Dates of Birth (various formats) ──
            ("DATE_OF_BIRTH", re.compile(
                r'\b(?:(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2})\b'  # DD/MM/YYYY
            ), 0.80),

            ("DATE_OF_BIRTH", re.compile(
                r'\b(?:(?:19|20)\d{2}[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01]))\b'  # YYYY/MM/DD
            ), 0.80),

            ("DATE_OF_BIRTH", re.compile(
                r'\b(?:(?:January|February|March|April|May|June|July|August|September|October|November|December)'
                r'\s+\d{1,2},?\s+\d{4})\b',
                re.IGNORECASE
            ), 0.75),

            ("DATE_OF_BIRTH", re.compile(
                r'\b(?:\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)'
                r',?\s+\d{4})\b',
                re.IGNORECASE
            ), 0.75),

            # ── Enrollment/Roll Numbers (contextual) ──
            ("ENROLLMENT_NUMBER", re.compile(
                r'\b(?:Enroll(?:ment)?\s*(?:No|Number)?[\s:.]*\s*)(\d{2}[A-Z]{2,4}\d{2,4})\b',
                re.IGNORECASE
            ), 0.90),
        ]

    def detect(self, text: str) -> List[PIIEntity]:
        """Run all regex patterns against the text and return detected entities."""
        entities = []
        for pii_type, pattern, confidence in self.patterns:
            for match in pattern.finditer(text):
                # For enrollment numbers, we capture the group
                if pii_type == "ENROLLMENT_NUMBER" and match.lastindex:
                    start = match.start(1)
                    end = match.end(1)
                    matched_text = match.group(1)
                else:
                    start = match.start()
                    end = match.end()
                    matched_text = match.group()

                # Skip very short matches that are likely false positives
                if len(matched_text.strip()) < 3:
                    continue

                # Filter out common false positives for phone numbers
                if pii_type == "PHONE":
                    digits_only = re.sub(r'\D', '', matched_text)
                    if len(digits_only) < 7 or len(digits_only) > 15:
                        continue
                    # Skip if it looks like a year (4 digits only)
                    if len(digits_only) == 4:
                        continue

                # Filter out IP addresses that are actually version numbers
                if pii_type == "IP_ADDRESS":
                    # Check context - if preceded by 'v' or 'version', skip
                    if start > 0 and text[start-1:start].lower() in ('v', '.'):
                        continue

                entities.append(PIIEntity(
                    start=start,
                    end=end,
                    text=matched_text,
                    pii_type=pii_type,
                    confidence=confidence,
                    source="regex"
                ))

        return entities


class NERDetector:
    """
    Detects unstructured PII using spaCy's Named Entity Recognition.
    Covers: PERSON names, ORG (companies), GPE/LOC (locations/addresses).

    Includes extensive false-positive filtering for technical documents
    containing code snippets, framework names, and section headings.
    """

    def __init__(self, model_name: str = "en_core_web_sm"):
        import spacy
        try:
            self.nlp = spacy.load(model_name)
        except OSError:
            print(f"Downloading spaCy model '{model_name}'...")
            from spacy.cli import download
            download(model_name)
            self.nlp = spacy.load(model_name)

    # Mapping from spaCy entity labels to our PII types
    LABEL_MAP = {
        "PERSON": "NAME",
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",          # Geo-Political Entity (countries, cities, states)
        "LOC": "LOCATION",          # Non-GPE locations
        "FAC": "LOCATION",          # Facilities (buildings, airports, bridges)
    }

    # ── Comprehensive skip list for non-PII entities ──
    # Includes: tech frameworks, Java/Spring class names, SQL types,
    # document section headings, generic terms, code constructs
    SKIP_ENTITIES = {
        # Programming languages & frameworks
        "react", "react.js", "reactjs", "spring boot", "spring", "postgresql",
        "postgres", "jwt", "json web token", "vite", "axios", "jpa", "hibernate",
        "java", "javascript", "python", "html", "css", "sql", "rest", "restful",
        "node", "node.js", "angular", "vue", "tomcat", "maven", "gradle",
        "spring data jpa", "spring security", "react router", "context api",

        # API/HTTP terms
        "api", "apis", "http", "https", "get", "post", "put", "delete",
        "bearer", "content-type", "authorization",

        # Project/domain acronyms
        "ipr", "hrms", "nextgen", "nextgen hrms", "hod", "spa", "crud",
        "dto", "dtos", "uid", "ui", "dsc", "pdf",

        # SQL/database types & keywords
        "boolean", "varchar", "bigint", "numeric", "timestamp", "varchar(255",
        "date", "text", "null", "default", "primary key", "foreign key",
        "unique", "not null", "nullable", "sequence", "cascade", "acid",

        # Status enums
        "draft", "submitted", "approved", "returned", "created",

        # Role enums
        "role_employee", "role_hod", "role_authority",

        # Relation/type enums
        "self", "spouse", "joint", "purchase", "gift", "inheritance",
        "land", "house", "apartment",

        # Service groups
        "ias", "scs", "ips",

        # Libraries & tools
        "pdf", "pdfbox", "itext", "javamailsender", "sms",
        "form vi",

        # Common technical terms NER misflags
        "property", "employees", "employee", "authority", "authorities",
        "users", "objectives", "bonafide", "data layer", "data access",
        "single page application", "bachelor of technology",
        "assistant professor", "technical director",

        # Java class names that NER might detect
        "employeecontroller", "employeeservice", "employeeresponse",
        "propertycontroller", "propertyservice", "propertyrequest",
        "propertyresponse", "responseentity", "httpstatus",
        "exceptionhandler", "errorresponse", "preauthorize",
        "iprdeclaration", "iprreturn", "requiredargsconstructor",
        "restcontrolleradvice", "globalexceptionhandler",

        # Common non-PII phrases the NER picks up
        "head of department", "heads of departments",
        "data transfer objects", "digital signature certificates",
        "presentation layer", "business logic layer",
        "not_found", "string", "json",
        "frontend api", "global exception handling framework",
        "exception handler", "exception handling",
        "dto decoupling pattern", "jakarta",

        # Section headings / document structure phrases
        "agartala",  # city name used as section header
        "ipr return", "ipr module", "ipr id", "ipr management system",
        "ipr return management module", "immovable property returns",
        "returned ipr", "property management module",
        "employee dashboards & profiles module",
        "backend validation layer", "future enhancements",
        "database design & entity relationships",
        "architectural flow & employee",
        "authentication & authorization",
        "security & method-level authorization",
        "input data constraints", "manage property records",
        "multi-step form syncing", "property service operations",
        "verify filing window", "create or load ipr return draft",
        "cadre/service", "department, office",
        "authorities, employees", "ipr return, property",

        # National org abbreviations (these ARE real orgs but context-specific)
        # We keep them detectable but add the full forms
    }

    def _is_code_or_heading(self, text: str) -> bool:
        """
        Heuristic check: is this text actually a code snippet, section heading,
        or table header rather than real PII?
        """
        stripped = text.strip()

        # Contains newlines — likely a multi-line block incorrectly merged
        if '\n' in stripped:
            return True

        # Contains code-like symbols: parentheses, braces, dots (method calls)
        code_indicators = ['(', ')', '{', '}', '=', ';', '::', '&&', '||',
                           '->', '=>', '\\', '//', '/*', '*/']
        code_count = sum(1 for c in code_indicators if c in stripped)
        if code_count >= 1:
            return True

        # Contains a dot AND is not a known org name pattern
        # (catches ex.getMessage, java.util etc but not "N.I.T.")
        if '.' in stripped and re.search(r'[a-z]\.[a-z]', stripped):
            return True

        # Looks like a Java/Spring class name (PascalCase with no spaces)
        if re.match(r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$', stripped):
            return True

        # All uppercase + looks like a section heading (more than 2 words)
        words = stripped.split()
        if len(words) > 2 and all(w.isupper() or w in {'&', 'OF', 'AND', 'THE', 'IN', 'FOR'} for w in words):
            return True

        # Contains quotes (JSON key/value)
        if '"' in stripped or "'" in stripped:
            return True

        # Starts with "the " — likely a phrase, not an entity name
        if stripped.lower().startswith("the "):
            return True

        # Contains http/localhost
        if 'http' in stripped.lower() or 'localhost' in stripped.lower():
            return True

        # Contains Java-like package names
        if re.search(r'[a-z]+\.[a-z]+\.[a-z]+', stripped):
            return True

        # Contains a colon followed by text (section heading pattern)
        if ':' in stripped and not stripped.endswith(':'):
            return True

        # Ends with colon (heading pattern like "State Machine Coordination:")
        if stripped.endswith(':'):
            return True

        # Contains '&' with surrounding words — section heading style
        if '&' in stripped and len(stripped.split()) > 2:
            return True

        # Ends with common module/layer/pattern words
        heading_suffixes = ['module', 'layer', 'pattern', 'patterns', 'framework',
                           'operations', 'constraints', 'records', 'enhancements',
                           'relationships', 'syncing', 'integration', 'window',
                           'authorization', 'verification', 'validation']
        if any(stripped.lower().endswith(s) for s in heading_suffixes):
            return True

        # Contains "Logo Placeholder"
        if 'placeholder' in stripped.lower():
            return True

        return False

    def _is_plausible_name(self, text: str) -> bool:
        """Check if the text looks like a plausible person name."""
        stripped = text.strip()
        words = stripped.split()

        # Names typically have 2-4 words, each capitalized
        if len(words) < 1 or len(words) > 5:
            return False

        # Each word should be capitalized and alphabetic
        for word in words:
            if not word[0].isupper():
                return False
            if not re.match(r'^[A-Za-z\.\-\']+$', word):
                return False

        return True

    def _is_plausible_org(self, text: str) -> bool:
        """Check if the text looks like a plausible organization name."""
        stripped = text.strip()

        # Must be at least 2 characters
        if len(stripped) < 2:
            return False

        # Should not be longer than ~60 characters typically
        if len(stripped) > 80:
            return False

        # Should not contain obvious code elements
        if any(c in stripped for c in ['{', '}', '()', ';', '=', '::']):
            return False

        return True

    def detect(self, text: str) -> List[PIIEntity]:
        """Run spaCy NER on text and return detected PII entities."""
        doc = self.nlp(text)
        entities = []

        for ent in doc.ents:
            pii_type = self.LABEL_MAP.get(ent.label_)
            if not pii_type:
                continue

            ent_text = ent.text.strip()

            # Skip known non-PII entities (case-insensitive)
            if ent_text.lower() in self.SKIP_ENTITIES:
                continue

            # Skip very short entities (likely false positives)
            if len(ent_text) < 2:
                continue

            # Skip if it looks like code, a heading, or table data
            if self._is_code_or_heading(ent.text):
                continue

            # Type-specific validation
            if pii_type == "NAME":
                if not self._is_plausible_name(ent_text):
                    continue
                # Skip common role/title words mistaken for names
                if ent_text.lower() in {"employee", "authority", "supervisor",
                                         "guide", "mentor", "director", "professor",
                                         "aadhaar", "frontend api",
                                         "assistant professor", "technical director"}:
                    continue

            elif pii_type == "ORGANIZATION":
                if not self._is_plausible_org(ent_text):
                    continue

            elif pii_type == "LOCATION":
                # Skip single-word locations that are common English words
                if len(ent_text.split()) == 1:
                    if ent_text.lower() in {"the", "a", "an", "this", "that", "it",
                                             "its", "employee", "jakarta"}:
                        continue

            # Determine confidence based on entity label
            confidence = 0.80 if pii_type == "NAME" else 0.70

            entities.append(PIIEntity(
                start=ent.start_char,
                end=ent.end_char,
                text=ent_text,
                pii_type=pii_type,
                confidence=confidence,
                source="ner"
            ))

        return entities


class AddressDetector:
    """
    Detects physical/mailing addresses using contextual regex patterns.
    Addresses are hard to detect with pure NER or regex alone, so this
    uses a combination of street keywords, PIN codes, and contextual clues.
    """

    # Indian PIN code pattern
    PIN_PATTERN = re.compile(r'\b[1-9]\d{5}\b')

    # Address keywords
    ADDRESS_KEYWORDS = re.compile(
        r'\b(?:Road|Rd|Street|St|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
        r'Colony|Nagar|Marg|Path|Gali|Sector|Block|Plot|House\s*No|'
        r'Flat\s*No|Floor|Building|Tower|Apartment|Apt|Suite|'
        r'Near|Opposite|Behind|Adjacent|PO\s*Box|P\.?O\.?\s*Box|'
        r'MG\s*Road|NH[\s\-]?\d+|SH[\s\-]?\d+)\b',
        re.IGNORECASE
    )

    # Indian state names
    INDIAN_STATES = re.compile(
        r'\b(?:Andhra Pradesh|Arunachal Pradesh|Assam|Bihar|Chhattisgarh|Goa|Gujarat|'
        r'Haryana|Himachal Pradesh|Jharkhand|Karnataka|Kerala|Madhya Pradesh|Maharashtra|'
        r'Manipur|Meghalaya|Mizoram|Nagaland|Odisha|Punjab|Rajasthan|Sikkim|Tamil Nadu|'
        r'Telangana|Tripura|Uttar Pradesh|Uttarakhand|West Bengal|'
        r'Delhi|Chandigarh|Puducherry|Ladakh|Lakshadweep|'
        r'Jammu and Kashmir|Andaman and Nicobar|Dadra and Nagar Haveli)\b',
        re.IGNORECASE
    )

    def detect(self, text: str) -> List[PIIEntity]:
        """Detect physical addresses in text."""
        entities = []

        # Look for address-like patterns
        # Strategy: Find lines/sentences containing address keywords + location info
        lines = text.split('\n')
        offset = 0

        for line in lines:
            has_address_keyword = self.ADDRESS_KEYWORDS.search(line)
            has_pin = self.PIN_PATTERN.search(line)
            has_state = self.INDIAN_STATES.search(line)

            if has_address_keyword and (has_pin or has_state):
                # Extract the address portion
                cleaned = line.strip()
                if len(cleaned) > 10:  # Minimum reasonable address length
                    start = offset + line.find(cleaned[0]) if cleaned else offset
                    entities.append(PIIEntity(
                        start=text.find(cleaned, offset),
                        end=text.find(cleaned, offset) + len(cleaned),
                        text=cleaned,
                        pii_type="ADDRESS",
                        confidence=0.75,
                        source="regex"
                    ))

            offset += len(line) + 1  # +1 for \n

        # Also detect standalone addresses in JSON-like structures
        json_addr_pattern = re.compile(
            r'"locationAddress"\s*:\s*"([^"]+)"',
            re.IGNORECASE
        )
        for match in json_addr_pattern.finditer(text):
            entities.append(PIIEntity(
                start=match.start(1),
                end=match.end(1),
                text=match.group(1),
                pii_type="ADDRESS",
                confidence=0.90,
                source="regex"
            ))

        return entities


def merge_overlapping_entities(entities: List[PIIEntity]) -> List[PIIEntity]:
    """
    Merge overlapping entity detections, keeping the higher-confidence one.
    When two entities overlap, prefer:
    1. Higher confidence
    2. Longer span (more context captured)
    3. More specific type (regex > ner for structured data)
    """
    if not entities:
        return []

    # Sort by start position, then by length (descending)
    sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
    merged = [sorted_entities[0]]

    for current in sorted_entities[1:]:
        previous = merged[-1]

        # Check for overlap
        if current.start < previous.end:
            # Keep the one with higher confidence, or longer span if equal
            if current.confidence > previous.confidence:
                merged[-1] = current
            elif (current.confidence == previous.confidence and
                  (current.end - current.start) > (previous.end - previous.start)):
                merged[-1] = current
            # Otherwise keep previous (already in merged)
        else:
            merged.append(current)

    return merged
