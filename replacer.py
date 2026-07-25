"""
PII Redaction Tool - Replacer Module
=====================================
Generates consistent fake replacements for detected PII entities.
Uses the Faker library for realistic fake data, with a deterministic
mapping so the same original PII always maps to the same fake value.
"""

import hashlib
import random
from typing import Dict
from faker import Faker


class ConsistentReplacer:
    """
    Generates fake PII replacements with consistency guarantees:
    - Same input text always produces the same fake output
    - Names map to realistic fake names
    - Emails map to realistic fake emails (matching the fake name)
    - Addresses map to realistic fake addresses
    - All other types get format-preserving replacements
    """

    def __init__(self, seed: int = 42):
        self.fake = Faker()
        Faker.seed(seed)
        random.seed(seed)

        # Cache for consistency: same PII text -> same fake replacement
        self._cache: Dict[str, str] = {}

        # Track name -> fake name mapping for email consistency
        self._name_map: Dict[str, str] = {}

        # Pre-generate a pool of fake names for variety
        self._name_pool = [
            ("John", "Doe"), ("Jane", "Smith"), ("Peter", "Parker"),
            ("Mary", "Johnson"), ("Robert", "Williams"), ("Sarah", "Brown"),
            ("Michael", "Davis"), ("Emily", "Wilson"), ("David", "Taylor"),
            ("Lisa", "Anderson"), ("James", "Thomas"), ("Emma", "Martinez"),
            ("William", "Garcia"), ("Olivia", "Robinson"), ("Daniel", "Clark"),
            ("Sophia", "Lewis"), ("Alexander", "Walker"), ("Isabella", "Hall"),
            ("Benjamin", "Allen"), ("Mia", "Young"), ("Christopher", "King"),
            ("Charlotte", "Wright"), ("Matthew", "Lopez"), ("Amelia", "Hill"),
        ]
        self._name_index = 0

    def _get_seed_for_text(self, text: str) -> int:
        """Generate a deterministic seed from text for reproducible fakes."""
        return int(hashlib.md5(text.lower().strip().encode()).hexdigest(), 16) % (2**31)

    def _next_fake_name(self) -> tuple:
        """Get the next fake name from the pool, cycling if needed."""
        name = self._name_pool[self._name_index % len(self._name_pool)]
        self._name_index += 1
        return name

    def replace(self, original_text: str, pii_type: str) -> str:
        """
        Generate a fake replacement for the given PII text.

        Args:
            original_text: The original PII string detected in the document
            pii_type: The category of PII (NAME, EMAIL, PHONE, etc.)

        Returns:
            A fake replacement string of the same PII type
        """
        # Check cache first for consistency
        cache_key = f"{pii_type}:{original_text.lower().strip()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Generate replacement based on type
        replacement = self._generate_replacement(original_text, pii_type)

        # Cache the result
        self._cache[cache_key] = replacement
        return replacement

    def _generate_replacement(self, text: str, pii_type: str) -> str:
        """Generate a type-specific fake replacement."""

        if pii_type == "NAME":
            return self._replace_name(text)
        elif pii_type == "EMAIL":
            return self._replace_email(text)
        elif pii_type == "PHONE":
            return self._replace_phone(text)
        elif pii_type == "SSN":
            return self._replace_ssn(text)
        elif pii_type == "CREDIT_CARD":
            return self._replace_credit_card(text)
        elif pii_type == "IP_ADDRESS":
            return self._replace_ip(text)
        elif pii_type == "DATE_OF_BIRTH":
            return self._replace_dob(text)
        elif pii_type == "ORGANIZATION":
            return self._replace_organization(text)
        elif pii_type == "LOCATION":
            return self._replace_location(text)
        elif pii_type == "ADDRESS":
            return self._replace_address(text)
        elif pii_type == "AADHAAR":
            return self._replace_aadhaar(text)
        elif pii_type == "PAN":
            return self._replace_pan(text)
        elif pii_type == "ENROLLMENT_NUMBER":
            return self._replace_enrollment(text)
        else:
            return "[REDACTED]"

    def _replace_name(self, text: str) -> str:
        """Replace a person's name with a fake name."""
        first, last = self._next_fake_name()

        # Detect if it's a full name or just first/last
        parts = text.strip().split()
        if len(parts) == 1:
            fake_name = first
        elif len(parts) == 2:
            fake_name = f"{first} {last}"
        else:
            # Multi-part name (e.g., with title or middle name)
            fake_name = f"{first} {last}"

        # Store the mapping for email consistency
        self._name_map[text.lower().strip()] = fake_name
        return fake_name

    def _replace_email(self, text: str) -> str:
        """Replace an email with a fake email, trying to match the associated name."""
        local_part = text.split('@')[0]

        # Try to find a matching name in our mapping
        for original_name, fake_name in self._name_map.items():
            # Check if email's local part resembles the name
            name_parts = original_name.lower().split()
            local_lower = local_part.lower().replace('.', ' ').replace('_', ' ').replace('-', ' ')

            if any(part in local_lower for part in name_parts if len(part) > 2):
                # Build email from the fake name
                fake_parts = fake_name.lower().split()
                fake_local = '.'.join(fake_parts)
                return f"{fake_local}@example.com"

        # No matching name found, generate a generic fake email
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        first, last = self._next_fake_name()
        return f"{first.lower()}.{last.lower()}@example.com"

    def _replace_phone(self, text: str) -> str:
        """Replace a phone number with a fake one, preserving format."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)

        # Check if it has Indian format
        if text.strip().startswith('+91'):
            digits = ''.join([str(random.randint(0, 9)) for _ in range(10)])
            return f"+91 {digits[:5]} {digits[5:]}"
        elif text.strip().startswith('+'):
            # International format
            country_code = text.strip().split()[0] if ' ' in text else text[:3]
            digits = ''.join([str(random.randint(0, 9)) for _ in range(10)])
            return f"{country_code} {digits}"
        else:
            # US/generic format
            area = str(random.randint(200, 999))
            mid = str(random.randint(200, 999))
            last = str(random.randint(1000, 9999))
            if '(' in text:
                return f"({area}) {mid}-{last}"
            elif '-' in text:
                return f"{area}-{mid}-{last}"
            else:
                return f"{area} {mid} {last}"

    def _replace_ssn(self, text: str) -> str:
        """Replace SSN with a fake one, preserving format."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        area = str(random.randint(100, 665))
        group = str(random.randint(1, 99)).zfill(2)
        serial = str(random.randint(1, 9999)).zfill(4)

        if '-' in text:
            return f"{area}-{group}-{serial}"
        elif ' ' in text:
            return f"{area} {group} {serial}"
        else:
            return f"{area}{group}{serial}"

    def _replace_credit_card(self, text: str) -> str:
        """Replace credit card with a fake one."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        digits = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        # Use 4000 prefix (test card)
        digits = '4000' + digits[4:]

        if '-' in text:
            return f"{digits[0:4]}-{digits[4:8]}-{digits[8:12]}-{digits[12:16]}"
        elif ' ' in text:
            return f"{digits[0:4]} {digits[4:8]} {digits[8:12]} {digits[12:16]}"
        else:
            return digits

    def _replace_ip(self, text: str) -> str:
        """Replace IP address with a fake one in the reserved range."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)

        if ':' in text:
            # IPv6
            parts = [f"{random.randint(0, 65535):04x}" for _ in range(8)]
            return ':'.join(parts)
        else:
            # IPv4 - use 10.x.x.x private range
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _replace_dob(self, text: str) -> str:
        """Replace a date of birth with a fake date."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        fake_date = self.fake.date_of_birth(minimum_age=20, maximum_age=65)

        # Detect the format and match it
        if '/' in text:
            return fake_date.strftime('%d/%m/%Y')
        elif '-' in text and text[0:4].isdigit():
            return fake_date.strftime('%Y-%m-%d')
        elif '-' in text:
            return fake_date.strftime('%d-%m-%Y')
        elif any(m in text for m in ['January', 'February', 'March', 'April', 'May',
                                      'June', 'July', 'August', 'September', 'October',
                                      'November', 'December']):
            if text[0].isdigit():
                return fake_date.strftime('%d %B %Y')
            else:
                return fake_date.strftime('%B %d, %Y')
        else:
            return fake_date.strftime('%d/%m/%Y')

    def _replace_organization(self, text: str) -> str:
        """Replace organization name with a fake one."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)

        # Pool of fake organization names
        fake_orgs = [
            "Meridian Technologies", "Atlas Corporation", "Pinnacle Systems",
            "Nexus Solutions", "Vertex Industries", "Horizon Digital",
            "Catalyst Innovations", "Quantum Analytics", "Apex Enterprises",
            "Stellar Computing", "Prisma Labs", "Zenith Software",
            "Polaris Research", "Summit Technologies", "Helix Data Systems",
        ]
        return fake_orgs[seed % len(fake_orgs)]

    def _replace_location(self, text: str) -> str:
        """Replace a location/city/state with a fake one."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)

        fake_locations = [
            "Springfield", "Riverside", "Greenfield", "Lakewood",
            "Fairview", "Hillcrest", "Meadowbrook", "Oakville",
            "Pinewood", "Silverdale", "Crestview", "Maplewood",
        ]
        return fake_locations[seed % len(fake_locations)]

    def _replace_address(self, text: str) -> str:
        """Replace a physical address with a fake one."""
        seed = self._get_seed_for_text(text)
        Faker.seed(seed)
        return self.fake.address().replace('\n', ', ')

    def _replace_aadhaar(self, text: str) -> str:
        """Replace Aadhaar number with a fake 12-digit number."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        digits = ''.join([str(random.randint(0, 9)) for _ in range(12)])
        digits = str(random.randint(2, 9)) + digits[1:]  # First digit must be 2-9

        if ' ' in text:
            return f"{digits[0:4]} {digits[4:8]} {digits[8:12]}"
        elif '-' in text:
            return f"{digits[0:4]}-{digits[4:8]}-{digits[8:12]}"
        else:
            return digits

    def _replace_pan(self, text: str) -> str:
        """Replace PAN number with a fake one."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        letters1 = ''.join([chr(random.randint(65, 90)) for _ in range(5)])
        digits = ''.join([str(random.randint(0, 9)) for _ in range(4)])
        letter2 = chr(random.randint(65, 90))
        return f"{letters1}{digits}{letter2}"

    def _replace_enrollment(self, text: str) -> str:
        """Replace enrollment/roll number with a fake one."""
        seed = self._get_seed_for_text(text)
        random.seed(seed)
        year = str(random.randint(20, 26))
        dept = ''.join([chr(random.randint(65, 90)) for _ in range(3)])
        num = str(random.randint(1, 200)).zfill(3)
        return f"{year}{dept}{num}"
