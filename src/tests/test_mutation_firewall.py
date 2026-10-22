Python
import json
import os
import pytest
from jsonschema import validate, ValidationError

def test_firewall_schema_exists():
    assert os.path.exists("schemas/mutation_firewall_schema.json"), "Mutation firewall schema missing!"

def test_valid_mutation_record():
    schema_path = "schemas/mutation_firewall_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    valid_payload = {
        "mutation_id": "c7a8b9d0-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
        "timestamp": "2026-10-22T14:55:00Z",
        "source_module": "src-300.ts",
        "mutation_type": "STATE_WRITE",
        "cryptographic_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "judicial_compliance_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        "sentinel_verification_sig": "f0e9d8c7b6a543210fedcba9876543210fedcba9876543210fedcba987654321"
    }

    validate(instance=valid_payload, schema=schema)

def test_invalid_mutation_type_fails():
    schema_path = "schemas/mutation_firewall_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    invalid_payload = {
        "mutation_id": "c7a8b9d0-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
        "timestamp": "2026-10-22T14:55:00Z",
        "source_module": "src-300.ts",
        "mutation_type": "UNAUTHORIZED_ACTION",  # Invalid enum type
        "cryptographic_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "judicial_compliance_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        "sentinel_verification_sig": "f0e9d8c7b6a543210fedcba9876543210fedcba9876543210fedcba987654321"
    }

    with pytest.raises(ValidationError):
        validate(instance=invalid_payload, schema=schema)
300-Character Description for mutation-firewall
Plaintext
The mutation-firewall repository enforces deterministic state protection for BEAST
