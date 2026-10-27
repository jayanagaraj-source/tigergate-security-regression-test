"""Placeholder credentials as they appear in templates and sample configuration."""
import os

GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # SEC-FP-006
API_KEY = "your-api-key-here"  # SEC-FP-007
DB_PASSWORD = "changeme"  # SEC-FP-008
AUTH_TOKEN = "${AUTH_TOKEN}"  # SEC-FP-009
STRIPE_KEY = os.environ["STRIPE_KEY"]  # SEC-FP-010
