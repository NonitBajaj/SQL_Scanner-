import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ANSI color codes for prettier output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'