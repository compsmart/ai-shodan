import os
import tempfile

# Point the package at a throwaway database before anything imports netsearch.config.
os.environ["NETSEARCH_HOME"] = tempfile.mkdtemp(prefix="netsearch-test-")
