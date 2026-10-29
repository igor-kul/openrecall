import sys

# openrecall.config parses sys.argv at import time; hide pytest's own
# arguments so they are not rejected as unknown OpenRecall options.
sys.argv = sys.argv[:1]
