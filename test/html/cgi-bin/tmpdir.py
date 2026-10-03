#!/usr/bin/env python3

import os

print("Content-Type: text/plain")
print()
print("hex($TMPDIR):", os.environb.get(b"TMPDIR", b"").hex())
