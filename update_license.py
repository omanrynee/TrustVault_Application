#!/usr/bin/env python3
"""
Script to update TrustVault to MIT License
"""

import os
from pathlib import Path

# 1. Create LICENSE file
LICENSE_CONTENT = """MIT License

Copyright © 2026 Oman Ryne. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

# Write LICENSE file
with open("LICENSE", "w") as f:
    f.write(LICENSE_CONTENT)
print("✓ Created LICENSE file")

# 2. Update main.py with license header
HEADER = '''"""
TrustVault - Advanced File Integrity Monitoring System
Copyright © 2026 Oman Ryne. All Rights Reserved.

MIT License
See LICENSE file for full license text.
"""\n\n'''

# Read main.py and prepend header
try:
    with open("main.py", "r") as f:
        content = f.read()
    
    if not content.startswith('"""'):
        with open("main.py", "w") as f:
            f.write(HEADER + content)
        print("✓ Updated main.py with license header")
except FileNotFoundError:
    print("⚠ main.py not found, skipping")

print("\n✅ MIT License implementation complete!")
print("Next steps:")
print("1. Update About dialog in your GUI code")
print("2. Add headers to other key source files")
print("3. Update README.md with license info")
