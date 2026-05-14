# CheckIntegrityLinux

## Prerequisites
pip install - r requirements.txt

# Usage

Scan common folders recursively:

```bash
python3 CheckIntegrity.py ~/Documents

python3 CheckIntegrity.py ~/Desktop

python3 CheckIntegrity.py ~

python3 CheckIntegrity.py ~/Downloads
```

Or scan them all at once

```bash
python3 CheckIntegrity.py ~/Documents ~/Downloads ~/Pictures
```

Statuses:

- `OK`: no obvious corruption found.
- `Suspicious`: the file could be read, but a caution condition was found.
- `Corrupt`: validation found a broken header, parser error, or structure issue.
- `Error`: the file could not be opened or inspected.

This tool is a quick integrity check, not a forensic recovery tool. A clean
result means no obvious corruption was detected by the checks implemented here.
