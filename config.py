import os
BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
INSTITUTION = "SLIIT Northern Uni"
NODES = ["University-A", "Employer-B", "Institute-C"]      # 3 organisations (permissioned network)
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://127.0.0.1:5000")
OFFICIAL_DOMAIN = "127.0.0.1"                              # domain the QR code is expected to point to
# Hook for Blue Team (C2/C4): baseline | vertical | horizontal
DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "baseline")
