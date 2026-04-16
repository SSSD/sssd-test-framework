from __future__ import annotations

test_venv = "/opt/test_venv"
test_venv_bin = f"{test_venv}/bin"
scauto_path = f"{test_venv_bin}/scauto"

USER_RESOLVABLE_ATTEMPTS: int = 15
"""Maximum number of polling attempts when waiting for a user to become resolvable by SSSD."""

USER_RESOLVABLE_INTERVAL_S: int = 2
"""Seconds to sleep between each polling attempt when waiting for a user to be resolvable."""

USER_RESOLVABLE_CACHE_EXPIRY_ATTEMPT: int = 3
"""Attempt number at which ``sss_cache -E`` is called to flush the SSSD cache."""
