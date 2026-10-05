"""Cryptographic routines used to decrypt protection on IPAs the operator owns or is authorised to assess.

These are deliberately opt-in: no stage in the default pipeline calls them.  The ``cocos_decrypt`` stage runs
only when ``Config.cocos.decrypt`` is set (CLI ``--cocos-decrypt``), which the operator turns on explicitly for
their own apps or an authorised engagement.  The algorithms here recover keys that the app embeds in its own
binary and use them to decrypt the app's own scripts/resources; they break no transport or platform cryptography
and are the standard toolkit of a mobile-security review.
"""
from __future__ import annotations

__all__ = ["xxtea", "cocos"]
