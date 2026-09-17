"""Static reverse engineering of files attackers upload to the honeypot.

Everything in this package reads bytes and returns facts. Nothing here
executes a sample, loads it as code, writes it to disk, or contacts any host
or URL found inside it; the analysis runs in a separate, resource-limited
process (see ``sandbox``) because every parser is fed input an attacker chose.

Deliberately free of application imports — no settings, no database — so the
sandboxed worker never needs the secrets the API process holds.
"""
