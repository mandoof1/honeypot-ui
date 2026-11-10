"""Fingerprint self-audit: how far the decoys are from the daemons they claim to be.

Vetterl and Clayton ("Bitter Harvest", USENIX WOOT '18) tell honeypots from
real servers by sending a handful of probes to both and comparing the
answers. This package runs that comparison against the project's own decoys:
the same probe bytes go to a decoy and to a stock install of the daemon it
imitates, and every difference is written down.

It is a measuring instrument for the team's own software and only talks to
loopback addresses. See README.md in this directory.
"""

#: Written into every result file so a reader can tell which layout it has.
SCHEMA = "honeysentinel.fingerprint-audit/1"

PROTOCOLS = ("ssh", "ftp", "http", "telnet")
