Requirements
============

- ``netaddr``

What
====

- read a list of IPs or IP ranges and perform ``whois`` and return owner of the
  associated range
- if an IP is already part of a tested IP range, the ``whois`` request is not
  performed


Why
===

- fw rules analysis
- red team/external pentests
