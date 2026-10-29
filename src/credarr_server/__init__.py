"""The credarr server package: the working copy the app reads and writes.

The engine (`credarr`) stays the only implementation of audit, plan and
rotation. What lives here is state the command line did not need to keep:
the topology, and next the HTTP layer over it.
"""
