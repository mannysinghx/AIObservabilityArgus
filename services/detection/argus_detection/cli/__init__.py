"""Command-line entry points.

The detection *service* is pure — no disk, no network, no clock. The CLI is the
other half of that bargain: it is the edge component that holds the file, does
the reading, and hands the service a manifest. Keeping it in this package means
the CLI and the service run byte-identical rule code, so a verdict in CI and a
verdict in the dashboard can never disagree about what the allowlist says.
"""
