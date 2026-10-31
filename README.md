# Salfetka Infrastructure

Private development repository for standalone panel/node installation and versioned releases.

Status: development. No installable GitHub release is published yet.

The product is independent of the Salfetka production network. A server is identified
by a name and an IP address. One node service manages multiple VPN connections.

Planned operator flow:
1. Add a server by name and IP in your own panel.
2. Run the verified installer and enter a one-use enrollment code.
3. Select Reality, Hysteria2, gRPC and XHTTP in the panel.
4. Automatic certificates and renewal, a local cover site, and default ports.
5. Check signed versioned releases; explicit update with compatibility checks and rollback.

Do not run arbitrary scripts from the main branch on a production machine.
Installer distribution is not ready until the release is signed and Linux acceptance passes.
No production databases, subscription credentials or infrastructure secrets belong here.
