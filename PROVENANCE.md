# Source and extraction notes

Source checkout: `qkd-demo-apps`, commit
`fb332e2` (`Fixed localhost SameAccess policy`).

| New file/directory | Source |
| --- | --- |
| `src/qkd_kms/simulator.py` | `src/kms/mock_kms_server.py`, adapted |
| `src/qkd_kms/web.py` | `src/kms/mock_kms_web.py`, adapted |
| `src/qkd_kms/static/` | `src/kms/static/`, adapted |
| `src/qkd_kms/presets/` | `src/kms/presets/`, copied |
| Simulation regression tests | Selected standalone cases from `tests/test_mock_kms_server.py` |

The buffer and stochastic rate model, metric history, presets and legacy JSON
socket protocol are retained. Portal authentication, portal database access,
managed-session tokens and physical-KMS lease routing were removed. Dashboard
portal links, hardware reservation controls and references to external font
assets were removed. Standalone dashboard password login remains available.
The CLI now binds locally and uses a random seed unless one is supplied.

`client.py`, the package exports, AES example, packaging, documentation, CI,
and adapter/AES integration tests are new. The original `mock_qkd_kms014.py` and
`ThinkQuantumKMS.py` informed the adapter boundary, but were not copied: the new
clients use a consistent single-key return type and decoded bytes. The real
adapter speaks ETSI HTTPS directly and needs no vendor-specific library.

Excluded: all existing certificates and private keys (including root CA keys),
machine-specific hardware settings and paths, SNMP tools, deployment settings,
the portal, relay and application code, and all original Git history.

No top-level license was found in the source checkout. This extraction does not
assign a new license or change ownership. Before public release, the owners
should confirm permission to redistribute these files and choose a license.
The new repository is local; no GitHub repository has been created or published.
