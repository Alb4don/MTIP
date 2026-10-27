### `MTIP`

- ingests public Android threat intelligence in STIX 2.1, deduplicates indicators across feeds and correlates them against malware families, campaigns and intrusion sets. 

<img width="1263" height="539" alt="mtip_frontend" src="https://github.com/user-attachments/assets/95217c58-b23e-49db-98b6-30e937f9ae9b" />

### `Install`

      install.bat                         create .venv, install dependencies, run the self-check
      run.bat                             desktop window, or the browser if PySide6 is unavailable
      run.bat serve                       web interface at http://127.0.0.1:8765/
      run.bat import bundle.json          --source my-feed
      run.bat correlate                   run correlation and print statistics as JSON
      run.bat migrate                     apply schema migrations after taking a backup
      run.bat doctor                      check Python, dependencies, data folder and port

- If startup fails, run doctor. It lists every dependency with its installed version.
- A missing package is named together with the exact pip command for the interpreter that is actually running.
- Other settings are environment variables:

      | Variable | Default | Effect |
      |---|---|---|
      | MTIP_PORT | 8765 | Listening port; a busy port falls back to a free one, and the URL is printed |
      | MTIP_MAX_UPLOAD_MB | 64 | Largest accepted STIX upload |
      | MTIP_RATE_LIMIT | 600 | API requests per minute per client |
      | MTIP_ALLOW_PRIVATE_TAXII | off | Permit TAXII servers on private networks; enable only for an internal server you trust |

### `Getting data`

- Upload a STIX 2.1 bundle in the Import view, or use `import` on the command line. Each upload belongs to a named source. 
- Re-importing an identical file for the same source is detected by SHA-256 and skipped. 
- TAXII 2.1 collections can be discovered and pulled from the same view, optionally restricted with added_after.

- Recognised observable types:
 
      | STIX path | Indicator kind |
      |---|---|
      | domain-name:value | domain (IP literals become ipv4/ipv6) |
      | url:value | url |
      | ipv4-addr:value, ipv6-addr:value | ipv4, ipv6 |
      | email-addr:value | email |
      | file:hashes MD5, SHA-1, SHA-256 | md5, sha1, sha256 |
      | file:name, file:path, process:name | file_name, file_path, process_name |
      | app:id`, software:x_android_package | app_id (Android package) |
      | app:cert.sha256 / sha1, x509-certificate:hashes | cert_sha256, cert_sha1 |
      | android-property:name | android_property |

- The platform was validated against three public sources: MITRE ATT&CK Mobile (mitre-attack/attack-stix-data), the Echap stalkerware indicators (AssoEchap/stalkerware-indicators) 
- And the Amnesty Tech investigations (AmnestyTech/investigations). Together they load 10,201 canonical indicators in about 13 seconds.

### `Reports and API`

- The Reports view exports an HTML report, a JSON report and a STIX 2.1 bundle.
- A CSV export of all indicators and their association status ships as a feature module.
- The interface sits on a local REST API under `/api/v1`:

      | Endpoints | Purpose |
      |---|---|
      | health, overview, metrics/history | status, metrics, history per run |
      | indicators, indicators/{id} | filter by kind, association status or source; full provenance per indicator |
      | inferences, feedback | review inferences; confirm or reject them |
      | sources, entities, graph | reliability and import history; families and campaigns; campaign graph |
      | imports/file, taxii/discover, taxii/import | ingestion, run as background jobs |
      | correlation/run, jobs, jobs/{id} | start a run; poll job status |
      | reports/{json,html,stix}, features | exports; loaded feature modules |
 
- State changing calls need the per-launch token from the served page in an `X-MTIP-Token` header. Interactive API docs are disabled.

### `Tests`

      pip install -r requirements-dev.txt
      pytest
      MTIP_REAL_DATA=/path/to/feeds pytest

- The suite has 175 tests:
 
- Unit tests for normalisation, the statistics (checked against exact integer arithmetic), import, the engine and the service layer
- BDD scenarios in `tests/bdd/features`
- Hypothesis fuzzing of the normaliser, pattern parser, JSON guards, importer and API
- security tests for headers, CSRF, injection, upload limits, SSRF and error leakage
- performance budgets
- A static check that every third-party import is declared in the requirements

- The real feed end-to-end test runs when `MTIP_REAL_DATA` points to a folder containing the three public sources.
