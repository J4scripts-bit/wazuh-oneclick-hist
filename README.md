# Wazuh One-Click Historical Log Importer

**Automated historical log collection, preservation, parsing, and indexing for Ubuntu/Linux servers using Wazuh Indexer (OpenSearch).**

## Overview

Wazuh One-Click Historical Log Importer is a Python-based utility designed to simplify the collection and centralization of historical server logs for security investigations, incident response, and infrastructure auditing.

The tool automates a process that would otherwise require manually connecting to individual servers, locating and exporting log files, decompressing archives, processing different log formats, creating OpenSearch indexes, and uploading potentially millions of log entries.

With a single command, administrators can collect available historical logs from remote Ubuntu servers and import supported records into a centralized Wazuh Indexer environment.

**No Wazuh agent installation is required on the target servers.**

## Core Features

### Automated Remote Collection

Connects securely to Ubuntu servers using OpenSSH.

The user provides the target server's hostname, IP address, and desired historical collection period.

The importer handles SSH authentication and supports both passwordless sudo and environments requiring additional sudo authentication.

### Comprehensive Historical Log Collection

Collects the available `/var/log` directory, including:

- Apache2 access and error logs from multiple virtual hosts.
- Rotated and compressed historical log archives.
- Linux authentication and system logs.
- Systemd journal records.
- Package installation and update history.
- Additional readable application and service logs.

Files that cannot be automatically parsed remain preserved in the original archive.

### Evidence Preservation and Integrity Verification

Before processing, the importer creates a local evidence archive.

Original log files are preserved separately from working copies. SHA-256 checksums are generated to verify the integrity of the collected files.

Each collection is organized by server and capture timestamp, allowing administrators to maintain separate historical datasets.

A file-coverage manifest identifies which files were processed, indexed, or retained only in their original form.

### Automatic Log Processing

Recognized Apache and Linux log formats are converted into structured JSON documents.

Where supported, the importer extracts:

- Original event timestamps.
- Source server identification.
- Original filenames and line numbers.
- HTTP request methods, URLs, response codes and client IP addresses.
- Linux service, process and system information.

Unknown readable log formats are indexed separately, preserving their original content for later investigation.

For records whose timestamps cannot be reliably extracted, the importer uses collection time and marks the limitation.

### Automatic Wazuh Indexer Integration

The importer connects directly to the Wazuh Indexer through its HTTPS API.

It automatically creates the required historical indexes, validates index mappings, and uploads documents using controlled bulk operations.

Records are organized into three categories:

| Index | Purpose |
|---|---|
| `wazuh-historical-apache-*` | Apache access and error records |
| `wazuh-historical-system-*` | Ubuntu system, authentication and journal records |
| `wazuh-historical-raw-*` | Additional readable log records |

Uploads are performed in batches to reduce the impact of large datasets. Responses are validated to detect indexing failures.

### Multi-Server Support

The importer is designed for environments containing multiple Ubuntu servers.

Each server receives its own historical indexes and evidence directory.

Administrators can execute the same workflow against multiple hosts without manually configuring separate collection pipelines.

### Resume and Reprocessing Support

Previously collected archives can be reused without downloading them again.

This allows administrators to retry interrupted imports, process additional supported log formats, or upload historical data into the Indexer without repeating SSH collection.

### Search and Investigation

After indexing, historical records can be explored through the Wazuh Dashboard using OpenSearch queries.

The centralized dataset provides a foundation for:

- Historical security investigations.
- Threat hunting and suspicious activity searches.
- SSH authentication analysis.
- Apache exploit-attempt analysis.
- Privilege escalation investigations.
- Cross-server event correlation.
- Forensic timeline reconstruction.

## Technical Requirements

The importer runs on Linux or Ubuntu under WSL and requires Python 3.9 or newer, an OpenSSH client, and access to a Wazuh Indexer instance.

It uses Python's standard library and does not require additional third-party Python packages.

Target servers must provide authorized SSH access and sufficient permissions to read the requested logs.

## Security Considerations

SSH passwords, sudo credentials and Indexer authentication are requested interactively rather than stored in configuration files.

Original logs can contain sensitive information such as IP addresses, usernames, authentication events, personal data and URL tokens. Evidence archives and indexes must therefore be stored securely with appropriate access controls.

## Important Limitations

The importer is designed for **historical log collection and indexing**, not automatic compromise detection.

Bulk-imported records do not automatically execute Wazuh Manager detection rules.

Some binary formats, proprietary application logs and logs outside `/var/log` require additional processing or collection.

The tool cannot recover deleted historical records or establish that a server has never been compromised.

Its primary purpose is to make available historical evidence accessible, searchable and ready for subsequent security analysis.

## Project Goal

To provide a repeatable, agentless and largely automated solution for collecting historical Ubuntu server logs and centralizing them in Wazuh.

**Collect → Preserve → Verify → Parse → Index → Investigate.**

The project is intended to reduce manual administration, improve historical log accessibility, and support organizations conducting security assessments across multiple Linux servers.
