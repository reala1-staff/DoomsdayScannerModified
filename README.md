# DoomsdayScannerModified
Doomsday Client Scanner v3 — PowerShell forensic scanner made by Real. Detects Doomsday Client traces using Prefetch, USN Journal, JAR analysis, byte signatures and evidence-based detection.
# Doomsday Client Scanner

A PowerShell forensic scanner designed to detect traces and possible installations of **Doomsday Client** on Windows systems.

The scanner analyzes Java-related Prefetch data, referenced files, JAR contents, byte signatures, class patterns and NTFS USN Journal activity to provide multiple sources of evidence instead of relying on a single filename or location.

## Features

- Scans Windows Java Prefetch entries
- Extracts file references from Prefetch
- Supports Windows 10 and Windows 11 Prefetch formats
- Searches referenced files across available drives
- Detects JAR files even when the extension has been changed
- Analyzes `.class` files inside JAR archives
- Searches for known Doomsday byte patterns
- Detects suspicious class structures and obfuscation patterns
- Uses the NTFS USN Journal to check recent file activity
- Calculates SHA-256 hashes for analyzed files
- Uses an evidence-based detection score
- Displays detailed detection information
- Generates a forensic JSON report

## Detection System

The scanner does not rely on a single indicator.

Different pieces of evidence contribute to the final detection score. Strong Doomsday-specific signatures have significantly more weight than generic indicators such as obfuscated class names or a renamed JAR.

Results are classified by confidence:

| Confidence | Meaning |
|---|---|
| HIGH | Strong evidence associated with Doomsday was detected |
| MEDIUM | Multiple suspicious indicators were detected |
| LOW | Some indicators were found, but they are not enough for a strong detection |
| NONE | No relevant indicators were detected |

A detection should always be reviewed together with the evidence displayed by the scanner.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer
- Administrator privileges
- NTFS filesystem for USN Journal analysis
- Windows Prefetch enabled for Prefetch-based detection

Some detection methods may not be available if Prefetch or the USN Journal has been disabled or cleared.

## Usage

Download:

```text
doomsday-scanner-v2.ps1
```

Open PowerShell or Windows Terminal as **Administrator**.

Go to the directory containing the scanner:

```powershell
cd "C:\Path\To\Scanner"
```

Run:

```powershell
.\doomsday-scanner-v2.ps1
```

If PowerShell prevents the script from running because of the local execution policy, review your PowerShell execution-policy settings rather than disabling system protections globally.

## How It Works

The scanner follows several stages.

### 1. Prefetch Analysis

Windows Prefetch entries related to Java are inspected and file references are extracted.

This can reveal files previously accessed during Java execution even when their original names or locations are no longer immediately obvious.

### 2. Path Resolution

Extracted paths are checked against the available drives on the system.

If a referenced file is no longer present at its expected location, the scanner can compare that information with recent NTFS activity.

### 3. USN Journal Analysis

On supported NTFS volumes, recent filesystem activity from the USN Journal is collected.

This provides additional forensic context for referenced files that may have recently changed or disappeared.

### 4. JAR Analysis

Candidate JAR/ZIP files are opened and their Java classes are inspected.

The scanner looks for several indicators, including:

- Known byte signatures
- Known class patterns
- Obfuscated single-letter classes
- JAR/ZIP files using unexpected extensions

Generic indicators alone have a lower impact on the final result to reduce false positives.

### 5. Evidence Scoring

All relevant indicators are combined into a detection score.

The final confidence level is based on the strength and combination of the available evidence rather than one generic characteristic.

### 6. Report

Detected files include useful forensic information such as:

- File path
- Detection score
- Confidence
- SHA-256
- File size
- File timestamps
- Matched byte signatures
- Matched class indicators
- Renamed JAR status
- Available filesystem evidence

A JSON report is also generated so results can be reviewed or archived after the scan.

## False Positives

No forensic scanner should treat every suspicious characteristic as definitive proof.

For example, Java applications may legitimately contain:

- Obfuscated classes
- Single-letter class names
- ZIP/JAR data with unusual extensions

For this reason, these characteristics are treated as supporting indicators rather than definitive Doomsday signatures.

Known binary signatures and combinations of independent evidence receive greater weight.

## Important

This project is intended for defensive analysis and authorized ScreenShare/forensic environments.

Only scan systems you own or have permission to inspect.

The scanner reports technical indicators. A detection should be evaluated using the evidence shown instead of treating the confidence label alone as absolute proof.

## Version

**Doomsday Client Scanner v2**

Main improvements over the original version:

- Improved detection scoring
- Better false-positive handling
- USN Journal integration
- SHA-256 collection
- Improved JAR analysis
- Higher class-analysis limits
- Better scan performance
- More detailed evidence
- JSON forensic reports

## Credits

Original scanner concept and signatures:

**iTake (@cheatinformer) @ FM Forensics**

Additional improvements and modifications can be credited separately by repository maintainers.

## Disclaimer

This software is provided for educational, defensive and forensic purposes.

The authors and contributors are not responsible for misuse of the software or actions performed without authorization.
