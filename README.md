# DoomsdayScannerModified

**Doomsday Client Scanner v3** is a PowerShell forensic script made by **Real** for detecting traces of the Doomsday ghost client on Windows.

The scanner combines multiple sources of local evidence instead of relying only on filenames or known locations.

## Features

- Java Prefetch analysis
- NTFS USN Journal analysis
- JAR/ZIP inspection by file content
- Known Doomsday byte signatures
- Class structure analysis
- Detection of renamed or disguised archives
- Nested archive inspection
- SHA-256 hashing
- Recent file activity analysis
- Evidence-based scoring
- JSON forensic reports
- Windows 10 / Windows 11 support
- PowerShell 5.1+ support

## Usage

No installer is required.

The scanner is a standalone PowerShell script:

```text
Doomsday-scannerv3.ps1
```

Open **PowerShell as Administrator**, open the folder containing the script and run:

```powershell
.\Doomsday-scannerv3.ps1
```

### Scan an additional folder

You can also specify folders that should be scanned recursively:

```powershell
.\Doomsday-scannerv3.ps1 -ScanPath "$env:APPDATA\.minecraft"
```

### Debug output

```powershell
.\Doomsday-scannerv3.ps1 -DebugLog
```

### Custom report location

```powershell
.\Doomsday-scannerv3.ps1 -OutputPath "C:\Reports"
```

## How detection works

DoomsdayScannerModified does not automatically flag a file just because it has a suspicious name or extension.

The scanner collects several types of evidence and combines them into a detection score.

### Strong evidence

Known Doomsday bytecode signatures and known hashes are treated as the strongest indicators.

### Structural evidence

The scanner analyzes Java class structures and known class patterns associated with the client.

### Secondary evidence

Additional characteristics can increase confidence, including:

- JAR content hidden behind another extension
- Hidden class data
- Suspicious archive structure
- Java Agent metadata
- NTFS alternate data streams
- Obfuscation characteristics

These indicators alone are not considered enough to prove that a file is Doomsday.

### Context evidence

Windows artifacts can provide additional context:

- Java Prefetch
- NTFS USN Journal
- Recent file activity

Context shows that a file may have existed or been used, but does not identify the file as Doomsday by itself.

## Detection levels

| Result | Meaning |
|---|---|
| `HIGH` | Strong Doomsday-specific evidence was found |
| `MEDIUM` | Relevant evidence was found but should be reviewed |
| `NONE` | Not enough evidence for a detection |

The scanner also displays the evidence responsible for the final result.

## USN Journal

On NTFS drives, the scanner can inspect the Windows USN Journal to obtain additional filesystem context.

This can help identify recent activity involving files referenced by other forensic artifacts.

The scanner distinguishes between:

- Existing files
- Historical references
- Recent filesystem activity
- Rename activity
- Possible deletion evidence

A missing Prefetch path is **not automatically considered a deleted cheat**.

## JAR Analysis

Archives are inspected by their actual contents rather than only their extension.

This means the scanner can analyze Java archives even when they have been renamed or disguised.

The scanner can inspect:

- `.jar`
- `.zip`
- archives using unexpected extensions
- Java class files
- nested archives

Class files are analyzed individually to avoid treating unrelated data from different archive entries as one signature.

## Scoring

Doomsday-specific evidence has significantly more weight than generic characteristics.

For example:

```text
Score: 85/100
Confidence: HIGH

Evidence:
[+] Known Doomsday byte signature
[+] Matching class structure
[+] Referenced by Java Prefetch
[i] Recent NTFS activity
[i] SHA-256 calculated
```

A renamed JAR, obfuscated classes or recent filesystem activity alone should not produce a strong Doomsday detection.

## Reports

After a scan, the script can generate a structured JSON forensic report containing information such as:

```text
Scanner version
Scan time
File path
SHA-256
File size
Timestamps
Detection score
Confidence
Matched signatures
Matched classes
Prefetch evidence
USN evidence
Detection reasons
Errors and warnings
```

This makes it easier to review the result after the ScreenShare.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer
- Administrator privileges recommended
- NTFS for USN Journal functionality

Some evidence sources may be unavailable when Windows Prefetch or the NTFS USN Journal is disabled or has been cleared.

## Parameters

```powershell
# Normal scan
.\Doomsday-scannerv3.ps1

# Scan additional location
.\Doomsday-scannerv3.ps1 -ScanPath "C:\SomeFolder"

# Change recent USN time window
.\Doomsday-scannerv3.ps1 -RecentMinutes 120

# Change maximum candidate file size
.\Doomsday-scannerv3.ps1 -MaxFileSizeMB 256

# Disable USN analysis
.\Doomsday-scannerv3.ps1 -NoUsn

# Disable JSON report
.\Doomsday-scannerv3.ps1 -NoJson

# Enable debug information
.\Doomsday-scannerv3.ps1 -DebugLog
```

## False positives

No single generic Java characteristic should be considered proof of a ghost client.

Legitimate Java software can contain:

- Obfuscated classes
- Short class names
- Unusual archive structures
- Renamed archives

For this reason, DoomsdayScannerModified gives stronger weight to Doomsday-specific signatures and combinations of independent evidence.

Always review the evidence shown by the scanner before making a decision.

## Privacy

The scanner performs its analysis locally.

It does not require an external API or cloud service to perform the scan.

The forensic report is generated locally on the computer.

## Credits

**DoomsdayScannerModified v3**

Made by **Real**

Based on the original Doomsday detection concept and signatures by:

**iTake (@cheatinformer) @ FM Forensics**

## Disclaimer

This project is intended for defensive analysis, authorized ScreenShares and forensic research.

Only use it on systems you own or have permission to inspect.

A detection represents technical evidence found by the scanner and should be reviewed before reaching a conclusion.
