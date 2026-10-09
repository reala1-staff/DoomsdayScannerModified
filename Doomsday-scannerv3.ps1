        if ($row.Key -eq 'Errors' -and $script:ScanErrors.Count -gt 0) { $color = 'Yellow' }
        Write-Host ('  {0,-22} {1}' -f $row.Key, $row.Value) -ForegroundColor $color
    }
    Write-Host ''
    if ($high -gt 0) { Write-Host 'Doomsday client found on this system.' -ForegroundColor Red }
    elseif ($detections.Count -gt 0) { Write-Host 'Possible Doomsday traces found. Review the evidence above.' -ForegroundColor Yellow }
    else { Write-Host 'No Doomsday client detected.' -ForegroundColor Green }

    if ($script:ScanErrors.Count -gt 0 -and $script:Options.DebugLog) {
        Write-Host ''
        Write-Host 'Errors' -ForegroundColor Yellow
        foreach ($e in $script:ScanErrors) { Write-Host "  [$($e.Stage)] $($e.Target): $($e.Message)" -ForegroundColor DarkGray }
    }

    if ($script:Options.NoJson) { Write-Host ''; return }

    $report = [ordered]@{
        Scanner    = [ordered]@{
            Name           = 'Doomsday Client Scanner'
            Version        = $script:ScannerVersion
            ScanStartedUtc = Format-IsoTime $startedUtc
            ScanFinishedUtc = Format-IsoTime $finishedUtc
            DurationSeconds = [Math]::Round(($finishedUtc - $startedUtc).TotalSeconds, 1)
            Computer       = $env:COMPUTERNAME
            User           = "$env:USERDOMAIN\$env:USERNAME"
            OS             = "$osName build $($os.Build)"
            PowerShell     = $PSVersionTable.PSVersion.ToString()
        }
        Settings   = [ordered]@{
            RecentMinutes    = $script:Options.RecentMinutes
            MaxFileSizeMB    = [int]($script:Options.MaxFileBytes / 1MB)
            ScanPath         = @($script:Options.ScanPath)
            UsnEnabled       = -not $script:Options.NoUsn
            KnownHashes      = $script:KnownHashes.Count
            Weights          = $script:Weights
            Thresholds       = $script:Thresholds
        }
        Summary    = [ordered]@{
            PrefetchParsed   = $prefetch.Parsed
            PrefetchFiles    = $prefetch.Files.Count
            HistoricalPaths  = $script:Refs.Count
            ReferenceStates  = $refStates
            FilesAnalyzed    = $checked
            Archives         = $analyzed.Count
            Candidates       = $jars.Count
            Detections       = $detections.Count
            High             = $high
            Medium           = $medium
            Low              = $low
            ManualReview     = $suspicious.Count
            TooLarge         = @($tooLarge | ForEach-Object { [ordered]@{ Path = $_.Path; Size = $_.Stat.Size } })
            Errors           = $script:ScanErrors.Count
        }
        Detections = @($detections | ForEach-Object { ConvertTo-ReportCandidate $_ })
        ManualReview = @($suspicious | ForEach-Object { ConvertTo-ReportCandidate $_ })
        Archives   = @($analyzed | Where-Object { -not $_.Assessment.Detected -and -not $_.Assessment.Suspicious } | ForEach-Object {
                [ordered]@{ Path = $_.Path; Sources = @($_.Sources); Size = $_.Stat.Size; Sha256 = $_.Sha256; ClassEntries = $_.Jar.ClassEntries; Score = $_.Assessment.Score }
            })
        History    = @($script:Refs.Values | Where-Object { $_.State -ne 'Present' } | ForEach-Object {
                [ordered]@{
                    Path          = $_.Path
                    RawPath       = $_.RawPath
                    State         = $_.State
                    Detail        = $_.StateDetail
                    CurrentPath   = $_.CurrentPath
                    VolumeMapping = $_.ResolveMethod
                    DeletedUtc    = Format-IsoTime $_.DeletedUtc
                    FileIds       = @($_.FileIds | ForEach-Object { '0x{0:X16}' -f $_ })
                    Prefetch      = @($_.Prefetch | ForEach-Object { [ordered]@{ Prefetch = $_.Name; LastRunUtc = Format-IsoTime $_.LastRunUtc } })
                    RecentLinks   = @($_.Links | ForEach-Object { $_.Link })
                    Usn           = @(ConvertTo-ReportEvents $_.Usn)
                }
            })
        UsnDeletedJars = @($script:UsnOnlyHistory | Select-Object -First 500 | ForEach-Object {
                [ordered]@{ Path = $_.Path; DeletedUtc = Format-IsoTime $_.TimeUtc; FileId = $_.FileId; Usn = @(ConvertTo-ReportEvents $_.Timeline) }
            })
        Prefetch   = [ordered]@{
            Directory        = $prefetch.Directory
            TotalFiles       = $prefetch.TotalPrefetch
            OldestCreatedUtc = Format-IsoTime $prefetch.OldestPrefetch
            EnablePrefetcher = $prefetch.Settings.EnablePrefetcher
            SysMain          = $prefetch.Settings.SysMain
            Java             = @($prefetch.Files | ForEach-Object {
                    $info = $_.Info
                    [ordered]@{
                        Name       = $_.Name
                        Error      = $_.Error
                        Version    = if ($info) { $info.Version } else { $null }
                        Compressed = if ($info) { $info.Compressed } else { $null }
                        Executable = if ($info) { $info.Executable } else { $null }
                        RunCount   = if ($info) { $info.RunCount } else { $null }
                        LastRunsUtc = if ($info) { @($info.LastRunsUtc | ForEach-Object { Format-IsoTime $_ }) } else { @() }
                        Files      = if ($info) { $info.Files.Count } else { 0 }
                        Volumes    = if ($info) { @($info.Volumes | ForEach-Object { [ordered]@{ Device = $_.DevicePath; Serial = $_.Serial.ToString('X8') } }) } else { @() }
                        Warnings   = if ($info) { @($info.Warnings) } else { @() }
                    }
                })
        }
        UsnJournals = @($script:UsnJournals | ForEach-Object {
                [ordered]@{
                    Drive       = $_.Drive
                    Available   = $_.Available
                    Error       = $_.Error
                    CreatedUtc  = Format-IsoTime $_.CreatedUtc
                    OldestUtc   = Format-IsoTime $_.OldestUtc
                    NewestUtc   = Format-IsoTime $_.NewestUtc
                    RecordsRead = $_.RecordsRead
                    RecordsKept = $_.RecordsKept
                    Truncated   = $_.Truncated
                    MaximumSize = $_.MaximumSize
                }
            })
        Errors     = @($script:ScanErrors)
    }

    $path = Get-ReportPath
    try {
        $folder = Split-Path -Parent $path
        if ($folder -and -not (Test-Path -LiteralPath $folder)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
        $json = $report | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
        Write-Host ''
        Write-Good "Report saved: $path"
    }
    catch {
        Write-Warn "Could not write the report to ${path}: $(Get-ErrorText $_)"
    }
    Write-Host ''
