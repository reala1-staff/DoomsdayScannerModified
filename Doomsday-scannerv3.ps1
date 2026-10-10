    $suspicious = @($analyzed | Where-Object { $_.Assessment.Suspicious } | Sort-Object { $_.Assessment.Score } -Descending)
    $high = @($detections | Where-Object { $_.Assessment.Confidence -eq 'HIGH' }).Count
    $medium = @($detections | Where-Object { $_.Assessment.Confidence -eq 'MEDIUM' }).Count
    $low = @($detections | Where-Object { $_.Assessment.Confidence -eq 'LOW' }).Count
    $checked = @($script:Candidates.Values | Where-Object { $_.Status -notin 'pending', 'gone', 'directory' }).Count
    $tooLarge = @($script:Candidates.Values | Where-Object { $_.Status -eq 'too-large' })

    if ($detections.Count -gt 0) {
        Write-Host ''
        Write-Host '========================================' -ForegroundColor Red
        Write-Host 'DETECTIONS' -ForegroundColor Red
        Write-Host '========================================' -ForegroundColor Red
        Write-Host '  [+] Doomsday-specific  [~] secondary  [>] context  [i] info' -ForegroundColor DarkGray
        Write-Host ''
        $n = 1
        foreach ($c in $detections) { Write-Candidate $c $n; $n++ }
    }

    if ($suspicious.Count -gt 0) {
        Write-Host ''
        Write-Host 'Worth a manual look (generic indicators only, not detections)' -ForegroundColor Yellow
        Write-Host ''
        $n = 1
        foreach ($c in $suspicious | Select-Object -First 15) { Write-Candidate $c $n; $n++ }
        if ($suspicious.Count -gt 15) { Write-Host "  ... $($suspicious.Count - 15) more in the JSON report" -ForegroundColor DarkGray }
    }

    Write-History

    $finishedUtc = [DateTime]::UtcNow
    $refStates = @{}
    foreach ($ref in $script:Refs.Values) { $refStates[$ref.State] = 1 + [int]$refStates[$ref.State] }

    Write-Host ''
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host 'SUMMARY' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    $rows = [ordered]@{
        'Java Prefetch parsed'  = "$($prefetch.Parsed)/$($prefetch.Files.Count)"
        'Historical paths'      = "$($script:Refs.Count) (deleted $([int]$refStates['Deleted']), missing $([int]$refStates['Missing']), moved $([int]$refStates['Moved']))"
        'Files analyzed'        = $checked
        'Candidates'            = "$($jars.Count) with Java code ($($analyzed.Count) archives/class files opened)"
        'Detections'            = $detections.Count
        '  HIGH'                = $high
        '  MEDIUM'              = $medium
        '  LOW'                 = $low
        'Manual review'         = $suspicious.Count
        'Too large to open'     = $tooLarge.Count
        'Errors'                = $script:ScanErrors.Count
        'Duration'              = '{0:N1} s' -f ($finishedUtc - $startedUtc).TotalSeconds
    }
    foreach ($row in $rows.GetEnumerator()) {
        $color = 'Gray'
        if ($row.Key -eq 'Detections' -and $detections.Count -gt 0) { $color = 'Red' }
        if ($row.Key -eq '  HIGH' -and $high -gt 0) { $color = 'Red' }
        if ($row.Key -eq '  MEDIUM' -and $medium -gt 0) { $color = 'Yellow' }
        if ($row.Key -eq 'Errors' -and $script:ScanErrors.Count -gt 0) { $color = 'Yellow' }
        Write-Host ('  {0,-22} {1}' -f $row.Key, $row.Value) -ForegroundColor $color
    }
    Write-Host ''
    if ($high -gt 0) { Write-Host 'High-confidence Doomsday indicators detected. Review the evidence.' -ForegroundColor Red }
    elseif ($detections.Count -gt 0) { Write-Host 'Possible Doomsday indicators detected. Manual review required.' -ForegroundColor Yellow }
    elseif ($script:ScanErrors.Count -gt 0) { Write-Host 'No detections found, but some scan operations failed. Review errors.' -ForegroundColor Yellow }
    else { Write-Host 'No Doomsday indicators detected in the scanned data.' -ForegroundColor Green }

    if ($script:ScanErrors.Count -gt 0 -and $script:Options.DebugLog) {
        Write-Host ''
        Write-Host 'Errors' -ForegroundColor Yellow
        foreach ($e in $script:ScanErrors) { Write-Host "  [$($e.Stage)] $($e.Target): $($e.Message)" -ForegroundColor DarkGray }
    }

    if ($script:Options.NoJson) { Write-Host ''; return }

    $report = [ordered]@{
        Version = $script:ScannerVersion
        Date = Format-IsoTime $finishedUtc
        Duration = [Math]::Round(($finishedUtc - $startedUtc).TotalSeconds, 1)
        Summary = [ordered]@{
            FilesChecked = $checked
            ArchivesChecked = $analyzed.Count
            High = $high
            Medium = $medium
            Low = $low
            NeedsReview = $suspicious.Count
            Errors = $script:ScanErrors.Count
        }
        Detections = @($detections | ForEach-Object { ConvertTo-ReportCandidate $_ })
        NeedsReview = @($suspicious | ForEach-Object { ConvertTo-ReportCandidate $_ })
        DeletedFiles = @($script:Refs.Values | Where-Object { $_.State -ne 'Present' } | ForEach-Object {
            [ordered]@{
                Path = $_.Path
                State = $_.State
                LastSeen = Format-IsoTime $_.DeletedUtc
                CurrentPath = $_.CurrentPath
            }
        })
        UsnDeletedJars = @($script:UsnOnlyHistory | Select-Object -First 500 | ForEach-Object {
            [ordered]@{ Path = $_.Path; DeletedUtc = Format-IsoTime $_.TimeUtc }
        })
        Errors = @($script:ScanErrors | ForEach-Object {
            [ordered]@{ Stage = $_.Stage; Target = $_.Target; Message = $_.Message }
        })
    }

    $path = Get-ReportPath
    try {
        $folder = Split-Path -Parent $path
        if ($folder -and -not (Test-Path -LiteralPath $folder)) { [void](New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop) }
        $json = $report | ConvertTo-Json -Depth 20 -ErrorAction Stop
        [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
        Write-Host ''
        Write-Good "Report saved: $path"
    }
    catch {
        Write-Warn "Could not write the report to ${path}: $(Get-ErrorText $_)"
    }
    Write-Host ''
}

Start-DoomsdayScan
