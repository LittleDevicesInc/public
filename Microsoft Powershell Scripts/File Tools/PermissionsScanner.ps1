# Ask user for the drive letter
$DriveLetter = Read-Host "Enter the drive letter you want to run the script on (e.g., C, D)"
$RootPath = "$($DriveLetter):\"

# Ask user about including inherited permissions
$IncludeInherited = Read-Host "Would you like to include files and directories with inherited permissions? (Y/N)"
$IncludeInherited = $IncludeInherited.ToUpper() -eq 'Y'

# Ask user about including SYSTEM permissions
$IncludeSystem = Read-Host "Would you like to include files and directories owned by NT AUTHORITY\SYSTEM? (Y/N)"
$IncludeSystem = $IncludeSystem.ToUpper() -eq 'Y'

# Ask user about including BUILTIN permissions
$IncludeBuiltin = Read-Host "Would you like to include files and directories owned by BUILTIN groups? (Y/N)"
$IncludeBuiltin = $IncludeBuiltin.ToUpper() -eq 'Y'

# Get desktop path
$DesktopPath = [Environment]::GetFolderPath('Desktop')

# Create timestamp for unique filenames
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create CSV filenames with timestamp
$CsvFileName = "$DriveLetter-drive-permissions_$TimeStamp.csv"
$CsvPath = Join-Path -Path $DesktopPath -ChildPath $CsvFileName

# Create skipped directories filename with timestamp
$SkippedCsvFileName = "$DriveLetter-skipped-directories_$TimeStamp.csv"
$SkippedCsvPath = Join-Path -Path $DesktopPath -ChildPath $SkippedCsvFileName

# Function to check if a path is a system directory
function Test-IsSystemPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $systemPaths = @(
        # System Directories
        '\$RECYCLE.BIN',
        '\System Volume Information',
        '\Sysmon',
        '\Config.Msi',
        '\Recovery',
        '\Windows\ServiceProfiles',
        '\Program Files\WindowsApps',
        '\ProgramData\Microsoft\Crypto',
        '\Windows\CSC',
        '\Windows\LiveKernelReports',
        '\Windows\Minidump',
        '\Windows\ModemLogs',
        '\Windows\Prefetch',
        '\Windows\ServiceState',
        '\Windows\SystemTemp',
        '\Windows\WUModels',
        '\OneDriveTemp',
        '\ProgramData\Packages',
        '\ProgramData\WindowsHolographicDevices',
        '\ProgramData\Netbird',
        '\Documents and Settings',  # Legacy Windows directory
        '\Archivos de programa',    # Spanish Program Files

        # System Files
        'NTUSER.DAT',
        'ntuser.pol',
        'hiberfil.sys',
        'pagefile.sys',
        'swapfile.sys',
        'DumpStack.log',
        'DumpStack.log.tmp',

        # Protected User Directories
        '\Users\defaultuser',
        '\Users\Public',
        '\Users\Default',
        '\Users\All Users'
    )

    # Check exact matches first
    foreach ($sysPath in $systemPaths) {
        if ($Path -like "*$sysPath*") {
            return $true
        }
    }

    # Additional checks for specific patterns
    if ($Path -match '\\Users\\[^\\]+$') {  # Root of any user profile
        return $true
    }

    # Check for Windows system directories
    if ($Path -like "C:\Windows*" -and (
        $Path -notlike "*\Fonts*" -and
        $Path -notlike "*\Help*" -and
        $Path -notlike "*\Media*"
    )) {
        return $true
    }

    # Check for ProgramData system directories
    if ($Path -like "C:\ProgramData*" -and (
        $Path -notlike "*\Microsoft\Windows\Start Menu*" -and
        $Path -notlike "*\Desktop*" -and
        $Path -notlike "*\Documents*"
    )) {
        return $true
    }

    return $false
}

# Initialize variables
$scanStartTime = Get-Date
$globalStartTime = Get-Date
$count = 0
$items = @()
$Output = [System.Collections.ArrayList]::new()
$SkippedDirs = [System.Collections.ArrayList]::new()

try {
    Write-Host "`nPhase 1: Enumerating files and directories..." -ForegroundColor Yellow
    Write-Host "Scanning $RootPath..." -ForegroundColor Yellow

    # Get initial items, excluding system paths
    try {
        $rootItems = Get-ChildItem -LiteralPath $RootPath -Force -ErrorAction Stop |
            Where-Object { -not (Test-IsSystemPath -Path $_.FullName) }

        if ($null -eq $rootItems) {
            Write-Host "`nWarning: No items found in $RootPath" -ForegroundColor Yellow
            return
        }
    }
    catch {
        Write-Host "Error accessing root path: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Add root directory to items
    try {
        $rootDir = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
        if ($null -ne $rootDir) {
            $items += $rootDir
        }
    }
    catch {
        Write-Host "Error accessing root directory: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Process each item
    foreach ($item in $rootItems) {
        if ($null -eq $item) { continue }

        $items += $item
        $count++

        # If it's a directory, process its contents
        if ($item.PSIsContainer) {
            try {
                # Get files
                $files = Get-ChildItem -LiteralPath $item.FullName -File -Force -ErrorAction Stop |
                    Where-Object { -not (Test-IsSystemPath -Path $_.FullName) }
                if ($files) {
                    $items += $files
                    $count += $files.Count
                }

                # Get directories
                $subdirs = Get-ChildItem -LiteralPath $item.FullName -Directory -Force -ErrorAction Stop |
                    Where-Object { -not (Test-IsSystemPath -Path $_.FullName) }
                if ($subdirs) {
                    $items += $subdirs
                    $count += $subdirs.Count
                }
            }
            catch {
                # Only log non-system directory errors
                if (-not (Test-IsSystemPath -Path $item.FullName)) {
                    Write-Host "Warning: Could not access $($item.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
                    [void]$SkippedDirs.Add([PSCustomObject]@{
                        'Path' = $item.FullName
                        'Reason' = $_.Exception.Message
                        'TimeStamp' = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        'ElapsedTime' = [math]::Round(((Get-Date) - $scanStartTime).TotalSeconds)
                    })
                }
            }
        }

        # Update progress
        if ($count % 100 -eq 0) {
            $elapsedTime = [math]::Round(((Get-Date) - $scanStartTime).TotalSeconds)
            $itemsPerSecond = if ($elapsedTime -gt 0) { [math]::Round($count / $elapsedTime, 1) } else { 0 }
            Write-Progress -Activity "Scanning Files and Directories" `
                -Status "Found $count items" `
                -CurrentOperation "$itemsPerSecond items/sec" `
                -PercentComplete -1
        }
    }

    # Show summary
    $DirectoryCount = ($items | Where-Object { $_.PSIsContainer }).Count
    $FileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
    Write-Host "`nFound $DirectoryCount directories and $FileCount files (Total: $($items.Count) items)" -ForegroundColor Green

    # Process permissions
    Write-Host "`nPhase 2: Processing permissions..." -ForegroundColor Yellow
    $processed = 0

    foreach ($item in $items) {
        if ($null -eq $item -or (Test-IsSystemPath -Path $item.FullName)) { continue }

        try {
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop

            if ($IncludeInherited -or $acl.AreAccessRulesProtected) {
                foreach ($access in $acl.Access) {
                    if ((-not $IncludeSystem -and $access.IdentityReference -eq 'NT AUTHORITY\SYSTEM') -or
                        (-not $IncludeBuiltin -and $access.IdentityReference -like 'BUILTIN\*')) {
                        continue
                    }

                    $cleanPath = ($item.FullName) -replace '[\n\r"]', ' '
                    $obj = [PSCustomObject]@{
                        'Path' = $cleanPath
                        'Type' = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                        'Group/User' = $access.IdentityReference
                        'Permissions' = $access.FileSystemRights
                        'Inherited' = $access.IsInherited
                        'InheritanceFlags' = $access.InheritanceFlags
                        'PropagationFlags' = $access.PropagationFlags
                    }
                    [void]$Output.Add($obj)
                }
            }
        }
        catch {
            # Only log non-system path errors
            if (-not (Test-IsSystemPath -Path $item.FullName)) {
                Write-Host "Error processing $($item.FullName) : $($_.Exception.Message)" -ForegroundColor Red
                [void]$SkippedDirs.Add([PSCustomObject]@{
                    'Path' = $item.FullName
                    'Reason' = $_.Exception.Message
                    'TimeStamp' = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    'ElapsedTime' = [math]::Round(((Get-Date) - $scanStartTime).TotalSeconds)
                })
            }
        }

        $processed++
        if ($processed % 100 -eq 0) {
            $percentComplete = [math]::Round(($processed / $items.Count) * 100)
            Write-Progress -Activity "Processing Permissions" `
                -Status "$percentComplete% Complete" `
                -PercentComplete $percentComplete
        }
    }

    # Export results
    if ($Output.Count -gt 0) {
        $Output | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $CsvPath" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo permissions found to export." -ForegroundColor Yellow
    }

    # Export skipped items (only non-system paths)
    $nonSystemSkipped = $SkippedDirs | Where-Object { -not (Test-IsSystemPath -Path $_.Path) }
    if ($nonSystemSkipped.Count -gt 0) {
        $nonSystemSkipped | Export-Csv -Path $SkippedCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Skipped items exported to: $SkippedCsvPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "`nError during scan: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Progress -Activity "Processing Permissions" -Completed
}
