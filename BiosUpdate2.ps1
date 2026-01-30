<#
.SYNOPSIS
    MDT Multi-Stage BIOS Update Script for HP, Dell, and Lenovo systems.

.DESCRIPTION
    This script handles systems that require intermediate BIOS updates before
    applying the final version. It supports a two-stage update process:
    1. Bios1.exe - Intermediate version (if current version is older)
    2. Bios2.exe - Final target version
    
    The script intelligently determines which updates are needed based on the
    current BIOS version and applies them sequentially.

.PARAMETER DeployRoot
    The root path of the MDT deployment share. Defaults to the MDT environment variable.

.PARAMETER WhatIf
    Shows what would happen if the script runs without actually making changes.

.PARAMETER Confirm
    Prompts for confirmation before making changes.

.EXAMPLE
    .\BiosUpdate2.ps1
    Runs the multi-stage BIOS update check and applies updates if needed.

.EXAMPLE
    .\BiosUpdate2.ps1 -DeployRoot "D:\DeploymentShare" -WhatIf
    Tests the script without applying updates using a custom deployment root.

.NOTES
    Author: Senior Windows Systems Administrator
    Version: 1.0
    Required Folder Structure:
        %DeployRoot%\Applications\Bios and Firmware Upgrade\
            BiosUpdate2.ps1
            Source\
                Dell\
                    [Model Name]\
                        Bios1.exe (Intermediate version)
                        Version1.txt (Intermediate version number)
                        Bios2.exe (Final version)
                        Version2.txt (Final version number)
                HP\
                    [Model Name]\
                        Bios1.exe
                        Version1.txt
                        Bios2.exe
                        Version2.txt
                Lenovo\
                    [Model Name]\
                        Bios1.exe
                        Version1.txt
                        Bios2.exe
                        Version2.txt
    
    Task Sequence Configuration:
        Add condition: Run2nd equals "yes"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$DeployRoot = $env:DeployRoot
)

#Requires -RunAsAdministrator

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

#region Configuration
$script:ScriptName = 'BiosUpdate2'
$script:LogDirectory = 'C:\Logs'
$script:LogFile = Join-Path -Path $script:LogDirectory -ChildPath "$script:ScriptName.log"
$script:MaxLogSizeMB = 10
$script:ApplicationFolder = 'Bios and Firmware Upgrade'
$script:MaxUpdateAttempts = 3
#endregion

#region Logging Function
function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped log entries to console and file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    begin {
        # Ensure log directory exists
        if (-not (Test-Path -Path $script:LogDirectory)) {
            try {
                New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-Warning "Failed to create log directory: $_"
                return
            }
        }
        
        # Rotate log file if it exceeds max size
        if (Test-Path -Path $script:LogFile) {
            $logSize = (Get-Item -Path $script:LogFile).Length / 1MB
            if ($logSize -gt $script:MaxLogSizeMB) {
                $archivePath = $script:LogFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $script:LogFile -Destination $archivePath -Force
            }
        }
    }
    
    process {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "[$timestamp] [$Level] $Message"
        
        # Console output with color coding
        switch ($Level) {
            'Error'   { Write-Host $logEntry -ForegroundColor Red }
            'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
            'Success' { Write-Host $logEntry -ForegroundColor Green }
            default   { Write-Host $logEntry -ForegroundColor White }
        }
        
        # File output
        try {
            Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}
#endregion

#region Helper Functions
function Get-SystemManufacturer {
    <#
    .SYNOPSIS
        Retrieves the system manufacturer from WMI.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Manufacturer
        
        # Normalize manufacturer names
        switch -Wildcard ($manufacturer) {
            '*Dell*'   { return 'Dell' }
            '*HP*'     { return 'HP' }
            '*Hewlett*' { return 'HP' }
            '*Lenovo*' { return 'Lenovo' }
            default    { return $manufacturer }
        }
    }
    catch {
        Write-Log -Message "Failed to retrieve manufacturer: $_" -Level Error
        throw
    }
}

function Get-SystemModel {
    <#
    .SYNOPSIS
        Retrieves the system model from WMI.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $model = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Model
        
        # Clean up model name for Lenovo (remove version info)
        if ($model -match '^(\d{4})') {
            $model = $Matches[1]
        }
        
        return $model.Trim()
    }
    catch {
        Write-Log -Message "Failed to retrieve model: $_" -Level Error
        throw
    }
}

function Get-CurrentBiosVersion {
    <#
    .SYNOPSIS
        Retrieves the current BIOS version from WMI.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $biosVersion = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SMBIOSBIOSVersion
        return $biosVersion.Trim()
    }
    catch {
        Write-Log -Message "Failed to retrieve BIOS version: $_" -Level Error
        throw
    }
}

function Get-TargetBiosVersion {
    <#
    .SYNOPSIS
        Reads the target BIOS version from the version file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VersionFilePath
    )
    
    try {
        if (-not (Test-Path -Path $VersionFilePath)) {
            throw "Version file not found: $VersionFilePath"
        }
        
        $version = (Get-Content -Path $VersionFilePath -ErrorAction Stop)[0].Trim()
        
        if ([string]::IsNullOrWhiteSpace($version)) {
            throw "Version file is empty: $VersionFilePath"
        }
        
        return $version
    }
    catch {
        Write-Log -Message "Failed to read target BIOS version: $_" -Level Error
        throw
    }
}

function Test-BiosUpdateRequired {
    <#
    .SYNOPSIS
        Compares current and target BIOS versions to determine if an update is needed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CurrentVersion,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetVersion
    )
    
    # Case-insensitive comparison
    $updateRequired = $CurrentVersion -ne $TargetVersion
    
    if ($updateRequired) {
        Write-Log -Message "BIOS update required: Current=$CurrentVersion, Target=$TargetVersion" -Level Info
    }
    else {
        Write-Log -Message "BIOS version matches target: Version=$CurrentVersion" -Level Success
    }
    
    return $updateRequired
}

function Invoke-BiosUpdate {
    <#
    .SYNOPSIS
        Executes the BIOS update executable with manufacturer-specific parameters.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BiosExePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Dell', 'HP', 'Lenovo')]
        [string]$Manufacturer,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stage1', 'Stage2')]
        [string]$UpdateStage
    )
    
    try {
        if (-not (Test-Path -Path $BiosExePath)) {
            throw "BIOS update file not found: $BiosExePath"
        }
        
        # Define manufacturer-specific update arguments
        $updateArgs = switch ($Manufacturer) {
            'Dell'   { "/s /f /l=`"C:\Logs\Dell_BIOS_Update_$UpdateStage.log`"" }
            'HP'     { '/s /f /a' }
            'Lenovo' { '/silent /sccm' }
        }
        
        Write-Log -Message "Executing BIOS update ($UpdateStage): $BiosExePath $updateArgs" -Level Info
        
        if ($PSCmdlet.ShouldProcess($BiosExePath, "Execute BIOS Update - $UpdateStage")) {
            $process = Start-Process -FilePath $BiosExePath -ArgumentList $updateArgs -Wait -PassThru -NoNewWindow
            
            $exitCode = $process.ExitCode
            Write-Log -Message "BIOS update process completed with exit code: $exitCode" -Level Info
            
            # Check for successful exit codes (manufacturer-specific)
            $successCodes = switch ($Manufacturer) {
                'Dell'   { @(0, 2) }  # 0=Success, 2=Success but reboot required
                'HP'     { @(0, 3010) }  # 0=Success, 3010=Success but reboot required
                'Lenovo' { @(0, 3010) }  # 0=Success, 3010=Success but reboot required
            }
            
            if ($exitCode -in $successCodes) {
                Write-Log -Message "BIOS update ($UpdateStage) completed successfully" -Level Success
                return $true
            }
            else {
                Write-Log -Message "BIOS update ($UpdateStage) failed with exit code: $exitCode" -Level Error
                return $false
            }
        }
        else {
            Write-Log -Message "WhatIf: Would execute BIOS update ($UpdateStage)" -Level Info
            return $true
        }
    }
    catch {
        Write-Log -Message "Failed to execute BIOS update ($UpdateStage): $_" -Level Error
        throw
    }
}

function Invoke-MultiStageUpdate {
    <#
    .SYNOPSIS
        Manages multi-stage BIOS updates with retry logic for Dell systems.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BiosExePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Dell', 'HP', 'Lenovo')]
        [string]$Manufacturer,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Stage1', 'Stage2')]
        [string]$UpdateStage,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetVersion
    )
    
    $attemptCount = 0
    $updateSuccess = $false
    
    while ($attemptCount -lt $script:MaxUpdateAttempts -and -not $updateSuccess) {
        $attemptCount++
        Write-Log -Message "BIOS update attempt $attemptCount of $script:MaxUpdateAttempts for $UpdateStage" -Level Info
        
        $updateSuccess = Invoke-BiosUpdate -BiosExePath $BiosExePath -Manufacturer $Manufacturer -UpdateStage $UpdateStage
        
        if ($updateSuccess) {
            Write-Log -Message "BIOS update ($UpdateStage) succeeded on attempt $attemptCount" -Level Success
            
            # Verify the update was applied (only if not in WhatIf mode)
            if (-not $WhatIfPreference) {
                Start-Sleep -Seconds 5  # Brief pause before checking version
                $currentVersion = Get-CurrentBiosVersion
                
                if ($currentVersion -eq $TargetVersion) {
                    Write-Log -Message "BIOS version verified: $currentVersion matches target" -Level Success
                    return $true
                }
                else {
                    Write-Log -Message "BIOS version mismatch after update: Current=$currentVersion, Expected=$TargetVersion" -Level Warning
                    
                    # For Dell systems, retry may be needed
                    if ($Manufacturer -eq 'Dell' -and $attemptCount -lt $script:MaxUpdateAttempts) {
                        Write-Log -Message "Dell system detected - retrying update" -Level Info
                        $updateSuccess = $false
                    }
                }
            }
            else {
                return $true
            }
        }
        else {
            Write-Log -Message "BIOS update ($UpdateStage) failed on attempt $attemptCount" -Level Warning
            
            if ($attemptCount -lt $script:MaxUpdateAttempts) {
                Write-Log -Message "Waiting 10 seconds before retry..." -Level Info
                Start-Sleep -Seconds 10
            }
        }
    }
    
    if (-not $updateSuccess) {
        Write-Log -Message "BIOS update ($UpdateStage) failed after $attemptCount attempts" -Level Error
    }
    
    return $updateSuccess
}
#endregion

#region Main Execution
function Start-MultiStageBiosUpdate {
    <#
    .SYNOPSIS
        Main function that orchestrates the multi-stage BIOS update process.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    
    try {
        Write-Log -Message "========== Multi-Stage BIOS Update Script Started ==========" -Level Info
        Write-Log -Message "Script Version: 1.0" -Level Info
        Write-Log -Message "Execution User: $env:USERNAME" -Level Info
        Write-Log -Message "Computer Name: $env:COMPUTERNAME" -Level Info
        
        # Validate DeployRoot parameter
        if ([string]::IsNullOrWhiteSpace($DeployRoot)) {
            throw "DeployRoot parameter is not set. Ensure MDT environment variable is configured or provide the parameter."
        }
        
        Write-Log -Message "Deployment Root: $DeployRoot" -Level Info
        
        # Get system information
        Write-Log -Message "Detecting system information..." -Level Info
        $manufacturer = Get-SystemManufacturer
        $model = Get-SystemModel
        $currentBiosVersion = Get-CurrentBiosVersion
        
        Write-Log -Message "Manufacturer: $manufacturer" -Level Info
        Write-Log -Message "Model: $model" -Level Info
        Write-Log -Message "Current BIOS Version: $currentBiosVersion" -Level Info
        
        # Validate manufacturer is supported
        if ($manufacturer -notin @('Dell', 'HP', 'Lenovo')) {
            throw "Unsupported manufacturer: $manufacturer. This script supports Dell, HP, and Lenovo only."
        }
        
        # Construct paths to BIOS update files
        $biosBasePath = Join-Path -Path $DeployRoot -ChildPath "Applications\$script:ApplicationFolder\Source\$manufacturer\$model"
        
        $bios1ExePath = Join-Path -Path $biosBasePath -ChildPath 'Bios1.exe'
        $version1FilePath = Join-Path -Path $biosBasePath -ChildPath 'Version1.txt'
        $bios2ExePath = Join-Path -Path $biosBasePath -ChildPath 'Bios2.exe'
        $version2FilePath = Join-Path -Path $biosBasePath -ChildPath 'Version2.txt'
        
        Write-Log -Message "BIOS Base Path: $biosBasePath" -Level Info
        
        # Validate BIOS update package exists
        if (-not (Test-Path -Path $biosBasePath)) {
            throw "BIOS update package not found for $manufacturer $model at: $biosBasePath"
        }
        
        # Get target BIOS versions
        $intermediateVersion = Get-TargetBiosVersion -VersionFilePath $version1FilePath
        $finalVersion = Get-TargetBiosVersion -VersionFilePath $version2FilePath
        
        Write-Log -Message "Intermediate BIOS Version: $intermediateVersion" -Level Info
        Write-Log -Message "Final BIOS Version: $finalVersion" -Level Info
        
        # Determine update strategy
        $stage1Required = Test-BiosUpdateRequired -CurrentVersion $currentBiosVersion -TargetVersion $intermediateVersion
        $stage2Required = Test-BiosUpdateRequired -CurrentVersion $currentBiosVersion -TargetVersion $finalVersion
        
        $overallSuccess = $true
        
        # Stage 1: Apply intermediate update if current version is older
        if ($stage1Required) {
            Write-Log -Message "Stage 1: Applying intermediate BIOS update to version $intermediateVersion" -Level Info
            
            $stage1Success = Invoke-MultiStageUpdate -BiosExePath $bios1ExePath `
                                                      -Manufacturer $manufacturer `
                                                      -UpdateStage 'Stage1' `
                                                      -TargetVersion $intermediateVersion
            
            if (-not $stage1Success) {
                Write-Log -Message "Stage 1 BIOS update failed. Aborting multi-stage update process." -Level Error
                exit 1
            }
            
            Write-Log -Message "Stage 1 completed. Updating current BIOS version..." -Level Info
            $currentBiosVersion = Get-CurrentBiosVersion
            Write-Log -Message "Current BIOS Version after Stage 1: $currentBiosVersion" -Level Info
            
            # Re-evaluate if Stage 2 is needed
            $stage2Required = Test-BiosUpdateRequired -CurrentVersion $currentBiosVersion -TargetVersion $finalVersion
        }
        else {
            Write-Log -Message "Stage 1: Intermediate update not required (current version is $currentBiosVersion)" -Level Info
        }
        
        # Stage 2: Apply final update if not already at target version
        if ($stage2Required) {
            Write-Log -Message "Stage 2: Applying final BIOS update to version $finalVersion" -Level Info
            
            $stage2Success = Invoke-MultiStageUpdate -BiosExePath $bios2ExePath `
                                                      -Manufacturer $manufacturer `
                                                      -UpdateStage 'Stage2' `
                                                      -TargetVersion $finalVersion
            
            if (-not $stage2Success) {
                Write-Log -Message "Stage 2 BIOS update failed" -Level Error
                $overallSuccess = $false
            }
            else {
                Write-Log -Message "Stage 2 completed successfully" -Level Success
            }
        }
        else {
            Write-Log -Message "Stage 2: Final update not required (current version is $currentBiosVersion)" -Level Success
        }
        
        # Final status
        if ($overallSuccess) {
            Write-Log -Message "Multi-stage BIOS update completed successfully. System restart required." -Level Success
            exit 0
        }
        else {
            Write-Log -Message "Multi-stage BIOS update completed with errors" -Level Error
            exit 1
        }
    }
    catch {
        Write-Log -Message "Critical error in multi-stage BIOS update process: $_" -Level Error
        Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        exit 1
    }
    finally {
        Write-Log -Message "========== Multi-Stage BIOS Update Script Completed ==========" -Level Info
    }
}
#endregion

# Script entry point
try {
    Start-MultiStageBiosUpdate
}
catch {
    Write-Log -Message "Unhandled exception: $_" -Level Error
    exit 1
}
