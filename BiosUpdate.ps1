<#
.SYNOPSIS
    MDT BIOS Update Script for HP, Dell, and Lenovo systems.

.DESCRIPTION
    This script automatically detects the manufacturer and model of the system,
    then applies the appropriate BIOS update if a newer version is available.
    Supports HP, Dell, and Lenovo systems with centralized BIOS update management.
    
    The script compares the current BIOS version against the target version stored
    in a text file, and only applies the update if necessary.

.PARAMETER DeployRoot
    The root path of the MDT deployment share. Defaults to the MDT environment variable.

.PARAMETER WhatIf
    Shows what would happen if the script runs without actually making changes.

.PARAMETER Confirm
    Prompts for confirmation before making changes.

.EXAMPLE
    .\BiosUpdate.ps1
    Runs the BIOS update check and applies updates if needed.

.EXAMPLE
    .\BiosUpdate.ps1 -DeployRoot "D:\DeploymentShare" -WhatIf
    Tests the script without applying updates using a custom deployment root.

.NOTES
    Author: Senior Windows Systems Administrator
    Version: 1.0
    Required Folder Structure:
        %DeployRoot%\Applications\Bios and Firmware Upgrade\
            BiosUpdate.ps1
            Source\
                Dell\
                    [Model Name]\
                        Bios1.exe
                        Version1.txt
                HP\
                    [Model Name]\
                        Bios1.exe
                        Version1.txt
                Lenovo\
                    [Model Name]\
                        Bios1.exe
                        Version1.txt
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
$script:ScriptName = 'BiosUpdate'
$script:LogDirectory = 'C:\Logs'
$script:LogFile = Join-Path -Path $script:LogDirectory -ChildPath "$script:ScriptName.log"
$script:MaxLogSizeMB = 10
$script:ApplicationFolder = 'Bios and Firmware Upgrade'
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
        Write-Log -Message "BIOS is current: Version=$CurrentVersion" -Level Success
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
        [string]$Manufacturer
    )
    
    try {
        if (-not (Test-Path -Path $BiosExePath)) {
            throw "BIOS update file not found: $BiosExePath"
        }
        
        # Define manufacturer-specific update arguments
        $updateArgs = switch ($Manufacturer) {
            'Dell'   { '/s /f /l="C:\Logs\Dell_BIOS_Update.log"' }
            'HP'     { '/s /f /a' }
            'Lenovo' { '/silent /sccm' }
        }
        
        Write-Log -Message "Executing BIOS update: $BiosExePath $updateArgs" -Level Info
        
        if ($PSCmdlet.ShouldProcess($BiosExePath, "Execute BIOS Update")) {
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
                Write-Log -Message "BIOS update completed successfully" -Level Success
                
                # Set MDT Task Sequence variable for potential second update
                try {
                    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
                    $tsenv.Value('Run2nd') = 'yes'
                    Write-Log -Message "Set Task Sequence variable: Run2nd=yes" -Level Info
                }
                catch {
                    Write-Log -Message "Not running in MDT Task Sequence environment or failed to set variable: $_" -Level Warning
                }
                
                return $true
            }
            else {
                Write-Log -Message "BIOS update failed with exit code: $exitCode" -Level Error
                return $false
            }
        }
        else {
            Write-Log -Message "WhatIf: Would execute BIOS update" -Level Info
            return $true
        }
    }
    catch {
        Write-Log -Message "Failed to execute BIOS update: $_" -Level Error
        throw
    }
}
#endregion

#region Main Execution
function Start-BiosUpdateProcess {
    <#
    .SYNOPSIS
        Main function that orchestrates the BIOS update process.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    
    try {
        Write-Log -Message "========== BIOS Update Script Started ==========" -Level Info
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
        $biosExePath = Join-Path -Path $biosBasePath -ChildPath 'Bios1.exe'
        $versionFilePath = Join-Path -Path $biosBasePath -ChildPath 'Version1.txt'
        
        Write-Log -Message "BIOS Base Path: $biosBasePath" -Level Info
        
        # Validate BIOS update package exists
        if (-not (Test-Path -Path $biosBasePath)) {
            throw "BIOS update package not found for $manufacturer $model at: $biosBasePath"
        }
        
        # Get target BIOS version
        $targetBiosVersion = Get-TargetBiosVersion -VersionFilePath $versionFilePath
        Write-Log -Message "Target BIOS Version: $targetBiosVersion" -Level Info
        
        # Check if update is required
        $updateRequired = Test-BiosUpdateRequired -CurrentVersion $currentBiosVersion -TargetVersion $targetBiosVersion
        
        if ($updateRequired) {
            Write-Log -Message "Proceeding with BIOS update..." -Level Info
            $updateSuccess = Invoke-BiosUpdate -BiosExePath $biosExePath -Manufacturer $manufacturer
            
            if ($updateSuccess) {
                Write-Log -Message "BIOS update process completed successfully. System restart required." -Level Success
                exit 0
            }
            else {
                Write-Log -Message "BIOS update process failed" -Level Error
                exit 1
            }
        }
        else {
            Write-Log -Message "No BIOS update required. System is current." -Level Success
            exit 0
        }
    }
    catch {
        Write-Log -Message "Critical error in BIOS update process: $_" -Level Error
        Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        exit 1
    }
    finally {
        Write-Log -Message "========== BIOS Update Script Completed ==========" -Level Info
    }
}
#endregion

# Script entry point
try {
    Start-BiosUpdateProcess
}
catch {
    Write-Log -Message "Unhandled exception: $_" -Level Error
    exit 1
}
