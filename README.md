# MDT BIOS Update Scripts

Production-ready PowerShell scripts that automate BIOS updates for HP, Dell, and Lenovo systems during MDT deployments.

BiosUpdate.ps1: Single-stage updates

BiosUpdate2.ps1: Multi-stage updates (for models requiring intermediate versions)

# Folder Structure

%DeployRoot%\Applications\Bios and Firmware Upgrade\
│
├── BiosUpdate.ps1
├── BiosUpdate2.ps1
│
└── Source\
    ├── Dell\
    │   └── [Model Name]\
    │       ├── Bios1.exe
    │       ├── Version1.txt
    │       ├── Bios2.exe      (optional, for multi-stage)
    │       └── Version2.txt   (optional, for multi-stage)
    ├── HP\
    │   └── [Model Name]\
    │       └── (same as above)
    └── Lenovo\
        └── [Model Name]\
            └── (same as above)

# Quick Setup

Create folders: %DeployRoot%\Applications\Bios and Firmware Upgrade\Source\[Dell|HP|Lenovo]\[Model Name]

For each model:

Download BIOS update from vendor, rename to Bios1.exe

Create Version1.txt with target version number (e.g., "A18")

For multi-stage: Add Bios2.exe and Version2.txt for final version


Copy scripts to %DeployRoot%\Applications\Bios and Firmware Upgrade\

Add to MDT Task Sequence (State Restore phase):

Add "Run PowerShell Script": %DeployRoot%\Applications\Bios and Firmware Upgrade\BiosUpdate.ps1

Add "Restart Computer"

For multi-stage: Add another "Run PowerShell Script" with BiosUpdate2.ps1

Add condition: Task Sequence Variable Run2nd equals yes

Add "Restart Computer"

# Usage

Test mode (recommended first)
.\BiosUpdate.ps1 -WhatIf

Run update
.\BiosUpdate.ps1

Multi-stage update
.\BiosUpdate2.ps1

Custom deployment path
.\BiosUpdate.ps1 -DeployRoot "E:\CustomDeployment"

# How It Works

Both scripts detect manufacturer/model from WMI, compare current BIOS version to target version, and only update if needed. Updates use manufacturer-specific silent parameters.

BiosUpdate2.ps1 handles multi-stage updates with automatic retry logic (up to 3 attempts) for Dell systems.

Logs are written to C:\Logs\BiosUpdate.log and C:\Logs\BiosUpdate2.log

# Manufacturer Notes

Dell: Exit codes 0/2, uses /s /f parameters, includes retry logic

HP: Exit codes 0/3010, uses /s /f /a parameters

Lenovo: Exit codes 0/3010, uses /silent /sccm parameters

# Troubleshooting

"BIOS update package not found"

Check model name matches exactly: (Get-CimInstance Win32_ComputerSystem).Model

"Version file is empty"

Ensure Version1.txt contains only the version number with no extra spaces

# Update fails

Verify correct BIOS executable for model
Ensure AC power (laptops)
Check logs in C:\Logs\

# Get system info:

Get-CimInstance Win32_ComputerSystem | Select Manufacturer, Model
Get-CimInstance Win32_BIOS | Select SMBIOSBIOSVersion
