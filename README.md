# MDT PowerShell BIOS Update

This project provides a PowerShell-based solution for updating BIOS firmware during an MDT deployment.

Unlike many scripts that only support a single model or manufacturer, this script supports HP, Dell, and Lenovo systems and works across multiple models.

# Folder Structure Setup

Place the PowerShell script (BiosUpdate.ps1) in the Applications folder within your MDT deployment share.

Name the application folder:

Bios and Firmware Upgrade

Inside this folder, create a subfolder named:

Source

Inside the Source folder, create the following manufacturer folders:

Dell

HP

Lenovo

# Model-Specific BIOS Setup

For each model you want to support:

Create a model-specific folder inside the appropriate manufacturer folder.

Example (Dell Latitude E6420):

Source\
  Dell\
    Latitude E6420\

Download the BIOS update executable for that model and place it in the model folder.

Rename the BIOS executable to:

Bios1.exe

Take note of the BIOS version contained in the update (for example, A18).

# BIOS Version File

In the same model folder, create a text file.

Inside the file, enter the BIOS version number (for example):

A18

Save the file as:

Version1

The script will read this file and compare it to the currently installed BIOS version to determine whether an update is required.

# MDT Task Sequence Configuration (Single BIOS Update)

In your MDT Task Sequence, navigate to the State Restore section.

Add a Run PowerShell Script step.

For the PowerShell script path, enter:

%DeployRoot%\Applications\Bios and Firmware Upgrade\BiosUpdate.ps1

Add a Restart Computer step immediately after the PowerShell step.

This restart allows the BIOS update to apply.

Click Apply to save the Task Sequence.

# Systems Requiring an Intermediate BIOS Update

Some systems require an intermediate BIOS version before updating to the latest version. For these systems, a second script (BiosUpdate2.ps1) is used.

Folder Setup for Intermediate Updates

The existing Bios1.exe and Version1 represent the intermediate BIOS version.

Download the final BIOS version and place it in the same model folder.

Rename the final BIOS executable to:

Bios2.exe

Create another text file containing the final BIOS version number and name it:

Version2

# MDT Task Sequence Configuration (Second BIOS Update)

Add another Run PowerShell Script step in the Task Sequence.

Use the following script path:

%DeployRoot%\Applications\Bios and Firmware Upgrade\BiosUpdate2.ps1

In the Options tab, add a Task Sequence variable:

Variable: Run2nd

Value: yes

Click Apply.

# Notes

Some Dell systems may require the BIOS update process to run more than once.

The scripts are designed to handle these cases automatically.

Ensure BIOS updates are tested thoroughly before deploying in production.
