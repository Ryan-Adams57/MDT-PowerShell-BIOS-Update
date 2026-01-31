# MDT-PowerShell-BIOS-Update

This project provides a PowerShell-based solution for updating BIOS firmware during an MDT deployment. Unlike many scripts that only support a single model or manufacturer, this script supports HP, Dell, and Lenovo systems and works across multiple models.

# Setup Instructions

Step 1: Create Folder Structure

Navigate to your MDT Deployment Share (e.g., D:\DeploymentShare)

Create the following folder:

Applications\Bios and Firmware Upgrade\Source

Inside the Source folder, create three manufacturer folders:

Dell
HP
Lenovo

Step 2: Add BIOS Updates for Each Model

For Single-Stage Updates (BiosUpdate.ps1):

Create a folder with the exact model name (e.g., "Latitude E6420") inside the appropriate manufacturer folder

Download the BIOS update executable from the vendor's website

Rename the executable to Bios1.exe

Create a text file named Version1.txt

In Version1.txt, enter ONLY the target BIOS version (e.g., "A18")

Save the file

# Disclaimer

These scripts are provided as-is. Always test in a lab environment before production deployment.

# Additional Resources

Dell BIOS Downloads: https://www.dell.com/support

HP BIOS Downloads: https://support.hp.com

Lenovo BIOS Downloads: https://support.lenovo.com

MDT Documentation: https://docs.microsoft.com/en-us/windows/deployment/deploy-windows-mdt/
