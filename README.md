# MDT PowerShell BIOS Update

A PowerShell solution for updating BIOS firmware during an **MDT (Microsoft Deployment Toolkit)** deployment.

Unlike scripts that only handle a single model or vendor, this one works across **HP, Dell, and Lenovo** systems and supports multiple models. It decides whether an update is needed by comparing the machine's currently installed BIOS version against a version you define in a small text file.

## How it works

For each model, you provide the BIOS update executable and a text file stating the target BIOS version. During deployment, the script reads that version, compares it to what's installed, and only applies the update if the machine is out of date.

## Step 1 - Set up the folder structure

1. Place the script `BiosUpdate.ps1` in the **Applications** folder of your MDT deployment share.
2. Name the application folder:

   ```
   Bios and Firmware Upgrade
   ```

3. Inside it, create a subfolder named `Source`.
4. Inside `Source`, create one folder per manufacturer: `Dell`, `HP`, and `Lenovo`.

## Step 2 - Add each model's BIOS

For every model you want to support:

1. Inside the matching manufacturer folder, create a **model-specific folder**. For example, for a Dell Latitude E6420:

   ```
   Source\Dell\Latitude E6420\
   ```

2. Download the BIOS update executable for that model, place it in the model folder, and rename it to `Bios1.exe`.
3. Note the BIOS version included in that update (for example, `A18`).

## Step 3 - Create the BIOS version file

1. In the same model folder, create a plain text file.
2. Enter the target BIOS version inside it (for example, `A18`).
3. Save the file as `Version1` (no extension).

The script reads this file and compares it against the installed BIOS version to decide whether an update is required.

## Step 4 - Configure the MDT Task Sequence

1. In your Task Sequence, go to the **State Restore** section.
2. Add a **Run PowerShell Script** step with this path:

   ```
   %DeployRoot%\Applications\Bios and Firmware Upgrade\BiosUpdate.ps1
   ```

3. Add a **Restart Computer** step immediately after it. This lets the BIOS update apply.
4. Click **Apply** to save.

## Systems that need an intermediate BIOS update

Some machines must be updated to an intermediate BIOS version before they can jump to the latest one. For these, a second script (`BiosUpdate2.ps1`) handles the final step.

### Folder setup

- The existing `Bios1.exe` and `Version1` now represent the **intermediate** version.
- Download the **final** BIOS version, place it in the same model folder, and rename it to `Bios2.exe`.
- Create another text file with the final BIOS version number and name it `Version2`.

### Task Sequence setup for the second update

1. Add another **Run PowerShell Script** step using this path:

   ```
   %DeployRoot%\Applications\Bios and Firmware Upgrade\BiosUpdate2.ps1
   ```

2. On the **Options** tab, add a Task Sequence variable:
   - **Variable:** `Run2nd`
   - **Value:** `yes`
3. Click **Apply**.

## Notes

- Some Dell systems may need the BIOS update to run more than once. The scripts handle this automatically.
- Always test BIOS updates thoroughly before rolling them out to production.
