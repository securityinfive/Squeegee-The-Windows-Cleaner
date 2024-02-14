# Squeegee
Squeegee - The Windows Cleaner

Squeegee is a tool written in Powershell to gather and analyze data about your Windows machine. 
This tool is meant for data gathering for assistance in troubleshooting, performance management, forensic investigations or just leaning about what your machine is doing. 

The data sets collected
- Computer Information
- Operating System Information
- Network Adapter Information
- Current Network Connections
- Security Event Log Scanning

Squeegee will create a report with all the data collected for easy analysis. 

# Running the script

If you run Squeegee from the Powershell ISE, VSCode or another editor make sure you run the editor as an Administrator. 

If you run the .ps1 fil directly you can run the batch file or use the command 'powershell -STA -File Squeegee-v1.ps1'.


# UPDATES
9/21/21 - Added the actual even logs entries when they are found in the output and in the Squeegee log.

9/22/21 - Added in the contents of the HKLM.../Run and /RunOnce locations to identify applications ran at startup.

2/14/24 - A small tweak and added instruction comments to help with execution blocks if your local policies are too tight.


