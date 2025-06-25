# Veeam AV Exclusion Script for Windows

## Disclaimer:
Important - I do not provide any guarantees that the script I have successfully tested will run without errors in every environment.
The script is solely intended to simplify and standardize hardening standards, which may not be applicable or appropriate for all environments!
Furthermore, I do not guarantee the completeness of the tests!


## Prerequisities and limitations:
The script is designed for new and existing installations (add-on character)!

- The script is tested for all listed Veeam components within the script
- The script is not tested and designed for Veeam components within a management domain (Active Directory)
- The operating system has to be Windows Server 2022 or 2025 Standard or Datacenter (other systems are not tested)
- The operating system language has to be English (no language pack on another language is allowed!)


## Actions to apply the script:
1. Install Windows Server (as required).
2. Install drivers (VMware Tools or vendor-specific drivers).
3. Set IP configurations (assign IP address, etc.).
4. Set server name and workgroup, then restart the server.
5. Create a folder named “Install” on drive C:.
6. Perform Windows OS hardening (e.g. by script)
7. Allow the server to restart (if required) and install Veeam.
8. Apply / implement the Veeam Security & Compliance script.
9. Copy the AV script into the Install folder.
10. Execute the script with administrative privileges (PowerShell).
11. Run the script by selecting the appropriate components (multipe component selections - one after the other - are possible!)


## Additional information:
- The output file (manuscript) is located at C:\Install after the script execution
