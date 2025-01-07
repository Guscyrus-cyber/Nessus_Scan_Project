# Nessus_Scan_Project
Project Title: Vulnerability Scanning and Remediation with Nessus
Project Overview

This project involves performing a vulnerability scan on a Windows machine using Tenable's Nessus, analyzing the vulnerabilities detected, and providing remediation steps for the identified issues. The primary goal is to demonstrate how vulnerability scanning can identify potential security risks in a system, followed by applying fixes to mitigate these vulnerabilities.

Objectives

    Perform a vulnerability scan using Nessus.
    Identify critical and medium vulnerabilities in a Windows system.
    Provide remediation steps for each identified vulnerability.
    Document the scan results and the process for resolving the issues.
    Upload the project and the report to GitHub for future reference.

Scan Details

Scan Policy: Basic Network Scan
Scanner: Local Scanner
Start Time: Today at 10:41 PM
End Time: Today at 10:50 PM
Elapsed Time: 10 minutes
Status: Completed

Scan Results Overview

    Total Vulnerabilities Found: 28
    Critical Vulnerabilities: 1
    High Severity Vulnerabilities: 1
    Medium Severity Vulnerabilities: 1
    Low Severity Vulnerabilities: 0
    Info Severity Vulnerabilities: 25

Key Vulnerabilities Identified

  1. Unsupported Windows OS (Critical)
        Plugin ID: 108797
        Severity: Critical (CVSS v3.0: 10.0)
        Description: The Windows system is running an unsupported version of the OS, which no longer receives security updates.
        Remediation: Upgrade to a supported version of Windows. Consider updating the operating system to the latest version to ensure continued security updates and patches.
   2. SMB Signing Not Required (Medium)

    Plugin ID: 57608
    Severity: Medium (CVSS v3.0: 5.3)
    Description: SMB (Server Message Block) signing is not required, which may allow attackers to perform man-in-the-middle attacks on the network traffic.
    Remediation: Enable SMB signing on the server and client machines to ensure that SMB traffic is encrypted and protected from potential attacks.
  3. Unsupported SMB Protocol Version (Info)

    Plugin ID: 96982
    Severity: Info
    Description: SMB Protocol Version 1 is enabled on the system, which is considered insecure.
    Remediation: Disable SMBv1 on the system to prevent exploitation of vulnerabilities associated with this outdated protocol.
   4. OS Security Patch Assessment Not Available (Info)

    Plugin ID: 11936
    Severity: Info
    Description: Nessus was unable to determine the status of security patches for the OS.
    Remediation: Ensure that the system is fully patched by regularly updating the operating system through Windows Update.
   5. Traceroute Information (Info)

    Plugin ID: 10287
    Severity: Info
    Description: The system returned information related to traceroute operations that could potentially disclose network structure information.
    Remediation: Restrict or configure network services to avoid leaking network topology and routing details.

   Steps for Remediation

   For Unsupported Windows OS:
        Update the Windows OS to the latest supported version.
        Use Windows Update or upgrade using installation media.

   For SMB Signing Not Required:
        Enable SMB signing through the group policy or registry.
        On the Windows machine, run the following command in PowerShell:
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

   For Disabling SMBv1:

    Disable SMBv1 by running the following command:
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

For OS Security Patch Assessment:

    Ensure Windows Update is enabled and regularly updates the system.
    Apply any missing security patches as per Microsoft’s official update guide.

For Traceroute Information:

    Restrict or block ICMP and other diagnostic services that could leak network topology data using firewall rules or network configuration.
Conclusion

This project demonstrates the practical use of Nessus for vulnerability scanning and provides an actionable plan for securing systems. By following the remediation steps outlined above, system administrators can reduce the risk of exploitation due to known vulnerabilities.

This project involved scanning a window IP address in a controlled, ethical environment. The scan was conducted on my own Windows machine within my local network, ensuring no unauthorized access or harm to any other systems. The purpose of the scan was solely for educational and security assessment, following ethical guidelines and industry best practices.
