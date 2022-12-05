import re

def sigma_suspicious_reg_add_bitlocker(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_reg_bitlocker.yml
    title: Suspicious Reg Add BitLocker
    fields: ['CommandLine']
    level: high
    description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("REG") and record['COMMAND_LINE'].contains("ADD") and record['COMMAND_LINE'].contains("\\SOFTWARE\\Policies\\Microsoft\\FVE") and record['COMMAND_LINE'].contains("/v") and record['COMMAND_LINE'].contains("/f") and (record['COMMAND_LINE'].contains("EnableBDEWithNoTPM") or record['COMMAND_LINE'].contains("UseAdvancedStartup") or record['COMMAND_LINE'].contains("UseTPM") or record['COMMAND_LINE'].contains("UseTPMKey") or record['COMMAND_LINE'].contains("UseTPMKeyPIN") or record['COMMAND_LINE'].contains("RecoveryKeyMessageSource") or record['COMMAND_LINE'].contains("UseTPMPIN") or record['COMMAND_LINE'].contains("RecoveryKeyMessage")))

sigma_suspicious_reg_add_bitlocker.sigma_meta = dict(
    level="high"
)

def sigma_application_whitelisting_bypass_via_dxcap_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_dxcap.yml
    title: Application Whitelisting Bypass via Dxcap.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects execution of of Dxcap.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\DXCap.exe") or record['ORIGINAL_FILE_NAME'] == "DXCap.exe") and record['COMMAND_LINE'].contains("-c"))

sigma_application_whitelisting_bypass_via_dxcap_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_offlinescannershell_exe_execution_from_another_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_offlinescannershell.yml
    title: Suspicious OfflineScannerShell.exe Execution From Another Folder
    fields: ['Image', 'CurrentDirectory']
    level: medium
    description: Use OfflineScannerShell.exe to execute mpclient.dll library in the current working directory
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\OfflineScannerShell.exe") and not ((record['PROCESS_PATH'] == "C:\\Program Files\\Windows Defender\\Offline") or (record.get('PROCESS_PATH', None) == None)))

sigma_suspicious_offlinescannershell_exe_execution_from_another_folder.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_sysaidserver_child(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_web_sysaidserver.yml
    title: Suspicious SysAidServer Child
    fields: ['ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and record['PARENT_COMMAND_LINE'].contains("SysAidServer"))

sigma_suspicious_sysaidserver_child.sigma_meta = dict(
    level="medium"
)

def sigma_hurricane_panda_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_hurricane_panda.yml
    title: Hurricane Panda Activity
    fields: ['CommandLine']
    level: high
    description: Detects Hurricane Panda Activity
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("localgroup") and record['COMMAND_LINE'].contains("admin") and record['COMMAND_LINE'].contains("/add")) or record['COMMAND_LINE'].contains("\\Win64.exe"))

sigma_hurricane_panda_activity.sigma_meta = dict(
    level="high"
)

def sigma_uninstall_sysinternals_sysmon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uninstall_sysmon.yml
    title: Uninstall Sysinternals Sysmon
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the uninstallation of Sysinternals Sysmon, which could be the result of legitimate administration or a manipulation for defense evasion
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\Sysmon64.exe") or record['PROCESS_NAME'].endswith("\\Sysmon.exe")) and record['COMMAND_LINE'].contains("-u"))

sigma_uninstall_sysinternals_sysmon.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_event_viewer_recentviews(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr.yml
    title: UAC Bypass Using Event Viewer RecentViews
    fields: ['CommandLine']
    level: high
    description: Detects the pattern of UAC Bypass using Event Viewer RecentViews
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\Event Viewer\\RecentViews") or record['COMMAND_LINE'].contains("\\EventV~1\\RecentViews")) and record['COMMAND_LINE'].contains(">"))

sigma_uac_bypass_using_event_viewer_recentviews.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_obfuscated_iex_invocation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_obfuscated_iex_commandline.yml
    title: Invoke-Obfuscation Obfuscated IEX Invocation
    fields: ['CommandLine']
    level: high
    description: Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the following code block
    logsource: category:process_creation - product:windows
    """
    return (re.match('\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\[', record['COMMAND_LINE']) or re.match('\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\[', record['COMMAND_LINE']) or re.match('\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\[', record['COMMAND_LINE']) or re.match('\$env:ComSpec\[(\s*\d{1,3}\s*,){2}', record['COMMAND_LINE']) or re.match('\\\\*mdr\\\\*\W\s*\)\.Name', record['COMMAND_LINE']) or re.match('\$VerbosePreference\.ToString\(', record['COMMAND_LINE']) or re.match('\\\\String\]\s*\$VerbosePreference', record['COMMAND_LINE']))

sigma_invoke_obfuscation_obfuscated_iex_invocation.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_changepk_and_slui(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_changepk_slui.yml
    title: UAC Bypass Using ChangePK and SLUI
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\changepk.exe") and record['PARENT_NAME'].endswith("\\slui.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_changepk_and_slui.sigma_meta = dict(
    level="high"
)

def sigma_krbrelay_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_krbrelay.yml
    title: KrbRelay Hack Tool
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the use of KrbRelay, a Kerberos relaying tool
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\KrbRelay.exe") or record['ORIGINAL_FILE_NAME'] == "KrbRelay.exe" or (record['COMMAND_LINE'].contains("-spn") and record['COMMAND_LINE'].contains("-clsid") and record['COMMAND_LINE'].contains("-rbcd")) or (record['COMMAND_LINE'].contains("shadowcred") and record['COMMAND_LINE'].contains("clsid") and record['COMMAND_LINE'].contains("spn")) or (record['COMMAND_LINE'].contains("spn") and record['COMMAND_LINE'].contains("session") and record['COMMAND_LINE'].contains("clsid")))

sigma_krbrelay_hack_tool.sigma_meta = dict(
    level="high"
)

def sigma_user_discovery_and_export_via_get_aduser_cmdlet(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_user_discovery_get_aduser.yml
    title: User Discovery And Export Via Get-ADUser Cmdlet
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll")) and (record['COMMAND_LINE'].contains("Get-ADUser") and record['COMMAND_LINE'].contains("-Filter ") and (record['COMMAND_LINE'].contains(">") or record['COMMAND_LINE'].contains("| Select") or record['COMMAND_LINE'].contains("Out-File") or record['COMMAND_LINE'].contains("Set-Content") or record['COMMAND_LINE'].contains("Add-Content"))))

sigma_user_discovery_and_export_via_get_aduser_cmdlet.sigma_meta = dict(
    level="medium"
)

def sigma_application_whitelisting_bypass_via_dll_loaded_by_odbcconf_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_odbcconf.yml
    title: Application Whitelisting Bypass via DLL Loaded by odbcconf.exe
    fields: ['CommandLine', 'OriginalFilename', 'Image', 'ParentImage']
    level: medium
    description: Detects defence evasion attempt via odbcconf.exe execution to load DLL
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\odbcconf.exe") or record['ORIGINAL_FILENAME'] == "odbcconf.exe") and (record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("-f") or record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("/f") or record['COMMAND_LINE'].contains("regsvr"))) or (record['PARENT_NAME'].endswith("\\odbcconf.exe") and record['PROCESS_NAME'].endswith("\\rundll32.exe")))

sigma_application_whitelisting_bypass_via_dll_loaded_by_odbcconf_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_child_process_created_as_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml
    title: Suspicious Child Process Created as System
    fields: ['IntegrityLevel', 'CommandLine', 'Image', 'ParentUser', 'User']
    level: high
    description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE accounts
    logsource: category:process_creation - product:windows - definition:ParentUser field needs sysmon >= 13.30
    """
    return (((record['PARENT_USER'] == "NT AUTHORITY\\NETWORK SERVICE" or record['PARENT_USER'] == "NT AUTHORITY\\LOCAL SERVICE" or record['PARENT_USER'] == "AUTORITE NT") and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")) and (record['USERNAME'].endswith("\\SYSTEM") or record['USERNAME'].endswith("\\СИСТЕМА")) and record['INTEGRITY_LEVEL'] == "System") and not (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("DavSetCookie")))

sigma_suspicious_child_process_created_as_system.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_mshta_process_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mshta_pattern.yml
    title: Suspicious MSHTA Process Patterns
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects suspicious mshta process patterns
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\mshta.exe") and ((record['PARENT_NAME'].endswith("\\cmd.exe") or record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe")) or (record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("C:\\Users\\Public")))) or (record['PROCESS_NAME'].endswith("\\mshta.exe") and not (((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64"))) or ((record['COMMAND_LINE'].contains(".htm") or record['COMMAND_LINE'].contains(".hta")) and (record['COMMAND_LINE'].endswith("mshta.exe") or record['COMMAND_LINE'].endswith("mshta"))))))

sigma_suspicious_mshta_process_patterns.sigma_meta = dict(
    level="high"
)

def sigma_use_of_ttdinject_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_ttdinject.yml
    title: Use of TTDInject.exe
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects the executiob of TTDInject.exe, which is used by Windows 10 v1809 and newer to debug time travel (underlying call of tttracer.exe)
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("ttdinject.exe") or record['ORIGINAL_FILE_NAME'] == "TTDInject.EXE")

sigma_use_of_ttdinject_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_powershell_download_and_execute_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml
    title: Suspicious PowerShell Download and Execute Pattern
    fields: ['CommandLine']
    level: high
    description: Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("IEX ((New-Object Net.WebClient).DownloadString") or record['COMMAND_LINE'].contains("IEX (New-Object Net.WebClient).DownloadString") or record['COMMAND_LINE'].contains("IEX((New-Object Net.WebClient).DownloadString") or record['COMMAND_LINE'].contains("IEX(New-Object Net.WebClient).DownloadString") or record['COMMAND_LINE'].contains("-command (New-Object System.Net.WebClient).DownloadFile(") or record['COMMAND_LINE'].contains("-c (New-Object System.Net.WebClient).DownloadFile("))

sigma_suspicious_powershell_download_and_execute_pattern.sigma_meta = dict(
    level="high"
)

def sigma_kavremover_dropped_binary_lolbin_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_kavremover.yml
    title: Kavremover Dropped Binary LOLBIN Usage
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("run run-cmd") and not ((record['PARENT_NAME'].endswith("\\kavremover.exe") or record['PARENT_NAME'].endswith("\\cleanapi.exe"))))

sigma_kavremover_dropped_binary_lolbin_usage.sigma_meta = dict(
    level="high"
)

def sigma_windows_credential_manager_access_via_vaultcmd(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_vaultcmd.yml
    title: Windows Credential Manager Access via VaultCmd
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: List credentials currently stored in Windows Credential Manager via the native Windows utility vaultcmd.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\VaultCmd.exe") or record['ORIGINAL_FILE_NAME'] == "VAULTCMD.EXE") and record['COMMAND_LINE'].contains("/listcreds:"))

sigma_windows_credential_manager_access_via_vaultcmd.sigma_meta = dict(
    level="medium"
)

def sigma_download_files_using_notepad_gup_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_gup_download.yml
    title: Download Files Using Notepad++ GUP Utility
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\GUP.exe") or record['ORIGINAL_FILE_NAME'] == "gup.exe") and (record['COMMAND_LINE'].contains("-unzipTo") and record['COMMAND_LINE'].contains("http"))) and not (record['PARENT_NAME'].endswith("\\notepad++.exe")))

sigma_download_files_using_notepad_gup_utility.sigma_meta = dict(
    level="high"
)

def sigma_uefi_persistence_via_wpbbin_processcreation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wpbbin_persistence.yml
    title: UEFI Persistence Via Wpbbin - ProcessCreation
    fields: ['Image']
    level: high
    description: Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section
    logsource: product:windows - category:process_creation
    """
    return record['PROCESS_NAME'] == "C:\\Windows\\System32\\wpbbin.exe"

sigma_uefi_persistence_via_wpbbin_processcreation.sigma_meta = dict(
    level="high"
)

def sigma_bitsadmin_download_file_with_suspicious_extension(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_ext.yml
    title: Bitsadmin Download File with Suspicious Extension
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of bitsadmin downloading a file with a suspicious extension
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/transfer") or record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and (record['COMMAND_LINE'].contains(".asax") or record['COMMAND_LINE'].contains(".ashx") or record['COMMAND_LINE'].contains(".asmx") or record['COMMAND_LINE'].contains(".asp") or record['COMMAND_LINE'].contains(".aspx") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cfm") or record['COMMAND_LINE'].contains(".cgi") or record['COMMAND_LINE'].contains(".chm") or record['COMMAND_LINE'].contains(".cmd") or record['COMMAND_LINE'].contains(".gif") or record['COMMAND_LINE'].contains(".jpeg") or record['COMMAND_LINE'].contains(".jpg") or record['COMMAND_LINE'].contains(".jsp") or record['COMMAND_LINE'].contains(".jspx") or record['COMMAND_LINE'].contains(".png") or record['COMMAND_LINE'].contains(".ps1") or record['COMMAND_LINE'].contains(".psm1") or record['COMMAND_LINE'].contains(".scf") or record['COMMAND_LINE'].contains(".sct") or record['COMMAND_LINE'].contains(".txt") or record['COMMAND_LINE'].contains(".vbe") or record['COMMAND_LINE'].contains(".vbs") or record['COMMAND_LINE'].contains(".war") or record['COMMAND_LINE'].contains(".wsf") or record['COMMAND_LINE'].contains(".wsh") or record['COMMAND_LINE'].contains(".zip") or record['COMMAND_LINE'].contains(".rar") or record['COMMAND_LINE'].contains(".dll")))

sigma_bitsadmin_download_file_with_suspicious_extension.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_ieinstal_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_ieinstal.yml
    title: UAC Bypass Using IEInstal - Process
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
    logsource: category:process_creation - product:windows
    """
    return ((record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and record['PARENT_NAME'].endswith("\\ieinstal.exe") and record['PROCESS_NAME'].contains("\\AppData\\Local\\Temp") and record['PROCESS_NAME'].endswith("consent.exe"))

sigma_uac_bypass_using_ieinstal_process.sigma_meta = dict(
    level="high"
)

def sigma_abuse_of_service_permissions_to_hide_services_in_tools(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_using_sc_to_hide_sevices.yml
    title: Abuse of Service Permissions to Hide Services in Tools
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detection of sc.exe utility adding a new service with special permission which hides that service.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sc.exe") or record['ORIGINAL_FILE_NAME'] == "sc.exe") and (record['COMMAND_LINE'].contains("sdset") and record['COMMAND_LINE'].contains("DCLCWPDTSD")))

sigma_abuse_of_service_permissions_to_hide_services_in_tools.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_findstr_385201_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_findstr_385201.yml
    title: Suspicious Findstr 385201 Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Discovery of an installed Sysinternals Sysmon service using driver altitude (even if the name is changed).
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\findstr.exe") and record['COMMAND_LINE'].contains("385201"))

sigma_suspicious_findstr_385201_execution.sigma_meta = dict(
    level="high"
)

def sigma_file_download_with_headless_browser(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_headless_browser_file_download.yml
    title: File Download with Headless Browser
    fields: ['CommandLine', 'Image']
    level: high
    description: This is an unusual method to download files. It starts a browser headless and downloads a file from a location. This can be used by threat actors to download files.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msedge.exe") or record['PROCESS_NAME'].endswith("\\chrome.exe")) and record['COMMAND_LINE'].contains("--headless") and record['COMMAND_LINE'].contains("dump-dom") and record['COMMAND_LINE'].contains("http"))

sigma_file_download_with_headless_browser.sigma_meta = dict(
    level="high"
)

def sigma_protocolhandler_exe_downloaded_suspicious_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_protocolhandler_susp_file.yml
    title: ProtocolHandler.exe Downloaded Suspicious File
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Emulates attack via documents through protocol handler in Microsoft Office. On successful execution you should see Microsoft Word launch a blank file.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\protocolhandler.exe") or record['ORIGINAL_FILE_NAME'] == "ProtocolHandler.exe") and (record['COMMAND_LINE'].contains("\"ms-word") and record['COMMAND_LINE'].contains(".docx\"")))

sigma_protocolhandler_exe_downloaded_suspicious_file.sigma_meta = dict(
    level="medium"
)

def sigma_crackmapexec_command_line_flags(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_crackmapexec_flags.yml
    title: CrackMapExec Command Line Flags
    fields: ['CommandLine']
    level: high
    description: This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-M pe_inject") or (record['COMMAND_LINE'].contains("--local-auth") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-x")) or (record['COMMAND_LINE'].contains("--local-auth") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and record['COMMAND_LINE'].contains("-H \'NTHASH\'")) or (record['COMMAND_LINE'].contains("mssql") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and record['COMMAND_LINE'].contains("-M") and record['COMMAND_LINE'].contains("-d")) or (record['COMMAND_LINE'].contains("smb") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-H") and record['COMMAND_LINE'].contains("-M") and record['COMMAND_LINE'].contains("-o")) or (record['COMMAND_LINE'].contains("smb") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and record['COMMAND_LINE'].contains("--local-auth"))) or (record['COMMAND_LINE'].contains("--local-auth") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and record['COMMAND_LINE'].contains("10.") and record['COMMAND_LINE'].contains("192.168.") and record['COMMAND_LINE'].contains("/24")))

sigma_crackmapexec_command_line_flags.sigma_meta = dict(
    level="high"
)

def sigma_mstsc_shadowing(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rdp_hijack_shadowing.yml
    title: MSTSC Shadowing
    fields: ['CommandLine']
    level: high
    description: Detects RDP session hijacking by using MSTSC shadowing
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("noconsentprompt") and record['COMMAND_LINE'].contains("shadow:"))

sigma_mstsc_shadowing.sigma_meta = dict(
    level="high"
)

def sigma_hh_exe_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hh_chm.yml
    title: HH.exe Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Identifies usage of hh.exe executing recently modified .chm files.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\hh.exe") and record['COMMAND_LINE'].contains(".chm"))

sigma_hh_exe_execution.sigma_meta = dict(
    level="high"
)

def sigma_renamed_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_powershell.yml
    title: Renamed PowerShell
    fields: ['Image', 'Company', 'Description']
    level: high
    description: Detects the execution of a renamed PowerShell often used by attackers or malware
    logsource: product:windows - category:process_creation
    """
    return (((record['DESCRIPTION'].startswith("Windows PowerShell") or record['DESCRIPTION'].startswith("pwsh")) and record['COMPANY'] == "Microsoft Corporation") and not ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe"))))

sigma_renamed_powershell.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_printerports_creation_cve_2020_1048_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2020_1048.yml
    title: Suspicious PrinterPorts Creation (CVE-2020-1048)
    fields: ['CommandLine']
    level: high
    description: Detects new commands that add new printer port which point to suspicious file
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Add-PrinterPort -Name") and (record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bat"))) or record['COMMAND_LINE'].contains("Generic / Text Only"))

sigma_suspicious_printerports_creation_cve_2020_1048_.sigma_meta = dict(
    level="high"
)

def sigma_anydesk_inline_piped_password(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_anydesk_piped_password_via_cli.yml
    title: AnyDesk Inline Piped Password
    fields: ['CommandLine']
    level: high
    description: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains("--set-password"))

sigma_anydesk_inline_piped_password.sigma_meta = dict(
    level="high"
)

def sigma_bitsadmin_download_to_suspicious_target_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.yml
    title: Bitsadmin Download to Suspicious Target Folder
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of bitsadmin downloading a file to a suspicious target folder
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/transfer") or record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and (record['COMMAND_LINE'].contains("C:\\Users\\Public") or record['COMMAND_LINE'].contains("%public%") or record['COMMAND_LINE'].contains("\\Desktop")))

sigma_bitsadmin_download_to_suspicious_target_folder.sigma_meta = dict(
    level="high"
)

def sigma_use_of_pktmon_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_pktmon.yml
    title: Use of PktMon.exe
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Tools to Capture Network Packets on the windows 10 with October 2018 Update or later.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("PktMon.exe") or record['ORIGINAL_FILE_NAME'] == "PktMon.exe")

sigma_use_of_pktmon_exe.sigma_meta = dict(
    level="medium"
)

def sigma_pingback_backdoor(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pingback_backdoor.yml
    title: Pingback Backdoor
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report
    logsource: product:windows - category:process_creation
    """
    return (record['PARENT_NAME'].endswith("updata.exe") and record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("msdtc") and record['COMMAND_LINE'].contains("start") and record['COMMAND_LINE'].contains("auto"))

sigma_pingback_backdoor.sigma_meta = dict(
    level="high"
)

def sigma_mshta_spawning_windows_shell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mshta_spawn_shell.yml
    title: MSHTA Spawning Windows Shell
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a Windows command line executable started from MSHTA
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\mshta.exe") and ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\reg.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe")) or record['PROCESS_NAME'].contains("\\BITSADMIN")))

sigma_mshta_spawning_windows_shell.sigma_meta = dict(
    level="high"
)

def sigma_firewall_disabled_via_netsh(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_netsh_firewall_disable.yml
    title: Firewall Disabled via Netsh
    fields: ['CommandLine']
    level: medium
    description: Detects netsh commands that turns off the Windows firewall
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("opmode") and record['COMMAND_LINE'].contains("mode=disable")) or (record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("advfirewall") and record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("state") and record['COMMAND_LINE'].contains("off")))

sigma_firewall_disabled_via_netsh.sigma_meta = dict(
    level="medium"
)

def sigma_sideloading_link_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_sideload_link_binary.yml
    title: Sideloading Link.EXE
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects the execution utitilies often found in Visual Studio tools that hardcode the call to the binary "link.exe". They can be abused to sideload any binary with the same name
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\link.exe") and record['COMMAND_LINE'].contains("LINK /")) and not (((record['PARENT_NAME'].startswith("C:\\Program Files\\Microsoft Visual Studio") or record['PARENT_NAME'].startswith("C:\\Program Files (x86)\\Microsoft Visual Studio")) and record['PARENT_NAME'].contains("\\VC\\Tools\\MSVC"))))

sigma_sideloading_link_exe.sigma_meta = dict(
    level="medium"
)

def sigma_shadow_copies_creation_using_operating_systems_utilities(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shadow_copies_creation.yml
    title: Shadow Copies Creation Using Operating Systems Utilities
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Shadow Copies creation using operating systems utilities, possible credential access
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\vssadmin.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['ORIGINAL_FILE_NAME'] == "VSSADMIN.EXE")) and (record['COMMAND_LINE'].contains("shadow") and record['COMMAND_LINE'].contains("create")))

sigma_shadow_copies_creation_using_operating_systems_utilities.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_vboxdrvinst_exe_parameters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_vboxdrvinst.yml
    title: Suspicious VBoxDrvInst.exe Parameters
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detect VBoxDrvInst.exe run with parameters allowing processing INF file.
This allows to create values in the registry and install drivers.
For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\VBoxDrvInst.exe") and record['COMMAND_LINE'].contains("driver") and record['COMMAND_LINE'].contains("executeinf"))

sigma_suspicious_vboxdrvinst_exe_parameters.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ldifde_command_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ldifde_file_load.yml
    title: Suspicious Ldifde Command Usage
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects the use of Ldifde.exe with specific command line arguments to potentially load an LDIF file containing HTTP-based arguments.
Ldifde.exe is present, by default, on domain controllers and only requires user-level authentication to execute.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ldifde.exe") or record['ORIGINAL_FILE_NAME'] == "ldifde.exe.mui") and (record['COMMAND_LINE'].contains("-i") and record['COMMAND_LINE'].contains("-f")))

sigma_suspicious_ldifde_command_usage.sigma_meta = dict(
    level="medium"
)

def sigma_new_lolbin_process_by_office_applications(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbins_by_office_applications.yml
    title: New Lolbin Process by Office Applications
    fields: ['Image', 'ParentImage']
    level: high
    description: This rule will monitor any office apps that spins up a new LOLBin process. This activity is pretty suspicious and should be investigated.
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\verclsid.exe") or record['PROCESS_NAME'].endswith("\\msdt.exe") or record['PROCESS_NAME'].endswith("\\control.exe") or record['PROCESS_NAME'].endswith("\\msidb.exe")) and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe") or record['PARENT_NAME'].endswith("\\msaccess.exe") or record['PARENT_NAME'].endswith("\\mspub.exe") or record['PARENT_NAME'].endswith("\\eqnedt32.exe") or record['PARENT_NAME'].endswith("\\visio.exe") or record['PARENT_NAME'].endswith("\\wordpad.exe") or record['PARENT_NAME'].endswith("\\wordview.exe")))

sigma_new_lolbin_process_by_office_applications.sigma_meta = dict(
    level="high"
)

def sigma_execution_via_cl_invocation_ps1(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_cl_invocation.yml
    title: Execution via CL_Invocation.ps1
    fields: ['CommandLine']
    level: high
    description: Detects Execution via SyncInvoke in CL_Invocation.ps1 module
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("CL_Invocation.ps1") and record['COMMAND_LINE'].contains("SyncInvoke"))

sigma_execution_via_cl_invocation_ps1.sigma_meta = dict(
    level="high"
)

def sigma_interactive_at_job(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_interactive_at.yml
    title: Interactive AT Job
    fields: ['CommandLine', 'Image']
    level: high
    description: Detect an interactive AT job, which may be used as a form of privilege escalation.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\at.exe") and record['COMMAND_LINE'].contains("interactive"))

sigma_interactive_at_job.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_tscon_start_as_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_tscon_localsystem.yml
    title: Suspicious TSCON Start as SYSTEM
    fields: ['User', 'Image']
    level: high
    description: Detects a tscon.exe start as LOCAL SYSTEM
    logsource: category:process_creation - product:windows
    """
    return ((record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")) and record['PROCESS_NAME'].endswith("\\tscon.exe"))

sigma_suspicious_tscon_start_as_system.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_vsls_agent_command_with_agentextensionpath_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_vslsagent_agentextensionpath_load.yml
    title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\vsls-agent.exe") and record['COMMAND_LINE'].contains("--agentExtensionPath")) and not (record['COMMAND_LINE'].contains("Microsoft.VisualStudio.LiveShare.Agent.")))

sigma_suspicious_vsls_agent_command_with_agentextensionpath_load.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_paexec(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_renamed_paexec.yml
    title: Renamed PAExec
    fields: ['Image', 'OriginalFileName', 'Description']
    level: high
    description: Detects execution of renamed version of PAExec. Often used by attackers
    logsource: category:process_creation - product:windows
    """
    return ((record['DESCRIPTION'] == "PAExec Application" or record['ORIGINAL_FILE_NAME'] == "PAExec.exe") and not (record['PROCESS_NAME'].endswith("\\paexec.exe") or record['PROCESS_NAME'].startswith("C:\\Windows\\PAExec-")))

sigma_renamed_paexec.sigma_meta = dict(
    level="high"
)

def sigma_possible_ransomware_or_unauthorized_mbr_modifications(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_bcdedit.yml
    title: Possible Ransomware or Unauthorized MBR Modifications
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects, possibly, malicious unauthorized usage of bcdedit.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\bcdedit.exe") and (record['COMMAND_LINE'].contains("delete") or record['COMMAND_LINE'].contains("deletevalue") or record['COMMAND_LINE'].contains("import") or record['COMMAND_LINE'].contains("safeboot") or record['COMMAND_LINE'].contains("network")))

sigma_possible_ransomware_or_unauthorized_mbr_modifications.sigma_meta = dict(
    level="medium"
)

def sigma_persistence_via_typedpaths_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_persistence_typed_paths.yml
    title: Persistence Via TypedPaths - CommandLine
    fields: ['CommandLine']
    level: medium
    description: Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")

sigma_persistence_via_typedpaths_commandline.sigma_meta = dict(
    level="medium"
)

def sigma_using_settingsynchost_exe_as_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.yml
    title: Using SettingSyncHost.exe as LOLBin
    fields: ['Image', 'ParentCommandLine']
    level: high
    description: Detects using SettingSyncHost.exe to run hijacked binary
    logsource: category:process_creation - product:windows
    """
    return (not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64"))) and (record['PARENT_COMMAND_LINE'].contains("cmd.exe /c") and record['PARENT_COMMAND_LINE'].contains("RoamDiag.cmd") and record['PARENT_COMMAND_LINE'].contains("-outputpath")))

sigma_using_settingsynchost_exe_as_lolbin.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_gup_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_gup.yml
    title: Suspicious GUP Usage
    fields: ['Image']
    level: high
    description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\GUP.exe") and not (((record['PROCESS_NAME'].endswith("\\Program Files\\Notepad++\\updater\\GUP.exe") or record['PROCESS_NAME'].endswith("\\Program Files (x86)\\Notepad++\\updater\\GUP.exe"))) or (record['PROCESS_NAME'].contains("\\Users") and (record['PROCESS_NAME'].endswith("\\AppData\\Local\\Notepad++\\updater\\GUP.exe") or record['PROCESS_NAME'].endswith("\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe")))))

sigma_suspicious_gup_usage.sigma_meta = dict(
    level="high"
)

def sigma_wlrmdr_lolbin_use_as_launcher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_wlrmdr.yml
    title: Wlrmdr Lolbin Use as Launcher
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects use of Wlrmdr.exe in which the -u parameter is passed to ShellExecute
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wlrmdr.exe") and record['COMMAND_LINE'].contains("-s") and record['COMMAND_LINE'].contains("-f") and record['COMMAND_LINE'].contains("-t") and record['COMMAND_LINE'].contains("-m") and record['COMMAND_LINE'].contains("-a") and record['COMMAND_LINE'].contains("-u")) and not ((record['PARENT_NAME'] == "C:\\Windows\\System32\\winlogon.exe") or (record['PARENT_NAME'] == "-")))

sigma_wlrmdr_lolbin_use_as_launcher.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_rundll32_exe_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_rundll32.yml
    title: Renamed Rundll32.exe Execution
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects the execution of rundll32.exe that has been renamed to a different name to avoid detection
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" and not (record['PROCESS_NAME'].endswith("\\rundll32.exe")))

sigma_renamed_rundll32_exe_execution.sigma_meta = dict(
    level="high"
)

def sigma_deletion_of_volume_shadow_copies_via_wmi_with_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shadowcopy_deletion_via_powershell.yml
    title: Deletion of Volume Shadow Copies via WMI with PowerShell
    fields: ['ScriptBlockText']
    level: high
    description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
    logsource: category:process_creation - product:windows
    """
    return ((record['SCRIPT_BLOCK_TEXT'].contains("Get-WmiObject") or record['SCRIPT_BLOCK_TEXT'].contains("gwmi") or record['SCRIPT_BLOCK_TEXT'].contains("Get-CimInstance") or record['SCRIPT_BLOCK_TEXT'].contains("gcim")) and record['SCRIPT_BLOCK_TEXT'].contains("Win32_Shadowcopy") and (record['SCRIPT_BLOCK_TEXT'].contains(".Delete()") or record['SCRIPT_BLOCK_TEXT'].contains("Remove-WmiObject") or record['SCRIPT_BLOCK_TEXT'].contains("rwmi") or record['SCRIPT_BLOCK_TEXT'].contains("Remove-CimInstance") or record['SCRIPT_BLOCK_TEXT'].contains("rcim")))

sigma_deletion_of_volume_shadow_copies_via_wmi_with_powershell.sigma_meta = dict(
    level="high"
)

def sigma_obfuscated_ip_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_obfuscated_ip_download.yml
    title: Obfuscated IP Download
    fields: ['CommandLine']
    level: medium
    description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Invoke-WebRequest") or record['COMMAND_LINE'].contains("iwr") or record['COMMAND_LINE'].contains("wget") or record['COMMAND_LINE'].contains("curl") or record['COMMAND_LINE'].contains("DownloadFile") or record['COMMAND_LINE'].contains("DownloadString")) and ((record['COMMAND_LINE'].contains("//0x") or record['COMMAND_LINE'].contains(".0x") or record['COMMAND_LINE'].contains(".00x")) or (record['COMMAND_LINE'].contains("http://%") and record['COMMAND_LINE'].contains("%2e"))))

sigma_obfuscated_ip_download.sigma_meta = dict(
    level="medium"
)

def sigma_launch_trufflesnout_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_trufflesnout.yml
    title: Launch TruffleSnout Executable
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detect use of TruffleSnout.exe
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "TruffleSnout.exe" or record['PROCESS_NAME'].endswith("\\TruffleSnout.exe"))

sigma_launch_trufflesnout_executable.sigma_meta = dict(
    level="medium"
)

def sigma_droppers_exploiting_cve_2017_11882(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2017_11882.yml
    title: Droppers Exploiting CVE-2017-11882
    fields: ['ParentImage']
    level: critical
    description: Detects exploits that use CVE-2017-11882 to start EQNEDT32.EXE and other sub processes like mshta.exe
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\EQNEDT32.EXE")

sigma_droppers_exploiting_cve_2017_11882.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_commandline_escape(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cli_escape.yml
    title: Suspicious Commandline Escape
    fields: ['CommandLine']
    level: low
    description: Detects suspicious process that use escape characters
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("h^t^t^p") or record['COMMAND_LINE'].contains("h\"t\"t\"p"))

sigma_suspicious_commandline_escape.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_workstation_locking_via_rundll32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_user32_dll.yml
    title: Suspicious Workstation Locking via Rundll32
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects a suspicious call to the user32.dll function that locks the user workstation
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['PARENT_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("user32.dll,") and record['COMMAND_LINE'].contains("LockWorkStation"))

sigma_suspicious_workstation_locking_via_rundll32.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_powershell_parent_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_parent_process.yml
    title: Suspicious PowerShell Parent Process
    fields: ['CommandLine', 'Image', 'ParentImage', 'Product', 'Description']
    level: high
    description: Detects a suspicious parents of powershell.exe
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\mshta.exe") or record['PARENT_NAME'].endswith("\\rundll32.exe") or record['PARENT_NAME'].endswith("\\regsvr32.exe") or record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\wmiprvse.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\msaccess.exe") or record['PARENT_NAME'].endswith("\\mspub.exe") or record['PARENT_NAME'].endswith("\\visio.exe") or record['PARENT_NAME'].endswith("\\outlook.exe") or record['PARENT_NAME'].endswith("\\amigo.exe") or record['PARENT_NAME'].endswith("\\chrome.exe") or record['PARENT_NAME'].endswith("\\firefox.exe") or record['PARENT_NAME'].endswith("\\iexplore.exe") or record['PARENT_NAME'].endswith("\\microsoftedgecp.exe") or record['PARENT_NAME'].endswith("\\microsoftedge.exe") or record['PARENT_NAME'].endswith("\\browser.exe") or record['PARENT_NAME'].endswith("\\vivaldi.exe") or record['PARENT_NAME'].endswith("\\safari.exe") or record['PARENT_NAME'].endswith("\\sqlagent.exe") or record['PARENT_NAME'].endswith("\\sqlserver.exe") or record['PARENT_NAME'].endswith("\\sqlservr.exe") or record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\httpd.exe") or record['PARENT_NAME'].endswith("\\nginx.exe") or record['PARENT_NAME'].endswith("\\php-cgi.exe") or record['PARENT_NAME'].endswith("\\jbosssvc.exe") or record['PARENT_NAME'].endswith("\\MicrosoftEdgeSH.exe")) or record['PARENT_NAME'].contains("tomcat")) and ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['COMMAND_LINE'].contains("/c powershell") or record['COMMAND_LINE'].contains("/c pwsh")) or record['DESCRIPTION'] == "Windows PowerShell" or record['PRODUCT_NAME'] == "PowerShell Core 6"))

sigma_suspicious_powershell_parent_process.sigma_meta = dict(
    level="high"
)

def sigma_registry_defender_tampering(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_defender_tampering.yml
    title: Registry Defender Tampering
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects reg command lines that disable certain important features of Microsoft Defender
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and (record['COMMAND_LINE'].contains("SOFTWARE\\Microsoft\\Windows Defender") or record['COMMAND_LINE'].contains("SOFTWARE\\Policies\\Microsoft\\Windows Defender"))) and ((record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("/d 0") and (record['COMMAND_LINE'].contains("Real-Time Protection") or record['COMMAND_LINE'].contains("TamperProtection"))) or (record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("/d 1") and record['COMMAND_LINE'].contains("Notification_Suppress"))))

sigma_registry_defender_tampering.sigma_meta = dict(
    level="high"
)

def sigma_mshta_suspicious_execution_01(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mshta_execution.yml
    title: MSHTA Suspicious Execution 01
    fields: ['CommandLine', 'Image']
    level: high
    description: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\mshta.exe") and (record['COMMAND_LINE'].contains("vbscript") or record['COMMAND_LINE'].contains(".jpg") or record['COMMAND_LINE'].contains(".png") or record['COMMAND_LINE'].contains(".lnk") or record['COMMAND_LINE'].contains(".xls") or record['COMMAND_LINE'].contains(".doc") or record['COMMAND_LINE'].contains(".zip") or record['COMMAND_LINE'].contains(".dll")))

sigma_mshta_suspicious_execution_01.sigma_meta = dict(
    level="high"
)

def sigma_cobaltstrike_load_by_rundll32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cobaltstrike_load_by_rundll32.yml
    title: CobaltStrike Load by Rundll32
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" or (record['COMMAND_LINE'].contains("rundll32.exe") or record['COMMAND_LINE'].contains("rundll32"))) and (record['COMMAND_LINE'].contains(".dll") and (record['COMMAND_LINE'].endswith("StartW") or record['COMMAND_LINE'].endswith(",StartW"))))

sigma_cobaltstrike_load_by_rundll32.sigma_meta = dict(
    level="high"
)

def sigma_node_exe_process_abuse(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_node_abuse.yml
    title: Node.exe Process Abuse
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the execution node.exe which is shipped with multiple softwares such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\node.exe") and (record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("--eval")) and record['COMMAND_LINE'].contains(".exec(") and record['COMMAND_LINE'].contains("net.socket") and record['COMMAND_LINE'].contains(".connect") and record['COMMAND_LINE'].contains("child_process"))

sigma_node_exe_process_abuse.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msiexec_directory(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_msiexec_cwd.yml
    title: Suspicious MsiExec Directory
    fields: ['Image']
    level: high
    description: Detects execution of msiexec from an uncommon directory
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\msiexec.exe") and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64") or record['PROCESS_NAME'].startswith("C:\\Windows\\WinSxS"))))

sigma_suspicious_msiexec_directory.sigma_meta = dict(
    level="high"
)

def sigma_psexec_accepteula_condition(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexec_eula.yml
    title: Psexec Accepteula Condition
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects user accept agreement execution in psexec commandline
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\psexec.exe") and record['COMMAND_LINE'].contains("accepteula"))

sigma_psexec_accepteula_condition.sigma_meta = dict(
    level="medium"
)

def sigma_hh_exe_remote_chm_file_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hh_chm_http.yml
    title: HH.exe Remote CHM File Execution
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of hh.exe to execute/download remotely hosted .chm files.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\hh.exe") and record['COMMAND_LINE'].contains("http"))

sigma_hh_exe_remote_chm_file_execution.sigma_meta = dict(
    level="medium"
)

def sigma_findstr_lsass(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_findstr_lsass.yml
    title: Findstr LSASS
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\findstr.exe") and record['COMMAND_LINE'].contains("lsass")) or (record['COMMAND_LINE'].contains("/i lsass.exe") or record['COMMAND_LINE'].contains("/i \"lsass") or record['COMMAND_LINE'].contains("findstr lsass") or record['COMMAND_LINE'].contains("findstr.exe lsass") or record['COMMAND_LINE'].contains("findstr \"lsass") or record['COMMAND_LINE'].contains("findstr.exe \"lsass")))

sigma_findstr_lsass.sigma_meta = dict(
    level="high"
)

def sigma_fireball_archer_install(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_crime_fireball.yml
    title: Fireball Archer Install
    fields: ['CommandLine']
    level: high
    description: Detects Archer malware invocation via rundll32
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("InstallArcherSvc"))

sigma_fireball_archer_install.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msiexec_quiet_install(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msiexec_install_quiet.yml
    title: Suspicious Msiexec Quiet Install
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)

    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['ORIGINAL_FILE_NAME'] == "msiexec.exe") and (record['COMMAND_LINE'].contains("/i") or record['COMMAND_LINE'].contains("-i") or record['COMMAND_LINE'].contains("/package") or record['COMMAND_LINE'].contains("-package") or record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("/j") or record['COMMAND_LINE'].contains("-j")) and (record['COMMAND_LINE'].contains("/q") or record['COMMAND_LINE'].contains("-q"))) and not ((record['PARENT_NAME'].startswith("C:\\Users") and record['PARENT_NAME'].contains("\\AppData\\Local\\Temp")) or (record['PARENT_NAME'].startswith("C:\\Windows\\Temp"))))

sigma_suspicious_msiexec_quiet_install.sigma_meta = dict(
    level="medium"
)

def sigma_whoami_as_parameter(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml
    title: WhoAmI as Parameter
    fields: ['CommandLine']
    level: high
    description: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains(".exe whoami")

sigma_whoami_as_parameter.sigma_meta = dict(
    level="high"
)

def sigma_verclsid_exe_runs_com_object(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_verclsid_runs_com.yml
    title: Verclsid.exe Runs COM Object
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects when verclsid.exe is used to run COM object via GUID
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\verclsid.exe") or record['ORIGINAL_FILE_NAME'] == "verclsid.exe") and (record['COMMAND_LINE'].contains("/S") and record['COMMAND_LINE'].contains("/C")))

sigma_verclsid_exe_runs_com_object.sigma_meta = dict(
    level="medium"
)

def sigma_tor_client_or_tor_browser_use(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tor_browser.yml
    title: Tor Client or Tor Browser Use
    fields: ['Image']
    level: high
    description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\tor.exe") or record['PROCESS_NAME'].endswith("\\Tor Browser\\Browser\\firefox.exe"))

sigma_tor_client_or_tor_browser_use.sigma_meta = dict(
    level="high"
)

def sigma_hydra_password_guessing_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_hydra.yml
    title: Hydra Password Guessing Hack Tool
    fields: ['CommandLine']
    level: high
    description: Detects command line parameters used by Hydra password guessing hack tool
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and (record['COMMAND_LINE'].contains("^USER^") or record['COMMAND_LINE'].contains("^PASS^")))

sigma_hydra_password_guessing_hack_tool.sigma_meta = dict(
    level="high"
)

def sigma_process_access_via_trolleyexpress_exclusion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_trolleyexpress_procdump.yml
    title: Process Access via TrolleyExpress Exclusion
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\TrolleyExpress 7") or record['COMMAND_LINE'].contains("\\TrolleyExpress 8") or record['COMMAND_LINE'].contains("\\TrolleyExpress 9") or record['COMMAND_LINE'].contains("\\TrolleyExpress.exe 7") or record['COMMAND_LINE'].contains("\\TrolleyExpress.exe 8") or record['COMMAND_LINE'].contains("\\TrolleyExpress.exe 9") or record['COMMAND_LINE'].contains("\\TrolleyExpress.exe -ma")) or (record['PROCESS_NAME'].endswith("\\TrolleyExpress.exe") and not ((record['ORIGINAL_FILE_NAME'].contains("CtxInstall")) or (record.get('ORIGINAL_FILE_NAME', None) == None))))

sigma_process_access_via_trolleyexpress_exclusion.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_load_dll_via_certoc_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_certoc_execution.yml
    title: Suspicious Load DLL via CertOC.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects when a user installs certificates by using CertOC.exe to loads the target DLL file.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certoc.exe") or record['ORIGINAL_FILE_NAME'] == "CertOC.exe") and (record['COMMAND_LINE'].contains("-LoadDLL") or record['COMMAND_LINE'].contains("/LoadDLL")))

sigma_suspicious_load_dll_via_certoc_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_userinit_child_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_userinit_child.yml
    title: Suspicious Userinit Child Process
    fields: ['CommandLine', 'Image', 'ImageFileName', 'ParentImage']
    level: medium
    description: Detects a suspicious child process of userinit
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\userinit.exe") and not ((record['COMMAND_LINE'].contains("\\netlogon")) or (record['PROCESS_NAME'].endswith("\\explorer.exe") or record['IMAGE_FILE_NAME'] == "explorer.exe")))

sigma_suspicious_userinit_child_process.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_rundll32_without_any_commandline_params(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_no_params.yml
    title: Suspicious Rundll32 Without Any CommandLine Params
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].endswith("\\rundll32.exe") and not ((record['PARENT_NAME'].endswith("\\svchost.exe")) or ((record['PARENT_NAME'].contains("\\AppData\\Local") or record['PARENT_NAME'].contains("\\Microsoft\\Edge")))))

sigma_suspicious_rundll32_without_any_commandline_params.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_mailbox_export_to_share(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mailboxexport_share.yml
    title: Suspicious PowerShell Mailbox Export to Share
    fields: ['CommandLine']
    level: critical
    description: Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("New-MailboxExportRequest") and record['COMMAND_LINE'].contains("-Mailbox") and record['COMMAND_LINE'].contains("-FilePath "))

sigma_suspicious_powershell_mailbox_export_to_share.sigma_meta = dict(
    level="critical"
)

def sigma_meterpreter_or_cobalt_strike_getsystem_service_start(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
    title: Meterpreter or Cobalt Strike Getsystem Service Start
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\services.exe") and ((record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains("\\pipe")) or (record['COMMAND_LINE'].contains("%COMSPEC%") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains("\\pipe")) or (record['COMMAND_LINE'].contains("cmd.exe") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains("\\pipe")) or (record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains(".dll,a") and record['COMMAND_LINE'].contains("/p:")))) and not (record['COMMAND_LINE'].contains("MpCmdRun")))

sigma_meterpreter_or_cobalt_strike_getsystem_service_start.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_dosfuscation_character_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.yml
    title: Suspicious Dosfuscation Character in Commandline
    fields: ['CommandLine']
    level: medium
    description: Detects possible payload obfuscation via the commandline
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("^^") or record['COMMAND_LINE'].contains(",;,") or record['COMMAND_LINE'].contains("%COMSPEC:~") or record['COMMAND_LINE'].contains("s^et") or record['COMMAND_LINE'].contains("s^e^t") or record['COMMAND_LINE'].contains("se^t"))

sigma_suspicious_dosfuscation_character_in_commandline.sigma_meta = dict(
    level="medium"
)

def sigma_exploit_for_cve_2017_8759(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2017_8759.yml
    title: Exploit for CVE-2017-8759
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects Winword starting uncommon sub process csc.exe as used in exploits for CVE-2017-8759
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\WINWORD.EXE") and record['PROCESS_NAME'].endswith("\\csc.exe"))

sigma_exploit_for_cve_2017_8759.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_csc_exe_source_file_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_csc_folder.yml
    title: Suspicious Csc.exe Source File Folder
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\csc.exe") and (record['COMMAND_LINE'].contains("\\AppData") or record['COMMAND_LINE'].contains("\\Windows\\Temp"))) and not (record['PARENT_NAME'].startswith("C:\\Program Files") or (record['PARENT_NAME'].endswith("\\sdiagnhost.exe") or record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\choco.exe")) or record['PARENT_COMMAND_LINE'].contains("\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection")))

sigma_suspicious_csc_exe_source_file_folder.sigma_meta = dict(
    level="medium"
)

def sigma_judgement_panda_credential_access_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_bear_activity_gtr19.yml
    title: Judgement Panda Credential Access Activity
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: critical
    description: Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\xcopy.exe") or record['ORIGINAL_FILE_NAME'] == "XCOPY.EXE") and (record['COMMAND_LINE'].contains("/S") and record['COMMAND_LINE'].contains("/E") and record['COMMAND_LINE'].contains("/C") and record['COMMAND_LINE'].contains("/Q") and record['COMMAND_LINE'].contains("/H") and record['COMMAND_LINE'].contains(""))) or ((record['PROCESS_NAME'].endswith("\\adexplorer.exe") or record['ORIGINAL_FILE_NAME'] == "AdExp") and (record['COMMAND_LINE'].contains("-snapshot") and record['COMMAND_LINE'].contains("\"\"") and record['COMMAND_LINE'].contains("c:\\users"))))

sigma_judgement_panda_credential_access_activity.sigma_meta = dict(
    level="critical"
)

def sigma_taskkill_symantec_endpoint_protection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_taskkill_sep.yml
    title: Taskkill Symantec Endpoint Protection
    fields: ['CommandLine']
    level: high
    description: Detects one of the possible scenarios for disabling symantec endpoint protection.
Symantec Endpoint Protection antivirus software services incorrectly implement the protected service mechanism.
As a result, the NT AUTHORITY/SYSTEM user can execute the taskkill /im command several times ccSvcHst.exe /f, thereby killing the process belonging to the service, and thus shutting down the service.

    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("taskkill") and record['COMMAND_LINE'].contains("/F") and record['COMMAND_LINE'].contains("/IM") and record['COMMAND_LINE'].contains("ccSvcHst.exe"))

sigma_taskkill_symantec_endpoint_protection.sigma_meta = dict(
    level="high"
)

def sigma_msdt_exe_execution_with_suspicious_cab_option(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msdt_susp_cab_options.yml
    title: MSDT.EXE Execution With Suspicious Cab Option
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects execution of msdt.exe using the "cab" flag which could indicates suspicious diagcab files with embedded answer files leveraging CVE-2022-30190
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msdt.exe") or record['ORIGINAL_FILE_NAME'] == "msdt.exe") and (record['COMMAND_LINE'].contains("/cab") or record['COMMAND_LINE'].contains("-cab")))

sigma_msdt_exe_execution_with_suspicious_cab_option.sigma_meta = dict(
    level="medium"
)

def sigma_exchange_powershell_snap_ins_used_by_hafnium(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_snapins_hafnium.yml
    title: Exchange PowerShell Snap-Ins Used by HAFNIUM
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects adding and using Exchange PowerShell snap-ins to export mailbox data by HAFNIUM
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("add-pssnapin microsoft.exchange.powershell.snapin"))

sigma_exchange_powershell_snap_ins_used_by_hafnium.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_no_file_or_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_schtasks_powershell_windowsapps_execution.yml
    title: Suspicious Powershell No File or Command
    fields: ['CommandLine']
    level: high
    description: Detects suspicious powershell execution that ends with a common flag instead of a command or a filename to execute (could be a sign of implicit execution that uses files in WindowsApps directory)
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].endswith("-windowstyle hidden\"") or record['COMMAND_LINE'].endswith("-windowstyle hidden") or record['COMMAND_LINE'].endswith("-windowstyle hidden\'") or record['COMMAND_LINE'].endswith("-w hidden\"") or record['COMMAND_LINE'].endswith("-w hidden") or record['COMMAND_LINE'].endswith("-w hidden\'") or record['COMMAND_LINE'].endswith("-ep bypass\"") or record['COMMAND_LINE'].endswith("-ep bypass") or record['COMMAND_LINE'].endswith("-ep bypass\'") or record['COMMAND_LINE'].endswith("-noni\"") or record['COMMAND_LINE'].endswith("-noni") or record['COMMAND_LINE'].endswith("-noni\'"))

sigma_suspicious_powershell_no_file_or_command.sigma_meta = dict(
    level="high"
)

def sigma_execution_of_non_existing_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_image_missing.yml
    title: Execution Of Non-Existing File
    fields: ['CommandLine', 'Image']
    level: high
    description: Checks whether the image specified in a process creation event is not a full, absolute path (caused by process ghosting or other unorthodox methods to start a process)
    logsource: category:process_creation - product:windows
    """
    return (not (record['PROCESS_NAME'].contains("")) and not ((record.get('PROCESS_NAME', None) == None) or ((record['PROCESS_NAME'] == "-" or record['PROCESS_NAME'] == "")) or ((record['PROCESS_NAME'] == "Registry" or record['PROCESS_NAME'] == "MemCompression" or record['PROCESS_NAME'] == "vmmem") or (record['COMMAND_LINE'] == "Registry" or record['COMMAND_LINE'] == "MemCompression" or record['COMMAND_LINE'] == "vmmem"))))

sigma_execution_of_non_existing_file.sigma_meta = dict(
    level="high"
)

def sigma_anydesk_silent_installation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_anydesk_silent_install.yml
    title: AnyDesk Silent Installation
    fields: ['CommandLine']
    level: high
    description: Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("--install") and record['COMMAND_LINE'].contains("--start-with-win") and record['COMMAND_LINE'].contains("--silent"))

sigma_anydesk_silent_installation.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_processes_spawned_by_winrm(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shell_spawn_from_winrm.yml
    title: Suspicious Processes Spawned by WinRM
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious processes including shells spawnd from WinRM host process
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\wsmprovhost.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wsl.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe")))

sigma_suspicious_processes_spawned_by_winrm.sigma_meta = dict(
    level="high"
)

def sigma_execution_via_diskshadow_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_diskshadow.yml
    title: Execution via Diskshadow.exe
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects using Diskshadow.exe to execute arbitrary code in text file
    logsource: category:process_creation - product:windows - definition:Requirements: Sysmon ProcessCreation logging must be activated and Windows audit must Include command line in process creation events
    """
    return (record['PROCESS_NAME'].endswith("\\diskshadow.exe") and (record['COMMAND_LINE'].contains("/s") or record['COMMAND_LINE'].contains("-s")))

sigma_execution_via_diskshadow_exe.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_calculator_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_calc.yml
    title: Suspicious Calculator Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\calc.exe") or (record['PROCESS_NAME'].endswith("\\calc.exe") and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64") or record['PROCESS_NAME'].startswith("C:\\Windows\\WinSxS")))))

sigma_suspicious_calculator_usage.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_scan_loop_network(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_network_scan_loop.yml
    title: Suspicious Scan Loop Network
    fields: ['CommandLine']
    level: medium
    description: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("for") or record['COMMAND_LINE'].contains("foreach")) and (record['COMMAND_LINE'].contains("nslookup") or record['COMMAND_LINE'].contains("ping")))

sigma_suspicious_scan_loop_network.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_aspnet_compiler_exe_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_aspnet_compiler.yml
    title: Suspicious aspnet_compiler.exe Execution
    fields: ['Image']
    level: medium
    description: Execute C# code with the Build Provider and proper folder structure in place.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].contains("C:\\Windows\\Microsoft.NET\\Framework") and record['PROCESS_NAME'].contains("aspnet_compiler.exe"))

sigma_suspicious_aspnet_compiler_exe_execution.sigma_meta = dict(
    level="medium"
)

def sigma_wbadmin_delete_systemstatebackup(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_delete_systemstatebackup.yml
    title: Wbadmin Delete Systemstatebackup
    fields: ['CommandLine', 'Image']
    level: high
    description: Deletes the Windows systemstatebackup using wbadmin.exe.
This technique is used by numerous ransomware families.
This may only be successful on server platforms that have Windows Backup enabled.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wbadmin.exe") or record['COMMAND_LINE'].contains("wbadmin")) and (record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("systemstatebackup") and record['COMMAND_LINE'].contains("-keepVersions:0")))

sigma_wbadmin_delete_systemstatebackup.sigma_meta = dict(
    level="high"
)

def sigma_encoded_powershell_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_cmdline_specific_comb_methods.yml
    title: Encoded PowerShell Command Line
    fields: ['CommandLine', 'Image']
    level: low
    description: Detects specific combinations of encoding methods in the PowerShell command lines
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (((record['COMMAND_LINE'].contains("ToInt") or record['COMMAND_LINE'].contains("ToDecimal") or record['COMMAND_LINE'].contains("ToByte") or record['COMMAND_LINE'].contains("ToUint") or record['COMMAND_LINE'].contains("ToSingle") or record['COMMAND_LINE'].contains("ToSByte")) and (record['COMMAND_LINE'].contains("ToChar") or record['COMMAND_LINE'].contains("ToString") or record['COMMAND_LINE'].contains("String"))) or ((record['COMMAND_LINE'].contains("char") and record['COMMAND_LINE'].contains("join")) or (record['COMMAND_LINE'].contains("split") and record['COMMAND_LINE'].contains("join")))))

sigma_encoded_powershell_command_line.sigma_meta = dict(
    level="low"
)

def sigma_copy_from_volume_shadow_copy(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cmd_shadowcopy_access.yml
    title: Copy from Volume Shadow Copy
    fields: ['CommandLine']
    level: medium
    description: Detects a copy execution that targets a shadow copy (sometimes used to copy registry hives that are in use)
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("copy \\\\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy")

sigma_copy_from_volume_shadow_copy.sigma_meta = dict(
    level="medium"
)

def sigma_crackmapexec_powershell_obfuscation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_crackmapexec_powershell_obfuscation.yml
    title: CrackMapExec PowerShell Obfuscation
    fields: ['CommandLine']
    level: high
    description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("powershell.exe") or record['COMMAND_LINE'].contains("pwsh.exe")) and (record['COMMAND_LINE'].contains("join*split") or record['COMMAND_LINE'].contains("( $ShellId[1]+$ShellId[13]+\'x\')") or record['COMMAND_LINE'].contains("( $PSHome[*]+$PSHOME[*]+") or record['COMMAND_LINE'].contains("( $env:Public[13]+$env:Public[5]+\'x\')") or record['COMMAND_LINE'].contains("( $env:ComSpec[4,*,25]-Join\'\')") or record['COMMAND_LINE'].contains("[1,3]+\'x\'-Join\'\')")))

sigma_crackmapexec_powershell_obfuscation.sigma_meta = dict(
    level="high"
)

def sigma_windows_hacktool_imphash(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hacktool_imphashes.yml
    title: Windows Hacktool Imphash
    fields: ['Hashes', 'Imphash']
    level: high
    description: Detects the use of Windows hacktools based on their import hash (imphash) even if the files have been renamed
    logsource: category:process_creation - product:windows
    """
    return ((record['IMPHASH'] == "bcca3c247b619dcd13c8cdff5f123932" or record['IMPHASH'] == "3a19059bd7688cb88e70005f18efc439" or record['IMPHASH'] == "bf6223a49e45d99094406777eb6004ba" or record['IMPHASH'] == "0c106686a31bfe2ba931ae1cf6e9dbc6" or record['IMPHASH'] == "0d1447d4b3259b3c2a1d4cfb7ece13c3" or record['IMPHASH'] == "1b0369a1e06271833f78ffa70ffb4eaf" or record['IMPHASH'] == "4c1b52a19748428e51b14c278d0f58e3" or record['IMPHASH'] == "4d927a711f77d62cebd4f322cb57ec6f" or record['IMPHASH'] == "66ee036df5fc1004d9ed5e9a94a1086a" or record['IMPHASH'] == "672b13f4a0b6f27d29065123fe882dfc" or record['IMPHASH'] == "6bbd59cea665c4afcc2814c1327ec91f" or record['IMPHASH'] == "725bb81dc24214f6ecacc0cfb36ad30d" or record['IMPHASH'] == "9528a0e91e28fbb88ad433feabca2456" or record['IMPHASH'] == "9da6d5d77be11712527dcab86df449a3" or record['IMPHASH'] == "a6e01bc1ab89f8d91d9eab72032aae88" or record['IMPHASH'] == "b24c5eddaea4fe50c6a96a2a133521e4" or record['IMPHASH'] == "d21bbc50dcc169d7b4d0f01962793154" or record['IMPHASH'] == "fcc251cceae90d22c392215cc9a2d5d6" or record['IMPHASH'] == "23867a89c2b8fc733be6cf5ef902f2d1" or record['IMPHASH'] == "a37ff327f8d48e8a4d2f757e1b6e70bc" or record['IMPHASH'] == "f9a28c458284584a93b14216308d31bd" or record['IMPHASH'] == "6118619783fc175bc7ebecff0769b46e" or record['IMPHASH'] == "959a83047e80ab68b368fdb3f4c6e4ea" or record['IMPHASH'] == "563233bfa169acc7892451f71ad5850a" or record['IMPHASH'] == "87575cb7a0e0700eb37f2e3668671a08" or record['IMPHASH'] == "13f08707f759af6003837a150a371ba1" or record['IMPHASH'] == "1781f06048a7e58b323f0b9259be798b" or record['IMPHASH'] == "233f85f2d4bc9d6521a6caae11a1e7f5" or record['IMPHASH'] == "24af2584cbf4d60bbe5c6d1b31b3be6d" or record['IMPHASH'] == "632969ddf6dbf4e0f53424b75e4b91f2" or record['IMPHASH'] == "713c29b396b907ed71a72482759ed757" or record['IMPHASH'] == "749a7bb1f0b4c4455949c0b2bf7f9e9f" or record['IMPHASH'] == "8628b2608957a6b0c6330ac3de28ce2e" or record['IMPHASH'] == "8b114550386e31895dfab371e741123d" or record['IMPHASH'] == "94cb940a1a6b65bed4d5a8f849ce9793" or record['IMPHASH'] == "9d68781980370e00e0bd939ee5e6c141" or record['IMPHASH'] == "b18a1401ff8f444056d29450fbc0a6ce" or record['IMPHASH'] == "cb567f9498452721d77a451374955f5f" or record['IMPHASH'] == "730073214094cd328547bf1f72289752" or record['IMPHASH'] == "17b461a082950fc6332228572138b80c" or record['IMPHASH'] == "dc25ee78e2ef4d36faa0badf1e7461c9" or record['IMPHASH'] == "819b19d53ca6736448f9325a85736792" or record['IMPHASH'] == "829da329ce140d873b4a8bde2cbfaa7e" or record['IMPHASH'] == "c547f2e66061a8dffb6f5a3ff63c0a74" or record['IMPHASH'] == "0588081ab0e63ba785938467e1b10cca" or record['IMPHASH'] == "0d9ec08bac6c07d9987dfd0f1506587c" or record['IMPHASH'] == "bc129092b71c89b4d4c8cdf8ea590b29" or record['IMPHASH'] == "4da924cf622d039d58bce71cdf05d242" or record['IMPHASH'] == "e7a3a5c377e2d29324093377d7db1c66" or record['IMPHASH'] == "9a9dbec5c62f0380b4fa5fd31deffedf" or record['IMPHASH'] == "af8a3976ad71e5d5fdfb67ddb8dadfce" or record['IMPHASH'] == "0c477898bbf137bbd6f2a54e3b805ff4" or record['IMPHASH'] == "0ca9f02b537bcea20d4ea5eb1a9fe338" or record['IMPHASH'] == "3ab3655e5a14d4eefc547f4781bf7f9e" or record['IMPHASH'] == "e6f9d5152da699934b30daab206471f6" or record['IMPHASH'] == "3ad59991ccf1d67339b319b15a41b35d" or record['IMPHASH'] == "ffdd59e0318b85a3e480874d9796d872" or record['IMPHASH'] == "0cf479628d7cc1ea25ec7998a92f5051" or record['IMPHASH'] == "07a2d4dcbd6cb2c6a45e6b101f0b6d51" or record['IMPHASH'] == "d6d0f80386e1380d05cb78e871bc72b1" or record['IMPHASH'] == "38d9e015591bbfd4929e0d0f47fa0055" or record['IMPHASH'] == "0e2216679ca6e1094d63322e3412d650" or record['IMPHASH'] == "ada161bf41b8e5e9132858cb54cab5fb" or record['IMPHASH'] == "2a1bc4913cd5ecb0434df07cb675b798" or record['IMPHASH'] == "11083e75553baae21dc89ce8f9a195e4" or record['IMPHASH'] == "a23d29c9e566f2fa8ffbb79267f5df80" or record['IMPHASH'] == "4a07f944a83e8a7c2525efa35dd30e2f" or record['IMPHASH'] == "767637c23bb42cd5d7397cf58b0be688" or record['IMPHASH'] == "14c4e4c72ba075e9069ee67f39188ad8" or record['IMPHASH'] == "3c782813d4afce07bbfc5a9772acdbdc" or record['IMPHASH'] == "7d010c6bb6a3726f327f7e239166d127" or record['IMPHASH'] == "89159ba4dd04e4ce5559f132a9964eb3" or record['IMPHASH'] == "6f33f4a5fc42b8cec7314947bd13f30f" or record['IMPHASH'] == "5834ed4291bdeb928270428ebbaf7604" or record['IMPHASH'] == "5a8a8a43f25485e7ee1b201edcbc7a38" or record['IMPHASH'] == "dc7d30b90b2d8abf664fbed2b1b59894" or record['IMPHASH'] == "41923ea1f824fe63ea5beb84db7a3e74" or record['IMPHASH'] == "3de09703c8e79ed2ca3f01074719906b" or record['IMPHASH'] == "a53a02b997935fd8eedcb5f7abab9b9f" or record['IMPHASH'] == "e96a73c7bf33a464c510ede582318bf2" or record['IMPHASH'] == "32089b8851bbf8bc2d014e9f37288c83" or record['IMPHASH'] == "09D278F9DE118EF09163C6140255C690" or record['IMPHASH'] == "03866661686829d806989e2fc5a72606" or record['IMPHASH'] == "e57401fbdadcd4571ff385ab82bd5d6d" or record['IMPHASH'] == "84B763C45C0E4A3E7CA5548C710DB4EE" or record['IMPHASH'] == "19584675d94829987952432e018d5056" or record['IMPHASH'] == "330768a4f172e10acb6287b87289d83b") or (record['HASHES'].contains("IMPHASH=BCCA3C247B619DCD13C8CDFF5F123932") or record['HASHES'].contains("IMPHASH=3A19059BD7688CB88E70005F18EFC439") or record['HASHES'].contains("IMPHASH=bf6223a49e45d99094406777eb6004ba") or record['HASHES'].contains("IMPHASH=0C106686A31BFE2BA931AE1CF6E9DBC6") or record['HASHES'].contains("IMPHASH=0D1447D4B3259B3C2A1D4CFB7ECE13C3") or record['HASHES'].contains("IMPHASH=1B0369A1E06271833F78FFA70FFB4EAF") or record['HASHES'].contains("IMPHASH=4C1B52A19748428E51B14C278D0F58E3") or record['HASHES'].contains("IMPHASH=4D927A711F77D62CEBD4F322CB57EC6F") or record['HASHES'].contains("IMPHASH=66EE036DF5FC1004D9ED5E9A94A1086A") or record['HASHES'].contains("IMPHASH=672B13F4A0B6F27D29065123FE882DFC") or record['HASHES'].contains("IMPHASH=6BBD59CEA665C4AFCC2814C1327EC91F") or record['HASHES'].contains("IMPHASH=725BB81DC24214F6ECACC0CFB36AD30D") or record['HASHES'].contains("IMPHASH=9528A0E91E28FBB88AD433FEABCA2456") or record['HASHES'].contains("IMPHASH=9DA6D5D77BE11712527DCAB86DF449A3") or record['HASHES'].contains("IMPHASH=A6E01BC1AB89F8D91D9EAB72032AAE88") or record['HASHES'].contains("IMPHASH=B24C5EDDAEA4FE50C6A96A2A133521E4") or record['HASHES'].contains("IMPHASH=D21BBC50DCC169D7B4D0F01962793154") or record['HASHES'].contains("IMPHASH=FCC251CCEAE90D22C392215CC9A2D5D6") or record['HASHES'].contains("IMPHASH=23867A89C2B8FC733BE6CF5EF902F2D1") or record['HASHES'].contains("IMPHASH=A37FF327F8D48E8A4D2F757E1B6E70BC") or record['HASHES'].contains("IMPHASH=F9A28C458284584A93B14216308D31BD") or record['HASHES'].contains("IMPHASH=6118619783FC175BC7EBECFF0769B46E") or record['HASHES'].contains("IMPHASH=959A83047E80AB68B368FDB3F4C6E4EA") or record['HASHES'].contains("IMPHASH=563233BFA169ACC7892451F71AD5850A") or record['HASHES'].contains("IMPHASH=87575CB7A0E0700EB37F2E3668671A08") or record['HASHES'].contains("IMPHASH=13F08707F759AF6003837A150A371BA1") or record['HASHES'].contains("IMPHASH=1781F06048A7E58B323F0B9259BE798B") or record['HASHES'].contains("IMPHASH=233F85F2D4BC9D6521A6CAAE11A1E7F5") or record['HASHES'].contains("IMPHASH=24AF2584CBF4D60BBE5C6D1B31B3BE6D") or record['HASHES'].contains("IMPHASH=632969DDF6DBF4E0F53424B75E4B91F2") or record['HASHES'].contains("IMPHASH=713C29B396B907ED71A72482759ED757") or record['HASHES'].contains("IMPHASH=749A7BB1F0B4C4455949C0B2BF7F9E9F") or record['HASHES'].contains("IMPHASH=8628B2608957A6B0C6330AC3DE28CE2E") or record['HASHES'].contains("IMPHASH=8B114550386E31895DFAB371E741123D") or record['HASHES'].contains("IMPHASH=94CB940A1A6B65BED4D5A8F849CE9793") or record['HASHES'].contains("IMPHASH=9D68781980370E00E0BD939EE5E6C141") or record['HASHES'].contains("IMPHASH=B18A1401FF8F444056D29450FBC0A6CE") or record['HASHES'].contains("IMPHASH=CB567F9498452721D77A451374955F5F") or record['HASHES'].contains("IMPHASH=730073214094CD328547BF1F72289752") or record['HASHES'].contains("IMPHASH=17B461A082950FC6332228572138B80C") or record['HASHES'].contains("IMPHASH=DC25EE78E2EF4D36FAA0BADF1E7461C9") or record['HASHES'].contains("IMPHASH=819B19D53CA6736448F9325A85736792") or record['HASHES'].contains("IMPHASH=829DA329CE140D873B4A8BDE2CBFAA7E") or record['HASHES'].contains("IMPHASH=C547F2E66061A8DFFB6F5A3FF63C0A74") or record['HASHES'].contains("IMPHASH=0588081AB0E63BA785938467E1B10CCA") or record['HASHES'].contains("IMPHASH=0D9EC08BAC6C07D9987DFD0F1506587C") or record['HASHES'].contains("IMPHASH=BC129092B71C89B4D4C8CDF8EA590B29") or record['HASHES'].contains("IMPHASH=4DA924CF622D039D58BCE71CDF05D242") or record['HASHES'].contains("IMPHASH=E7A3A5C377E2D29324093377D7DB1C66") or record['HASHES'].contains("IMPHASH=9A9DBEC5C62F0380B4FA5FD31DEFFEDF") or record['HASHES'].contains("IMPHASH=AF8A3976AD71E5D5FDFB67DDB8DADFCE") or record['HASHES'].contains("IMPHASH=0C477898BBF137BBD6F2A54E3B805FF4") or record['HASHES'].contains("IMPHASH=0CA9F02B537BCEA20D4EA5EB1A9FE338") or record['HASHES'].contains("IMPHASH=3AB3655E5A14D4EEFC547F4781BF7F9E") or record['HASHES'].contains("IMPHASH=E6F9D5152DA699934B30DAAB206471F6") or record['HASHES'].contains("IMPHASH=3AD59991CCF1D67339B319B15A41B35D") or record['HASHES'].contains("IMPHASH=FFDD59E0318B85A3E480874D9796D872") or record['HASHES'].contains("IMPHASH=0CF479628D7CC1EA25EC7998A92F5051") or record['HASHES'].contains("IMPHASH=07A2D4DCBD6CB2C6A45E6B101F0B6D51") or record['HASHES'].contains("IMPHASH=D6D0F80386E1380D05CB78E871BC72B1") or record['HASHES'].contains("IMPHASH=38D9E015591BBFD4929E0D0F47FA0055") or record['HASHES'].contains("IMPHASH=0E2216679CA6E1094D63322E3412D650") or record['HASHES'].contains("IMPHASH=ADA161BF41B8E5E9132858CB54CAB5FB") or record['HASHES'].contains("IMPHASH=2A1BC4913CD5ECB0434DF07CB675B798") or record['HASHES'].contains("IMPHASH=11083E75553BAAE21DC89CE8F9A195E4") or record['HASHES'].contains("IMPHASH=A23D29C9E566F2FA8FFBB79267F5DF80") or record['HASHES'].contains("IMPHASH=4A07F944A83E8A7C2525EFA35DD30E2F") or record['HASHES'].contains("IMPHASH=767637C23BB42CD5D7397CF58B0BE688") or record['HASHES'].contains("IMPHASH=14C4E4C72BA075E9069EE67F39188AD8") or record['HASHES'].contains("IMPHASH=3C782813D4AFCE07BBFC5A9772ACDBDC") or record['HASHES'].contains("IMPHASH=7D010C6BB6A3726F327F7E239166D127") or record['HASHES'].contains("IMPHASH=89159BA4DD04E4CE5559F132A9964EB3") or record['HASHES'].contains("IMPHASH=6F33F4A5FC42B8CEC7314947BD13F30F") or record['HASHES'].contains("IMPHASH=5834ED4291BDEB928270428EBBAF7604") or record['HASHES'].contains("IMPHASH=5A8A8A43F25485E7EE1B201EDCBC7A38") or record['HASHES'].contains("IMPHASH=DC7D30B90B2D8ABF664FBED2B1B59894") or record['HASHES'].contains("IMPHASH=41923EA1F824FE63EA5BEB84DB7A3E74") or record['HASHES'].contains("IMPHASH=3DE09703C8E79ED2CA3F01074719906B") or record['HASHES'].contains("IMPHASH=A53A02B997935FD8EEDCB5F7ABAB9B9F") or record['HASHES'].contains("IMPHASH=E96A73C7BF33A464C510EDE582318BF2") or record['HASHES'].contains("IMPHASH=32089B8851BBF8BC2D014E9F37288C83") or record['HASHES'].contains("IMPHASH=09D278F9DE118EF09163C6140255C690") or record['HASHES'].contains("IMPHASH=03866661686829d806989e2fc5a72606") or record['HASHES'].contains("IMPHASH=e57401fbdadcd4571ff385ab82bd5d6d") or record['HASHES'].contains("IMPHASH=84B763C45C0E4A3E7CA5548C710DB4EE") or record['HASHES'].contains("IMPHASH=19584675D94829987952432E018D5056") or record['HASHES'].contains("IMPHASH=330768A4F172E10ACB6287B87289D83B")))

sigma_windows_hacktool_imphash.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_cmd_execution_via_wmi(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cmd_exectution_via_wmi.yml
    title: Suspicious Cmd Execution via WMI
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious command execution (cmd) via Windows Management Instrumentation (WMI) on a remote host. This could be indicative of adversary lateral movement.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['PARENT_NAME'].endswith("\\WmiPrvSE.exe") and record['COMMAND_LINE'].contains("\\\\\\\\127.0.0.1") and (record['COMMAND_LINE'].contains("2>&1") or record['COMMAND_LINE'].contains("1>")))

sigma_suspicious_cmd_execution_via_wmi.sigma_meta = dict(
    level="medium"
)

def sigma_elise_backdoor(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_elise.yml
    title: Elise Backdoor
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects Elise backdoor acitivty as used by APT32
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'] == "C:\\Windows\\SysWOW64\\cmd.exe" and record['COMMAND_LINE'].contains("\\Windows\\Caches\\NavShExt.dll")) or record['COMMAND_LINE'].endswith("\\AppData\\Roaming\\MICROS~1\\Windows\\Caches\\NavShExt.dll,Setting"))

sigma_elise_backdoor.sigma_meta = dict(
    level="critical"
)

def sigma_ilasm_lolbin_use_compile_c_sharp(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_ilasm.yml
    title: Ilasm Lolbin Use Compile C-Sharp
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detect use of Ilasm.exe to compile c# code into dll or exe.
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\ilasm.exe") or record['ORIGINAL_FILE_NAME'] == "ilasm.exe")

sigma_ilasm_lolbin_use_compile_c_sharp.sigma_meta = dict(
    level="medium"
)

def sigma_unc2452_process_creation_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_unc2452_cmds.yml
    title: UNC2452 Process Creation Patterns
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects a specific process creation patterns as seen used by UNC2452 and provided by Microsoft as Microsoft Defender ATP queries
    logsource: category:process_creation - product:windows
    """
    return ((((record['COMMAND_LINE'].contains("7z.exe a -v500m -mx9 -r0 -p") or (record['PARENT_COMMAND_LINE'].contains("wscript.exe") and record['PARENT_COMMAND_LINE'].contains(".vbs") and record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("C:\\Windows") and record['COMMAND_LINE'].contains(".dll,Tk_"))) or (record['PARENT_NAME'].endswith("\\rundll32.exe") and record['PARENT_COMMAND_LINE'].contains("C:\\Windows") and record['COMMAND_LINE'].contains("cmd.exe /C"))) or (record['COMMAND_LINE'].contains("rundll32 c:\\windows") and record['COMMAND_LINE'].contains(".dll"))) or ((record['PARENT_NAME'].endswith("\\rundll32.exe") and record['PROCESS_NAME'].endswith("\\dllhost.exe")) and not ((record['COMMAND_LINE'] == "" or record['COMMAND_LINE'] == ""))))

sigma_unc2452_process_creation_patterns.sigma_meta = dict(
    level="high"
)

def sigma_psexec_service_start(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_psexesvc_start.yml
    title: PsExec Service Start
    fields: ['CommandLine']
    level: low
    description: Detects a PsExec service start
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'] == "C:\\Windows\\PSEXESVC.exe"

sigma_psexec_service_start.sigma_meta = dict(
    level="low"
)

def sigma_powertool_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powertool_execution.yml
    title: PowerTool Execution
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects the execution of the tool PowerTool which has the ability to kill a process, delete its process file, unload drivers, and delete the driver files
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\PowerTool.exe") or record['PROCESS_NAME'].endswith("\\PowerTool64.exe")) or record['ORIGINAL_FILE_NAME'] == "PowerTool.exe")

sigma_powertool_execution.sigma_meta = dict(
    level="high"
)

def sigma_harvesting_of_wifi_credentials_using_netsh_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_wifi_credential_harvesting.yml
    title: Harvesting of Wifi Credentials Using netsh.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detect the harvesting of wifi credentials using netsh.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("wlan") and record['COMMAND_LINE'].contains("s") and record['COMMAND_LINE'].contains("p") and record['COMMAND_LINE'].contains("k") and record['COMMAND_LINE'].contains("=clear"))

sigma_harvesting_of_wifi_credentials_using_netsh_exe.sigma_meta = dict(
    level="medium"
)

def sigma_operator_bloopers_cobalt_strike_commands(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cobaltstrike_bloopers_cmd.yml
    title: Operator Bloopers Cobalt Strike Commands
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects use of Cobalt Strike commands accidentally entered in the CMD shell
    logsource: category:process_creation - product:windows
    """
    return (((record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['PROCESS_NAME'].endswith("\\cmd.exe")) and ((record['COMMAND_LINE'].startswith("cmd.exe") or record['COMMAND_LINE'].startswith("c:\\windows\\system32\\cmd.exe")) and (record['COMMAND_LINE'].contains("psinject") or record['COMMAND_LINE'].contains("spawnas") or record['COMMAND_LINE'].contains("make_token") or record['COMMAND_LINE'].contains("remote-exec") or record['COMMAND_LINE'].contains("rev2self") or record['COMMAND_LINE'].contains("dcsync") or record['COMMAND_LINE'].contains("logonpasswords") or record['COMMAND_LINE'].contains("execute-assembly") or record['COMMAND_LINE'].contains("getsystem")))) and not ((record['PARENT_NAME'].endswith("\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe") and record['COMMAND_LINE'].contains("/d /s /c") and record['COMMAND_LINE'].contains("checkfilenameiocs --ioc-path"))))

sigma_operator_bloopers_cobalt_strike_commands.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_sigverif_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_sigverif.yml
    title: Suspicious Sigverif Execution
    fields: ['ParentImage']
    level: medium
    description: Detects the execution of sigverif binary as a parent process which could indicate it being used as a LOLBIN to proxy execution
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\sigverif.exe")

sigma_suspicious_sigverif_execution.sigma_meta = dict(
    level="medium"
)

def sigma_detected_windows_software_discovery(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_software_discovery.yml
    title: Detected Windows Software Discovery
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("query") and record['COMMAND_LINE'].contains("\\software") and record['COMMAND_LINE'].contains("/v") and record['COMMAND_LINE'].contains("svcversion"))

sigma_detected_windows_software_discovery.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_runscripthelper_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_runscripthelper.yml
    title: Suspicious Runscripthelper.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects execution of powershell scripts via Runscripthelper.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Runscripthelper.exe") and record['COMMAND_LINE'].contains("surfacecheck"))

sigma_suspicious_runscripthelper_exe.sigma_meta = dict(
    level="medium"
)

def sigma_false_sysinternals_suite_tools(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_false_sysinternalsuite.yml
    title: False Sysinternals Suite Tools
    fields: ['Image', 'Company']
    level: medium
    description: Rename as a legitimate Sysinternals Suite tool to evade detection
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\accesschk.exe") or record['PROCESS_NAME'].endswith("\\accesschk64.exe") or record['PROCESS_NAME'].endswith("\\AccessEnum.exe") or record['PROCESS_NAME'].endswith("\\ADExplorer.exe") or record['PROCESS_NAME'].endswith("\\ADExplorer64.exe") or record['PROCESS_NAME'].endswith("\\ADInsight.exe") or record['PROCESS_NAME'].endswith("\\ADInsight64.exe") or record['PROCESS_NAME'].endswith("\\adrestore.exe") or record['PROCESS_NAME'].endswith("\\adrestore64.exe") or record['PROCESS_NAME'].endswith("\\Autologon.exe") or record['PROCESS_NAME'].endswith("\\Autologon64.exe") or record['PROCESS_NAME'].endswith("\\Autoruns.exe") or record['PROCESS_NAME'].endswith("\\Autoruns64.exe") or record['PROCESS_NAME'].endswith("\\autorunsc.exe") or record['PROCESS_NAME'].endswith("\\autorunsc64.exe") or record['PROCESS_NAME'].endswith("\\Bginfo.exe") or record['PROCESS_NAME'].endswith("\\Bginfo64.exe") or record['PROCESS_NAME'].endswith("\\Cacheset.exe") or record['PROCESS_NAME'].endswith("\\Cacheset64.exe") or record['PROCESS_NAME'].endswith("\\Clockres.exe") or record['PROCESS_NAME'].endswith("\\Clockres64.exe") or record['PROCESS_NAME'].endswith("\\Contig.exe") or record['PROCESS_NAME'].endswith("\\Contig64.exe") or record['PROCESS_NAME'].endswith("\\Coreinfo.exe") or record['PROCESS_NAME'].endswith("\\Coreinfo64.exe") or record['PROCESS_NAME'].endswith("\\CPUSTRES.EXE") or record['PROCESS_NAME'].endswith("\\CPUSTRES64.EXE") or record['PROCESS_NAME'].endswith("\\ctrl2cap.exe") or record['PROCESS_NAME'].endswith("\\Dbgview.exe") or record['PROCESS_NAME'].endswith("\\dbgview64.exe") or record['PROCESS_NAME'].endswith("\\Desktops.exe") or record['PROCESS_NAME'].endswith("\\Desktops64.exe") or record['PROCESS_NAME'].endswith("\\disk2vhd.exe") or record['PROCESS_NAME'].endswith("\\disk2vhd64.exe") or record['PROCESS_NAME'].endswith("\\diskext.exe") or record['PROCESS_NAME'].endswith("\\diskext64.exe") or record['PROCESS_NAME'].endswith("\\Diskmon.exe") or record['PROCESS_NAME'].endswith("\\Diskmon64.exe") or record['PROCESS_NAME'].endswith("\\DiskView.exe") or record['PROCESS_NAME'].endswith("\\DiskView64.exe") or record['PROCESS_NAME'].endswith("\\du.exe") or record['PROCESS_NAME'].endswith("\\du64.exe") or record['PROCESS_NAME'].endswith("\\efsdump.exe") or record['PROCESS_NAME'].endswith("\\FindLinks.exe") or record['PROCESS_NAME'].endswith("\\FindLinks64.exe") or record['PROCESS_NAME'].endswith("\\handle.exe") or record['PROCESS_NAME'].endswith("\\handle64.exe") or record['PROCESS_NAME'].endswith("\\hex2dec.exe") or record['PROCESS_NAME'].endswith("\\hex2dec64.exe") or record['PROCESS_NAME'].endswith("\\junction.exe") or record['PROCESS_NAME'].endswith("\\junction64.exe") or record['PROCESS_NAME'].endswith("\\ldmdump.exe") or record['PROCESS_NAME'].endswith("\\listdlls.exe") or record['PROCESS_NAME'].endswith("\\listdlls64.exe") or record['PROCESS_NAME'].endswith("\\livekd.exe") or record['PROCESS_NAME'].endswith("\\livekd64.exe") or record['PROCESS_NAME'].endswith("\\loadOrd.exe") or record['PROCESS_NAME'].endswith("\\loadOrd64.exe") or record['PROCESS_NAME'].endswith("\\loadOrdC.exe") or record['PROCESS_NAME'].endswith("\\loadOrdC64.exe") or record['PROCESS_NAME'].endswith("\\logonsessions.exe") or record['PROCESS_NAME'].endswith("\\logonsessions64.exe") or record['PROCESS_NAME'].endswith("\\movefile.exe") or record['PROCESS_NAME'].endswith("\\movefile64.exe") or record['PROCESS_NAME'].endswith("\\notmyfault.exe") or record['PROCESS_NAME'].endswith("\\notmyfault64.exe") or record['PROCESS_NAME'].endswith("\\notmyfaultc.exe") or record['PROCESS_NAME'].endswith("\\notmyfaultc64.exe") or record['PROCESS_NAME'].endswith("\\ntfsinfo.exe") or record['PROCESS_NAME'].endswith("\\ntfsinfo64.exe") or record['PROCESS_NAME'].endswith("\\pendmoves.exe") or record['PROCESS_NAME'].endswith("\\pendmoves64.exe") or record['PROCESS_NAME'].endswith("\\pipelist.exe") or record['PROCESS_NAME'].endswith("\\pipelist64.exe") or record['PROCESS_NAME'].endswith("\\portmon.exe") or record['PROCESS_NAME'].endswith("\\procdump.exe") or record['PROCESS_NAME'].endswith("\\procdump64.exe") or record['PROCESS_NAME'].endswith("\\procexp.exe") or record['PROCESS_NAME'].endswith("\\procexp64.exe") or record['PROCESS_NAME'].endswith("\\Procmon.exe") or record['PROCESS_NAME'].endswith("\\Procmon64.exe") or record['PROCESS_NAME'].endswith("\\psExec.exe") or record['PROCESS_NAME'].endswith("\\psExec64.exe") or record['PROCESS_NAME'].endswith("\\psfile.exe") or record['PROCESS_NAME'].endswith("\\psfile64.exe") or record['PROCESS_NAME'].endswith("\\psGetsid.exe") or record['PROCESS_NAME'].endswith("\\psGetsid64.exe") or record['PROCESS_NAME'].endswith("\\psInfo.exe") or record['PROCESS_NAME'].endswith("\\psInfo64.exe") or record['PROCESS_NAME'].endswith("\\pskill.exe") or record['PROCESS_NAME'].endswith("\\pskill64.exe") or record['PROCESS_NAME'].endswith("\\pslist.exe") or record['PROCESS_NAME'].endswith("\\pslist64.exe") or record['PROCESS_NAME'].endswith("\\psLoggedon.exe") or record['PROCESS_NAME'].endswith("\\psLoggedon64.exe") or record['PROCESS_NAME'].endswith("\\psloglist.exe") or record['PROCESS_NAME'].endswith("\\psloglist64.exe") or record['PROCESS_NAME'].endswith("\\pspasswd.exe") or record['PROCESS_NAME'].endswith("\\pspasswd64.exe") or record['PROCESS_NAME'].endswith("\\psping.exe") or record['PROCESS_NAME'].endswith("\\psping64.exe") or record['PROCESS_NAME'].endswith("\\psService.exe") or record['PROCESS_NAME'].endswith("\\psService64.exe") or record['PROCESS_NAME'].endswith("\\psshutdown.exe") or record['PROCESS_NAME'].endswith("\\psshutdown64.exe") or record['PROCESS_NAME'].endswith("\\pssuspend.exe") or record['PROCESS_NAME'].endswith("\\pssuspend64.exe") or record['PROCESS_NAME'].endswith("\\RAMMap.exe") or record['PROCESS_NAME'].endswith("\\RDCMan.exe") or record['PROCESS_NAME'].endswith("\\RegDelNull.exe") or record['PROCESS_NAME'].endswith("\\RegDelNull64.exe") or record['PROCESS_NAME'].endswith("\\regjump.exe") or record['PROCESS_NAME'].endswith("\\ru.exe") or record['PROCESS_NAME'].endswith("\\ru64.exe") or record['PROCESS_NAME'].endswith("\\sdelete.exe") or record['PROCESS_NAME'].endswith("\\sdelete64.exe") or record['PROCESS_NAME'].endswith("\\ShareEnum.exe") or record['PROCESS_NAME'].endswith("\\ShareEnum64.exe") or record['PROCESS_NAME'].endswith("\\shellRunas.exe") or record['PROCESS_NAME'].endswith("\\sigcheck.exe") or record['PROCESS_NAME'].endswith("\\sigcheck64.exe") or record['PROCESS_NAME'].endswith("\\streams.exe") or record['PROCESS_NAME'].endswith("\\streams64.exe") or record['PROCESS_NAME'].endswith("\\strings.exe") or record['PROCESS_NAME'].endswith("\\strings64.exe") or record['PROCESS_NAME'].endswith("\\sync.exe") or record['PROCESS_NAME'].endswith("\\sync64.exe") or record['PROCESS_NAME'].endswith("\\Sysmon.exe") or record['PROCESS_NAME'].endswith("\\Sysmon64.exe") or record['PROCESS_NAME'].endswith("\\tcpvcon.exe") or record['PROCESS_NAME'].endswith("\\tcpvcon64.exe") or record['PROCESS_NAME'].endswith("\\tcpview.exe") or record['PROCESS_NAME'].endswith("\\tcpview64.exe") or record['PROCESS_NAME'].endswith("\\Testlimit.exe") or record['PROCESS_NAME'].endswith("\\Testlimit64.exe") or record['PROCESS_NAME'].endswith("\\vmmap.exe") or record['PROCESS_NAME'].endswith("\\vmmap64.exe") or record['PROCESS_NAME'].endswith("\\Volumeid.exe") or record['PROCESS_NAME'].endswith("\\Volumeid64.exe") or record['PROCESS_NAME'].endswith("\\whois.exe") or record['PROCESS_NAME'].endswith("\\whois64.exe") or record['PROCESS_NAME'].endswith("\\Winobj.exe") or record['PROCESS_NAME'].endswith("\\Winobj64.exe") or record['PROCESS_NAME'].endswith("\\ZoomIt.exe") or record['PROCESS_NAME'].endswith("\\ZoomIt64.exe")) and not (((record['COMPANY'] == "Sysinternals - www.sysinternals.com" or record['COMPANY'] == "Sysinternals")) or (record.get('COMPANY', None) == None)))

sigma_false_sysinternals_suite_tools.sigma_meta = dict(
    level="medium"
)

def sigma_malicious_windows_script_components_file_execution_by_taef_detection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_use_of_te_bin.yml
    title: Malicious Windows Script Components File Execution by TAEF Detection
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: low
    description: Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces
Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\te.exe") or record['PARENT_NAME'].endswith("\\te.exe") or record['ORIGINAL_FILE_NAME'] == "\\te.exe")

sigma_malicious_windows_script_components_file_execution_by_taef_detection.sigma_meta = dict(
    level="low"
)

def sigma_renamed_psexec(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_psexec.yml
    title: Renamed PsExec
    fields: ['Image', 'Product', 'Description']
    level: high
    description: Detects the execution of a renamed PsExec often used by attackers or malware
    logsource: product:windows - category:process_creation
    """
    return ((record['DESCRIPTION'] == "Execute processes remotely" and record['PRODUCT_NAME'] == "Sysinternals PsExec") and not ((record['PROCESS_NAME'].endswith("\\PsExec.exe") or record['PROCESS_NAME'].endswith("\\PsExec64.exe"))))

sigma_renamed_psexec.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_bitstransfer_via_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_bitstransfer.yml
    title: Suspicious Bitstransfer via PowerShell
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects transferring files from system on a server bitstransfer Powershell cmdlets
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("Get-BitsTransfer") or record['COMMAND_LINE'].contains("Add-BitsFile")))

sigma_suspicious_bitstransfer_via_powershell.sigma_meta = dict(
    level="medium"
)

def sigma_lockergoga_ransomware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_lockergoga_ransomware.yml
    title: LockerGoga Ransomware
    fields: ['CommandLine']
    level: critical
    description: Detects LockerGoga Ransomware command line.
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("-i SM-tgytutrc -s")

sigma_lockergoga_ransomware.sigma_meta = dict(
    level="critical"
)

def sigma_hermetic_wiper_tg_process_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_hermetic_wiper_activity.yml
    title: Hermetic Wiper TG Process Patterns
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects process execution patterns found in intrusions related to the Hermetic Wiper malware attacks against Ukraine in February 2022
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\policydefinitions\\postgresql.exe") or (record['COMMAND_LINE'].contains("CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp") or record['COMMAND_LINE'].contains("1> \\\\\\\\127.0.0.1\\ADMIN$\\__16")) or (record['COMMAND_LINE'].contains("powershell -c") and record['COMMAND_LINE'].contains("\\comsvcs.dll MiniDump") and record['COMMAND_LINE'].contains("\\winupd.log full")))

sigma_hermetic_wiper_tg_process_patterns.sigma_meta = dict(
    level="high"
)

def sigma_rundll32_js_runhtmlapplication_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_js_runhtmlapplication.yml
    title: Rundll32 JS RunHTMLApplication Pattern
    fields: ['CommandLine']
    level: high
    description: Detects suspicious command line patterns used when rundll32 is used to run JavaScript code
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("javascript") and record['COMMAND_LINE'].contains("..\\..\\mshtml,RunHTMLApplication")) or record['COMMAND_LINE'].contains(";document.write();GetObject(\"script"))

sigma_rundll32_js_runhtmlapplication_pattern.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_msconfig_token_modification_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_msconfig_gui.yml
    title: UAC Bypass Using MSConfig Token Modification - Process
    fields: ['CommandLine', 'IntegrityLevel', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
    logsource: category:process_creation - product:windows
    """
    return ((record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and record['PARENT_NAME'].endswith("\\AppData\\Local\\Temp\\pkgmgr.exe") and record['COMMAND_LINE'] == "\"C:\\Windows\\system32\\msconfig.exe\" -5")

sigma_uac_bypass_using_msconfig_token_modification_process.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_abusing_winsat_path_parsing_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_winsat.yml
    title: UAC Bypass Abusing Winsat Path Parsing - Process
    fields: ['IntegrityLevel', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
    logsource: category:process_creation - product:windows
    """
    return ((record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and record['PARENT_NAME'].endswith("\\AppData\\Local\\Temp\\system32\\winsat.exe") and record['PARENT_COMMAND_LINE'].contains("C:\\Windows \\system32\\winsat.exe"))

sigma_uac_bypass_abusing_winsat_path_parsing_process.sigma_meta = dict(
    level="high"
)

def sigma_discovery_execution_via_dnscmd_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dnscmd_discovery.yml
    title: Discovery/Execution via dnscmd.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects an attempt to add a potentially crafted DLL as a plug in of the DNS Service.
Detects an attempt to leverage dnscmd.exe to enumerate the DNS zones of a domain.
DNS zones used to host the DNS records for a particular domain

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\dnscmd.exe") and ((record['COMMAND_LINE'].contains("/enumrecords") or record['COMMAND_LINE'].contains("/enumzones") or record['COMMAND_LINE'].contains("/ZonePrint") or record['COMMAND_LINE'].contains("/info")) or (record['COMMAND_LINE'].contains("/config") and record['COMMAND_LINE'].contains("/serverlevelplugindll"))))

sigma_discovery_execution_via_dnscmd_exe.sigma_meta = dict(
    level="medium"
)

def sigma_rubeus_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_rubeus.yml
    title: Rubeus Hack Tool
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Description']
    level: critical
    description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Rubeus.exe") or record['ORIGINAL_FILE_NAME'] == "Rubeus.exe" or record['DESCRIPTION'] == "Rubeus" or (record['COMMAND_LINE'].contains("asreproast") or record['COMMAND_LINE'].contains("dump /service:krbtgt") or record['COMMAND_LINE'].contains("dump /luid:0x") or record['COMMAND_LINE'].contains("kerberoast") or record['COMMAND_LINE'].contains("createnetonly /program:") or record['COMMAND_LINE'].contains("ptt /ticket:") or record['COMMAND_LINE'].contains("/impersonateuser:") or record['COMMAND_LINE'].contains("renew /ticket:") or record['COMMAND_LINE'].contains("asktgt /user:") or record['COMMAND_LINE'].contains("harvest /interval:") or record['COMMAND_LINE'].contains("s4u /user:") or record['COMMAND_LINE'].contains("s4u /ticket:") or record['COMMAND_LINE'].contains("hash /password:") or record['COMMAND_LINE'].contains("golden /aes256:") or record['COMMAND_LINE'].contains("silver /user:")))

sigma_rubeus_hack_tool.sigma_meta = dict(
    level="critical"
)

def sigma_possible_installerfiletakeover_lpe_cve_2021_41379(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_lpe_cve_2021_41379.yml
    title: Possible InstallerFileTakeOver LPE CVE-2021-41379
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: critical
    description: Detects signs of the exploitation of LPE CVE-2021-41379 to spawn a cmd.exe with LOCAL_SYSTEM rights
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['PARENT_NAME'].endswith("\\elevation_service.exe") and record['INTEGRITY_LEVEL'] == "System")

sigma_possible_installerfiletakeover_lpe_cve_2021_41379.sigma_meta = dict(
    level="critical"
)

def sigma_sdiagnhost_calling_suspicious_child_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sdiagnhost_susp_child.yml
    title: Sdiagnhost Calling Suspicious Child Process
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\sdiagnhost.exe") and (record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\taskkill.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\calc.exe")))

sigma_sdiagnhost_calling_suspicious_child_process.sigma_meta = dict(
    level="high"
)

def sigma_sticky_key_backdoor_copy_cmd_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sticky_keys_unauthenticated_privileged_cmd_access.yml
    title: Sticky-Key Backdoor Copy Cmd.exe
    fields: ['CommandLine']
    level: medium
    description: By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system.
When the sticky keys are "activated" the privilleged shell is launched.

    logsource: product:windows - category:process_creation
    """
    return record['COMMAND_LINE'] == "copy /y C:\\windows\\system32\\cmd.exe C:\\windows\\system32\\sethc.exe"

sigma_sticky_key_backdoor_copy_cmd_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_sysmon_as_execution_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysmon_exploitation.yml
    title: Suspicious Sysmon as Execution Parent
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious process executions in which Sysmon itself is the parent of a process, which could be a sign of exploitation (e.g. CVE-2022-41120)
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\Sysmon.exe") or record['PARENT_NAME'].endswith("\\Sysmon64.exe")) and not ((record['PROCESS_NAME'] == "C:\\Windows\\Sysmon64.exe" or record['PROCESS_NAME'] == "C:\\Windows\\System32\\conhost.exe")))

sigma_suspicious_sysmon_as_execution_parent.sigma_meta = dict(
    level="high"
)

def sigma_use_of_anydesk_remote_access_software_from_suspicious_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_anydesk_susp_folder.yml
    title: Use of Anydesk Remote Access Software from Suspicious Folder
    fields: ['Image', 'Product', 'Company', 'Description']
    level: high
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\AnyDesk.exe") or record['DESCRIPTION'] == "AnyDesk" or record['PRODUCT_NAME'] == "AnyDesk" or record['COMPANY'] == "AnyDesk Software GmbH") and not ((record['PROCESS_NAME'].contains("\\AppData") or record['PROCESS_NAME'].contains("Program Files (x86)\\AnyDesk") or record['PROCESS_NAME'].contains("Program Files\\AnyDesk"))))

sigma_use_of_anydesk_remote_access_software_from_suspicious_folder.sigma_meta = dict(
    level="high"
)

def sigma_renamed_jusched_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_jusched.yml
    title: Renamed jusched.exe
    fields: ['Image', 'Description']
    level: high
    description: Detects renamed jusched.exe used by cobalt group
    logsource: category:process_creation - product:windows
    """
    return ((record['DESCRIPTION'] == "Java Update Scheduler" or record['DESCRIPTION'] == "Java(TM) Update Scheduler") and not (record['PROCESS_NAME'].endswith("\\jusched.exe")))

sigma_renamed_jusched_exe.sigma_meta = dict(
    level="high"
)

def sigma_indirect_command_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_indirect_cmd.yml
    title: Indirect Command Execution
    fields: ['ParentImage']
    level: low
    description: Detect indirect command execution via Program Compatibility Assistant (pcalua.exe or forfiles.exe).
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\pcalua.exe") or record['PARENT_NAME'].endswith("\\forfiles.exe"))

sigma_indirect_command_execution.sigma_meta = dict(
    level="low"
)

def sigma_xwizard_dll_sideloading(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_dll_sideload_xwizard.yml
    title: Xwizard DLL Sideloading
    fields: ['Image']
    level: high
    description: Detects the execution of Xwizard tool from the non-default directory which can be used to sideload a custom xwizards.dll
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\xwizard.exe") and not (record['PROCESS_NAME'].startswith("C:\\Windows\\System32")))

sigma_xwizard_dll_sideloading.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_shells_spawned_by_java(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shell_spawn_by_java.yml
    title: Suspicious Shells Spawned by Java
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious shell spawned from Java host process (e.g. log4j exploitation)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\java.exe") and (record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\scrcons.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\mftrace.exe") or record['PROCESS_NAME'].endswith("\\AppVLP.exe") or record['PROCESS_NAME'].endswith("\\curl.exe")))

sigma_suspicious_shells_spawned_by_java.sigma_meta = dict(
    level="high"
)

def sigma_dism_remove_online_package(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dsim_remove.yml
    title: Dism Remove Online Package
    fields: ['CommandLine', 'Image', 'ParentCommandLine']
    level: medium
    description: Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\DismHost.exe") and record['PARENT_COMMAND_LINE'].contains("/Online") and record['PARENT_COMMAND_LINE'].contains("/Disable-Feature")) or (record['PROCESS_NAME'].endswith("\\Dism.exe") and record['COMMAND_LINE'].contains("/Online") and record['COMMAND_LINE'].contains("/Disable-Feature")))

sigma_dism_remove_online_package.sigma_meta = dict(
    level="medium"
)

def sigma_abusing_print_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_print.yml
    title: Abusing Print Executable
    fields: ['CommandLine', 'Image']
    level: medium
    description: Attackers can use print.exe for remote file copy
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\print.exe") and record['COMMAND_LINE'].startswith("print") and record['COMMAND_LINE'].contains("/D") and record['COMMAND_LINE'].contains(".exe")) and not (record['COMMAND_LINE'].contains("print.exe")))

sigma_abusing_print_executable.sigma_meta = dict(
    level="medium"
)

def sigma_complus_etwenabled_command_line_arguments(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_etw_modification_cmdline.yml
    title: COMPlus_ETWEnabled Command Line Arguments
    fields: ['CommandLine']
    level: high
    description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("COMPlus_ETWEnabled=0")

sigma_complus_etwenabled_command_line_arguments.sigma_meta = dict(
    level="high"
)

def sigma_wmi_spawning_windows_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmi_spwns_powershell.yml
    title: WMI Spawning Windows PowerShell
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects WMI spawning a PowerShell process
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\wmiprvse.exe") and ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll"))) and not (record['COMMAND_LINE'] == "null")) and not (record.get('COMMAND_LINE', None) == None))

sigma_wmi_spawning_windows_powershell.sigma_meta = dict(
    level="high"
)

def sigma_windows_network_enumeration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_enum.yml
    title: Windows Network Enumeration
    fields: ['CommandLine', 'Image']
    level: low
    description: Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("view")) and not (record['COMMAND_LINE'].contains("")))

sigma_windows_network_enumeration.sigma_meta = dict(
    level="low"
)

def sigma_blackbyte_ransomware_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ransom_blackbyte.yml
    title: BlackByte Ransomware Patterns
    fields: ['CommandLine', 'Image']
    level: high
    description: This command line patterns found in BlackByte Ransomware operations
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].startswith("C:\\Users\\Public") and record['COMMAND_LINE'].contains("-single")) or (record['COMMAND_LINE'].contains("del C:\\Windows\\System32\\Taskmgr.exe") or record['COMMAND_LINE'].contains(";Set-Service -StartupType Disabled $") or record['COMMAND_LINE'].contains("powershell -command \"$x =[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(") or record['COMMAND_LINE'].contains("do start wordpad.exe /p")))

sigma_blackbyte_ransomware_patterns.sigma_meta = dict(
    level="high"
)

def sigma_possible_spn_enumeration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_spn_enum.yml
    title: Possible SPN Enumeration
    fields: ['CommandLine', 'Image', 'Description']
    level: medium
    description: Detects Service Principal Name Enumeration used for Kerberoasting
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\setspn.exe") or (record['DESCRIPTION'].contains("Query or reset the computer") and record['DESCRIPTION'].contains("SPN attribute"))) and record['COMMAND_LINE'].contains("-q"))

sigma_possible_spn_enumeration.sigma_meta = dict(
    level="medium"
)

def sigma_sofacy_trojan_loader_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_sofacy.yml
    title: Sofacy Trojan Loader Activity
    fields: ['CommandLine']
    level: high
    description: Detects Trojan loader activity as used by APT28
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("%APPDATA%")) and (record['COMMAND_LINE'].contains(".dat\",") or (record['COMMAND_LINE'].endswith(".dll\",#1") or record['COMMAND_LINE'].endswith(".dll #1") or record['COMMAND_LINE'].endswith(".dll\" #1"))))

sigma_sofacy_trojan_loader_activity.sigma_meta = dict(
    level="high"
)

def sigma_indirect_command_exectuion_via_forfiles(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_indirect_command_execution_forfiles.yml
    title: Indirect Command Exectuion via Forfiles
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects the use of native Windows tool, forfiles to execute a file. Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters.
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\forfiles.exe") and (record['PARENT_COMMAND_LINE'].contains("/c") or record['PARENT_COMMAND_LINE'].contains("-c")) and (record['PARENT_COMMAND_LINE'].contains("/p") or record['PARENT_COMMAND_LINE'].contains("-p")) and (record['PARENT_COMMAND_LINE'].contains("/m") or record['PARENT_COMMAND_LINE'].contains("-m"))) and not (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("xcopy") and record['COMMAND_LINE'].contains("cmd /c del")))

sigma_indirect_command_exectuion_via_forfiles.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_schtasks_from_env_var_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_env_folder.yml
    title: Suspicious Schtasks From Env Var Folder
    fields: ['CommandLine', 'Image', 'ParentCommandLine']
    level: high
    description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/create") and (record['COMMAND_LINE'].contains("%AppData%") or record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("\\AppData\\Roaming") or record['COMMAND_LINE'].contains("%Public%") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("C:\\Perflogs"))) or (record['PARENT_COMMAND_LINE'].endswith("\\svchost.exe -k netsvcs -p -s Schedule") and (record['COMMAND_LINE'].contains("%Public%") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("C:\\Perflogs")))) and not (((record['COMMAND_LINE'].contains("update_task.xml") or record['COMMAND_LINE'].contains("/Create /TN TVInstallRestore /TR")) or record['PARENT_COMMAND_LINE'].contains("unattended.ini"))))

sigma_suspicious_schtasks_from_env_var_folder.sigma_meta = dict(
    level="high"
)

def sigma_systemnightmare_exploitation_script_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_systemnightmare.yml
    title: SystemNightmare Exploitation Script Execution
    fields: ['CommandLine']
    level: critical
    description: Detects the exploitation of PrinterNightmare to get a shell as LOCAL_SYSTEM
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("printnightmare.gentilkiwi.com") or record['COMMAND_LINE'].contains("/user:gentilguest") or record['COMMAND_LINE'].contains("Kiwi Legit Printer"))

sigma_systemnightmare_exploitation_script_execution.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_modification_of_scheduled_tasks(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_change.yml
    title: Suspicious Modification Of Scheduled Tasks
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
Instead they modify the task after creation to include their malicious payload

    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Change") and record['COMMAND_LINE'].contains("/TN") and (record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("\\AppData\\Roaming") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\WINDOWS\\Temp") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Temporary Internet") or record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("C:\\Perflogs") or record['COMMAND_LINE'].contains("%ProgramData%") or record['COMMAND_LINE'].contains("%appdata%") or record['COMMAND_LINE'].contains("%comspec%") or record['COMMAND_LINE'].contains("%localappdata%")) and (record['COMMAND_LINE'].contains("regsvr32") or record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd /r") or record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("wscript") or record['COMMAND_LINE'].contains("cscript") or record['COMMAND_LINE'].contains("certutil") or record['COMMAND_LINE'].contains("bitsadmin") or record['COMMAND_LINE'].contains("bash.exe") or record['COMMAND_LINE'].contains("bash") or record['COMMAND_LINE'].contains("scrcons") or record['COMMAND_LINE'].contains("wmic") or record['COMMAND_LINE'].contains("wmic.exe") or record['COMMAND_LINE'].contains("forfiles") or record['COMMAND_LINE'].contains("scriptrunner") or record['COMMAND_LINE'].contains("hh.exe") or record['COMMAND_LINE'].contains("hh")))

sigma_suspicious_modification_of_scheduled_tasks.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_screensave_change_by_reg_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_screensaver_reg.yml
    title: Suspicious ScreenSave Change by Reg.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") and (record['COMMAND_LINE'].contains("HKEY_CURRENT_USER\\Control Panel\\Desktop") or record['COMMAND_LINE'].contains("HKCU\\Control Panel\\Desktop"))) and ((record['COMMAND_LINE'].contains("/v ScreenSaveActive") and record['COMMAND_LINE'].contains("/t REG_SZ") and record['COMMAND_LINE'].contains("/d 1") and record['COMMAND_LINE'].contains("/f")) or (record['COMMAND_LINE'].contains("/v ScreenSaveTimeout") and record['COMMAND_LINE'].contains("/t REG_SZ") and record['COMMAND_LINE'].contains("/d") and record['COMMAND_LINE'].contains("/f")) or (record['COMMAND_LINE'].contains("/v ScreenSaverIsSecure") and record['COMMAND_LINE'].contains("/t REG_SZ") and record['COMMAND_LINE'].contains("/d 0") and record['COMMAND_LINE'].contains("/f")) or (record['COMMAND_LINE'].contains("/v SCRNSAVE.EXE") and record['COMMAND_LINE'].contains("/t REG_SZ") and record['COMMAND_LINE'].contains("/d") and record['COMMAND_LINE'].contains(".scr") and record['COMMAND_LINE'].contains("/f"))))

sigma_suspicious_screensave_change_by_reg_exe.sigma_meta = dict(
    level="medium"
)

def sigma_abusable_invoke_athremotefxvgpudisablementcommand(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_athremotefxvgpudisablementcommand.yml
    title: Abusable Invoke-ATHRemoteFXvGPUDisablementCommand
    fields: ['CommandLine']
    level: medium
    description: RemoteFXvGPUDisablement.exe is an abusable, signed PowerShell host executable that was introduced in Windows 10 and Server 2019 (OS Build 17763.1339).
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("Invoke-ATHRemoteFXvGPUDisablementCommand") and (record['COMMAND_LINE'].contains("-ModuleName") or record['COMMAND_LINE'].contains("-ModulePath") or record['COMMAND_LINE'].contains("-ScriptBlock") or record['COMMAND_LINE'].contains("-RemoteFXvGPUDisablementFilePath")))

sigma_abusable_invoke_athremotefxvgpudisablementcommand.sigma_meta = dict(
    level="medium"
)

def sigma_possible_privilege_escalation_via_service_permissions_weakness(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_possible_privilege_escalation_via_service_reg_perm.yml
    title: Possible Privilege Escalation via Service Permissions Weakness
    fields: ['CommandLine', 'IntegrityLevel']
    level: high
    description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
    logsource: product:windows - category:process_creation
    """
    return (record['INTEGRITY_LEVEL'] == "Medium" and record['COMMAND_LINE'].contains("ControlSet") and record['COMMAND_LINE'].contains("services") and (record['COMMAND_LINE'].contains("\\ImagePath") or record['COMMAND_LINE'].contains("\\FailureCommand") or record['COMMAND_LINE'].contains("\\ServiceDll")))

sigma_possible_privilege_escalation_via_service_permissions_weakness.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_windowsterminal_child_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_windows_terminal_susp_children.yml
    title: Suspicious WindowsTerminal Child Processes
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\WindowsTerminal.exe") and ((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\csc.exe")) or (record['PROCESS_NAME'].contains("C:\\Users\\Public") or record['PROCESS_NAME'].contains("\\Downloads") or record['PROCESS_NAME'].contains("\\Desktop") or record['PROCESS_NAME'].contains("\\AppData\\Local\\Temp") or record['PROCESS_NAME'].contains("\\Windows\\TEMP")) or (record['COMMAND_LINE'].contains("iex") or record['COMMAND_LINE'].contains("Invoke-") or record['COMMAND_LINE'].contains("Import-Module") or record['COMMAND_LINE'].contains("DownloadString(") or record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/k") or record['COMMAND_LINE'].contains("/r")))) and not ((record['COMMAND_LINE'].contains("Import-Module") and record['COMMAND_LINE'].contains("Microsoft.VisualStudio.DevShell.dll") and record['COMMAND_LINE'].contains("Enter-VsDevShell")) or (record['COMMAND_LINE'].contains("\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_") and record['COMMAND_LINE'].contains("\\LocalState\\settings.json")) or (record['COMMAND_LINE'].contains("C:\\Program Files\\Microsoft Visual Studio") and record['COMMAND_LINE'].contains("\\Common7\\Tools\\VsDevCmd.bat"))))

sigma_suspicious_windowsterminal_child_processes.sigma_meta = dict(
    level="medium"
)

def sigma_powershell_encoded_character_syntax(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_encoded_param.yml
    title: PowerShell Encoded Character Syntax
    fields: ['CommandLine']
    level: high
    description: Detects suspicious encoded character syntax often used for defense evasion
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("(WCHAR)0x")

sigma_powershell_encoded_character_syntax.sigma_meta = dict(
    level="high"
)

def sigma_quarks_pwdump_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_quarks_pwdump.yml
    title: Quarks PwDump Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects usage of the Quarks PwDump tool via commandline arguments
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\QuarksPwDump.exe") or (record['COMMAND_LINE'] == "-dhl" or record['COMMAND_LINE'] == "--dump-hash-local" or record['COMMAND_LINE'] == "-dhdc" or record['COMMAND_LINE'] == "--dump-hash-domain-cached" or record['COMMAND_LINE'] == "--dump-bitlocker" or record['COMMAND_LINE'] == "-dhd" or record['COMMAND_LINE'] == "--dump-hash-domain" or record['COMMAND_LINE'] == "--ntds-file"))

sigma_quarks_pwdump_usage.sigma_meta = dict(
    level="high"
)

def sigma_dns_serverlevelplugindll_install(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dns_serverlevelplugindll.yml
    title: DNS ServerLevelPluginDll Install
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\dnscmd.exe") and record['COMMAND_LINE'].contains("/config") and record['COMMAND_LINE'].contains("/serverlevelplugindll"))

sigma_dns_serverlevelplugindll_install.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_execution_of_sharpview_aka_powerview(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_sharpview.yml
    title: Suspicious Execution of SharpView Aka PowerView
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "SharpView.exe" or record['PROCESS_NAME'].endswith("\\SharpView.exe") or (record['COMMAND_LINE'].contains("Get-DomainGPOUserLocalGroupMapping") or record['COMMAND_LINE'].contains("Find-GPOLocation") or record['COMMAND_LINE'].contains("Get-DomainGPOComputerLocalGroupMapping") or record['COMMAND_LINE'].contains("Find-GPOComputerAdmin") or record['COMMAND_LINE'].contains("Get-DomainObjectAcl") or record['COMMAND_LINE'].contains("Add-DomainObjectAcl") or record['COMMAND_LINE'].contains("Add-ObjectAcl") or record['COMMAND_LINE'].contains("Remove-DomainObjectAcl") or record['COMMAND_LINE'].contains("Get-RegLoggedOn") or record['COMMAND_LINE'].contains("Get-LoggedOnLocal") or record['COMMAND_LINE'].contains("Get-NetRDPSession") or record['COMMAND_LINE'].contains("Test-AdminAccess") or record['COMMAND_LINE'].contains("Invoke-CheckLocalAdminAccess") or record['COMMAND_LINE'].contains("Get-WMIProcess") or record['COMMAND_LINE'].contains("Get-NetProcess") or record['COMMAND_LINE'].contains("Get-WMIRegProxy") or record['COMMAND_LINE'].contains("Get-WMIRegLastLoggedOn") or record['COMMAND_LINE'].contains("Get-LastLoggedOn") or record['COMMAND_LINE'].contains("Get-WMIRegCachedRDPConnection") or record['COMMAND_LINE'].contains("Get-CachedRDPConnection") or record['COMMAND_LINE'].contains("Get-WMIRegMountedDrive") or record['COMMAND_LINE'].contains("Get-RegistryMountedDrive") or record['COMMAND_LINE'].contains("Find-InterestingDomainAcl") or record['COMMAND_LINE'].contains("Invoke-ACLScanner") or record['COMMAND_LINE'].contains("Get-NetShare") or record['COMMAND_LINE'].contains("Get-NetLoggedon") or record['COMMAND_LINE'].contains("Get-NetLocalGroup") or record['COMMAND_LINE'].contains("Get-NetLocalGroupMember") or record['COMMAND_LINE'].contains("Get-NetSession") or record['COMMAND_LINE'].contains("Get-PathAcl") or record['COMMAND_LINE'].contains("ConvertFrom-UACValue") or record['COMMAND_LINE'].contains("Get-PrincipalContext") or record['COMMAND_LINE'].contains("New-DomainGroup") or record['COMMAND_LINE'].contains("New-DomainUser") or record['COMMAND_LINE'].contains("Add-DomainGroupMember") or record['COMMAND_LINE'].contains("Set-DomainUserPassword") or record['COMMAND_LINE'].contains("Invoke-Kerberoast") or record['COMMAND_LINE'].contains("Export-PowerViewCSV") or record['COMMAND_LINE'].contains("Find-LocalAdminAccess") or record['COMMAND_LINE'].contains("Find-DomainLocalGroupMember") or record['COMMAND_LINE'].contains("Find-DomainShare") or record['COMMAND_LINE'].contains("Find-DomainUserEvent") or record['COMMAND_LINE'].contains("Find-DomainProcess") or record['COMMAND_LINE'].contains("Find-DomainUserLocation") or record['COMMAND_LINE'].contains("Find-InterestingFile") or record['COMMAND_LINE'].contains("Find-InterestingDomainShareFile") or record['COMMAND_LINE'].contains("Find-DomainObjectPropertyOutlier") or record['COMMAND_LINE'].contains("Get-NetDomain") or record['COMMAND_LINE'].contains("Get-DomainComputer") or record['COMMAND_LINE'].contains("Get-NetComputer") or record['COMMAND_LINE'].contains("Get-DomainController") or record['COMMAND_LINE'].contains("Get-NetDomainController") or record['COMMAND_LINE'].contains("Get-DomainFileServer") or record['COMMAND_LINE'].contains("Get-NetFileServer") or record['COMMAND_LINE'].contains("Convert-ADName") or record['COMMAND_LINE'].contains("Get-DomainObject") or record['COMMAND_LINE'].contains("Get-ADObject") or record['COMMAND_LINE'].contains("Get-DomainUser") or record['COMMAND_LINE'].contains("Get-NetUser") or record['COMMAND_LINE'].contains("Get-DomainGroup") or record['COMMAND_LINE'].contains("Get-DomainDFSShare") or record['COMMAND_LINE'].contains("Get-DFSshare") or record['COMMAND_LINE'].contains("Get-DomainDNSRecord") or record['COMMAND_LINE'].contains("Get-DomainForeignGroupMember") or record['COMMAND_LINE'].contains("Find-ForeignGroup") or record['COMMAND_LINE'].contains("Get-DomainForeignUser") or record['COMMAND_LINE'].contains("Find-ForeignUser") or record['COMMAND_LINE'].contains("ConvertFrom-SID") or record['COMMAND_LINE'].contains("Convert-SidToName") or record['COMMAND_LINE'].contains("Get-DomainGroupMember") or record['COMMAND_LINE'].contains("Get-NetGroupMember") or record['COMMAND_LINE'].contains("Get-DomainManagedSecurityGroup") or record['COMMAND_LINE'].contains("Find-ManagedSecurityGroups") or record['COMMAND_LINE'].contains("Get-DomainOU") or record['COMMAND_LINE'].contains("Get-NetOU") or record['COMMAND_LINE'].contains("Get-DomainSID") or record['COMMAND_LINE'].contains("Get-NetForest") or record['COMMAND_LINE'].contains("Get-ForestTrust") or record['COMMAND_LINE'].contains("Get-NetForestTrust") or record['COMMAND_LINE'].contains("Get-DomainTrust") or record['COMMAND_LINE'].contains("Get-NetDomainTrust") or record['COMMAND_LINE'].contains("Get-ForestDomain") or record['COMMAND_LINE'].contains("Get-NetForestDomain") or record['COMMAND_LINE'].contains("Get-DomainSite") or record['COMMAND_LINE'].contains("Get-NetSite") or record['COMMAND_LINE'].contains("Get-DomainSubnet") or record['COMMAND_LINE'].contains("Get-NetSubnet") or record['COMMAND_LINE'].contains("Get-DomainTrustMapping") or record['COMMAND_LINE'].contains("Invoke-MapDomainTrust") or record['COMMAND_LINE'].contains("Get-ForestGlobalCatalog") or record['COMMAND_LINE'].contains("Get-NetForestCatalog") or record['COMMAND_LINE'].contains("Get-DomainUserEvent") or record['COMMAND_LINE'].contains("Get-DomainGUIDMap") or record['COMMAND_LINE'].contains("Resolve-IPAddress") or record['COMMAND_LINE'].contains("ConvertTo-SID") or record['COMMAND_LINE'].contains("Invoke-UserImpersonation") or record['COMMAND_LINE'].contains("Get-DomainSPNTicket") or record['COMMAND_LINE'].contains("Request-SPNTicket") or record['COMMAND_LINE'].contains("Get-NetComputerSiteName") or record['COMMAND_LINE'].contains("Get-DomainGPO") or record['COMMAND_LINE'].contains("Get-NetGPO") or record['COMMAND_LINE'].contains("Set-DomainObject") or record['COMMAND_LINE'].contains("Add-RemoteConnection") or record['COMMAND_LINE'].contains("Remove-RemoteConnection") or record['COMMAND_LINE'].contains("Get-GptTmpl") or record['COMMAND_LINE'].contains("Get-GroupsXML") or record['COMMAND_LINE'].contains("Get-DomainPolicyData") or record['COMMAND_LINE'].contains("Get-DomainPolicy") or record['COMMAND_LINE'].contains("Get-DomainGPOLocalGroup") or record['COMMAND_LINE'].contains("Get-NetGPOGroup") or record['COMMAND_LINE'].contains("Invoke-Sharefinder")))

sigma_suspicious_execution_of_sharpview_aka_powerview.sigma_meta = dict(
    level="high"
)

def sigma_cmd_exe_commandline_path_traversal(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_commandline_path_traversal.yml
    title: Cmd.exe CommandLine Path Traversal
    fields: ['CommandLine', 'ParentCommandLine', 'ParentImage']
    level: high
    description: detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_COMMAND_LINE'].contains("cmd") or record['PARENT_NAME'].endswith("\\cmd.exe")) and ((record['PARENT_COMMAND_LINE'].contains("/c") or record['PARENT_COMMAND_LINE'].contains("/k") or record['PARENT_COMMAND_LINE'].contains("/r")) and record['COMMAND_LINE'].contains("/../../"))) and not ((record['COMMAND_LINE'].contains("\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java"))))

sigma_cmd_exe_commandline_path_traversal.sigma_meta = dict(
    level="high"
)

def sigma_wmi_backdoor_exchange_transport_agent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmi_backdoor_exchange_transport_agent.yml
    title: WMI Backdoor Exchange Transport Agent
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\EdgeTransport.exe") and not (record['PROCESS_NAME'] == "C:\\Windows\\System32\\conhost.exe"))

sigma_wmi_backdoor_exchange_transport_agent.sigma_meta = dict(
    level="critical"
)

def sigma_invoke_obfuscation_stdin_launcher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_stdin.yml
    title: Invoke-Obfuscation STDIN+ Launcher
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated use of stdin to execute PowerShell
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("powershell") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/r"))) and (record['COMMAND_LINE'].contains("noexit") or (record['COMMAND_LINE'].contains("input") and record['COMMAND_LINE'].contains("$"))))

sigma_invoke_obfuscation_stdin_launcher.sigma_meta = dict(
    level="high"
)

def sigma_msiexec_web_install(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_msiexec_web_install.yml
    title: MsiExec Web Install
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious msiexec process starts with web addresses as parameter
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("msiexec") and record['COMMAND_LINE'].contains("://"))

sigma_msiexec_web_install.sigma_meta = dict(
    level="medium"
)

def sigma_createdump_process_dump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proc_dump_createdump.yml
    title: CreateDump Process Dump
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects uses of the createdump.exe LOLOBIN utility to dump process memory
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\createdump.exe") or record['ORIGINAL_FILE_NAME'] == "FX_VER_INTERNALNAME_STR") and (record['COMMAND_LINE'].contains("-u") or record['COMMAND_LINE'].contains("--full") or record['COMMAND_LINE'].contains("-f") or record['COMMAND_LINE'].contains("--name") or record['COMMAND_LINE'].contains(".dmp")))

sigma_createdump_process_dump.sigma_meta = dict(
    level="high"
)

def sigma_adcspwn_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_adcspwn.yml
    title: ADCSPwn Hack Tool
    fields: ['CommandLine']
    level: high
    description: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("--adcs") and record['COMMAND_LINE'].contains("--port"))

sigma_adcspwn_hack_tool.sigma_meta = dict(
    level="high"
)

def sigma_abuse_of_service_permissions_to_hide_services_via_set_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_using_set_service_to_hide_services.yml
    title: Abuse of Service Permissions to Hide Services Via Set-Service
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['ORIGINAL_FILE_NAME'] == "pwsh.dll") and (record['COMMAND_LINE'].contains("Set-Service") and record['COMMAND_LINE'].contains("DCLCWPDTSD")) and (record['COMMAND_LINE'].contains("-SecurityDescriptorSddl") or record['COMMAND_LINE'].contains("-sd")))

sigma_abuse_of_service_permissions_to_hide_services_via_set_service.sigma_meta = dict(
    level="high"
)

def sigma_chisel_tunneling_tool_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_chisel_usage.yml
    title: Chisel Tunneling Tool Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects usage of the Chisel tunneling tool via the commandline arguments
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\chisel.exe") or ((record['COMMAND_LINE'].contains("exe client") or record['COMMAND_LINE'].contains("exe server")) and (record['COMMAND_LINE'].contains("--socks5") or record['COMMAND_LINE'].contains("--reverse") or record['COMMAND_LINE'].contains("r:") or record['COMMAND_LINE'].contains(":127.0.0.1:") or record['COMMAND_LINE'].contains("--tls-skip-verify") or record['COMMAND_LINE'].contains(":socks"))))

sigma_chisel_tunneling_tool_usage.sigma_meta = dict(
    level="high"
)

def sigma_seatbelt_pua_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pua_seatbelt.yml
    title: Seatbelt PUA Tool
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Description']
    level: high
    description: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\Seatbelt.exe") or record['ORIGINAL_FILE_NAME'] == "Seatbelt.exe" or record['DESCRIPTION'] == "Seatbelt" or (record['COMMAND_LINE'].contains("DpapiMasterKeys") or record['COMMAND_LINE'].contains("InterestingProcesses") or record['COMMAND_LINE'].contains("InterestingFiles") or record['COMMAND_LINE'].contains("CertificateThumbprints") or record['COMMAND_LINE'].contains("ChromiumBookmarks") or record['COMMAND_LINE'].contains("ChromiumHistory") or record['COMMAND_LINE'].contains("ChromiumPresence") or record['COMMAND_LINE'].contains("CloudCredentials") or record['COMMAND_LINE'].contains("CredEnum") or record['COMMAND_LINE'].contains("CredGuard") or record['COMMAND_LINE'].contains("FirefoxHistory") or record['COMMAND_LINE'].contains("ProcessCreationEvents"))) or ((record['COMMAND_LINE'].contains("-group=misc") or record['COMMAND_LINE'].contains("-group=remote") or record['COMMAND_LINE'].contains("-group=chromium") or record['COMMAND_LINE'].contains("-group=slack") or record['COMMAND_LINE'].contains("-group=system") or record['COMMAND_LINE'].contains("-group=user") or record['COMMAND_LINE'].contains("-group=all")) and record['COMMAND_LINE'].contains("-outputfile=")))

sigma_seatbelt_pua_tool.sigma_meta = dict(
    level="high"
)

def sigma_renamed_adfind_detection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_renamed_adfind.yml
    title: Renamed AdFind Detection
    fields: ['CommandLine', 'Image', 'Hashes', 'OriginalFileName', 'Imphash']
    level: high
    description: Detects the use of a renamed Adfind.exe. AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("domainlist") or record['COMMAND_LINE'].contains("trustdmp") or record['COMMAND_LINE'].contains("dcmodes") or record['COMMAND_LINE'].contains("adinfo") or record['COMMAND_LINE'].contains("dclist") or record['COMMAND_LINE'].contains("computer_pwdnotreqd") or record['COMMAND_LINE'].contains("objectcategory=") or record['COMMAND_LINE'].contains("-subnets -f") or record['COMMAND_LINE'].contains("name=\"Domain Admins\"") or record['COMMAND_LINE'].contains("-sc u:") or record['COMMAND_LINE'].contains("domainncs") or record['COMMAND_LINE'].contains("dompol") or record['COMMAND_LINE'].contains("oudmp") or record['COMMAND_LINE'].contains("subnetdmp") or record['COMMAND_LINE'].contains("gpodmp") or record['COMMAND_LINE'].contains("fspdmp") or record['COMMAND_LINE'].contains("users_noexpire") or record['COMMAND_LINE'].contains("computers_active") or record['COMMAND_LINE'].contains("computers_pwdnotreqd")) or (record['IMPHASH'] == "bca5675746d13a1f246e2da3c2217492" or record['IMPHASH'] == "53e117a96057eaf19c41380d0e87f1c2") or (record['HASHES'].contains("IMPHASH=BCA5675746D13A1F246E2DA3C2217492") or record['HASHES'].contains("IMPHASH=53E117A96057EAF19C41380D0E87F1C2")) or record['ORIGINAL_FILE_NAME'] == "AdFind.exe") and not (record['PROCESS_NAME'].endswith("\\AdFind.exe")))

sigma_renamed_adfind_detection.sigma_meta = dict(
    level="high"
)

def sigma_iox_tunneling_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_iox.yml
    title: IOX Tunneling Tool
    fields: ['CommandLine', 'Image', 'md5', 'Hashes', 'sha1', 'sha256']
    level: high
    description: Detects the use of IOX - a tool for port forwarding and intranet proxy purposes
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\iox.exe") or (record['COMMAND_LINE'].contains(".exe fwd -l") or record['COMMAND_LINE'].contains(".exe fwd -r") or record['COMMAND_LINE'].contains(".exe proxy -l") or record['COMMAND_LINE'].contains(".exe proxy -r")) or (record['HASHES'].contains("MD5=9DB2D314DD3F704A02051EF5EA210993") or record['HASHES'].contains("SHA1=039130337E28A6623ECF9A0A3DA7D92C5964D8DD") or record['HASHES'].contains("SHA256=C6CF82919B809967D9D90EA73772A8AA1C1EB3BC59252D977500F64F1A0D6731")) or record['MD5'] == "9db2d314dd3f704a02051ef5ea210993" or record['SHA1'] == "039130337e28a6623ecf9a0a3da7d92c5964d8dd" or record['SHA256'] == "c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731")

sigma_iox_tunneling_tool.sigma_meta = dict(
    level="high"
)

def sigma_visual_basic_command_line_compiler_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_visual_basic_compiler.yml
    title: Visual Basic Command Line Compiler Usage
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\vbc.exe") and record['PROCESS_NAME'].endswith("\\cvtres.exe"))

sigma_visual_basic_command_line_compiler_usage.sigma_meta = dict(
    level="high"
)

def sigma_start_of_nt_virtual_dos_machine(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_16bit_application.yml
    title: Start of NT Virtual DOS Machine
    fields: ['Image']
    level: medium
    description: Ntvdm.exe allows the execution of 16-bit Windows applications on 32-bit Windows operating systems, as well as the execution of both 16-bit and 32-bit DOS applications
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\ntvdm.exe") or record['PROCESS_NAME'].endswith("\\csrstub.exe"))

sigma_start_of_nt_virtual_dos_machine.sigma_meta = dict(
    level="medium"
)

def sigma_exploit_for_cve_2017_0261(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2017_0261.yml
    title: Exploit for CVE-2017-0261
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects Winword starting uncommon sub process FLTLDR.exe as used in exploits for CVE-2017-0261 and CVE-2017-0262
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\WINWORD.EXE") and record['PROCESS_NAME'].contains("\\FLTLDR.exe"))

sigma_exploit_for_cve_2017_0261.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_logmein_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_logmein.yml
    title: Use of LogMeIn Remote Access Software
    fields: ['Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "LMIGuardianSvc" or record['PRODUCT_NAME'] == "LMIGuardianSvc" or record['COMPANY'] == "LogMeIn, Inc.")

sigma_use_of_logmein_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_disabled_ie_security_features(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_disable_ie_features.yml
    title: Disabled IE Security Features
    fields: ['CommandLine']
    level: high
    description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-name IEHarden") and record['COMMAND_LINE'].contains("-value 0")) or (record['COMMAND_LINE'].contains("-name DEPOff") and record['COMMAND_LINE'].contains("-value 1")) or (record['COMMAND_LINE'].contains("-name DisableFirstRunCustomize") and record['COMMAND_LINE'].contains("-value 2")))

sigma_disabled_ie_security_features.sigma_meta = dict(
    level="high"
)

def sigma_use_of_sysinternals_psservice(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysinternals_psservice.yml
    title: Use of Sysinternals PsService
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects usage of Sysinternals PsService for service reconnaissance or tamper
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "psservice.exe" or (record['PROCESS_NAME'].endswith("\\PsService.exe") or record['PROCESS_NAME'].endswith("\\PsService64.exe")))

sigma_use_of_sysinternals_psservice.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_systeminfo(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_systeminfo.yml
    title: Suspicious Execution of Systeminfo
    fields: ['Image', 'OriginalFileName']
    level: low
    description: Detects usage of the "systeminfo" command to retrieve information
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\systeminfo.exe") or record['ORIGINAL_FILE_NAME'] == "sysinfo.exe")

sigma_suspicious_execution_of_systeminfo.sigma_meta = dict(
    level="low"
)

def sigma_execute_arbitrary_binaries_using_gup_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_gup_execution.yml
    title: Execute Arbitrary Binaries Using GUP Utility
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\gup.exe") and record['PROCESS_NAME'].endswith("\\explorer.exe")) and not ((record['PROCESS_NAME'].endswith("\\explorer.exe") and record['COMMAND_LINE'].contains("\\Notepad++\\notepad++.exe")) or (record['PARENT_NAME'].contains("\\Notepad++\\updater")) or (record.get('COMMAND_LINE', None) == None)))

sigma_execute_arbitrary_binaries_using_gup_utility.sigma_meta = dict(
    level="medium"
)

def sigma_automated_collection_command_prompt(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_automated_collection.yml
    title: Automated Collection Command Prompt
    fields: ['CommandLine', 'OriginalFileName']
    level: medium
    description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains(".doc") or record['COMMAND_LINE'].contains(".docx") or record['COMMAND_LINE'].contains(".xls") or record['COMMAND_LINE'].contains(".xlsx") or record['COMMAND_LINE'].contains(".ppt") or record['COMMAND_LINE'].contains(".pptx") or record['COMMAND_LINE'].contains(".rtf") or record['COMMAND_LINE'].contains(".pdf") or record['COMMAND_LINE'].contains(".txt")) and ((record['COMMAND_LINE'].contains("dir") and record['COMMAND_LINE'].contains("/b") and record['COMMAND_LINE'].contains("/s")) or (record['ORIGINAL_FILE_NAME'] == "FINDSTR.EXE" and (record['COMMAND_LINE'].contains("/e") or record['COMMAND_LINE'].contains("/si")))))

sigma_automated_collection_command_prompt.sigma_meta = dict(
    level="medium"
)

def sigma_dridex_process_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_dridex.yml
    title: Dridex Process Pattern
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detects typical Dridex process patterns
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\svchost.exe") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\Desktop")) or (record['PARENT_NAME'].endswith("\\svchost.exe") and ((record['PROCESS_NAME'].endswith("\\whoami.exe") and record['COMMAND_LINE'].contains("all")) or ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("view")))))

sigma_dridex_process_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_wsl_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_wsl.yml
    title: WSL Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Detects Possible usage of Windows Subsystem for Linux (WSL) binary as a LOLBIN
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wsl.exe") or record['ORIGINAL_FILE_NAME'] == "wsl.exe") and (record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("--exec") or record['COMMAND_LINE'].contains("--system") or record['COMMAND_LINE'].contains("/mnt/c"))) and not ((record['PARENT_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("-d") and record['COMMAND_LINE'].contains("-e kill"))))

sigma_wsl_execution.sigma_meta = dict(
    level="medium"
)

def sigma_dotnet_exe_exec_dll_and_execute_unsigned_code_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dotnet.yml
    title: Dotnet.exe Exec Dll and Execute Unsigned Code LOLBIN
    fields: ['CommandLine', 'Image']
    level: medium
    description: dotnet.exe will execute any DLL and execute unsigned code
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].endswith(".dll") or record['COMMAND_LINE'].endswith(".csproj")) and record['PROCESS_NAME'].endswith("\\dotnet.exe"))

sigma_dotnet_exe_exec_dll_and_execute_unsigned_code_lolbin.sigma_meta = dict(
    level="medium"
)

def sigma_hacktool_by_cube0x0(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_cube0x0_tools.yml
    title: Hacktool by Cube0x0
    fields: ['Company']
    level: high
    description: Detects the use of tools created by a well-known hacktool producer named Cube0x0, which includes his handle in all binaries as company information in the PE headers (SharpPrintNightmare, KrbRelay, SharpMapExec etc.)
    logsource: category:process_creation - product:windows
    """
    return record['COMPANY'] == "Cube0x0"

sigma_hacktool_by_cube0x0.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_via_use_rundll32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_rundll32.yml
    title: Invoke-Obfuscation Via Use Rundll32
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated Powershell via use Rundll32 in Scripts
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("&&") and record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("shell32.dll") and record['COMMAND_LINE'].contains("shellexec_rundll") and (record['COMMAND_LINE'].contains("value") or record['COMMAND_LINE'].contains("invoke") or record['COMMAND_LINE'].contains("comspec") or record['COMMAND_LINE'].contains("iex")))

sigma_invoke_obfuscation_via_use_rundll32.sigma_meta = dict(
    level="high"
)

def sigma_powershell_amsi_bypass_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_psh_amsi_bypass_pattern_nov22.yml
    title: PowerShell AMSI Bypass Pattern
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects attempts to disable AMSI in the command line. It is possible to bypass AMSI by disabling it before loading the main payload.
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe")) and record['COMMAND_LINE'].contains("[Ref].Assembly.GetType") and record['COMMAND_LINE'].contains("SetValue($null,$true)") and record['COMMAND_LINE'].contains("NonPublic,Static"))

sigma_powershell_amsi_bypass_pattern.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_via_windows_firewall_snap_in_hijack(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_hijacking_firwall_snap_in.yml
    title: UAC Bypass via Windows Firewall Snap-In Hijack
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\mmc.exe") and record['PARENT_COMMAND_LINE'].contains("WF.msc")) and not (record['PROCESS_NAME'].endswith("\\WerFault.exe")))

sigma_uac_bypass_via_windows_firewall_snap_in_hijack.sigma_meta = dict(
    level="medium"
)

def sigma_arbitrary_shell_command_execution_via_settingcontent_ms(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_arbitrary_shell_execution_via_settingcontent.yml
    title: Arbitrary Shell Command Execution Via Settingcontent-Ms
    fields: ['CommandLine']
    level: medium
    description: The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create "shortcuts" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains(".SettingContent-ms") and not (record['COMMAND_LINE'].contains("immersivecontrolpanel")))

sigma_arbitrary_shell_command_execution_via_settingcontent_ms.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_add_scheduled_task_from_user_appdata_temp(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_user_temp.yml
    title: Suspicious Add Scheduled Task From User AppData Temp
    fields: ['CommandLine', 'Image']
    level: high
    description: schtasks.exe create task from user AppData\Local\Temp
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create") and record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp")) and not ((record['COMMAND_LINE'].contains("/Create /TN \"klcp_update\" /XML") and record['COMMAND_LINE'].contains("\\klcp_update_task.xml"))))

sigma_suspicious_add_scheduled_task_from_user_appdata_temp.sigma_meta = dict(
    level="high"
)

def sigma_regsvr32_spawning_explorer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_spawn_explorer.yml
    title: Regsvr32 Spawning Explorer
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects "regsvr32.exe" spawning "explorer.exe", which is very uncommon.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\regsvr32.exe") and record['PROCESS_NAME'].endswith("\\explorer.exe"))

sigma_regsvr32_spawning_explorer.sigma_meta = dict(
    level="high"
)

def sigma_dropping_of_password_filter_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_credential_access_via_password_filter.yml
    title: Dropping Of Password Filter DLL
    fields: ['CommandLine']
    level: medium
    description: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa") and record['COMMAND_LINE'].contains("scecli\\0") and record['COMMAND_LINE'].contains("reg add"))

sigma_dropping_of_password_filter_dll.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_powershell_encoded_command_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_cmd_patterns.yml
    title: Suspicious PowerShell Encoded Command Patterns
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("-en") or record['COMMAND_LINE'].contains("-enc") or record['COMMAND_LINE'].contains("-enco")) and (record['COMMAND_LINE'].contains("JAB") or record['COMMAND_LINE'].contains("SUVYI") or record['COMMAND_LINE'].contains("SQBFAFgA") or record['COMMAND_LINE'].contains("aWV4I") or record['COMMAND_LINE'].contains("IAB") or record['COMMAND_LINE'].contains("PAA") or record['COMMAND_LINE'].contains("aQBlAHgA"))) and not ((record['PARENT_NAME'].contains("C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows") or record['PARENT_NAME'].contains("\\gc_worker.exe"))))

sigma_suspicious_powershell_encoded_command_patterns.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_encoded_obfuscated_load_string(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_base64_load.yml
    title: Suspicious Encoded Obfuscated LOAD String
    fields: ['CommandLine']
    level: high
    description: Detects suspicious base64 encoded and obbfuscated LOAD string often used for reflection.assembly load
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ") or record['COMMAND_LINE'].contains("oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA") or record['COMMAND_LINE'].contains("6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA") or record['COMMAND_LINE'].contains("OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ") or record['COMMAND_LINE'].contains("oAOgAoACIATABvACIAKwAiAGEAZAAiACkA") or record['COMMAND_LINE'].contains("6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA") or record['COMMAND_LINE'].contains("OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ") or record['COMMAND_LINE'].contains("oAOgAoACIATABvAGEAIgArACIAZAAiACkA") or record['COMMAND_LINE'].contains("6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA") or record['COMMAND_LINE'].contains("OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ") or record['COMMAND_LINE'].contains("oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA") or record['COMMAND_LINE'].contains("6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA") or record['COMMAND_LINE'].contains("OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ") or record['COMMAND_LINE'].contains("oAOgAoACcATABvACcAKwAnAGEAZAAnACkA") or record['COMMAND_LINE'].contains("6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA") or record['COMMAND_LINE'].contains("OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ") or record['COMMAND_LINE'].contains("oAOgAoACcATABvAGEAJwArACcAZAAnACkA") or record['COMMAND_LINE'].contains("6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA"))

sigma_suspicious_encoded_obfuscated_load_string.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_use_of_procdump_on_lsass(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_procdump_lsass.yml
    title: Suspicious Use of Procdump on LSASS
    fields: ['CommandLine']
    level: high
    description: Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-ma") or record['COMMAND_LINE'].contains("/ma")) and record['COMMAND_LINE'].contains("ls"))

sigma_suspicious_use_of_procdump_on_lsass.sigma_meta = dict(
    level="high"
)

def sigma_imports_registry_key_from_an_ads(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.yml
    title: Imports Registry Key From an ADS
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the import of a alternate datastream to the registry with regedit.exe.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regedit.exe") and (record['COMMAND_LINE'].contains("/i") or record['COMMAND_LINE'].contains(".reg")) and re.match(':[^ \\\\]', record['COMMAND_LINE'])) and not ((record['COMMAND_LINE'].contains("/e") or record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("-c"))))

sigma_imports_registry_key_from_an_ads.sigma_meta = dict(
    level="high"
)

def sigma_encoded_powershell_command_line_usage_of_convertto_securestring(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_cmdline_convertto_securestring.yml
    title: Encoded PowerShell Command Line Usage of ConvertTo-SecureString
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects specific encoding method of cOnvErTTO-SECUreStRIng in the PowerShell command lines
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("ConvertTo-SecureString"))

sigma_encoded_powershell_command_line_usage_of_convertto_securestring.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_kernel_dump_using_dtrace(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_dtrace_kernel_dump.yml
    title: Suspicious Kernel Dump Using Dtrace
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\dtrace.exe") and record['COMMAND_LINE'].contains("lkd(0)")) or (record['COMMAND_LINE'].contains("syscall:::return") and record['COMMAND_LINE'].contains("lkd(")))

sigma_suspicious_kernel_dump_using_dtrace.sigma_meta = dict(
    level="high"
)

def sigma_sourgum_actor_behaviours(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_sourgrum.yml
    title: SOURGUM Actor Behaviours
    fields: ['CommandLine', 'Image']
    level: high
    description: Suspicious behaviours related to an actor tracked by Microsoft as SOURGUM
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].contains("windows\\system32\\Physmem.sys") or record['PROCESS_NAME'].contains("Windows\\system32\\ime\\SHARED\\WimBootConfigurations.ini") or record['PROCESS_NAME'].contains("Windows\\system32\\ime\\IMEJP\\WimBootConfigurations.ini") or record['PROCESS_NAME'].contains("Windows\\system32\\ime\\IMETC\\WimBootConfigurations.ini")) or ((record['PROCESS_NAME'].contains("windows\\system32\\filepath2") or record['PROCESS_NAME'].contains("windows\\system32\\ime")) and record['COMMAND_LINE'].contains("reg add") and (record['COMMAND_LINE'].contains("HKEY_LOCAL_MACHINE\\software\\classes\\clsid\\{7c857801-7381-11cf-884d-00aa004b2e24}\\inprocserver32") or record['COMMAND_LINE'].contains("HKEY_LOCAL_MACHINE\\software\\classes\\clsid\\{cf4cc405-e2c5-4ddd-b3ce-5e7582d8c9fa}\\inprocserver32"))))

sigma_sourgum_actor_behaviours.sigma_meta = dict(
    level="high"
)

def sigma_always_install_elevated_windows_installer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_always_install_elevated_windows_installer.yml
    title: Always Install Elevated Windows Installer
    fields: ['IntegrityLevel', 'CommandLine', 'Image', 'ParentImage', 'User', 'ParentCommandLine']
    level: medium
    description: Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege
    logsource: product:windows - category:process_creation
    """
    return ((((record['PROCESS_NAME'].contains("\\Windows\\Installer") and record['PROCESS_NAME'].contains("msi") and record['PROCESS_NAME'].endswith("tmp")) or (record['PROCESS_NAME'].endswith("\\msiexec.exe") and record['INTEGRITY_LEVEL'] == "System")) and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))) and not ((record['PARENT_NAME'] == "C:\\Windows\\System32\\services.exe") or (record['COMMAND_LINE'].endswith("\\system32\\msiexec.exe /V") or record['PARENT_COMMAND_LINE'].endswith("\\system32\\msiexec.exe /V")) or ((record['PARENT_NAME'].startswith("C:\\ProgramData\\Sophos") or record['PARENT_NAME'].startswith("C:\\ProgramData\\Avira") or record['PARENT_NAME'].startswith("C:\\Program Files\\Avast Software") or record['PARENT_NAME'].startswith("C:\\Program Files (x86)\\Avast Software") or record['PARENT_NAME'].startswith("C:\\Program Files\\Google\\Update") or record['PARENT_NAME'].startswith("C:\\Program Files (x86)\\Google\\Update")))))

sigma_always_install_elevated_windows_installer.sigma_meta = dict(
    level="medium"
)

def sigma_powershell_get_clipboard_cmdlet_via_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_get_clipboard.yml
    title: PowerShell Get-Clipboard Cmdlet Via CLI
    fields: ['CommandLine']
    level: medium
    description: Detects usage of the 'Get-Clipboard' cmdlet via CLI
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("Get-Clipboard")

sigma_powershell_get_clipboard_cmdlet_via_cli.sigma_meta = dict(
    level="medium"
)

def sigma_compress_data_and_lock_with_password_for_exfiltration_with_winzip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_winzip.yml
    title: Compress Data and Lock With Password for Exfiltration With WINZIP
    fields: ['CommandLine']
    level: medium
    description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("winzip.exe") or record['COMMAND_LINE'].contains("winzip64.exe")) and record['COMMAND_LINE'].contains("-s\"") and (record['COMMAND_LINE'].contains("-min") or record['COMMAND_LINE'].contains("-a")))

sigma_compress_data_and_lock_with_password_for_exfiltration_with_winzip.sigma_meta = dict(
    level="medium"
)

def sigma_mshta_remotely_hosted_hta_file_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mshta_http.yml
    title: Mshta Remotely Hosted HTA File Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\mshta.exe") or record['ORIGINAL_FILE_NAME'] == "MSHTA.EXE") and (record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_mshta_remotely_hosted_hta_file_execution.sigma_meta = dict(
    level="high"
)

def sigma_data_compressed_rar_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_data_compressed_with_rar.yml
    title: Data Compressed - rar.exe
    fields: ['CommandLine', 'Image']
    level: low
    description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rar.exe") and record['COMMAND_LINE'].contains("a"))

sigma_data_compressed_rar_exe.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_del_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_del.yml
    title: Suspicious Del in CommandLine
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious command line to remove and 'exe' or 'dll'
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("del") and record['COMMAND_LINE'].contains("\\*.exe") and record['COMMAND_LINE'].contains("/f") and record['COMMAND_LINE'].contains("/q")) or (record['COMMAND_LINE'].contains("del") and record['COMMAND_LINE'].contains("\\*.dll") and record['COMMAND_LINE'].contains("C:\\ProgramData")))

sigma_suspicious_del_in_commandline.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_scheduled_task_creation_involving_temp_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtask_creation_temp_folder.yml
    title: Suspicious Scheduled Task Creation Involving Temp Folder
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/create") and record['COMMAND_LINE'].contains("/sc once") and record['COMMAND_LINE'].contains("\\Temp"))

sigma_suspicious_scheduled_task_creation_involving_temp_folder.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_iex_execution_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_iex_patterns.yml
    title: Suspicious PowerShell IEX Execution Patterns
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious ways to run Invoke-Execution using IEX acronym
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("| iex;") or record['COMMAND_LINE'].contains("| iex") or record['COMMAND_LINE'].contains("| iex}") or record['COMMAND_LINE'].contains("| IEX ;") or record['COMMAND_LINE'].contains("| IEX -Error") or record['COMMAND_LINE'].contains("| IEX (new") or record['COMMAND_LINE'].contains(");IEX")) and (record['COMMAND_LINE'].contains("::FromBase64String") or record['COMMAND_LINE'].contains(".GetString([System.Convert]::"))) or (record['COMMAND_LINE'].contains(")|iex;$") or record['COMMAND_LINE'].contains(");iex($") or record['COMMAND_LINE'].contains(");iex $") or record['COMMAND_LINE'].contains("| IEX |")))

sigma_suspicious_powershell_iex_execution_patterns.sigma_meta = dict(
    level="high"
)

def sigma_dumpstack_log_defender_evasion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dumpstack_log_evasion.yml
    title: DumpStack.log Defender Evasion
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\DumpStack.log") or record['COMMAND_LINE'].contains("-o DumpStack.log"))

sigma_dumpstack_log_defender_evasion.sigma_meta = dict(
    level="critical"
)

def sigma_use_of_pdq_deploy_remote_adminstartion_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pdq_deploy.yml
    title: Use of PDQ Deploy Remote Adminstartion Tool
    fields: ['OriginalFileName', 'Product', 'Company', 'Description']
    level: medium
    description: Detect use of PDQ Deploy remote admin tool
    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "PDQ Deploy Console" or record['PRODUCT_NAME'] == "PDQ Deploy" or record['COMPANY'] == "PDQ.com" or record['ORIGINAL_FILE_NAME'] == "PDQDeployConsole.exe")

sigma_use_of_pdq_deploy_remote_adminstartion_tool.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_dumpminitool_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proc_dump_susp_dumpminitool.yml
    title: Suspicious DumpMinitool Usage
    fields: ['CommandLine', 'Image', 'OriginalName']
    level: high
    description: Detects suspicious ways to use of a Visual Studio bundled tool named DumpMinitool.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\DumpMinitool.exe") or record['ORIGINAL_NAME'] == "DumpMinitool.exe") and ((not ((record['PROCESS_NAME'].contains("\\Microsoft Visual Studio") or record['PROCESS_NAME'].contains("\\Extensions"))) or record['COMMAND_LINE'].contains(".txt")) or (record['COMMAND_LINE'].contains("Full") and not (record['COMMAND_LINE'].contains("--dumpType")))))

sigma_suspicious_dumpminitool_usage.sigma_meta = dict(
    level="high"
)

def sigma_conhost_spawned_by_suspicious_parent_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_parent_of_conhost.yml
    title: Conhost Spawned By Suspicious Parent Process
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects when the Console Window Host (conhost.exe) process is spawned by a suspicious parent process, which could be indicative of code injection.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\conhost.exe") and (record['PARENT_NAME'].endswith("\\svchost.exe") or record['PARENT_NAME'].endswith("\\lsass.exe") or record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\smss.exe") or record['PARENT_NAME'].endswith("\\winlogon.exe") or record['PARENT_NAME'].endswith("\\explorer.exe") or record['PARENT_NAME'].endswith("\\rundll32.exe") or record['PARENT_NAME'].endswith("\\regsvr32.exe") or record['PARENT_NAME'].endswith("\\userinit.exe") or record['PARENT_NAME'].endswith("\\wininit.exe") or record['PARENT_NAME'].endswith("\\spoolsv.exe"))) and not ((record['PARENT_COMMAND_LINE'].contains("-k apphost -s AppHostSvc") or record['PARENT_COMMAND_LINE'].contains("-k imgsvc") or record['PARENT_COMMAND_LINE'].contains("-k LocalSystemNetworkRestricted -p -s NgcSvc") or record['PARENT_COMMAND_LINE'].contains("-k netsvcs -p -s NetSetupSvc") or record['PARENT_COMMAND_LINE'].contains("-k netsvcs -p -s wlidsvc") or record['PARENT_COMMAND_LINE'].contains("-k NetworkService -p -s DoSvc") or record['PARENT_COMMAND_LINE'].contains("-k wsappx -p -s AppXSvc") or record['PARENT_COMMAND_LINE'].contains("-k wsappx -p -s ClipSVC") or record['PARENT_COMMAND_LINE'].contains("C:\\Program Files (x86)\\Dropbox\\Client") or record['PARENT_COMMAND_LINE'].contains("C:\\Program Files\\Dropbox\\Client"))))

sigma_conhost_spawned_by_suspicious_parent_process.sigma_meta = dict(
    level="high"
)

def sigma_sysprep_on_appdata_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_sysprep_appdata.yml
    title: Sysprep on AppData Folder
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sysprep.exe") and record['COMMAND_LINE'].contains("\\AppData"))

sigma_sysprep_on_appdata_folder.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_binary.yml
    title: Renamed Binary
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['ORIGINAL_FILE_NAME'] == "CONHOST.EXE" or record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "powershell_ise.EXE" or record['ORIGINAL_FILE_NAME'] == "psexec.exe" or record['ORIGINAL_FILE_NAME'] == "psexec.c" or record['ORIGINAL_FILE_NAME'] == "cscript.exe" or record['ORIGINAL_FILE_NAME'] == "wscript.exe" or record['ORIGINAL_FILE_NAME'] == "MSHTA.EXE" or record['ORIGINAL_FILE_NAME'] == "REGSVR32.EXE" or record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['ORIGINAL_FILE_NAME'] == "CertUtil.exe" or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" or record['ORIGINAL_FILE_NAME'] == "CMSTP.EXE" or record['ORIGINAL_FILE_NAME'] == "msiexec.exe" or record['ORIGINAL_FILE_NAME'] == "7z.exe" or record['ORIGINAL_FILE_NAME'] == "WinRAR.exe" or record['ORIGINAL_FILE_NAME'] == "wevtutil.exe" or record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe" or record['ORIGINAL_FILE_NAME'] == "netsh.exe" or record['ORIGINAL_FILE_NAME'] == "InstallUtil.exe") and not ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\conhost.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\psexec.exe") or record['PROCESS_NAME'].endswith("\\psexec64.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\cmstp.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\7z.exe") or record['PROCESS_NAME'].endswith("\\WinRAR.exe") or record['PROCESS_NAME'].endswith("\\wevtutil.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe") or record['PROCESS_NAME'].endswith("\\netsh.exe") or record['PROCESS_NAME'].endswith("\\InstallUtil.exe"))))

sigma_renamed_binary.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_installutil_to_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_installutil_download.yml
    title: Suspicious Execution of InstallUtil To Download
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects the use the .NET InstallUtil.exe application in order to download arbitrary files. The files will be written to %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\InstallUtil.exe") or record['ORIGINAL_FILE_NAME'] == "InstallUtil.exe") and (record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_suspicious_execution_of_installutil_to_download.sigma_meta = dict(
    level="medium"
)

def sigma_wscript_or_cscript_dropper(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_script_dropper.yml
    title: WScript or CScript Dropper
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects wscript/cscript executions of scripts located in user directories
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe")) and (record['COMMAND_LINE'].contains("C:\\Users") or record['COMMAND_LINE'].contains("C:\\ProgramData")) and (record['COMMAND_LINE'].contains(".jse") or record['COMMAND_LINE'].contains(".vbe") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".vba") or record['COMMAND_LINE'].contains(".vbs"))) and not (record['PARENT_NAME'].contains("\\winzip")))

sigma_wscript_or_cscript_dropper.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_ntlm_authentication_on_the_printer_spooler_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ntlmrelay.yml
    title: Suspicious NTLM Authentication on the Printer Spooler Service
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("C:\\windows\\system32\\davclnt.dll,DavSetCookie") and record['COMMAND_LINE'].contains("http") and (record['COMMAND_LINE'].contains("spoolss") or record['COMMAND_LINE'].contains("srvsvc") or record['COMMAND_LINE'].contains("/print/pipe/")))

sigma_suspicious_ntlm_authentication_on_the_printer_spooler_service.sigma_meta = dict(
    level="high"
)

def sigma_exploiting_cve_2019_1388(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2019_1388.yml
    title: Exploiting CVE-2019-1388
    fields: ['CommandLine', 'IntegrityLevel', 'Image', 'ParentImage', 'User']
    level: critical
    description: Detects an exploitation attempt in which the UAC consent dialogue is used to invoke an Internet Explorer process running as LOCAL_SYSTEM
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\consent.exe") and record['PROCESS_NAME'].endswith("\\iexplore.exe") and record['COMMAND_LINE'].contains("http")) and (record['INTEGRITY_LEVEL'] == "System" or (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))))

sigma_exploiting_cve_2019_1388.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_get_local_groups_information_with_wmic(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_group_recon.yml
    title: Suspicious Get Local Groups Information with WMIC
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Adversaries may attempt to find local system groups and permission settings.
The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.

    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\wmic.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and record['COMMAND_LINE'].contains("group"))

sigma_suspicious_get_local_groups_information_with_wmic.sigma_meta = dict(
    level="low"
)

def sigma_ping_hex_ip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ping_hex_ip.yml
    title: Ping Hex IP
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a ping command that uses a hex encoded IP address
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\ping.exe") and record['COMMAND_LINE'].contains("0x"))

sigma_ping_hex_ip.sigma_meta = dict(
    level="high"
)

def sigma_gallium_artefacts(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_gallium.yml
    title: GALLIUM Artefacts
    fields: ['Image', 'sha1']
    level: high
    description: Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.
    logsource: product:windows - category:process_creation
    """
    return (record['SHA1'] == "e570585edc69f9074cb5e8a790708336bd45ca0f" and not ((record['PROCESS_NAME'].contains(":\\Program Files(x86)") or record['PROCESS_NAME'].contains(":\\Program Files"))))

sigma_gallium_artefacts.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_extrac32_alternate_data_stream_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_extrac32_ads.yml
    title: Suspicious Extrac32 Alternate Data Stream Execution
    fields: ['CommandLine']
    level: medium
    description: Extract data from cab file and hide it in an alternate data stream
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("extrac32.exe") and record['COMMAND_LINE'].contains(".cab") and re.match(':[^\\\\]', record['COMMAND_LINE']))

sigma_suspicious_extrac32_alternate_data_stream_execution.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ping_and_del_combination(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ping_del.yml
    title: Suspicious Ping And Del Combination
    fields: ['CommandLine']
    level: high
    description: Detects a method often used by ransomware. Which combines the "ping" to wait a couple of seconds and then "del" to delete the file in question. Its used to hide the file responsible for the initial infection for example
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-n") or record['COMMAND_LINE'].contains("/n")) and record['COMMAND_LINE'].contains("Nul") and (record['_raw'].contains("/f") or record['_raw'].contains("-f") or record['_raw'].contains("/q") or record['_raw'].contains("-q")) and (record['COMMAND_LINE'].contains("ping") and record['COMMAND_LINE'].contains("del")))

sigma_suspicious_ping_and_del_combination.sigma_meta = dict(
    level="high"
)

def sigma_dtrack_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_dtrack.yml
    title: DTRACK Process Creation
    fields: ['CommandLine']
    level: critical
    description: Detects specific process parameters as seen in DTRACK infections
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("echo EEEE >")

sigma_dtrack_process_creation.sigma_meta = dict(
    level="critical"
)

def sigma_copying_sensitive_files_with_credential_data(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_copying_sensitive_files_with_credential_data.yml
    title: Copying Sensitive Files with Credential Data
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Files with well-known filenames (sensitive files with credential data) copying
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\esentutl.exe") or record['ORIGINAL_FILE_NAME'] == "\\esentutl.exe") and (record['COMMAND_LINE'].contains("vss") or record['COMMAND_LINE'].contains("/m") or record['COMMAND_LINE'].contains("/y"))) or (record['COMMAND_LINE'].contains("\\windows\\ntds\\ntds.dit") or record['COMMAND_LINE'].contains("\\config\\sam") or record['COMMAND_LINE'].contains("\\config\\security") or record['COMMAND_LINE'].contains("\\config\\system") or record['COMMAND_LINE'].contains("\\repair\\sam") or record['COMMAND_LINE'].contains("\\repair\\system") or record['COMMAND_LINE'].contains("\\repair\\security") or record['COMMAND_LINE'].contains("\\config\\RegBack\\sam") or record['COMMAND_LINE'].contains("\\config\\RegBack\\system") or record['COMMAND_LINE'].contains("\\config\\RegBack\\security")))

sigma_copying_sensitive_files_with_credential_data.sigma_meta = dict(
    level="high"
)

def sigma_exports_critical_registry_keys_to_a_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regedit_export_critical_keys.yml
    title: Exports Critical Registry Keys To a File
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the export of a crital Registry key to a file.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\regedit.exe") and (record['COMMAND_LINE'].contains("/E") or record['COMMAND_LINE'].contains("-E")) and (record['COMMAND_LINE'].contains("hklm") or record['COMMAND_LINE'].contains("hkey_local_machine")) and (record['COMMAND_LINE'].endswith("\\system") or record['COMMAND_LINE'].endswith("\\sam") or record['COMMAND_LINE'].endswith("\\security")))

sigma_exports_critical_registry_keys_to_a_file.sigma_meta = dict(
    level="high"
)

def sigma_sharpchisel_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sharp_chisel_usage.yml
    title: SharpChisel Usage
    fields: ['Image', 'Product']
    level: high
    description: Detects usage of the Sharp Chisel via the commandline arguments
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SharpChisel.exe") or record['PRODUCT_NAME'] == "SharpChisel")

sigma_sharpchisel_usage.sigma_meta = dict(
    level="high"
)

def sigma_rundll32_without_parameters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.yml
    title: Rundll32 Without Parameters
    fields: ['CommandLine']
    level: high
    description: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'] == "rundll32.exe"

sigma_rundll32_without_parameters.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_certutil_command_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_certutil_command.yml
    title: Suspicious Certutil Command Usage
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certutil.exe") or record['ORIGINAL_FILE_NAME'] == "CertUtil.exe") and (record['COMMAND_LINE'].contains("-decode") or record['COMMAND_LINE'].contains("-decodehex") or record['COMMAND_LINE'].contains("-urlcache") or record['COMMAND_LINE'].contains("-verifyctl") or record['COMMAND_LINE'].contains("-encode") or record['COMMAND_LINE'].contains("-exportPFX") or record['COMMAND_LINE'].contains("/decode") or record['COMMAND_LINE'].contains("/decodehex") or record['COMMAND_LINE'].contains("/urlcache") or record['COMMAND_LINE'].contains("/verifyctl") or record['COMMAND_LINE'].contains("/encode") or record['COMMAND_LINE'].contains("/exportPFX")))

sigma_suspicious_certutil_command_usage.sigma_meta = dict(
    level="high"
)

def sigma_7zip_compressing_dump_files(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_7zip_dmp.yml
    title: 7Zip Compressing Dump Files
    fields: ['CommandLine', 'Image', 'Description']
    level: high
    description: Detects a suspicious 7zip execution that involves a file with a .dmp extension, which could be a step in a process of dump file exfiltration
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\7z.exe") or record['PROCESS_NAME'].endswith("\\7zr.exe") or record['PROCESS_NAME'].endswith("\\7za.exe")) or record['DESCRIPTION'].contains("7-Zip")) and record['COMMAND_LINE'].contains(".dmp"))

sigma_7zip_compressing_dump_files.sigma_meta = dict(
    level="high"
)

def sigma_conti_volume_shadow_listing(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_conti.yml
    title: Conti Volume Shadow Listing
    fields: ['CommandLine']
    level: high
    description: Detects a command used by conti to find volume shadow backups
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("vssadmin list shadows") and record['COMMAND_LINE'].contains("log.txt"))

sigma_conti_volume_shadow_listing.sigma_meta = dict(
    level="high"
)

def sigma_download_arbitrary_files_via_mspub_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_mspub_download.yml
    title: Download Arbitrary Files Via MSPUB.EXE
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\MSPUB.exe") or record['ORIGINAL_FILE_NAME'] == "MSPUB.exe") and (record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_download_arbitrary_files_via_mspub_exe.sigma_meta = dict(
    level="medium"
)

def sigma_lolbas_data_exfiltration_by_datasvcutil_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.yml
    title: LOLBAS Data Exfiltration by DataSvcUtil.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects when a user performs data exfiltration by using DataSvcUtil.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("/in:") or record['COMMAND_LINE'].contains("/out:") or record['COMMAND_LINE'].contains("/uri:")) and (record['PROCESS_NAME'].endswith("\\DataSvcUtil.exe") or record['ORIGINAL_FILE_NAME'] == "DataSvcUtil.exe"))

sigma_lolbas_data_exfiltration_by_datasvcutil_exe.sigma_meta = dict(
    level="medium"
)

def sigma_esentutl_gather_credentials(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_esentutl_params.yml
    title: Esentutl Gather Credentials
    fields: ['CommandLine']
    level: medium
    description: Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("esentutl") and record['COMMAND_LINE'].contains("/p"))

sigma_esentutl_gather_credentials.sigma_meta = dict(
    level="medium"
)

def sigma_procdump_evasion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_procdump_evasion.yml
    title: Procdump Evasion
    fields: ['CommandLine']
    level: high
    description: Detects uses of the SysInternals Procdump utility in which procdump or its output get renamed or a dump file is moved ot copied to a different name
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("copy procdump") or record['COMMAND_LINE'].contains("move procdump")) or (record['COMMAND_LINE'].contains("copy") and record['COMMAND_LINE'].contains(".dmp") and (record['COMMAND_LINE'].contains("2.dmp") or record['COMMAND_LINE'].contains("lsass") or record['COMMAND_LINE'].contains("out.dmp"))) or (record['COMMAND_LINE'].contains("copy lsass.exe_") or record['COMMAND_LINE'].contains("move lsass.exe_")))

sigma_procdump_evasion.sigma_meta = dict(
    level="high"
)

def sigma_terminal_service_process_spawn(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_termserv_proc_spawn.yml
    title: Terminal Service Process Spawn
    fields: ['Image', 'ParentCommandLine']
    level: high
    description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_COMMAND_LINE'].contains("\\svchost.exe") and record['PARENT_COMMAND_LINE'].contains("termsvcs")) and not (((record['PROCESS_NAME'].endswith("\\rdpclip.exe") or record['PROCESS_NAME'].endswith(":\\Windows\\System32\\csrss.exe") or record['PROCESS_NAME'].endswith(":\\Windows\\System32\\wininit.exe"))) or (record.get('PROCESS_NAME', None) == None)))

sigma_terminal_service_process_spawn.sigma_meta = dict(
    level="high"
)

def sigma_discovery_of_a_system_time(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_remote_time_discovery.yml
    title: Discovery of a System Time
    fields: ['CommandLine', 'Image']
    level: low
    description: Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("time")) or (record['PROCESS_NAME'].endswith("\\w32tm.exe") and record['COMMAND_LINE'].contains("tz")))

sigma_discovery_of_a_system_time.sigma_meta = dict(
    level="low"
)

def sigma_detection_of_powershell_execution_via_sqlps_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_use_of_sqlps_bin.yml
    title: Detection of PowerShell Execution via Sqlps.exe
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: This rule detects execution of a PowerShell code through the sqlps.exe utility, which is included in the standard set of utilities supplied with the MSSQL Server.
Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sqlps.exe") or record['PARENT_NAME'].endswith("\\sqlps.exe") or record['ORIGINAL_FILE_NAME'] == "\\sqlps.exe") and not (record['PARENT_NAME'].endswith("\\sqlagent.exe")))

sigma_detection_of_powershell_execution_via_sqlps_exe.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_using_consent_and_comctl32_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_consent_comctl32.yml
    title: UAC Bypass Using Consent and Comctl32 - Process
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\consent.exe") and record['PROCESS_NAME'].endswith("\\werfault.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_consent_and_comctl32_process.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_get_localgroup_member_recon.yml
    title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Get-LocalGroupMember") and (record['COMMAND_LINE'].contains("domain admins") or record['COMMAND_LINE'].contains("administrator") or record['COMMAND_LINE'].contains("administrateur") or record['COMMAND_LINE'].contains("enterprise admins") or record['COMMAND_LINE'].contains("Exchange Trusted Subsystem") or record['COMMAND_LINE'].contains("Remote Desktop Users") or record['COMMAND_LINE'].contains("Utilisateurs du Bureau à distance") or record['COMMAND_LINE'].contains("Usuarios de escritorio remoto")))

sigma_suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet.sigma_meta = dict(
    level="medium"
)

def sigma_mshta_javascript_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mshta_javascript.yml
    title: Mshta JavaScript Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Identifies suspicious mshta.exe commands.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\mshta.exe") and record['COMMAND_LINE'].contains("javascript"))

sigma_mshta_javascript_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_service_path_modification(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_path_modification.yml
    title: Suspicious Service Path Modification
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects service path modification via the "sc" binary to a suspicious command or path
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sc.exe") and record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("binPath") and (record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("cmd") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("wscript") or record['COMMAND_LINE'].contains("cscript") or record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("svchost") or record['COMMAND_LINE'].contains("dllhost") or record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd /r") or record['COMMAND_LINE'].contains("C:\\Users\\Public") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") or record['COMMAND_LINE'].contains("C:\\Windows\\TEMP") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp")))

sigma_suspicious_service_path_modification.sigma_meta = dict(
    level="high"
)

def sigma_nslookup_pwsh_download_cradle(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_nslookup_pwsh_download_cradle.yml
    title: Nslookup PwSh Download Cradle
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: This rule tries to detect powershell download cradles, e.g. powershell . (nslookup -q=txt http://some.owned.domain.com)[-1]
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\powershell.exe") and record['PROCESS_NAME'].contains("nslookup") and record['COMMAND_LINE'].contains("=txt"))

sigma_nslookup_pwsh_download_cradle.sigma_meta = dict(
    level="medium"
)

def sigma_operation_wocao_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_wocao.yml
    title: Operation Wocao Activity
    fields: ['CommandLine']
    level: high
    description: Detects activity mentioned in Operation Wocao report
    logsource: category:process_creation - product:windows - definition:The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
    """
    return (record['COMMAND_LINE'].contains("checkadmin.exe 127.0.0.1 -all") or record['COMMAND_LINE'].contains("netsh advfirewall firewall add rule name=powershell dir=in") or record['COMMAND_LINE'].contains("cmd /c powershell.exe -ep bypass -file c:\\s.ps1") or record['COMMAND_LINE'].contains("/tn win32times /f") or record['COMMAND_LINE'].contains("create win32times binPath=") or record['COMMAND_LINE'].contains("\\c$\\windows\\system32\\devmgr.dll") or record['COMMAND_LINE'].contains("-exec bypass -enc JgAg") or record['COMMAND_LINE'].contains("type *keepass\\KeePass.config.xml") or record['COMMAND_LINE'].contains("iie.exe iie.txt") or record['COMMAND_LINE'].contains("reg query HKEY_CURRENT_USER\\Software\\\\*\\PuTTY\\Sessions"))

sigma_operation_wocao_activity.sigma_meta = dict(
    level="high"
)

def sigma_mouse_lock_credential_gathering(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mouse_lock.yml
    title: Mouse Lock Credential Gathering
    fields: ['CommandLine', 'Product', 'Company']
    level: medium
    description: In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.
    logsource: product:windows - category:process_creation
    """
    return (record['PRODUCT_NAME'].contains("Mouse Lock") or record['COMPANY'].contains("Misc314") or record['COMMAND_LINE'].contains("Mouse Lock_"))

sigma_mouse_lock_credential_gathering.sigma_meta = dict(
    level="medium"
)

def sigma_shells_spawned_by_java(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shell_spawn_by_java.yml
    title: Shells Spawned by Java
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\java.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe"))) and not (record['PARENT_NAME'].contains("build") and record['COMMAND_LINE'].contains("build")))

sigma_shells_spawned_by_java.sigma_meta = dict(
    level="medium"
)

def sigma_crackmapexecwin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_dragonfly.yml
    title: CrackMapExecWin
    fields: ['Image']
    level: critical
    description: Detects CrackMapExecWin Activity as Described by NCSC
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\crackmapexec.exe")

sigma_crackmapexecwin.sigma_meta = dict(
    level="critical"
)

def sigma_non_privileged_usage_of_reg_or_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_non_priv_reg_or_ps.yml
    title: Non-privileged Usage of Reg or Powershell
    fields: ['CommandLine', 'IntegrityLevel']
    level: high
    description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add")) or (record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("set-itemproperty") or record['COMMAND_LINE'].contains("sp") or record['COMMAND_LINE'].contains("new-itemproperty"))) and (record['INTEGRITY_LEVEL'] == "Medium" and record['COMMAND_LINE'].contains("ControlSet") and record['COMMAND_LINE'].contains("Services") and (record['COMMAND_LINE'].contains("ImagePath") or record['COMMAND_LINE'].contains("FailureCommand") or record['COMMAND_LINE'].contains("ServiceDLL"))))

sigma_non_privileged_usage_of_reg_or_powershell.sigma_meta = dict(
    level="high"
)

def sigma_possible_shim_database_persistence_via_sdbinst_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml
    title: Possible Shim Database Persistence via sdbinst.exe
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sdbinst.exe") and record['COMMAND_LINE'].contains(".sdb")) and not (record['COMMAND_LINE'].contains("iisexpressshim.sdb")))

sigma_possible_shim_database_persistence_via_sdbinst_exe.sigma_meta = dict(
    level="high"
)

def sigma_stop_or_remove_antivirus_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_modification.yml
    title: Stop Or Remove Antivirus Service
    fields: ['CommandLine']
    level: high
    description: Detects usage of 'Stop-Service' or 'Remove-Service' powershell cmdlet to disable AV services.
Adversaries may disable security tools to avoid possible detection of their tools and activities by stopping antivirus service

    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Stop-Service") or record['COMMAND_LINE'].contains("Remove-Service")) and (record['COMMAND_LINE'].contains("McAfeeDLPAgentService") or record['COMMAND_LINE'].contains("Trend Micro Deep Security Manager") or record['COMMAND_LINE'].contains("TMBMServer") or record['COMMAND_LINE'].contains("Sophos") or record['COMMAND_LINE'].contains("Symantec")))

sigma_stop_or_remove_antivirus_service.sigma_meta = dict(
    level="high"
)

def sigma_finger_exe_suspicious_invocation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_finger_usage.yml
    title: Finger.exe Suspicious Invocation
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects suspicious aged finger.exe tool execution often used in malware attacks nowadays
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "finger.exe" or record['PROCESS_NAME'].endswith("\\finger.exe"))

sigma_finger_exe_suspicious_invocation.sigma_meta = dict(
    level="high"
)

def sigma_wusa_extracting_cab_files(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wusa_susp_cab_extraction.yml
    title: Wusa Extracting Cab Files
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of the "wusa.exe" (Windows Update Standalone Installer) utility to extract cab using the "/extract" argument which is not longer supported. This could indicate an attacker using an old technique
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wusa.exe") and record['COMMAND_LINE'].contains("/extract:"))

sigma_wusa_extracting_cab_files.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_system_user_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_system_user_anomaly.yml
    title: Suspicious SYSTEM User Process Creation
    fields: ['IntegrityLevel', 'CommandLine', 'Image', 'ParentImage', 'User', 'ParentCommandLine']
    level: high
    description: Detects a suspicious process creation as SYSTEM user (suspicious program or command line parameter)
    logsource: category:process_creation - product:windows
    """
    return (((record['INTEGRITY_LEVEL'] == "System" and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))) and ((record['PROCESS_NAME'].endswith("\\calc.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\ping.exe")) or (record['COMMAND_LINE'].contains("-NoP") or record['COMMAND_LINE'].contains("-W Hidden") or record['COMMAND_LINE'].contains("-decode") or record['COMMAND_LINE'].contains("/decode") or record['COMMAND_LINE'].contains("/urlcache") or record['COMMAND_LINE'].contains("-urlcache") or record['COMMAND_LINE'].contains("-e* JAB") or record['COMMAND_LINE'].contains("-e* SUVYI") or record['COMMAND_LINE'].contains("-e* SQBFAFgA") or record['COMMAND_LINE'].contains("-e* aWV4I") or record['COMMAND_LINE'].contains("-e* IAB") or record['COMMAND_LINE'].contains("-e* PAA") or record['COMMAND_LINE'].contains("-e* aQBlAHgA") or record['COMMAND_LINE'].contains("vssadmin delete shadows") or record['COMMAND_LINE'].contains("reg SAVE HKLM") or record['COMMAND_LINE'].contains("-ma") or record['COMMAND_LINE'].contains("Microsoft\\Windows\\CurrentVersion\\Run") or record['COMMAND_LINE'].contains(".downloadstring(") or record['COMMAND_LINE'].contains(".downloadfile(") or record['COMMAND_LINE'].contains("/ticket:") or record['COMMAND_LINE'].contains("dpapi::") or record['COMMAND_LINE'].contains("event::clear") or record['COMMAND_LINE'].contains("event::drop") or record['COMMAND_LINE'].contains("id::modify") or record['COMMAND_LINE'].contains("kerberos::") or record['COMMAND_LINE'].contains("lsadump::") or record['COMMAND_LINE'].contains("misc::") or record['COMMAND_LINE'].contains("privilege::") or record['COMMAND_LINE'].contains("rpc::") or record['COMMAND_LINE'].contains("sekurlsa::") or record['COMMAND_LINE'].contains("sid::") or record['COMMAND_LINE'].contains("token::") or record['COMMAND_LINE'].contains("vault::cred") or record['COMMAND_LINE'].contains("vault::list") or record['COMMAND_LINE'].contains("p::d") or record['COMMAND_LINE'].contains(";iex(") or record['COMMAND_LINE'].contains("MiniDump") or record['COMMAND_LINE'].contains("net user")))) and not ((record['COMMAND_LINE'] == "ping 127.0.0.1 -n 5") or (record['PROCESS_NAME'].endswith("\\PING.EXE") and record['PARENT_COMMAND_LINE'].contains("\\DismFoDInstall.cmd")) or (record['PARENT_NAME'].startswith("C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows"))))

sigma_suspicious_system_user_process_creation.sigma_meta = dict(
    level="high"
)

def sigma_new_kernel_driver_via_sc_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_new_kernel_driver_via_sc.yml
    title: New Kernel Driver Via SC.EXE
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects creation of a new service (kernel driver) with the type "kernel"
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sc.exe") and (record['COMMAND_LINE'].contains("create") or record['COMMAND_LINE'].contains("config")) and record['COMMAND_LINE'].contains("binPath") and record['COMMAND_LINE'].contains("type") and record['COMMAND_LINE'].contains("kernel"))

sigma_new_kernel_driver_via_sc_exe.sigma_meta = dict(
    level="medium"
)

def sigma_qbot_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_qbot.yml
    title: QBot Process Creation
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detects QBot like process executions
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\WinRAR.exe") and record['PROCESS_NAME'].endswith("\\wscript.exe")) or record['COMMAND_LINE'].contains("/c ping.exe -n 6 127.0.0.1 & type") or (record['COMMAND_LINE'].contains("regsvr32.exe") and record['COMMAND_LINE'].contains("C:\\ProgramData") and record['COMMAND_LINE'].contains(".tmp")))

sigma_qbot_process_creation.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_plink_port_forwarding(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_plink_port_forward.yml
    title: Suspicious Plink Port Forwarding
    fields: ['CommandLine', 'Description']
    level: high
    description: Detects suspicious Plink tunnel port forwarding to a local port
    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "Command-line SSH, Telnet, and Rlogin client" and record['COMMAND_LINE'].contains("-R"))

sigma_suspicious_plink_port_forwarding.sigma_meta = dict(
    level="high"
)

def sigma_rdrleakdiag_process_dump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proc_dump_rdrleakdiag.yml
    title: RdrLeakDiag Process Dump
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects uses of the rdrleakdiag.exe LOLOBIN utility to dump process memory
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rdrleakdiag.exe") and record['COMMAND_LINE'].contains("/fullmemdmp")) or (record['COMMAND_LINE'].contains("/fullmemdmp") and record['COMMAND_LINE'].contains("/o") and record['COMMAND_LINE'].contains("/p")))

sigma_rdrleakdiag_process_dump.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_use_of_psloglist(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psloglist.yml
    title: Suspicious Use of PsLogList
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Threat actors can use the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery.
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "psloglist.exe" or (record['PROCESS_NAME'].endswith("\\psloglist.exe") or record['PROCESS_NAME'].endswith("\\psloglist64.exe"))) or (record['COMMAND_LINE'].contains("security") and record['COMMAND_LINE'].contains("accepteula") and (record['COMMAND_LINE'].contains("-d") or record['COMMAND_LINE'].contains("/d") or record['COMMAND_LINE'].contains("-x") or record['COMMAND_LINE'].contains("/x") or record['COMMAND_LINE'].contains("-s") or record['COMMAND_LINE'].contains("/s"))))

sigma_suspicious_use_of_psloglist.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_forfiles_for_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_forfiles.yml
    title: Use of Forfiles For Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Execute commands and binaries from the context of "forfiles". This is used as a LOLBIN for example to bypass application whitelisting.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['ORIGINAL_FILE_NAME'] == "forfiles.exe") and (record['COMMAND_LINE'].contains("/p") or record['COMMAND_LINE'].contains("-p")) and (record['COMMAND_LINE'].contains("/m") or record['COMMAND_LINE'].contains("-m")) and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("-c")))

sigma_use_of_forfiles_for_execution.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_advancedrun_runas_priv_user(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_advancedrun_priv_user.yml
    title: Suspicious AdvancedRun Runas Priv User
    fields: ['CommandLine']
    level: high
    description: Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("/EXEFilename") or record['COMMAND_LINE'].contains("/CommandLine")) and ((record['COMMAND_LINE'].contains("/RunAs 8") or record['COMMAND_LINE'].contains("/RunAs 4") or record['COMMAND_LINE'].contains("/RunAs 10") or record['COMMAND_LINE'].contains("/RunAs 11")) or (record['COMMAND_LINE'].endswith("/RunAs 8") or record['COMMAND_LINE'].endswith("/RunAs 4") or record['COMMAND_LINE'].endswith("/RunAs 10") or record['COMMAND_LINE'].endswith("/RunAs 11"))))

sigma_suspicious_advancedrun_runas_priv_user.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_obfuscated_powershell_code(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ps_encoded_obfusc.yml
    title: Suspicious PowerShell Obfuscated PowerShell Code
    fields: ['CommandLine']
    level: high
    description: Detects suspicious UTF16 and base64 encoded and often obfuscated PowerShell code often used in command lines
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("IAAtAGIAeABvAHIAIAAwAHgA") or record['COMMAND_LINE'].contains("AALQBiAHgAbwByACAAMAB4A") or record['COMMAND_LINE'].contains("gAC0AYgB4AG8AcgAgADAAeA") or record['COMMAND_LINE'].contains("AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg") or record['COMMAND_LINE'].contains("AuAEkAbgB2AG8AawBlACgAKQAgAHwAI") or record['COMMAND_LINE'].contains("ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC") or record['COMMAND_LINE'].contains("AHsAMQB9AHsAMAB9ACIAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADEAfQB7ADAAfQAiACAALQBmAC") or record['COMMAND_LINE'].contains("AewAxAH0AewAwAH0AIgAgAC0AZgAg") or record['COMMAND_LINE'].contains("AHsAMAB9AHsAMwB9ACIAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADAAfQB7ADMAfQAiACAALQBmAC") or record['COMMAND_LINE'].contains("AewAwAH0AewAzAH0AIgAgAC0AZgAg") or record['COMMAND_LINE'].contains("AHsAMgB9AHsAMAB9ACIAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADIAfQB7ADAAfQAiACAALQBmAC") or record['COMMAND_LINE'].contains("AewAyAH0AewAwAH0AIgAgAC0AZgAg") or record['COMMAND_LINE'].contains("AHsAMQB9AHsAMAB9ACcAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADEAfQB7ADAAfQAnACAALQBmAC") or record['COMMAND_LINE'].contains("AewAxAH0AewAwAH0AJwAgAC0AZgAg") or record['COMMAND_LINE'].contains("AHsAMAB9AHsAMwB9ACcAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADAAfQB7ADMAfQAnACAALQBmAC") or record['COMMAND_LINE'].contains("AewAwAH0AewAzAH0AJwAgAC0AZgAg") or record['COMMAND_LINE'].contains("AHsAMgB9AHsAMAB9ACcAIAAtAGYAI") or record['COMMAND_LINE'].contains("B7ADIAfQB7ADAAfQAnACAALQBmAC") or record['COMMAND_LINE'].contains("AewAyAH0AewAwAH0AJwAgAC0AZgAg"))

sigma_suspicious_powershell_obfuscated_powershell_code.sigma_meta = dict(
    level="high"
)

def sigma_xordump_use(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_xordump.yml
    title: XORDump Use
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious use of XORDump process memory dumping utility
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\xordump.exe") or (record['COMMAND_LINE'].contains("-process lsass.exe") or record['COMMAND_LINE'].contains("-m comsvcs") or record['COMMAND_LINE'].contains("-m dbghelp") or record['COMMAND_LINE'].contains("-m dbgcore")))

sigma_xordump_use.sigma_meta = dict(
    level="high"
)

def sigma_mercury_command_line_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_mercury.yml
    title: MERCURY Command Line Patterns
    fields: ['CommandLine']
    level: high
    description: Detects suspicious command line patterns as seen being used by MERCURY threat actor
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-exec bypass -w 1 -enc") and record['COMMAND_LINE'].contains("UwB0AGEAcgB0AC0ASgBvAGIAIAAtAFMAYwByAGkAcAB0AEIAbABvAGMAaw"))

sigma_mercury_command_line_patterns.sigma_meta = dict(
    level="high"
)

def sigma_infdefaultinstall_exe_inf_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_infdefaultinstall.yml
    title: InfDefaultInstall.exe .inf Execution
    fields: ['CommandLine']
    level: medium
    description: Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("InfDefaultInstall.exe") and record['COMMAND_LINE'].contains(".inf"))

sigma_infdefaultinstall_exe_inf_execution.sigma_meta = dict(
    level="medium"
)

def sigma_domain_trust_discovery(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_trust_discovery.yml
    title: Domain Trust Discovery
    fields: ['CommandLine', 'Image']
    level: medium
    description: Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\nltest.exe") and (record['COMMAND_LINE'].contains("domain_trusts") or record['COMMAND_LINE'].contains("all_trusts") or record['COMMAND_LINE'].contains("/trusted_domains") or record['COMMAND_LINE'].contains("/dclist"))) or (record['PROCESS_NAME'].endswith("\\dsquery.exe") and record['COMMAND_LINE'].contains("trustedDomain")) or (record['PROCESS_NAME'].endswith("\\dsquery.exe") and record['COMMAND_LINE'].contains("-filter") and record['COMMAND_LINE'].contains("trustedDomain")))

sigma_domain_trust_discovery.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_rundll32_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_activity.yml
    title: Suspicious Rundll32 Activity
    fields: ['CommandLine', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects suspicious process related to rundll32 based on arguments
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("javascript:") and record['COMMAND_LINE'].contains(".RegisterXLL")) or (record['COMMAND_LINE'].contains("url.dll") and record['COMMAND_LINE'].contains("OpenURL")) or (record['COMMAND_LINE'].contains("url.dll") and record['COMMAND_LINE'].contains("OpenURLA")) or (record['COMMAND_LINE'].contains("url.dll") and record['COMMAND_LINE'].contains("FileProtocolHandler")) or (record['COMMAND_LINE'].contains("zipfldr.dll") and record['COMMAND_LINE'].contains("RouteTheCall")) or (record['COMMAND_LINE'].contains("shell32.dll") and record['COMMAND_LINE'].contains("Control_RunDLL")) or (record['COMMAND_LINE'].contains("shell32.dll") and record['COMMAND_LINE'].contains("ShellExec_RunDLL")) or (record['COMMAND_LINE'].contains("mshtml.dll") and record['COMMAND_LINE'].contains("PrintHTML")) or (record['COMMAND_LINE'].contains("advpack.dll") and record['COMMAND_LINE'].contains("LaunchINFSection")) or (record['COMMAND_LINE'].contains("advpack.dll") and record['COMMAND_LINE'].contains("RegisterOCX")) or (record['COMMAND_LINE'].contains("ieadvpack.dll") and record['COMMAND_LINE'].contains("LaunchINFSection")) or (record['COMMAND_LINE'].contains("ieadvpack.dll") and record['COMMAND_LINE'].contains("RegisterOCX")) or (record['COMMAND_LINE'].contains("ieframe.dll") and record['COMMAND_LINE'].contains("OpenURL")) or (record['COMMAND_LINE'].contains("shdocvw.dll") and record['COMMAND_LINE'].contains("OpenURL")) or (record['COMMAND_LINE'].contains("syssetup.dll") and record['COMMAND_LINE'].contains("SetupInfObjectInstallAction")) or (record['COMMAND_LINE'].contains("setupapi.dll") and record['COMMAND_LINE'].contains("InstallHinfSection")) or (record['COMMAND_LINE'].contains("pcwutl.dll") and record['COMMAND_LINE'].contains("LaunchApplication")) or (record['COMMAND_LINE'].contains("dfshim.dll") and record['COMMAND_LINE'].contains("ShOpenVerbApplication")) or (record['COMMAND_LINE'].contains("dfshim.dll") and record['COMMAND_LINE'].contains("ShOpenVerbShortcut")) or (record['COMMAND_LINE'].contains("scrobj.dll") and record['COMMAND_LINE'].contains("GenerateTypeLib") and record['COMMAND_LINE'].contains("http")) or (record['COMMAND_LINE'].contains("shimgvw.dll") and record['COMMAND_LINE'].contains("ImageView_Fullscreen") and record['COMMAND_LINE'].contains("http"))) and not ((record['COMMAND_LINE'].contains("shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver")) or (record['PARENT_NAME'] == "C:\\Windows\\System32\\control.exe" and record['PARENT_COMMAND_LINE'].contains(".cpl")) or (record['PARENT_NAME'] == "C:\\Windows\\System32\\control.exe" and record['COMMAND_LINE'].startswith("\"C:\\Windows\\system32\\rundll32.exe\" Shell32.dll,Control_RunDLL \"C:\\Windows\\System32") and record['COMMAND_LINE'].endswith(".cpl\","))))

sigma_suspicious_rundll32_activity.sigma_meta = dict(
    level="medium"
)

def sigma_regsvr32_command_line_without_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_no_dll.yml
    title: Regsvr32 Command Line Without DLL
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a regsvr.exe execution that doesn't contain a DLL in the command line
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\regsvr32.exe") and not ((record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".ocx") or record['COMMAND_LINE'].contains(".cpl") or record['COMMAND_LINE'].contains(".ax") or record['COMMAND_LINE'].contains(".bav") or record['COMMAND_LINE'].contains(".ppl")))) and not (record.get('COMMAND_LINE', None) == None)) and not (record['COMMAND_LINE'] == ""))

sigma_regsvr32_command_line_without_dll.sigma_meta = dict(
    level="high"
)

def sigma_copy_from_admin_share(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml
    title: Copy from Admin Share
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a suspicious copy command to or from an Admin share or remote
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("") and record['COMMAND_LINE'].contains("$")) and (((record['PROCESS_NAME'].endswith("\\robocopy.exe") or record['PROCESS_NAME'].endswith("\\xcopy.exe")) or ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['ORIGINAL_FILE_NAME'] == "Cmd.Exe") and record['COMMAND_LINE'].contains("copy"))) or (((record['PROCESS_NAME'].contains("\\powershell.exe") or record['PROCESS_NAME'].contains("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll")) and (record['COMMAND_LINE'].contains("copy-item") or record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("cpi") or record['COMMAND_LINE'].contains("cp") or record['COMMAND_LINE'].contains("move") or record['COMMAND_LINE'].contains("move-item") or record['COMMAND_LINE'].contains("mi") or record['COMMAND_LINE'].contains("mv")))))

sigma_copy_from_admin_share.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_execution_of_hostname(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_hostname.yml
    title: Suspicious Execution of Hostname
    fields: ['Image']
    level: low
    description: Use of hostname to get information
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\HOSTNAME.EXE")

sigma_suspicious_execution_of_hostname.sigma_meta = dict(
    level="low"
)

def sigma_printbrm_zip_creation_of_extraction(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_printbrm.yml
    title: PrintBrm ZIP Creation of Extraction
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\PrintBrm.exe") and record['COMMAND_LINE'].contains("-f") and record['COMMAND_LINE'].contains(".zip"))

sigma_printbrm_zip_creation_of_extraction.sigma_meta = dict(
    level="high"
)

def sigma_devicecredentialdeployment_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_device_credential_deployment.yml
    title: DeviceCredentialDeployment Execution
    fields: ['Image']
    level: medium
    description: Detects the execution of DeviceCredentialDeployment to hide a process from view
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\DeviceCredentialDeployment.exe")

sigma_devicecredentialdeployment_execution.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_megasync(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_megasync.yml
    title: Renamed MegaSync
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects the execution of a renamed meg.exe of MegaSync during incident response engagements associated with ransomware families like Nefilim, Sodinokibi, Pysa, and Conti.
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\explorer.exe") and record['COMMAND_LINE'].contains("C:\\Windows\\Temp\\meg.exe")) or (record['ORIGINAL_FILE_NAME'] == "meg.exe" and not (record['PROCESS_NAME'].endswith("\\meg.exe"))))

sigma_renamed_megasync.sigma_meta = dict(
    level="high"
)

def sigma_nslookup_powershell_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_nslookup_poweshell_download.yml
    title: Nslookup PowerShell Download
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects usage of powershell in conjunction with nslookup as a mean of download.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("powershell .") and record['COMMAND_LINE'].contains("nslookup") and record['COMMAND_LINE'].contains("-q=txt")) or (record['PARENT_NAME'].endswith("\\powershell.exe") and record['PROCESS_NAME'].contains("\\nslookup.exe") and (record['COMMAND_LINE'].contains("-q=txt") or record['COMMAND_LINE'].contains("-querytype=txt"))))

sigma_nslookup_powershell_download.sigma_meta = dict(
    level="high"
)

def sigma_trickbot_malware_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_trickbot_wermgr.yml
    title: Trickbot Malware Activity
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects Trickbot malware process tree pattern in which rundll32.exe is parent of wermgr.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wermgr.exe") and record['PARENT_NAME'].endswith("\\rundll32.exe") and record['PARENT_COMMAND_LINE'].contains("DllRegisterServer"))

sigma_trickbot_malware_activity.sigma_meta = dict(
    level="high"
)

def sigma_covenant_launcher_indicators(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_covenant.yml
    title: Covenant Launcher Indicators
    fields: ['CommandLine']
    level: high
    description: Detects suspicious command lines used in Covenant luanchers
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-Sta") and record['COMMAND_LINE'].contains("-Nop") and record['COMMAND_LINE'].contains("-Window") and record['COMMAND_LINE'].contains("Hidden") and (record['COMMAND_LINE'].contains("-Command") or record['COMMAND_LINE'].contains("-EncodedCommand"))) or (record['COMMAND_LINE'].contains("sv o (New-Object IO.MemorySteam);sv d") or record['COMMAND_LINE'].contains("mshta file.hta") or record['COMMAND_LINE'].contains("GruntHTTP") or record['COMMAND_LINE'].contains("-EncodedCommand cwB2ACAAbwAgA")))

sigma_covenant_launcher_indicators.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msiexec_load_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msiexec_dll.yml
    title: Suspicious Msiexec Load DLL
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects MsiExec loading a DLL and calling its DllUnregisterServer function
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\msiexec.exe") and (record['COMMAND_LINE'].contains("/z") or record['COMMAND_LINE'].contains("-z")) and record['COMMAND_LINE'].contains(".dll"))

sigma_suspicious_msiexec_load_dll.sigma_meta = dict(
    level="medium"
)

def sigma_proxy_execution_via_wuauclt(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proxy_execution_wuauclt.yml
    title: Proxy Execution via Wuauclt
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].contains("wuauclt") or record['ORIGINAL_FILE_NAME'] == "wuauclt.exe") and (record['COMMAND_LINE'].contains("UpdateDeploymentProvider") and record['COMMAND_LINE'].contains(".dll") and record['COMMAND_LINE'].contains("RunHandlerComServer"))) and not ((record['COMMAND_LINE'].contains("/UpdateDeploymentProvider UpdateDeploymentProvider.dll") or record['COMMAND_LINE'].contains("wuaueng.dll"))))

sigma_proxy_execution_via_wuauclt.sigma_meta = dict(
    level="high"
)

def sigma_exploited_cve_2020_10189_zoho_manageengine(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2020_10189.yml
    title: Exploited CVE-2020-10189 Zoho ManageEngine
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects the exploitation of Zoho ManageEngine Desktop Central Java Deserialization vulnerability reported as CVE-2020-10189
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("DesktopCentral_Server\\jre\\bin\\java.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe")))

sigma_exploited_cve_2020_10189_zoho_manageengine.sigma_meta = dict(
    level="high"
)

def sigma_service_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_service_execution.yml
    title: Service Execution
    fields: ['CommandLine', 'Image']
    level: low
    description: Detects manual service execution (start) via system utilities.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("start"))

sigma_service_execution.sigma_meta = dict(
    level="low"
)

def sigma_system_file_execution_location_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_system_exe_anomaly.yml
    title: System File Execution Location Anomaly
    fields: ['Image']
    level: high
    description: Detects a Windows program executable started from a suspicious folder
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\svchost.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\services.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\spoolsv.exe") or record['PROCESS_NAME'].endswith("\\lsass.exe") or record['PROCESS_NAME'].endswith("\\smss.exe") or record['PROCESS_NAME'].endswith("\\csrss.exe") or record['PROCESS_NAME'].endswith("\\conhost.exe") or record['PROCESS_NAME'].endswith("\\wininit.exe") or record['PROCESS_NAME'].endswith("\\lsm.exe") or record['PROCESS_NAME'].endswith("\\winlogon.exe") or record['PROCESS_NAME'].endswith("\\explorer.exe") or record['PROCESS_NAME'].endswith("\\taskhost.exe") or record['PROCESS_NAME'].endswith("\\Taskmgr.exe") or record['PROCESS_NAME'].endswith("\\sihost.exe") or record['PROCESS_NAME'].endswith("\\RuntimeBroker.exe") or record['PROCESS_NAME'].endswith("\\smartscreen.exe") or record['PROCESS_NAME'].endswith("\\dllhost.exe") or record['PROCESS_NAME'].endswith("\\audiodg.exe") or record['PROCESS_NAME'].endswith("\\wlanext.exe") or record['PROCESS_NAME'].endswith("\\dashost.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\wsl.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\atbroker.exe") or record['PROCESS_NAME'].endswith("\\bcdedit.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\certreq.exe") or record['PROCESS_NAME'].endswith("\\cmstp.exe") or record['PROCESS_NAME'].endswith("\\consent.exe") or record['PROCESS_NAME'].endswith("\\defrag.exe") or record['PROCESS_NAME'].endswith("\\dism.exe") or record['PROCESS_NAME'].endswith("\\dllhst3g.exe") or record['PROCESS_NAME'].endswith("\\eventvwr.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\runonce.exe") or record['PROCESS_NAME'].endswith("\\winver.exe") or record['PROCESS_NAME'].endswith("\\logonui.exe") or record['PROCESS_NAME'].endswith("\\userinit.exe") or record['PROCESS_NAME'].endswith("\\dwm.exe") or record['PROCESS_NAME'].endswith("\\LsaIso.exe") or record['PROCESS_NAME'].endswith("\\ntoskrnl.exe") or record['PROCESS_NAME'].endswith("\\wsmprovhost.exe") or record['PROCESS_NAME'].endswith("\\dfrgui.exe")) and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64") or record['PROCESS_NAME'].startswith("C:\\Windows\\WinSxS")) or record['PROCESS_NAME'].contains("\\SystemRoot\\System32") or (record['PROCESS_NAME'] == "C:\\Windows\\explorer.exe" or record['PROCESS_NAME'] == "C:\\Program Files\\PowerShell\\7\\pwsh.exe")))

sigma_system_file_execution_location_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_command_line_execution_with_suspicious_url_and_appdata_strings(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cmd_http_appdata.yml
    title: Command Line Execution with Suspicious URL and AppData Strings
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("http") and record['COMMAND_LINE'].contains("://") and record['COMMAND_LINE'].contains("%AppData%"))

sigma_command_line_execution_with_suspicious_url_and_appdata_strings.sigma_meta = dict(
    level="medium"
)

def sigma_registry_defender_exclusions(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_defender_exclusion.yml
    title: Registry Defender Exclusions
    fields: ['CommandLine', 'Image']
    level: medium
    description: Qbot used reg.exe to add Defender folder exceptions for folders within AppData and ProgramData.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and (record['COMMAND_LINE'].contains("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths") or record['COMMAND_LINE'].contains("SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths")) and record['COMMAND_LINE'].contains("ADD") and record['COMMAND_LINE'].contains("/t") and record['COMMAND_LINE'].contains("REG_DWORD") and record['COMMAND_LINE'].contains("/v") and record['COMMAND_LINE'].contains("/d") and record['COMMAND_LINE'].contains("0"))

sigma_registry_defender_exclusions.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_installutil_without_log(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_instalutil.yml
    title: Suspicious Execution of InstallUtil Without Log
    fields: ['CommandLine', 'Image']
    level: medium
    description: Uses the .NET InstallUtil.exe application in order to execute image without log
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\InstallUtil.exe") and record['PROCESS_NAME'].contains("Microsoft.NET\\Framework") and record['COMMAND_LINE'].contains("/logfile=") and record['COMMAND_LINE'].contains("/LogToConsole=false"))

sigma_suspicious_execution_of_installutil_without_log.sigma_meta = dict(
    level="medium"
)

def sigma_psexec_paexec_escalation_to_local_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexex_paexec_escalate_system.yml
    title: PsExec/PAExec Escalation to LOCAL SYSTEM
    fields: ['CommandLine']
    level: high
    description: Detects suspicious flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-s cmd") or record['COMMAND_LINE'].contains("/s cmd") or record['COMMAND_LINE'].contains("-s -i cmd") or record['COMMAND_LINE'].contains("/s /i cmd") or record['COMMAND_LINE'].contains("/s -i cmd") or record['COMMAND_LINE'].contains("-s /i cmd") or record['COMMAND_LINE'].contains("-i -s cmd") or record['COMMAND_LINE'].contains("/i /s cmd") or record['COMMAND_LINE'].contains("-i /s cmd") or record['COMMAND_LINE'].contains("/i -s cmd") or record['COMMAND_LINE'].contains("-s pwsh") or record['COMMAND_LINE'].contains("/s pwsh") or record['COMMAND_LINE'].contains("-s -i pwsh") or record['COMMAND_LINE'].contains("/s /i pwsh") or record['COMMAND_LINE'].contains("/s -i pwsh") or record['COMMAND_LINE'].contains("-s /i pwsh") or record['COMMAND_LINE'].contains("-i -s pwsh") or record['COMMAND_LINE'].contains("/i /s pwsh") or record['COMMAND_LINE'].contains("-i /s pwsh") or record['COMMAND_LINE'].contains("/i -s pwsh") or record['COMMAND_LINE'].contains("-s powershell") or record['COMMAND_LINE'].contains("/s powershell") or record['COMMAND_LINE'].contains("-s -i powershell") or record['COMMAND_LINE'].contains("/s /i powershell") or record['COMMAND_LINE'].contains("/s -i powershell") or record['COMMAND_LINE'].contains("-s /i powershell") or record['COMMAND_LINE'].contains("-i -s powershell") or record['COMMAND_LINE'].contains("/i /s powershell") or record['COMMAND_LINE'].contains("-i /s powershell") or record['COMMAND_LINE'].contains("/i -s powershell")) and (record['COMMAND_LINE'].contains("psexec") or record['COMMAND_LINE'].contains("paexec") or record['COMMAND_LINE'].contains("accepteula") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd /r")))

sigma_psexec_paexec_escalation_to_local_system.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_shells_spawn_by_sql_server(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shell_spawn_from_mssql.yml
    title: Suspicious Shells Spawn by SQL Server
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects suspicious shell spawn from MSSQL process, this might be sight of RCE or SQL Injection
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\sqlservr.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe"))) and not ((record['PARENT_NAME'].startswith("C:\\Program Files\\Microsoft SQL Server") and record['PARENT_NAME'].endswith("DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe") and record['PROCESS_NAME'] == "C:\\Windows\\System32\\cmd.exe" and record['COMMAND_LINE'].startswith("\"C:\\Windows\\system32\\cmd.exe\""))))

sigma_suspicious_shells_spawn_by_sql_server.sigma_meta = dict(
    level="high"
)

def sigma_use_ntfs_short_name_in_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ntfs_short_name_use_cli.yml
    title: Use NTFS Short Name in Command Line
    fields: ['CommandLine', 'ParentImage']
    level: medium
    description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("~1.exe") or record['COMMAND_LINE'].contains("~1.bat") or record['COMMAND_LINE'].contains("~1.msi") or record['COMMAND_LINE'].contains("~1.vbe") or record['COMMAND_LINE'].contains("~1.vbs") or record['COMMAND_LINE'].contains("~1.dll") or record['COMMAND_LINE'].contains("~1.ps1") or record['COMMAND_LINE'].contains("~1.js") or record['COMMAND_LINE'].contains("~1.hta") or record['COMMAND_LINE'].contains("~2.exe") or record['COMMAND_LINE'].contains("~2.bat") or record['COMMAND_LINE'].contains("~2.msi") or record['COMMAND_LINE'].contains("~2.vbe") or record['COMMAND_LINE'].contains("~2.vbs") or record['COMMAND_LINE'].contains("~2.dll") or record['COMMAND_LINE'].contains("~2.ps1") or record['COMMAND_LINE'].contains("~2.js") or record['COMMAND_LINE'].contains("~2.hta")) and not ((record['PARENT_NAME'].endswith("\\WebEx\\WebexHost.exe") or record['PARENT_NAME'].endswith("\\thor\\thor64.exe")) or record['COMMAND_LINE'].contains("C:\\xampp\\vcredist\\VCREDI~1.EXE")))

sigma_use_ntfs_short_name_in_command_line.sigma_meta = dict(
    level="medium"
)

def sigma_runxcmd_tool_execution_as_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tool_runx_as_system.yml
    title: RunXCmd Tool Execution As System
    fields: ['CommandLine']
    level: high
    description: Detects the use of RunXCmd tool for command execution
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/account=system") and record['COMMAND_LINE'].contains("/exec="))

sigma_runxcmd_tool_execution_as_system.sigma_meta = dict(
    level="high"
)

def sigma_format_com_filesystem_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_format.yml
    title: Format.com FileSystem LOLBIN
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the execution of format.com with a suspicious filesystem selection that could indicate a defense evasion activity in which format.com is used to load malicious DLL files or other programs
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\format.com") and record['COMMAND_LINE'].contains("/fs:")) and not (((record['COMMAND_LINE'].contains("/fs:FAT") or record['COMMAND_LINE'].contains("/fs:exFAT") or record['COMMAND_LINE'].contains("/fs:NTFS") or record['COMMAND_LINE'].contains("/fs:UDF") or record['COMMAND_LINE'].contains("/fs:ReFS")))))

sigma_format_com_filesystem_lolbin.sigma_meta = dict(
    level="high"
)

def sigma_use_of_adplus_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_adplus.yml
    title: Use of Adplus.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: The "AdPlus.exe" binary that is part of the Windows SDK can be used as a lolbin to dump process memory and execute arbitrary commands
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\adplus.exe") or record['ORIGINAL_FILE_NAME'] == "Adplus.exe") and (record['COMMAND_LINE'].contains("-hang") or record['COMMAND_LINE'].contains("-pn") or record['COMMAND_LINE'].contains("-pmn") or record['COMMAND_LINE'].contains("-p") or record['COMMAND_LINE'].contains("-po") or record['COMMAND_LINE'].contains("-c") or record['COMMAND_LINE'].contains("-sc")))

sigma_use_of_adplus_exe.sigma_meta = dict(
    level="medium"
)

def sigma_maze_ransomware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_crime_maze_ransomware.yml
    title: Maze Ransomware
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detects specific process characteristics of Maze ransomware word document droppers
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\WINWORD.exe") and record['PROCESS_NAME'].endswith(".tmp")) or (record['PROCESS_NAME'].endswith("\\wmic.exe") and record['PARENT_NAME'].contains("\\Temp") and record['COMMAND_LINE'].endswith("shadowcopy delete")) or (record['COMMAND_LINE'].endswith("shadowcopy delete") and record['COMMAND_LINE'].contains("\\..\\..\\system32")))

sigma_maze_ransomware.sigma_meta = dict(
    level="critical"
)

def sigma_jsc_convert_javascript_to_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_jsc.yml
    title: JSC Convert Javascript To Executable
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the execution of the LOLBIN jsc.exe used by .NET to compile javascript code to .exe or .dll format
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\jsc.exe") and record['COMMAND_LINE'].contains(".js"))

sigma_jsc_convert_javascript_to_executable.sigma_meta = dict(
    level="medium"
)

def sigma_impacket_tool_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_impacket_compiled_tools.yml
    title: Impacket Tool Execution
    fields: ['Image']
    level: high
    description: Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\goldenPac") or record['PROCESS_NAME'].contains("\\karmaSMB") or record['PROCESS_NAME'].contains("\\kintercept") or record['PROCESS_NAME'].contains("\\ntlmrelayx") or record['PROCESS_NAME'].contains("\\rpcdump") or record['PROCESS_NAME'].contains("\\samrdump") or record['PROCESS_NAME'].contains("\\secretsdump") or record['PROCESS_NAME'].contains("\\smbexec") or record['PROCESS_NAME'].contains("\\smbrelayx") or record['PROCESS_NAME'].contains("\\wmiexec") or record['PROCESS_NAME'].contains("\\wmipersist")) or (record['PROCESS_NAME'].endswith("\\atexec_windows.exe") or record['PROCESS_NAME'].endswith("\\dcomexec_windows.exe") or record['PROCESS_NAME'].endswith("\\dpapi_windows.exe") or record['PROCESS_NAME'].endswith("\\findDelegation_windows.exe") or record['PROCESS_NAME'].endswith("\\GetADUsers_windows.exe") or record['PROCESS_NAME'].endswith("\\GetNPUsers_windows.exe") or record['PROCESS_NAME'].endswith("\\getPac_windows.exe") or record['PROCESS_NAME'].endswith("\\getST_windows.exe") or record['PROCESS_NAME'].endswith("\\getTGT_windows.exe") or record['PROCESS_NAME'].endswith("\\GetUserSPNs_windows.exe") or record['PROCESS_NAME'].endswith("\\ifmap_windows.exe") or record['PROCESS_NAME'].endswith("\\mimikatz_windows.exe") or record['PROCESS_NAME'].endswith("\\netview_windows.exe") or record['PROCESS_NAME'].endswith("\\nmapAnswerMachine_windows.exe") or record['PROCESS_NAME'].endswith("\\opdump_windows.exe") or record['PROCESS_NAME'].endswith("\\psexec_windows.exe") or record['PROCESS_NAME'].endswith("\\rdp_check_windows.exe") or record['PROCESS_NAME'].endswith("\\sambaPipe_windows.exe") or record['PROCESS_NAME'].endswith("\\smbclient_windows.exe") or record['PROCESS_NAME'].endswith("\\smbserver_windows.exe") or record['PROCESS_NAME'].endswith("\\sniffer_windows.exe") or record['PROCESS_NAME'].endswith("\\sniff_windows.exe") or record['PROCESS_NAME'].endswith("\\split_windows.exe") or record['PROCESS_NAME'].endswith("\\ticketer_windows.exe")))

sigma_impacket_tool_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_diantz_alternate_data_stream_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_diantz_ads.yml
    title: Suspicious Diantz Alternate Data Stream Execution
    fields: ['CommandLine']
    level: medium
    description: Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("diantz.exe") and record['COMMAND_LINE'].contains(".cab") and re.match(':[^\\\\]', record['COMMAND_LINE']))

sigma_suspicious_diantz_alternate_data_stream_execution.sigma_meta = dict(
    level="medium"
)

def sigma_netsh_firewall_rule_deletion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_fw_delete.yml
    title: Netsh Firewall Rule Deletion
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("delete")) and not (record['PARENT_NAME'].endswith("\\Dropbox.exe") and record['COMMAND_LINE'].contains("name=Dropbox")))

sigma_netsh_firewall_rule_deletion.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_sysinternals_sdelete_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_sdelete.yml
    title: Renamed Sysinternals Sdelete Usage
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects the use of a renamed SysInternals Sdelete, which is something an administrator shouldn't do (the renaming)
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "sdelete.exe" and not ((record['PROCESS_NAME'].endswith("\\sdelete.exe") or record['PROCESS_NAME'].endswith("\\sdelete64.exe"))))

sigma_renamed_sysinternals_sdelete_usage.sigma_meta = dict(
    level="high"
)

def sigma_powershell_chromeloader_browser_hijacker(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_chrome_load_extension.yml
    title: Powershell ChromeLoader Browser Hijacker
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects PowerShell process spawning a 'chrome.exe' process with the 'load-extension' flag to start a new chrome instance with custom extensions, as seen being used in 'ChromeLoader'
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\chrome.exe") and (record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("--load-extension=") and record['COMMAND_LINE'].contains("\\AppData\\Local"))

sigma_powershell_chromeloader_browser_hijacker.sigma_meta = dict(
    level="high"
)

def sigma_net_exe_user_account_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_user_add.yml
    title: Net.exe User Account Creation
    fields: ['CommandLine', 'Image']
    level: medium
    description: Identifies creation of local users via the net.exe command.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("user") and record['COMMAND_LINE'].contains("add"))

sigma_net_exe_user_account_creation.sigma_meta = dict(
    level="medium"
)

def sigma_download_arbitrary_files_via_msohtmed_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_msohtmed_download.yml
    title: Download Arbitrary Files Via MSOHTMED.EXE
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of "MSOHTMED" to download arbitrary files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\MSOHTMED.exe") or record['ORIGINAL_FILE_NAME'] == "MsoHtmEd.exe") and (record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_download_arbitrary_files_via_msohtmed_exe.sigma_meta = dict(
    level="medium"
)

def sigma_ryuk_ransomware_command_line_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_ryuk.yml
    title: Ryuk Ransomware Command Line Activity
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects Ryuk Ransomware command lines
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("stop") and (record['COMMAND_LINE'].contains("samss") or record['COMMAND_LINE'].contains("audioendpointbuilder") or record['COMMAND_LINE'].contains("unistoresvc_")))

sigma_ryuk_ransomware_command_line_activity.sigma_meta = dict(
    level="critical"
)

def sigma_run_powershell_script_from_redirected_input_stream(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_run_powershell_script_from_input_stream.yml
    title: Run PowerShell Script from Redirected Input Stream
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects PowerShell script execution via input stream redirect
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('\s-\s*<', record['COMMAND_LINE']))

sigma_run_powershell_script_from_redirected_input_stream.sigma_meta = dict(
    level="high"
)

def sigma_mustang_panda_dropper(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_mustangpanda.yml
    title: Mustang Panda Dropper
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects specific process parameters as used by Mustang Panda droppers
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Temp\\wtask.exe /create") or record['COMMAND_LINE'].contains("%windir:~-3,1%%PUBLIC:~-9,1%") or record['COMMAND_LINE'].contains("/tn \"Security Script") or record['COMMAND_LINE'].contains("%windir:~-1,1%")) or (record['COMMAND_LINE'].contains("/E:vbscript") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains(".txt") and record['COMMAND_LINE'].contains("/F")) or record['PROCESS_NAME'].endswith("Temp\\winwsh.exe"))

sigma_mustang_panda_dropper.sigma_meta = dict(
    level="high"
)

def sigma_execution_of_renamed_remote_utilities_rat_rurat_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_rurat.yml
    title: Execution of Renamed Remote Utilities RAT (RURAT)
    fields: ['Image', 'Product']
    level: medium
    description: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
    logsource: category:process_creation - product:windows
    """
    return (record['PRODUCT_NAME'] == "Remote Utilities" and not ((record['PROCESS_NAME'].endswith("\\rutserv.exe") or record['PROCESS_NAME'].endswith("\\rfusclient.exe"))))

sigma_execution_of_renamed_remote_utilities_rat_rurat_.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_vbscript_un2452_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_vbscript_unc2452.yml
    title: Suspicious VBScript UN2452 Pattern
    fields: ['CommandLine']
    level: high
    description: Detects suspicious inline VBScript keywords as used by UNC2452
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Execute") and record['COMMAND_LINE'].contains("CreateObject") and record['COMMAND_LINE'].contains("RegRead") and record['COMMAND_LINE'].contains("window.close") and record['COMMAND_LINE'].contains("\\Microsoft\\Windows\\CurrentVersion")) and not (record['COMMAND_LINE'].contains("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")))

sigma_suspicious_vbscript_un2452_pattern.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_schtasks_schedule_types(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_schedule_type.yml
    title: Suspicious Schtasks Schedule Types
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects scheduled task creations or modification on a suspicious schedule type
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['ORIGINAL_FILE_NAME'] == "schtasks.exe") and (record['COMMAND_LINE'].contains("ONLOGON") or record['COMMAND_LINE'].contains("ONSTART") or record['COMMAND_LINE'].contains("ONCE") or record['COMMAND_LINE'].contains("ONIDLE"))) and not (((record['COMMAND_LINE'].contains("NT AUT") or record['COMMAND_LINE'].contains("SYSTEM") or record['COMMAND_LINE'].contains("HIGHEST")))))

sigma_suspicious_schtasks_schedule_types.sigma_meta = dict(
    level="high"
)

def sigma_script_interpreter_execution_from_suspicious_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_script_exec_from_env_folder.yml
    title: Script Interpreter Execution From Suspicious Folder
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a suspicious script executions in temporary folders or folders accessible by environment variables
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe")) or (record['COMMAND_LINE'].contains("-w hidden") or record['COMMAND_LINE'].contains("-ep bypass") or record['COMMAND_LINE'].contains("/e:vbscript") or record['COMMAND_LINE'].contains("/e:javascript")) or (record['ORIGINAL_FILE_NAME'] == "powershell.exe" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "mshta.exe" or record['ORIGINAL_FILE_NAME'] == "wscript.exe" or record['ORIGINAL_FILE_NAME'] == "cscript.exe" or record['ORIGINAL_FILE_NAME'] == "cmd.exe")) and (record['PROCESS_NAME'].contains("\\Windows\\Temp") or record['PROCESS_NAME'].contains("\\Temporary Internet") or record['PROCESS_NAME'].contains("\\AppData\\Local\\Temp") or record['PROCESS_NAME'].contains("\\AppData\\Roaming\\Temp") or record['PROCESS_NAME'].contains("C:\\Users\\Public") or record['PROCESS_NAME'].contains("C:\\Perflogs")))

sigma_script_interpreter_execution_from_suspicious_folder.sigma_meta = dict(
    level="high"
)

def sigma_jlaive_usage_for_assembly_execution_in_memory(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_jlaive_batch_execution.yml
    title: Jlaive Usage For Assembly Execution In-Memory
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: Detect the use of Jlaive to execute assemblies in a copied PowerShell
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\cmd.exe") and record['PARENT_COMMAND_LINE'].endswith(".bat")) and ((record['PROCESS_NAME'].endswith("\\xcopy.exe") and record['COMMAND_LINE'].contains("powershell.exe") and record['COMMAND_LINE'].contains(".bat.exe")) or (record['PROCESS_NAME'].endswith("\\xcopy.exe") and record['COMMAND_LINE'].contains("pwsh.exe") and record['COMMAND_LINE'].contains(".bat.exe")) or (record['PROCESS_NAME'].endswith("\\attrib.exe") and record['COMMAND_LINE'].contains("+s") and record['COMMAND_LINE'].contains("+h") and record['COMMAND_LINE'].contains(".bat.exe"))))

sigma_jlaive_usage_for_assembly_execution_in_memory.sigma_meta = dict(
    level="medium"
)

def sigma_microsoft_office_product_spawning_windows_shell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_shell.yml
    title: Microsoft Office Product Spawning Windows Shell
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a Windows command and scripting interpreter executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\WINWORD.EXE") or record['PARENT_NAME'].endswith("\\EXCEL.EXE") or record['PARENT_NAME'].endswith("\\POWERPNT.exe") or record['PARENT_NAME'].endswith("\\MSPUB.exe") or record['PARENT_NAME'].endswith("\\VISIO.exe") or record['PARENT_NAME'].endswith("\\MSACCESS.EXE") or record['PARENT_NAME'].endswith("\\EQNEDT32.EXE")) and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\scrcons.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\mftrace.exe") or record['PROCESS_NAME'].endswith("\\AppVLP.exe") or record['PROCESS_NAME'].endswith("\\svchost.exe") or record['PROCESS_NAME'].endswith("\\msbuild.exe")))

sigma_microsoft_office_product_spawning_windows_shell.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_program_names(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_progname.yml
    title: Suspicious Program Names
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious patterns in program names or folders that are often found in malicious samples or hacktools
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].contains("\\CVE-202") or (record['PROCESS_NAME'].endswith("\\poc.exe") or record['PROCESS_NAME'].endswith("\\artifact.exe") or record['PROCESS_NAME'].endswith("\\artifact64.exe") or record['PROCESS_NAME'].endswith("\\artifact_protected.exe") or record['PROCESS_NAME'].endswith("\\artifact32.exe") or record['PROCESS_NAME'].endswith("\\artifact32big.exe") or record['PROCESS_NAME'].endswith("obfuscated.exe") or record['PROCESS_NAME'].endswith("obfusc.exe") or record['PROCESS_NAME'].endswith("\\meterpreter")) or (record['COMMAND_LINE'].contains("inject.ps1") or record['COMMAND_LINE'].contains("Invoke-CVE") or record['COMMAND_LINE'].contains("pupy.ps1") or record['COMMAND_LINE'].contains("payload.ps1") or record['COMMAND_LINE'].contains("beacon.ps1") or record['COMMAND_LINE'].contains("PowerView.ps1") or record['COMMAND_LINE'].contains("bypass.ps1") or record['COMMAND_LINE'].contains("obfuscated.ps1") or record['COMMAND_LINE'].contains("obfusc.ps1") or record['COMMAND_LINE'].contains("obfus.ps1") or record['COMMAND_LINE'].contains("obfs.ps1") or record['COMMAND_LINE'].contains("evil.ps1") or record['COMMAND_LINE'].contains("MiniDogz.ps1") or record['COMMAND_LINE'].contains("_enc.ps1") or record['COMMAND_LINE'].contains("\\shell.ps1") or record['COMMAND_LINE'].contains("\\rshell.ps1") or record['COMMAND_LINE'].contains("revshell.ps1") or record['COMMAND_LINE'].contains("\\av.ps1") or record['COMMAND_LINE'].contains("\\av_test.ps1") or record['COMMAND_LINE'].contains("adrecon.ps1") or record['COMMAND_LINE'].contains("mimikatz.ps1") or record['COMMAND_LINE'].contains("\\PowerUp_") or record['COMMAND_LINE'].contains("powerup.ps1") or record['COMMAND_LINE'].contains("\\Temp\\a.ps1") or record['COMMAND_LINE'].contains("\\Temp\\p.ps1") or record['COMMAND_LINE'].contains("\\Temp\\1.ps1") or record['COMMAND_LINE'].contains("Hound.ps1") or record['COMMAND_LINE'].contains("encode.ps1") or record['COMMAND_LINE'].contains("powercat.ps1")))

sigma_suspicious_program_names.sigma_meta = dict(
    level="high"
)

def sigma_greenbug_campaign_indicators(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_greenbug_may20.yml
    title: Greenbug Campaign Indicators
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects tools and process executions as observed in a Greenbug campaign in May 2020
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("bitsadmin") and record['COMMAND_LINE'].contains("/transfer") and record['COMMAND_LINE'].contains("CSIDL_APPDATA")) or record['COMMAND_LINE'].contains("CSIDL_SYSTEM_DRIVE") or (record['COMMAND_LINE'].contains("\\msf.ps1") or record['COMMAND_LINE'].contains("8989 -e cmd.exe") or record['COMMAND_LINE'].contains("system.Data.SqlClient.SqlDataAdapter($cmd); [void]$da.fill") or record['COMMAND_LINE'].contains("-nop -w hidden -c $k=new-object") or record['COMMAND_LINE'].contains("[Net.CredentialCache]::DefaultCredentials;IEX") or record['COMMAND_LINE'].contains("-nop -w hidden -c $m=new-object net.webclient;$m") or record['COMMAND_LINE'].contains("-noninteractive -executionpolicy bypass whoami") or record['COMMAND_LINE'].contains("-noninteractive -executionpolicy bypass netstat -a") or record['COMMAND_LINE'].contains("L3NlcnZlcj1")) or (record['PROCESS_NAME'].endswith("\\adobe\\Adobe.exe") or record['PROCESS_NAME'].endswith("\\oracle\\local.exe") or record['PROCESS_NAME'].endswith("\\revshell.exe") or record['PROCESS_NAME'].endswith("infopagesbackup\\ncat.exe") or record['PROCESS_NAME'].endswith("CSIDL_SYSTEM\\cmd.exe") or record['PROCESS_NAME'].endswith("\\programdata\\oracle\\java.exe") or record['PROCESS_NAME'].endswith("CSIDL_COMMON_APPDATA\\comms\\comms.exe") or record['PROCESS_NAME'].endswith("\\Programdata\\VMware\\Vmware.exe")))

sigma_greenbug_campaign_indicators.sigma_meta = dict(
    level="critical"
)

def sigma_wmic_service_start_stop(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_service.yml
    title: WMIC Service Start/Stop
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of wmic to start or stop a service
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['PROCESS_NAME'].endswith("\\WMIC.exe")) and (record['COMMAND_LINE'].contains("service") and record['COMMAND_LINE'].contains("call") and (record['COMMAND_LINE'].contains("stopservice") or record['COMMAND_LINE'].contains("startservice"))))

sigma_wmic_service_start_stop.sigma_meta = dict(
    level="medium"
)

def sigma_exports_registry_key_to_a_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regedit_export_keys.yml
    title: Exports Registry Key To a File
    fields: ['CommandLine', 'Image']
    level: low
    description: Detects the export of the target Registry key to a file.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regedit.exe") and (record['COMMAND_LINE'].contains("/E") or record['COMMAND_LINE'].contains("-E"))) and not (((record['COMMAND_LINE'].contains("hklm") or record['COMMAND_LINE'].contains("hkey_local_machine"))) and ((record['COMMAND_LINE'].endswith("\\system") or record['COMMAND_LINE'].endswith("\\sam") or record['COMMAND_LINE'].endswith("\\security")))))

sigma_exports_registry_key_to_a_file.sigma_meta = dict(
    level="low"
)

def sigma_dumpminitool_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proc_dump_dumpminitool.yml
    title: DumpMinitool Usage
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects the use of a Visual Studio bundled tool named DumpMinitool.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\DumpMinitool.exe") or record['ORIGINAL_FILE_NAME'] == "DumpMinitool.exe") or (record['COMMAND_LINE'].contains("--processId") and record['COMMAND_LINE'].contains("--dumpType Full")))

sigma_dumpminitool_usage.sigma_meta = dict(
    level="medium"
)

def sigma_f_secure_c3_load_by_rundll32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_c3_load_by_rundll32.yml
    title: F-Secure C3 Load by Rundll32
    fields: ['CommandLine']
    level: critical
    description: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains(".dll") and record['COMMAND_LINE'].contains("StartNodeRelay"))

sigma_f_secure_c3_load_by_rundll32.sigma_meta = dict(
    level="critical"
)

def sigma_dllregisterserver_call_from_non_rundll32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml
    title: DllRegisterServer Call From Non Rundll32
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects when 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("DllRegisterServer") and not (record['PROCESS_NAME'].endswith("\\rundll32.exe")))

sigma_dllregisterserver_call_from_non_rundll32.sigma_meta = dict(
    level="high"
)

def sigma_sqlite_firefox_cookie_db_access(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sqlite_firefox_cookies.yml
    title: SQLite Firefox Cookie DB Access
    fields: ['CommandLine', 'Image', 'Product']
    level: high
    description: Detect use of sqlite binary to query the Firefox cookies.sqlite database and steal the cookie data contained within it
    logsource: category:process_creation - product:windows
    """
    return ((record['PRODUCT_NAME'] == "SQLite" or record['PROCESS_NAME'].endswith("\\sqlite.exe")) and record['COMMAND_LINE'].contains("cookies.sqlite"))

sigma_sqlite_firefox_cookie_db_access.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_curl_file_upload(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_curl_fileupload.yml
    title: Suspicious Curl File Upload
    fields: ['CommandLine', 'Image', 'Product']
    level: medium
    description: Detects a suspicious curl process start the adds a file to a web request
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\curl.exe") or record['PRODUCT_NAME'] == "The curl executable") and (record['COMMAND_LINE'].contains("-F") or record['COMMAND_LINE'].contains("--form") or record['COMMAND_LINE'].contains("-T") or record['COMMAND_LINE'].contains("--upload-file") or record['COMMAND_LINE'].contains("-d") or record['COMMAND_LINE'].contains("--data") or record['COMMAND_LINE'].contains("--data-")))

sigma_suspicious_curl_file_upload.sigma_meta = dict(
    level="medium"
)

def sigma_invoke_obfuscation_compress_obfuscation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_compress.yml
    title: Invoke-Obfuscation COMPRESS OBFUSCATION
    fields: ['CommandLine']
    level: medium
    description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("new-object") and record['COMMAND_LINE'].contains("text.encoding]::ascii") and (record['COMMAND_LINE'].contains("system.io.compression.deflatestream") or record['COMMAND_LINE'].contains("system.io.streamreader")) and record['COMMAND_LINE'].endswith("readtoend"))

sigma_invoke_obfuscation_compress_obfuscation.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_createdump_process_dump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_renamed_createdump.yml
    title: Renamed CreateDump Process Dump
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "FX_VER_INTERNALNAME_STR" or (record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-f") and record['COMMAND_LINE'].contains(".dmp"))) and not (record['PROCESS_NAME'].endswith("\\createdump.exe")))

sigma_renamed_createdump_process_dump.sigma_meta = dict(
    level="high"
)

def sigma_unusual_parent_process_for_cmd_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_unusual_parent_for_cmd.yml
    title: Unusual Parent Process for cmd.exe
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects suspicious parent process for cmd.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and (record['PARENT_NAME'].endswith("\\lsass.exe") or record['PARENT_NAME'].endswith("\\csrss.exe") or record['PARENT_NAME'].endswith("\\epad.exe") or record['PARENT_NAME'].endswith("\\regsvr32.exe") or record['PARENT_NAME'].endswith("\\dllhost.exe") or record['PARENT_NAME'].endswith("\\LogonUI.exe") or record['PARENT_NAME'].endswith("\\wergmgr.exe") or record['PARENT_NAME'].endswith("\\spoolsv.exe") or record['PARENT_NAME'].endswith("\\jucheck.exe") or record['PARENT_NAME'].endswith("\\jusched.exe") or record['PARENT_NAME'].endswith("\\ctfmon.exe") or record['PARENT_NAME'].endswith("\\taskhostw.exe") or record['PARENT_NAME'].endswith("\\GoogleUpdate.exe") or record['PARENT_NAME'].endswith("\\sppsvc.exe") or record['PARENT_NAME'].endswith("\\sihost.exe") or record['PARENT_NAME'].endswith("\\slui.exe") or record['PARENT_NAME'].endswith("\\SIHClient.exe") or record['PARENT_NAME'].endswith("\\SearchIndexer.exe") or record['PARENT_NAME'].endswith("\\SearchProtocolHost.exe") or record['PARENT_NAME'].endswith("\\FlashPlayerUpdateService.exe") or record['PARENT_NAME'].endswith("\\WerFault.exe") or record['PARENT_NAME'].endswith("\\WUDFHost.exe") or record['PARENT_NAME'].endswith("\\unsecapp.exe") or record['PARENT_NAME'].endswith("\\wlanext.exe")))

sigma_unusual_parent_process_for_cmd_exe.sigma_meta = dict(
    level="medium"
)

def sigma_mpiexec_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mpiexec_lolbin.yml
    title: MpiExec Lolbin
    fields: ['CommandLine', 'Image', 'Hashes', 'Imphash']
    level: high
    description: Detects a certain command line flag combination used by mpiexec.exe LOLBIN from HPC pack that can be used to execute any other binary
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\mpiexec.exe") or record['IMPHASH'] == "d8b52ef6aaa3a81501bdfff9dbb96217" or record['HASHES'].contains("IMPHASH=d8b52ef6aaa3a81501bdfff9dbb96217")) and (record['COMMAND_LINE'].contains("/n 1") or record['COMMAND_LINE'].contains("-n 1")))

sigma_mpiexec_lolbin.sigma_meta = dict(
    level="high"
)

def sigma_winrar_execution_in_non_standard_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_winrar_execution.yml
    title: Winrar Execution in Non-Standard Folder
    fields: ['Image', 'Description']
    level: high
    description: Detects a suspicious winrar execution in a folder which is not the default installation folder
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\rar.exe") or record['PROCESS_NAME'].endswith("\\winrar.exe")) or record['DESCRIPTION'] == "Command line RAR") and not ((record['PROCESS_NAME'].contains("\\WinRAR") or record['PROCESS_NAME'].contains("C:\\Windows\\Temp") or record['PROCESS_NAME'].contains("\\UnRAR.exe"))))

sigma_winrar_execution_in_non_standard_folder.sigma_meta = dict(
    level="high"
)

def sigma_renamed_sysinternals_debug_view(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_renamed_debugview.yml
    title: Renamed SysInternals Debug View
    fields: ['Image', 'OriginalFileName', 'Product']
    level: high
    description: Detects suspicious renamed SysInternals DebugView execution
    logsource: category:process_creation - product:windows
    """
    return (record['PRODUCT_NAME'] == "Sysinternals DebugView" and not (record['ORIGINAL_FILE_NAME'] == "Dbgview.exe" and record['PROCESS_NAME'].endswith("\\Dbgview.exe")))

sigma_renamed_sysinternals_debug_view.sigma_meta = dict(
    level="high"
)

def sigma_csexec_remote_execution_tool_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_csexec.yml
    title: CsExec Remote Execution Tool Usage
    fields: ['Image', 'Description']
    level: high
    description: Detects the use of the lesser known remote execution tool named CsExec (a PsExec alternative)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\csexec.exe") or record['DESCRIPTION'] == "csexec")

sigma_csexec_remote_execution_tool_usage.sigma_meta = dict(
    level="high"
)

def sigma_emotet_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_emotet.yml
    title: Emotet Process Creation
    fields: ['CommandLine']
    level: high
    description: Detects all Emotet like process executions that are not covered by the more generic rules
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-e* PAA") or record['COMMAND_LINE'].contains("JABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQ") or record['COMMAND_LINE'].contains("QAZQBuAHYAOgB1AHMAZQByAHAAcgBvAGYAaQBsAGUA") or record['COMMAND_LINE'].contains("kAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlA") or record['COMMAND_LINE'].contains("IgAoACcAKgAnACkAOwAkA") or record['COMMAND_LINE'].contains("IAKAAnACoAJwApADsAJA") or record['COMMAND_LINE'].contains("iACgAJwAqACcAKQA7ACQA") or record['COMMAND_LINE'].contains("JABGAGwAeAByAGgAYwBmAGQ") or record['COMMAND_LINE'].contains("PQAkAGUAbgB2ADoAdABlAG0AcAArACgA") or record['COMMAND_LINE'].contains("0AJABlAG4AdgA6AHQAZQBtAHAAKwAoA") or record['COMMAND_LINE'].contains("9ACQAZQBuAHYAOgB0AGUAbQBwACsAKA")) and not ((record['COMMAND_LINE'].contains("fAAgAEMAbwBuAHYAZQByAHQAVABvAC0ASgBzAG8AbgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQ") or record['COMMAND_LINE'].contains("wAIABDAG8AbgB2AGUAcgB0AFQAbwAtAEoAcwBvAG4AIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUA") or record['COMMAND_LINE'].contains("8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlA"))))

sigma_emotet_process_creation.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_encoded_powershell_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_enc_cmd.yml
    title: Suspicious Encoded PowerShell Command Line
    fields: ['CommandLine']
    level: high
    description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
    logsource: category:process_creation - product:windows
    """
    return ((((record['COMMAND_LINE'].contains("-e") and record['COMMAND_LINE'].contains("JAB")) or (record['COMMAND_LINE'].contains("-e") and record['COMMAND_LINE'].contains("JAB") and record['COMMAND_LINE'].contains("-w") and record['COMMAND_LINE'].contains("hidden"))) or (record['COMMAND_LINE'].contains("-e") and (record['COMMAND_LINE'].contains("BA^J") or record['COMMAND_LINE'].contains("SUVYI") or record['COMMAND_LINE'].contains("SQBFAFgA") or record['COMMAND_LINE'].contains("aQBlAHgA") or record['COMMAND_LINE'].contains("aWV4I") or record['COMMAND_LINE'].contains("IAA") or record['COMMAND_LINE'].contains("IAB") or record['COMMAND_LINE'].contains("UwB") or record['COMMAND_LINE'].contains("cwB"))) or record['COMMAND_LINE'].contains(".exe -ENCOD")) and not (record['COMMAND_LINE'].contains("-ExecutionPolicy") and record['COMMAND_LINE'].contains("remotesigned")))

sigma_suspicious_encoded_powershell_command_line.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_sub_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_sub_processes.yml
    title: Suspicious PowerShell Sub Processes
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects suspicious sub processes spawned by PowerShell
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\powershell_ise.exe")) and (record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\scrcons.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe"))) and not (record['PARENT_COMMAND_LINE'].contains("\\Program Files\\Amazon\\WorkspacesConfig\\Scripts") and record['COMMAND_LINE'].contains("\\Program Files\\Amazon\\WorkspacesConfig\\Scripts")))

sigma_suspicious_powershell_sub_processes.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rundll32_setupapi_dll_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_setupapi_installhinfsection.yml
    title: Suspicious Rundll32 Setupapi.dll Activity
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: medium
    description: setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers. This technique could be used to obtain persistence via modifying one of Run or RunOnce registry keys, run process or use other DLLs chain calls (see references) InstallHinfSection function in setupapi.dll calls runonce.exe executable regardless of actual content of INF file.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\runonce.exe") and record['PARENT_NAME'].endswith("\\rundll32.exe") and record['PARENT_COMMAND_LINE'].contains("setupapi.dll") and record['PARENT_COMMAND_LINE'].contains("InstallHinfSection"))

sigma_suspicious_rundll32_setupapi_dll_activity.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_script_execution_from_temp_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_script_exec_from_temp.yml
    title: Suspicious Script Execution From Temp Folder
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a suspicious script executions from temporary folder
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe")) and (record['COMMAND_LINE'].contains("\\Windows\\Temp") or record['COMMAND_LINE'].contains("\\Temporary Internet") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("\\AppData\\Roaming\\Temp") or record['COMMAND_LINE'].contains("%TEMP%") or record['COMMAND_LINE'].contains("%TMP%") or record['COMMAND_LINE'].contains("%LocalAppData%\\Temp"))) and not ((record['COMMAND_LINE'].contains(">") or record['COMMAND_LINE'].contains("Out-File") or record['COMMAND_LINE'].contains("ConvertTo-Json") or record['COMMAND_LINE'].contains("-WindowStyle hidden -Verb runAs") or record['COMMAND_LINE'].contains("\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows"))))

sigma_suspicious_script_execution_from_temp_folder.sigma_meta = dict(
    level="high"
)

def sigma_chopper_webshell_process_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webshell_chopper.yml
    title: Chopper Webshell Process Pattern
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\w3wp.exe")) and (record['COMMAND_LINE'].contains("&ipconfig&echo") or record['COMMAND_LINE'].contains("&quser&echo") or record['COMMAND_LINE'].contains("&whoami&echo") or record['COMMAND_LINE'].contains("&c:&echo") or record['COMMAND_LINE'].contains("&cd&echo") or record['COMMAND_LINE'].contains("&dir&echo") or record['COMMAND_LINE'].contains("&echo [E]") or record['COMMAND_LINE'].contains("&echo [S]")))

sigma_chopper_webshell_process_pattern.sigma_meta = dict(
    level="high"
)

def sigma_sc_exe_query_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sc_query.yml
    title: SC.EXE Query Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Detects execution of "sc.exe" to query information about registered services on the system
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sc.exe") and record['ORIGINAL_FILE_NAME'].endswith("sc.exe") and record['COMMAND_LINE'].contains("query"))

sigma_sc_exe_query_execution.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_execution_of_taskkill(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_taskkill.yml
    title: Suspicious Execution of Taskkill
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Adversaries may stop services or processes in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\taskkill.exe") or record['ORIGINAL_FILE_NAME'] == "taskkill.exe") and (record['COMMAND_LINE'].contains("/f") and record['COMMAND_LINE'].contains("/im")))

sigma_suspicious_execution_of_taskkill.sigma_meta = dict(
    level="low"
)

def sigma_launch_webbrowserpassview_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webbrowserpassview.yml
    title: Launch WebBrowserPassView Executable
    fields: ['Image', 'Description']
    level: medium
    description: Detect use of WebBrowserPassView.exe
    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "Web Browser Password Viewer" or record['PROCESS_NAME'].endswith("\\WebBrowserPassView.exe"))

sigma_launch_webbrowserpassview_executable.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_zipexec_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_zipexec.yml
    title: Suspicious ZipExec Execution
    fields: ['CommandLine']
    level: medium
    description: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("/generic:Microsoft_Windows_Shell_ZipFolder:filename=") and record['COMMAND_LINE'].contains(".zip") and record['COMMAND_LINE'].contains("/pass:") and record['COMMAND_LINE'].contains("/user:")) or (record['COMMAND_LINE'].contains("/delete") and record['COMMAND_LINE'].contains("Microsoft_Windows_Shell_ZipFolder:filename=") and record['COMMAND_LINE'].contains(".zip")))

sigma_suspicious_zipexec_execution.sigma_meta = dict(
    level="medium"
)

def sigma_rar_usage_with_password_and_compression_level(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rar_flags.yml
    title: Rar Usage with Password and Compression Level
    fields: ['CommandLine']
    level: high
    description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-hp") and (record['COMMAND_LINE'].contains("-m") or record['COMMAND_LINE'].contains("a")))

sigma_rar_usage_with_password_and_compression_level.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rundll32_script_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_script_run.yml
    title: Suspicious Rundll32 Script in CommandLine
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious process related to rundll32 based on arguments
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("mshtml,RunHTMLApplication") and (record['COMMAND_LINE'].contains("javascript:") or record['COMMAND_LINE'].contains("vbscript:")))

sigma_suspicious_rundll32_script_in_commandline.sigma_meta = dict(
    level="medium"
)

def sigma_wmiprvse_spawning_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmiprvse_spawning_process.yml
    title: Wmiprvse Spawning Process
    fields: ['LogonId', 'User', 'Image', 'ParentImage']
    level: high
    description: Detects wmiprvse spawning processes
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\WmiPrvSe.exe") and not ((record['LOGON_ID'] == "0x3e7" or record['LOGON_ID'] == "null") or (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")) or (record['PROCESS_NAME'].endswith("\\WmiPrvSE.exe") or record['PROCESS_NAME'].endswith("\\WerFault.exe")))) and not (record.get('LOGON_ID', None) == None))

sigma_wmiprvse_spawning_process.sigma_meta = dict(
    level="high"
)

def sigma_file_or_folder_permissions_modifications(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_file_permission_modifications.yml
    title: File or Folder Permissions Modifications
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects a file or folder's permissions being modified or tampered with.
    logsource: category:process_creation - product:windows
    """
    return ((((record['PROCESS_NAME'].endswith("\\cacls.exe") or record['PROCESS_NAME'].endswith("\\icacls.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and (record['COMMAND_LINE'].contains("/grant") or record['COMMAND_LINE'].contains("/setowner") or record['COMMAND_LINE'].contains("/inheritance:r"))) or (record['PROCESS_NAME'].endswith("\\attrib.exe") and record['COMMAND_LINE'].contains("-r")) or record['PROCESS_NAME'].endswith("\\takeown.exe")) and not ((record['COMMAND_LINE'].endswith("ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\connectivity.history /reset")) or (record['COMMAND_LINE'].contains("ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\config.properties /grant :r") and record['COMMAND_LINE'].contains("S-1-5-19:F")) or (record['COMMAND_LINE'].contains("\\AppData\\Local\\Programs\\Microsoft VS Code") or record['PARENT_NAME'].endswith("\\Microsoft VS Code\\Code.exe"))))

sigma_file_or_folder_permissions_modifications.sigma_meta = dict(
    level="medium"
)

def sigma_defendercheck_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pua_defendercheck.yml
    title: DefenderCheck Usage
    fields: ['Image', 'Description']
    level: high
    description: Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and thus used for AV evasion.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\DefenderCheck.exe") or record['DESCRIPTION'] == "DefenderCheck")

sigma_defendercheck_usage.sigma_meta = dict(
    level="high"
)

def sigma_java_running_with_remote_debugging(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_vul_java_remote_debugging.yml
    title: Java Running with Remote Debugging
    fields: ['CommandLine']
    level: medium
    description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("transport=dt_socket,address=") and (record['COMMAND_LINE'].contains("jre1.") or record['COMMAND_LINE'].contains("jdk1."))) and not (record['COMMAND_LINE'].contains("address=127.0.0.1") or record['COMMAND_LINE'].contains("address=localhost")))

sigma_java_running_with_remote_debugging.sigma_meta = dict(
    level="medium"
)

def sigma_execute_msdt_exe_using_diagcab_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msdt_diagcab.yml
    title: Execute MSDT.EXE Using Diagcab File
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects diagcab leveraging the "ms-msdt" handler or the "msdt.exe" binary to execute arbitrary commands as seen in CVE-2022-30190
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msdt.exe") or record['ORIGINAL_FILE_NAME'] == "msdt.exe") and (record['COMMAND_LINE'].contains("/cab") or record['COMMAND_LINE'].contains("-cab")))

sigma_execute_msdt_exe_using_diagcab_file.sigma_meta = dict(
    level="high"
)

def sigma_password_spraying_attempts_using_dsacls(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dsacls_password_spray.yml
    title: Password Spraying Attempts Using Dsacls
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects possible password spraying attempts using Dsacls
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\dsacls.exe") or record['ORIGINAL_FILE_NAME'] == "DSACLS.EXE") and (record['COMMAND_LINE'].contains("/user:") and record['COMMAND_LINE'].contains("/passwd:")))

sigma_password_spraying_attempts_using_dsacls.sigma_meta = dict(
    level="medium"
)

def sigma_wmic_uninstall_security_product(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wmic_security_product_uninstall.yml
    title: Wmic Uninstall Security Product
    fields: ['CommandLine']
    level: high
    description: Detects uninstallation or termination of security products using the WMIC utility
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("wmic") and record['COMMAND_LINE'].contains("product where") and record['COMMAND_LINE'].contains("call uninstall") and record['COMMAND_LINE'].contains("/nointeractive")) or (record['COMMAND_LINE'].contains("wmic") and record['COMMAND_LINE'].contains("caption like") and (record['COMMAND_LINE'].contains("call delete") or record['COMMAND_LINE'].contains("call terminate")))) and (record['COMMAND_LINE'].contains("Antivirus") or record['COMMAND_LINE'].contains("AVG") or record['COMMAND_LINE'].contains("Crowdstrike Sensor") or record['COMMAND_LINE'].contains("DLP Endpoint") or record['COMMAND_LINE'].contains("Endpoint Detection") or record['COMMAND_LINE'].contains("Endpoint Protection") or record['COMMAND_LINE'].contains("Endpoint Security") or record['COMMAND_LINE'].contains("Endpoint Sensor") or record['COMMAND_LINE'].contains("ESET File Security") or record['COMMAND_LINE'].contains("Malwarebytes") or record['COMMAND_LINE'].contains("McAfee Agent") or record['COMMAND_LINE'].contains("Microsoft Security Client") or record['COMMAND_LINE'].contains("Threat Protection") or record['COMMAND_LINE'].contains("VirusScan") or record['COMMAND_LINE'].contains("Webroot SecureAnywhere") or record['COMMAND_LINE'].contains("Windows Defender") or record['COMMAND_LINE'].contains("CarbonBlack") or record['COMMAND_LINE'].contains("Carbon Black") or record['COMMAND_LINE'].contains("Cb Defense Sensor 64-bit") or record['COMMAND_LINE'].contains("Dell Threat Defense") or record['COMMAND_LINE'].contains("Cylance") or record['COMMAND_LINE'].contains("LogRhythm System Monitor Service") or record['COMMAND_LINE'].contains("Sophos Anti-Virus") or record['COMMAND_LINE'].contains("Sophos AutoUpdate") or record['COMMAND_LINE'].contains("Sophos Management Console") or record['COMMAND_LINE'].contains("Sophos Management Database") or record['COMMAND_LINE'].contains("Sophos Credential Store") or record['COMMAND_LINE'].contains("Sophos Update Manager") or record['COMMAND_LINE'].contains("Sophos Management Server") or record['COMMAND_LINE'].contains("Sophos Remote Management System") or record['COMMAND_LINE'].contains("%Sophos%") or record['COMMAND_LINE'].contains("%carbon%") or record['COMMAND_LINE'].contains("%cylance%") or record['COMMAND_LINE'].contains("%eset%") or record['COMMAND_LINE'].contains("%symantec%")))

sigma_wmic_uninstall_security_product.sigma_meta = dict(
    level="high"
)

def sigma_use_short_name_path_in_image(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ntfs_short_name_path_use_image.yml
    title: Use Short Name Path in Image
    fields: ['Image', 'Company', 'ParentImage', 'Product', 'Description']
    level: high
    description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("~1") or record['PROCESS_NAME'].contains("~2")) and not (((record['PARENT_NAME'] == "C:\\Windows\\System32\\Dism.exe" or record['PARENT_NAME'] == "C:\\Windows\\System32\\cleanmgr.exe") or (record['PARENT_NAME'].endswith("\\WebEx\\WebexHost.exe") or record['PARENT_NAME'].endswith("\\thor\\thor64.exe")) or record['PRODUCT_NAME'] == "InstallShield (R)" or record['DESCRIPTION'] == "InstallShield (R) Setup Engine" or record['COMPANY'] == "InstallShield Software Corporation") or (record['PROCESS_NAME'].contains("\\AppData") and record['PROCESS_NAME'].contains("\\Temp") or (record['PROCESS_NAME'].endswith("~1\\unzip.exe") or record['PROCESS_NAME'].endswith("~1\\7zG.exe")))))

sigma_use_short_name_path_in_image.sigma_meta = dict(
    level="high"
)

def sigma_indirect_command_execution_by_program_compatibility_wizard(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_pcwrun.yml
    title: Indirect Command Execution By Program Compatibility Wizard
    fields: ['ParentImage']
    level: low
    description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\pcwrun.exe")

sigma_indirect_command_execution_by_program_compatibility_wizard.sigma_meta = dict(
    level="low"
)

def sigma_evilnum_golden_chickens_deployment_via_ocx_files(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_evilnum_jul20.yml
    title: EvilNum Golden Chickens Deployment via OCX Files
    fields: ['CommandLine']
    level: critical
    description: Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("regsvr32") and record['COMMAND_LINE'].contains("/s") and record['COMMAND_LINE'].contains("/i") and record['COMMAND_LINE'].contains("\\AppData\\Roaming") and record['COMMAND_LINE'].contains(".ocx"))

sigma_evilnum_golden_chickens_deployment_via_ocx_files.sigma_meta = dict(
    level="critical"
)

def sigma_mshtml_dll_runhtmlapplication_abuse(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mshtml_runhtmlapplication.yml
    title: Mshtml DLL RunHTMLApplication Abuse
    fields: ['CommandLine']
    level: high
    description: Detects suspicious command line using the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, htpp...)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\..") and record['COMMAND_LINE'].contains("mshtml") and record['COMMAND_LINE'].contains("RunHTMLApplication"))

sigma_mshtml_dll_runhtmlapplication_abuse.sigma_meta = dict(
    level="high"
)

def sigma_sysmon_driver_unload(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysmon_driver_unload.yml
    title: Sysmon Driver Unload
    fields: ['CommandLine', 'Image']
    level: high
    description: Detect possible Sysmon driver unload
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\fltmc.exe") and record['COMMAND_LINE'].contains("unload") and record['COMMAND_LINE'].contains("sys"))

sigma_sysmon_driver_unload.sigma_meta = dict(
    level="high"
)

def sigma_hidden_powershell_in_link_file_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_embed_exe_lnk.yml
    title: Hidden Powershell in Link File Pattern
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects events that appear when a user click on a link file with a powershell command in it
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'] == "C:\\Windows\\explorer.exe" and record['PROCESS_NAME'] == "C:\\Windows\\System32\\cmd.exe" and record['COMMAND_LINE'].contains("powershell") and record['COMMAND_LINE'].contains(".lnk"))

sigma_hidden_powershell_in_link_file_pattern.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_msiexec_quiet_install_from_remote_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msiexec_install_remote.yml
    title: Suspicious Msiexec Quiet Install From Remote Location
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['ORIGINAL_FILE_NAME'] == "msiexec.exe") and (record['COMMAND_LINE'].contains("/i") or record['COMMAND_LINE'].contains("-i") or record['COMMAND_LINE'].contains("/package") or record['COMMAND_LINE'].contains("-package") or record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("/j") or record['COMMAND_LINE'].contains("-j")) and (record['COMMAND_LINE'].contains("/q") or record['COMMAND_LINE'].contains("-q")) and (record['COMMAND_LINE'].contains("http") or record['COMMAND_LINE'].contains("")))

sigma_suspicious_msiexec_quiet_install_from_remote_location.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_parent_of_csc_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_csc.yml
    title: Suspicious Parent of Csc.exe
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\csc.exe") and (record['PARENT_NAME'].endswith("\\wscript.exe") or record['PARENT_NAME'].endswith("\\cscript.exe") or record['PARENT_NAME'].endswith("\\mshta.exe")))

sigma_suspicious_parent_of_csc_exe.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_configsecuritypolicy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_configsecuritypolicy.yml
    title: Suspicious ConfigSecurityPolicy Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Upload file, credentials or data exfiltration with Binary part of Windows Defender
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("ConfigSecurityPolicy.exe") or record['PROCESS_NAME'].endswith("\\ConfigSecurityPolicy.exe") or record['ORIGINAL_FILE_NAME'] == "ConfigSecurityPolicy.exe") and (record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_suspicious_configsecuritypolicy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_zxshell_malware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_zxshell.yml
    title: ZxShell Malware
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects a ZxShell start by the called and well-known function name
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and (record['COMMAND_LINE'].contains("zxFunction") or record['COMMAND_LINE'].contains("RemoteDiskXXXXX")))

sigma_zxshell_malware.sigma_meta = dict(
    level="critical"
)

def sigma_trustedpath_uac_bypass_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_uac_bypass_trustedpath.yml
    title: TrustedPath UAC Bypass Pattern
    fields: ['Image']
    level: critical
    description: Detects indicators of a UAC bypass method by mocking directories
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].contains("C:\\Windows \\System32")

sigma_trustedpath_uac_bypass_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_process_hacker_system_informer_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_process_hacker.yml
    title: Process Hacker / System Informer Usage
    fields: ['Image', 'md5', 'imphash', 'Hashes', 'OriginalFileName', 'Product', 'Description', 'sha1', 'sha256']
    level: high
    description: Detects suspicious use of Process Hacker and its newer version named System Informer, a tool to view and manipulate processes, kernel options and other low level stuff
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].contains("\\ProcessHacker_") or (record['PROCESS_NAME'].endswith("\\SystemInformer.exe") or record['PROCESS_NAME'].endswith("\\ProcessHacker.exe")) or (record['ORIGINAL_FILE_NAME'] == "ProcessHacker.exe" or record['ORIGINAL_FILE_NAME'] == "Process Hacker" or record['ORIGINAL_FILE_NAME'] == "SystemInformer.exe") or (record['DESCRIPTION'] == "Process Hacker" or record['DESCRIPTION'] == "System Informer") or record['PRODUCT_NAME'] == "Process Hacker" or (record['HASHES'].contains("MD5=68F9B52895F4D34E74112F3129B3B00D") or record['HASHES'].contains("SHA1=C5E2018BF7C0F314FED4FD7FE7E69FA2E648359E") or record['HASHES'].contains("SHA256=D4A0FE56316A2C45B9BA9AC1005363309A3EDC7ACF9E4DF64D326A0FF273E80F") or record['HASHES'].contains("IMPHASH=04DE0AD9C37EB7BD52043D2ECAC958DF") or record['HASHES'].contains("MD5=B365AF317AE730A67C936F21432B9C71") or record['HASHES'].contains("SHA1=A0BDFAC3CE1880B32FF9B696458327CE352E3B1D") or record['HASHES'].contains("SHA256=BD2C2CF0631D881ED382817AFCCE2B093F4E412FFB170A719E2762F250ABFEA4") or record['HASHES'].contains("IMPHASH=3695333C60DEDECDCAFF1590409AA462")) or (record['MD5'] == "68f9b52895f4d34e74112f3129b3b00d" or record['MD5'] == "b365af317ae730a67c936f21432b9c71") or (record['SHA1'] == "c5e2018bf7c0f314fed4fd7fe7e69fa2e648359e" or record['SHA1'] == "a0bdfac3ce1880b32ff9b696458327ce352e3b1d") or (record['SHA256'] == "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f" or record['SHA256'] == "bd2c2cf0631d881ed382817afcce2b093f4e412ffb170a719e2762f250abfea4") or (record['IMPHASH'] == "04de0ad9c37eb7bd52043d2ecac958df" or record['IMPHASH'] == "3695333c60dedecdcaff1590409aa462"))

sigma_process_hacker_system_informer_usage.sigma_meta = dict(
    level="high"
)

def sigma_mshta_spwaned_by_svchost(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lethalhta.yml
    title: MSHTA Spwaned by SVCHOST
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\svchost.exe") and record['PROCESS_NAME'].endswith("\\mshta.exe"))

sigma_mshta_spwaned_by_svchost.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_add_scheduled_command_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_pattern.yml
    title: Suspicious Add Scheduled Command Pattern
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious scheduled task creations with commands that are uncommon
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create")) and (((record['COMMAND_LINE'].contains("/sc minute") or record['COMMAND_LINE'].contains("/ru system")) and (record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd /r"))) or (record['COMMAND_LINE'].contains("bypass") or record['COMMAND_LINE'].contains(".DownloadString") or record['COMMAND_LINE'].contains(".DownloadFile") or record['COMMAND_LINE'].contains("FromBase64String") or record['COMMAND_LINE'].contains("-w hidden") or record['COMMAND_LINE'].contains("IEX") or record['COMMAND_LINE'].contains("-enc") or record['COMMAND_LINE'].contains("-decode") or record['COMMAND_LINE'].contains("/c start /min") or record['COMMAND_LINE'].contains("curl")) or (record['COMMAND_LINE'].contains("/xml C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local")) or (record['COMMAND_LINE'].contains("wscript.exe") and record['COMMAND_LINE'].contains("\\AppData"))))

sigma_suspicious_add_scheduled_command_pattern.sigma_meta = dict(
    level="high"
)

def sigma_windows_crypto_mining_indicators(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_crypto_mining_monero.yml
    title: Windows Crypto Mining Indicators
    fields: ['CommandLine']
    level: high
    description: Detects command line parameters or strings often used by crypto miners
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("--cpu-priority=") or record['COMMAND_LINE'].contains("--donate-level=0") or record['COMMAND_LINE'].contains("-o pool.") or record['COMMAND_LINE'].contains("--nicehash") or record['COMMAND_LINE'].contains("--algo=rx/0") or record['COMMAND_LINE'].contains("stratum+tcp://") or record['COMMAND_LINE'].contains("stratum+udp://") or record['COMMAND_LINE'].contains("LS1kb25hdGUtbGV2ZWw9") or record['COMMAND_LINE'].contains("0tZG9uYXRlLWxldmVsP") or record['COMMAND_LINE'].contains("tLWRvbmF0ZS1sZXZlbD") or record['COMMAND_LINE'].contains("c3RyYXR1bSt0Y3A6Ly") or record['COMMAND_LINE'].contains("N0cmF0dW0rdGNwOi8v") or record['COMMAND_LINE'].contains("zdHJhdHVtK3RjcDovL") or record['COMMAND_LINE'].contains("c3RyYXR1bSt1ZHA6Ly") or record['COMMAND_LINE'].contains("N0cmF0dW0rdWRwOi8v") or record['COMMAND_LINE'].contains("zdHJhdHVtK3VkcDovL")) and not ((record['COMMAND_LINE'].contains("pool.c") or record['COMMAND_LINE'].contains("pool.o") or record['COMMAND_LINE'].contains("gcc -"))))

sigma_windows_crypto_mining_indicators.sigma_meta = dict(
    level="high"
)

def sigma_application_whitelisting_bypass_via_dnx_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_dnx.yml
    title: Application Whitelisting Bypass via Dnx.exe
    fields: ['Image']
    level: medium
    description: Execute C# code located in the consoleapp folder
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\dnx.exe")

sigma_application_whitelisting_bypass_via_dnx_exe.sigma_meta = dict(
    level="medium"
)

def sigma_potential_suspicious_activity_using_secedit(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_secedit.yml
    title: Potential Suspicious Activity Using SeCEdit
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'SubjectUserName']
    level: medium
    description: Detects potential suspicious behaviour using secedit.exe. Such as exporting or modifying the security policy
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\secedit.exe") or record['ORIGINAL_FILE_NAME'] == "SeCEdit") and ((record['COMMAND_LINE'].contains("/export") and record['COMMAND_LINE'].contains("/cfg")) or (record['COMMAND_LINE'].contains("/configure") and record['COMMAND_LINE'].contains("/db")))) and not (record['SUBJECT_USER_NAME'].endswith("$")))

sigma_potential_suspicious_activity_using_secedit.sigma_meta = dict(
    level="medium"
)

def sigma_remote_procedure_call_service_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rpcss_anomalies.yml
    title: Remote Procedure Call Service Anomaly
    fields: ['ParentCommandLine']
    level: high
    description: Detects suspicious remote procedure call (RPC) service anomalies based on the spawned sub processes (long shot to detect the exploitation of vulnerabilities like CVE-2022-26809)
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_COMMAND_LINE'].startswith("C:\\WINDOWS\\system32\\svchost.exe -k RPCSS")

sigma_remote_procedure_call_service_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_syncappvpublishingserver_execute_arbitrary_powershell_code(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_execute_psh.yml
    title: SyncAppvPublishingServer Execute Arbitrary PowerShell Code
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\SyncAppvPublishingServer.exe") or record['ORIGINAL_FILE_NAME'] == "syncappvpublishingserver.exe") and record['COMMAND_LINE'].contains("\"n;"))

sigma_syncappvpublishingserver_execute_arbitrary_powershell_code.sigma_meta = dict(
    level="medium"
)

def sigma_nimgrab_file_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_nimgrab.yml
    title: Nimgrab File Download
    fields: ['Image', 'sha256', 'md5', 'Hashes', 'imphash']
    level: high
    description: Detects usage of nimgrab, a tool bundled with the Nim programming framework, downloading a file. This can be normal behaviour on developer systems.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\nimgrab.exe") or (record['HASHES'].contains("MD5=2DD44C3C29D667F5C0EF5F9D7C7FFB8B") or record['HASHES'].contains("SHA256=F266609E91985F0FE3E31C5E8FAEEEC4FFA5E0322D8B6F15FE69F4C5165B9559") or record['HASHES'].contains("IMPHASH=C07FDDD21D123EA9B3A08EEF44AAAC45")) or record['MD5'] == "2DD44C3C29D667F5C0EF5F9D7C7FFB8B" or record['SHA256'] == "F266609E91985F0FE3E31C5E8FAEEEC4FFA5E0322D8B6F15FE69F4C5165B9559" or record['IMPHASH'] == "C07FDDD21D123EA9B3A08EEF44AAAC45")

sigma_nimgrab_file_download.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_add_user_to_remote_desktop_users_group(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop.yml
    title: Suspicious Add User to Remote Desktop Users Group
    fields: ['CommandLine']
    level: high
    description: Detects suspicious command line in which a user gets added to the local Remote Desktop Users group
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("localgroup") and record['COMMAND_LINE'].contains("/add")) or (record['COMMAND_LINE'].contains("Add-LocalGroupMember") and record['COMMAND_LINE'].contains("-Group"))) and (record['COMMAND_LINE'].contains("Remote Desktop Users") or record['COMMAND_LINE'].contains("Utilisateurs du Bureau à distance") or record['COMMAND_LINE'].contains("Usuarios de escritorio remoto")))

sigma_suspicious_add_user_to_remote_desktop_users_group.sigma_meta = dict(
    level="high"
)

def sigma_capture_credentials_with_rpcping_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rpcping.yml
    title: Capture Credentials with Rpcping.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rpcping.exe") and (record['COMMAND_LINE'].contains("-s") or record['COMMAND_LINE'].contains("/s"))) and ((record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("NTLM")) or (record['COMMAND_LINE'].contains("/u") and record['COMMAND_LINE'].contains("NTLM")) or (record['COMMAND_LINE'].contains("-t") and record['COMMAND_LINE'].contains("ncacn_np")) or (record['COMMAND_LINE'].contains("/t") and record['COMMAND_LINE'].contains("ncacn_np"))))

sigma_capture_credentials_with_rpcping_exe.sigma_meta = dict(
    level="medium"
)

def sigma_computer_discovery_and_export_via_get_adcomputer_cmdlet(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_computer_discovery_get_adcomputer.yml
    title: Computer Discovery And Export Via Get-ADComputer Cmdlet
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll")) and (record['COMMAND_LINE'].contains("Get-ADComputer") and record['COMMAND_LINE'].contains("-Filter ") and (record['COMMAND_LINE'].contains(">") or record['COMMAND_LINE'].contains("| Select") or record['COMMAND_LINE'].contains("Out-File") or record['COMMAND_LINE'].contains("Set-Content") or record['COMMAND_LINE'].contains("Add-Content"))))

sigma_computer_discovery_and_export_via_get_adcomputer_cmdlet.sigma_meta = dict(
    level="medium"
)

def sigma_chcp_codepage_locale_lookup(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_codepage_lookup.yml
    title: CHCP CodePage Locale Lookup
    fields: ['CommandLine', 'Image', 'GrandparentCommandLine', 'ParentImage', 'ParentCommandLine']
    level: high
    description: Detects use of chcp to look up the system locale value as part of host discovery
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\cmd.exe") and (record['PARENT_COMMAND_LINE'].contains("/c") or record['PARENT_COMMAND_LINE'].contains("/r") or record['PARENT_COMMAND_LINE'].contains("/k")) and record['PROCESS_NAME'].endswith("\\chcp.com") and (record['COMMAND_LINE'].endswith("chcp") or record['COMMAND_LINE'].endswith("chcp") or record['COMMAND_LINE'].endswith("chcp"))) and not ((record['GRANDPARENT_COMMAND_LINE'].contains("/c C:\\ProgramData\\Anaconda3"))))

sigma_chcp_codepage_locale_lookup.sigma_meta = dict(
    level="high"
)

def sigma_unusual_child_porcess_of_dns_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_unusual_child_process_of_dns_exe.yml
    title: Unusual Child Porcess of dns.exe
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects an unexpected process spawning from dns.exe which may indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\dns.exe") and not (record['PROCESS_NAME'].endswith("\\conhost.exe")))

sigma_unusual_child_porcess_of_dns_exe.sigma_meta = dict(
    level="high"
)

def sigma_powershell_web_download_and_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_download_iex.yml
    title: PowerShell Web Download and Execution
    fields: ['CommandLine']
    level: high
    description: Detects suspicious ways to download files or content and execute them using PowerShell
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains(".DownloadString(") or record['COMMAND_LINE'].contains(".DownloadFile(") or record['COMMAND_LINE'].contains("Invoke-WebRequest")) and (record['COMMAND_LINE'].contains("IEX(") or record['COMMAND_LINE'].contains("IEX (") or record['COMMAND_LINE'].contains("I`EX") or record['COMMAND_LINE'].contains("IE`X") or record['COMMAND_LINE'].contains("I`E`X") or record['COMMAND_LINE'].contains("| IEX") or record['COMMAND_LINE'].contains("|IEX") or record['COMMAND_LINE'].contains("Invoke-Execution") or record['COMMAND_LINE'].contains(";iex $")))

sigma_powershell_web_download_and_execution.sigma_meta = dict(
    level="high"
)

def sigma_audio_capture_via_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_audio_capture.yml
    title: Audio Capture via PowerShell
    fields: ['CommandLine']
    level: medium
    description: Detects audio capture via PowerShell Cmdlet.
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("WindowsAudioDevice-Powershell-Cmdlet")

sigma_audio_capture_via_powershell.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_lolbin_acccheckconsole(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_acccheckconsole.yml
    title: Suspicious LOLBIN AccCheckConsole
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious LOLBIN AccCheckConsole execution with parameters as used to load an arbitrary DLL
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\AccCheckConsole.exe") or record['ORIGINAL_FILE_NAME'] == "AccCheckConsole.exe") and (record['COMMAND_LINE'].contains("-window") and record['COMMAND_LINE'].contains(".dll")))

sigma_suspicious_lolbin_acccheckconsole.sigma_meta = dict(
    level="high"
)

def sigma_ppid_spoofing_tool_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_selectmyparent.yml
    title: PPID Spoofing Tool Usage
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Hashes', 'Description', 'Imphash']
    level: high
    description: Detects the use of parent process ID spoofing tools like Didier Stevens tool SelectMyParent
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SelectMyParent.exe") or (record['COMMAND_LINE'].contains("PPID-spoof") or record['COMMAND_LINE'].contains("ppid_spoof") or record['COMMAND_LINE'].contains("spoof-ppid") or record['COMMAND_LINE'].contains("spoof_ppid") or record['COMMAND_LINE'].contains("ppidspoof") or record['COMMAND_LINE'].contains("spoofppid") or record['COMMAND_LINE'].contains("spoofedppid") or record['COMMAND_LINE'].contains("-spawnto")) or (record['ORIGINAL_FILE_NAME'].contains("PPID-spoof") or record['ORIGINAL_FILE_NAME'].contains("ppid_spoof") or record['ORIGINAL_FILE_NAME'].contains("spoof-ppid") or record['ORIGINAL_FILE_NAME'].contains("spoof_ppid") or record['ORIGINAL_FILE_NAME'].contains("ppidspoof") or record['ORIGINAL_FILE_NAME'].contains("spoofppid") or record['ORIGINAL_FILE_NAME'].contains("spoofedppid")) or record['DESCRIPTION'] == "SelectMyParent" or (record['IMPHASH'] == "04d974875bd225f00902b4cad9af3fbc" or record['IMPHASH'] == "a782af154c9e743ddf3f3eb2b8f3d16e" or record['IMPHASH'] == "89059503d7fbf470e68f7e63313da3ad" or record['IMPHASH'] == "ca28337632625c8281ab8a130b3d6bad") or (record['HASHES'].contains("IMPHASH=04D974875BD225F00902B4CAD9AF3FBC") or record['HASHES'].contains("IMPHASH=A782AF154C9E743DDF3F3EB2B8F3D16E") or record['HASHES'].contains("IMPHASH=89059503D7FBF470E68F7E63313DA3AD") or record['HASHES'].contains("IMPHASH=CA28337632625C8281AB8A130B3D6BAD")))

sigma_ppid_spoofing_tool_usage.sigma_meta = dict(
    level="high"
)

def sigma_windows_cmd_delete_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmd_delete.yml
    title: Windows Cmd Delete File
    fields: ['CommandLine']
    level: low
    description: Adversaries may delete files left behind by the actions of their intrusion activity.
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how.
Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.

    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("del") and record['COMMAND_LINE'].contains("/f")) or (record['COMMAND_LINE'].contains("rmdir") and record['COMMAND_LINE'].contains("/s") and record['COMMAND_LINE'].contains("/q")))

sigma_windows_cmd_delete_file.sigma_meta = dict(
    level="low"
)

def sigma_tap_installer_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tap_installer_execution.yml
    title: Tap Installer Execution
    fields: ['Image']
    level: medium
    description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\tapinstall.exe") and not (((record['PROCESS_NAME'] == "C:\\Program Files\\Avast Software\\SecureLine VPN\\tapinstall.exe" or record['PROCESS_NAME'] == "C:\\Program Files (x86)\\Avast Software\\SecureLine VPN\\tapinstall.exe"))))

sigma_tap_installer_execution.sigma_meta = dict(
    level="medium"
)

def sigma_nodejstools_pressanykey_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_pressynkey_lolbin.yml
    title: NodejsTools PressAnyKey Lolbin
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a certain command line flag combination used by Microsoft.NodejsTools.PressAnyKey.exe that can be used to execute any other binary
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Microsoft.NodejsTools.PressAnyKey.exe normal") or (record['COMMAND_LINE'].contains(".exe normal") and record['COMMAND_LINE'].endswith(".exe"))) and not ((record['PROCESS_NAME'].contains("\\Microsoft\\NodeJsTools\\NodeJsTools"))))

sigma_nodejstools_pressanykey_lolbin.sigma_meta = dict(
    level="high"
)

def sigma_accesschk_usage_to_check_privileges(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_accesschk_usage_after_priv_escalation.yml
    title: Accesschk Usage To Check Privileges
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Product', 'Description']
    level: medium
    description: Accesschk is an access and privilege audit tool developed by SysInternal and often being used by attacker to verify privileges
    logsource: product:windows - category:process_creation
    """
    return ((record['PRODUCT_NAME'].endswith("AccessChk") or record['DESCRIPTION'].contains("Reports effective permissions") or (record['PROCESS_NAME'].endswith("\\accesschk.exe") or record['PROCESS_NAME'].endswith("\\accesschk64.exe")) or record['ORIGINAL_FILE_NAME'] == "accesschk.exe") and (record['COMMAND_LINE'].contains("uwcqv") or record['COMMAND_LINE'].contains("kwsu") or record['COMMAND_LINE'].contains("qwsu") or record['COMMAND_LINE'].contains("uwdqs")))

sigma_accesschk_usage_to_check_privileges.sigma_meta = dict(
    level="medium"
)

def sigma_rundll32_installscreensaver_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_rundll32_installscreensaver.yml
    title: Rundll32 InstallScreenSaver Execution
    fields: ['CommandLine', 'Image']
    level: medium
    description: An attacker may execute an application as a SCR File using rundll32.exe desk.cpl,InstallScreenSaver
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("InstallScreenSaver"))

sigma_rundll32_installscreensaver_execution.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_fsharp_interpreters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_fsharp_interpreters.yml
    title: Use of FSharp Interpreters
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: The FSharp Interpreters, FsiAnyCpu.exe and FSi.exe, can be used for AWL bypass and is listed in Microsoft recommended block rules.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\fsianycpu.exe") or record['ORIGINAL_FILE_NAME'] == "fsianycpu.exe" or record['PROCESS_NAME'].endswith("\\fsi.exe") or record['ORIGINAL_FILE_NAME'] == "fsi.exe")

sigma_use_of_fsharp_interpreters.sigma_meta = dict(
    level="medium"
)

def sigma_windows_defender_download_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_mpcmdrun_download.yml
    title: Windows Defender Download Activity
    fields: ['CommandLine', 'Description']
    level: high
    description: Detect the use of Windows Defender to download payloads
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("MpCmdRun.exe") or record['DESCRIPTION'] == "Microsoft Malware Protection Command Line Utility") and (record['COMMAND_LINE'].contains("DownloadFile") and record['COMMAND_LINE'].contains("url")))

sigma_windows_defender_download_activity.sigma_meta = dict(
    level="high"
)

def sigma_remove_windows_defender_definition_files(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_remove_windows_defender_definition_files.yml
    title: Remove Windows Defender Definition Files
    fields: ['CommandLine', 'OriginalFileName']
    level: medium
    description: Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "MpCmdRun.exe" and record['COMMAND_LINE'].contains("-RemoveDefinitions") and record['COMMAND_LINE'].contains("-All"))

sigma_remove_windows_defender_definition_files.sigma_meta = dict(
    level="medium"
)

def sigma_abusing_permissions_using_dsacls(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dsacls_abuse_permissions.yml
    title: Abusing Permissions Using Dsacls
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of Dsacls to grant over permissive permissions
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\dsacls.exe") or record['ORIGINAL_FILE_NAME'] == "DSACLS.EXE") and record['COMMAND_LINE'].contains("/G") and (record['COMMAND_LINE'].contains("GR") or record['COMMAND_LINE'].contains("GE") or record['COMMAND_LINE'].contains("GW") or record['COMMAND_LINE'].contains("GA") or record['COMMAND_LINE'].contains("WP") or record['COMMAND_LINE'].contains("WD")))

sigma_abusing_permissions_using_dsacls.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_wfc_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_wfc.yml
    title: Use of Wfc.exe
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: The Workflow Command-line Compiler can be used for AWL bypass and is listed in Microsoft's recommended block rules.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wfc.exe") or record['ORIGINAL_FILE_NAME'] == "wfc.exe")

sigma_use_of_wfc_exe.sigma_meta = dict(
    level="medium"
)

def sigma_invoke_obfuscation_via_use_mshta(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_mhsta.yml
    title: Invoke-Obfuscation Via Use MSHTA
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated Powershell via use MSHTA in Scripts
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("&&") and record['COMMAND_LINE'].contains("mshta") and record['COMMAND_LINE'].contains("vbscript:createobject") and record['COMMAND_LINE'].contains(".run") and record['COMMAND_LINE'].contains("(window.close)"))

sigma_invoke_obfuscation_via_use_mshta.sigma_meta = dict(
    level="high"
)

def sigma_wmic_unquoted_services_path_lookup(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_unquoted_service_search.yml
    title: WMIC Unquoted Services Path Lookup
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects wmic known recon method to look for unquoted service paths, often used by pentest and attackers enum scripts
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['PROCESS_NAME'].endswith("\\WMIC.exe")) and (record['COMMAND_LINE'].contains("service") and record['COMMAND_LINE'].contains("get") and (record['COMMAND_LINE'].contains("name") or record['COMMAND_LINE'].contains("displayname") or record['COMMAND_LINE'].contains("pathname") or record['COMMAND_LINE'].contains("startmode"))))

sigma_wmic_unquoted_services_path_lookup.sigma_meta = dict(
    level="medium"
)

def sigma_sliver_c2_implant_activity_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_c2_sliver.yml
    title: Sliver C2 Implant Activity Pattern
    fields: ['CommandLine']
    level: critical
    description: Detects process activity patterns as seen being used by Sliver C2 framework implants
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8")

sigma_sliver_c2_implant_activity_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_plink_usage_rdp_tunneling(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_plink_usage.yml
    title: Suspicious Plink Usage RDP Tunneling
    fields: ['CommandLine', 'Image']
    level: high
    description: Execution of plink to perform data exfiltration and tunneling
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\plink.exe") and record['COMMAND_LINE'].contains(":127.0.0.1:3389")) or (record['PROCESS_NAME'].endswith("\\plink.exe") and record['COMMAND_LINE'].contains(":3389") and (record['COMMAND_LINE'].contains("-P 443") or record['COMMAND_LINE'].contains("-P 22"))))

sigma_suspicious_plink_usage_rdp_tunneling.sigma_meta = dict(
    level="high"
)

def sigma_hiding_files_with_attrib_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml
    title: Hiding Files with Attrib.exe
    fields: ['CommandLine', 'Image', 'ParentImage', 'OriginalFileName', 'ParentCommandLine']
    level: low
    description: Detects usage of attrib.exe to hide files from users.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\attrib.exe") or record['ORIGINAL_FILE_NAME'] == "ATTRIB.EXE") and record['COMMAND_LINE'].contains("+h")) and not ((record['COMMAND_LINE'].contains("\\desktop.ini")) or (record['PARENT_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'] == "+R +H +S +A \\\\\\*.cui" and record['PARENT_COMMAND_LINE'] == "C:\\\\WINDOWS\\\\system32\\\\\\*.bat")))

sigma_hiding_files_with_attrib_exe.sigma_meta = dict(
    level="low"
)

def sigma_disable_important_scheduled_task(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_disable.yml
    title: Disable Important Scheduled Task
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects when adversaries stop services or processes by disabling their respective schdueled tasks in order to conduct data destructive activities
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Change") and record['COMMAND_LINE'].contains("/TN") and record['COMMAND_LINE'].contains("/disable") and (record['COMMAND_LINE'].contains("\\Windows\\SystemRestore\\SR") or record['COMMAND_LINE'].contains("\\Windows\\Windows Defender") or record['COMMAND_LINE'].contains("\\Windows\\BitLocker") or record['COMMAND_LINE'].contains("\\Windows\\WindowsBackup") or record['COMMAND_LINE'].contains("\\Windows\\WindowsUpdate") or record['COMMAND_LINE'].contains("\\Windows\\UpdateOrchestrator") or record['COMMAND_LINE'].contains("\\Windows\\ExploitGuard")))

sigma_disable_important_scheduled_task.sigma_meta = dict(
    level="high"
)

def sigma_findstr_launching_lnk_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_findstr_lnk.yml
    title: Findstr Launching .lnk File
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\findstr.exe") and record['COMMAND_LINE'].endswith(".lnk"))

sigma_findstr_launching_lnk_file.sigma_meta = dict(
    level="medium"
)

def sigma_execute_msdt_via_answer_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_msdt_answer_file.yml
    title: Execute MSDT Via Answer File
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msdt.exe") and record['COMMAND_LINE'].contains("\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml") and (record['COMMAND_LINE'].contains("-af") or record['COMMAND_LINE'].contains("/af"))) and not (record['PARENT_NAME'].endswith("\\pcwrun.exe")))

sigma_execute_msdt_via_answer_file.sigma_meta = dict(
    level="high"
)

def sigma_malicious_base64_encoded_powershell_invoke_cmdlets(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_base64_invoke_susp_cmdlets.yml
    title: Malicious Base64 Encoded Powershell Invoke Cmdlets
    fields: ['CommandLine']
    level: high
    description: Detects base64 encoded powershell cmdlet invocation of known suspicious cmdlets
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBCAGwAbwBvAGQASABvAHUAbgBkA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0AQgBsAG8AbwBkAEgAbwB1AG4AZA") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAEIAbABvAG8AZABIAG8AdQBuAGQA") or record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6A") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAeg") or record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBXAE0ASQBFAHgAZQBjA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0AVwBNAEkARQB4AGUAYw") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAFcATQBJAEUAeABlAGMA"))

sigma_malicious_base64_encoded_powershell_invoke_cmdlets.sigma_meta = dict(
    level="high"
)

def sigma_nircmd_tool_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tool_nircmd.yml
    title: NirCmd Tool Execution
    fields: ['CommandLine', 'OriginalFileName']
    level: medium
    description: Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "NirCmd.exe" or (record['COMMAND_LINE'].contains("execmd") or record['COMMAND_LINE'].contains(".exe script") or record['COMMAND_LINE'].contains(".exe shexec") or record['COMMAND_LINE'].contains("runinteractive"))) or ((record['COMMAND_LINE'].contains("exec") or record['COMMAND_LINE'].contains("exec2")) and (record['COMMAND_LINE'].contains("show") or record['COMMAND_LINE'].contains("hide"))))

sigma_nircmd_tool_execution.sigma_meta = dict(
    level="medium"
)

def sigma_snatch_ransomware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_crime_snatch_ransomware.yml
    title: Snatch Ransomware
    fields: ['CommandLine']
    level: high
    description: Detects specific process characteristics of Snatch ransomware word document droppers
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("shutdown /r /f /t 00") or record['COMMAND_LINE'].contains("net stop SuperBackupMan"))

sigma_snatch_ransomware.sigma_meta = dict(
    level="high"
)

def sigma_cleanwipe_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cleanwipe.yml
    title: CleanWipe Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SepRemovalToolNative_x64.exe") or (record['PROCESS_NAME'].endswith("\\CATClean.exe") and record['COMMAND_LINE'].contains("--uninstall")) or (record['PROCESS_NAME'].endswith("\\NetInstaller.exe") and record['COMMAND_LINE'].contains("-r")) or (record['PROCESS_NAME'].endswith("\\WFPUnins.exe") and record['COMMAND_LINE'].contains("/uninstall") and record['COMMAND_LINE'].contains("/enterprise")))

sigma_cleanwipe_usage.sigma_meta = dict(
    level="high"
)

def sigma_adfind_usage_detection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_adfind_usage.yml
    title: AdFind Usage Detection
    fields: ['CommandLine']
    level: high
    description: AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("domainlist") or record['COMMAND_LINE'].contains("trustdmp") or record['COMMAND_LINE'].contains("dcmodes") or record['COMMAND_LINE'].contains("adinfo") or record['COMMAND_LINE'].contains("dclist") or record['COMMAND_LINE'].contains("computer_pwdnotreqd") or record['COMMAND_LINE'].contains("objectcategory=") or record['COMMAND_LINE'].contains("-subnets -f") or record['COMMAND_LINE'].contains("name=\"Domain Admins\"") or record['COMMAND_LINE'].contains("-sc u:") or record['COMMAND_LINE'].contains("domainncs") or record['COMMAND_LINE'].contains("dompol") or record['COMMAND_LINE'].contains("oudmp") or record['COMMAND_LINE'].contains("subnetdmp") or record['COMMAND_LINE'].contains("gpodmp") or record['COMMAND_LINE'].contains("fspdmp") or record['COMMAND_LINE'].contains("users_noexpire") or record['COMMAND_LINE'].contains("computers_active") or record['COMMAND_LINE'].contains("computers_pwdnotreqd"))

sigma_adfind_usage_detection.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_disk_cleanup(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.yml
    title: UAC Bypass Using Disk Cleanup
    fields: ['CommandLine', 'IntegrityLevel', 'ParentCommandLine']
    level: high
    description: Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].endswith("\"\\system32\\cleanmgr.exe /autoclean /d C:") and record['PARENT_COMMAND_LINE'] == "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule" and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_disk_cleanup.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_desktopimgdownldr_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_desktopimgdownldr.yml
    title: Suspicious Desktopimgdownldr Command
    fields: ['CommandLine']
    level: high
    description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("/lockscreenurl:") and not ((record['COMMAND_LINE'].contains(".jpg") or record['COMMAND_LINE'].contains(".jpeg") or record['COMMAND_LINE'].contains(".png")))) or (record['COMMAND_LINE'].contains("reg delete") and record['COMMAND_LINE'].contains("\\PersonalizationCSP")))

sigma_suspicious_desktopimgdownldr_command.sigma_meta = dict(
    level="high"
)

def sigma_rundll32_with_suspicious_parent_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rundll32_parent_explorer.yml
    title: Rundll32 With Suspicious Parent Process
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious start of rundll32.exe with a parent process of Explorer.exe. Variant of Raspberry Robin, as first reported by Red Canary.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['PARENT_NAME'].endswith("\\explorer.exe")) and not (record['COMMAND_LINE'].contains("\\shell32.dll,OpenAs_RunDLL")))

sigma_rundll32_with_suspicious_parent_process.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_cmdl32_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_cmdl32.yml
    title: Suspicious Cmdl32 Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: lolbas Cmdl32 is use to download a payload to evade antivirus
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmdl32.exe") or record['ORIGINAL_FILE_NAME'] == "CMDL32.EXE") and (record['COMMAND_LINE'].contains("/vpn") and record['COMMAND_LINE'].contains("/lan")))

sigma_suspicious_cmdl32_execution.sigma_meta = dict(
    level="medium"
)

def sigma_query_usage_to_exfil_data(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_query_session_exfil.yml
    title: Query Usage To Exfil Data
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Windows\\System32\\query.exe") and (record['COMMAND_LINE'].contains("session >") or record['COMMAND_LINE'].contains("process >")))

sigma_query_usage_to_exfil_data.sigma_meta = dict(
    level="medium"
)

def sigma_windows_credential_editor(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_wce.yml
    title: Windows Credential Editor
    fields: ['CommandLine', 'Image', 'ParentImage', 'Hashes', 'Imphash']
    level: critical
    description: Detects the use of Windows Credential Editor (WCE)
    logsource: category:process_creation - product:windows
    """
    return ((((record['IMPHASH'] == "a53a02b997935fd8eedcb5f7abab9b9f" or record['IMPHASH'] == "e96a73c7bf33a464c510ede582318bf2") or (record['HASHES'].contains("IMPHASH=a53a02b997935fd8eedcb5f7abab9b9f") or record['HASHES'].contains("IMPHASH=e96a73c7bf33a464c510ede582318bf2"))) or (record['COMMAND_LINE'].endswith(".exe -S") and record['PARENT_NAME'].endswith("\\services.exe"))) and not (record['PROCESS_NAME'].endswith("\\clussvc.exe")))

sigma_windows_credential_editor.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_stop_windows_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_stop.yml
    title: Suspicious Stop Windows Service
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the usage of one of the the commands to stop services such as 'net', 'sc'...etc in order to stop critical or important windows services such as AV, Backup...etc. As seen being used in some ransomware scripts
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\"Acronis VSS Provider\"") or record['COMMAND_LINE'].contains("\"Client Agent 7.60\"") or record['COMMAND_LINE'].contains("\"Enterprise Client Service\"") or record['COMMAND_LINE'].contains("\"Sophos Agent\"") or record['COMMAND_LINE'].contains("\"Sophos AutoUpdate Service\"") or record['COMMAND_LINE'].contains("\"Sophos Clean Service\"") or record['COMMAND_LINE'].contains("\"Sophos Device Control Service\"") or record['COMMAND_LINE'].contains("\"Sophos File Scanner Service\"") or record['COMMAND_LINE'].contains("\"Sophos Health Service\"") or record['COMMAND_LINE'].contains("\"Sophos MCS Agent\"") or record['COMMAND_LINE'].contains("\"Sophos MCS Client\"") or record['COMMAND_LINE'].contains("\"Sophos Message Router\"") or record['COMMAND_LINE'].contains("\"Sophos Safestore Service\"") or record['COMMAND_LINE'].contains("\"Sophos System Protection Service\"") or record['COMMAND_LINE'].contains("\"Sophos Web Control Service\"") or record['COMMAND_LINE'].contains("\"SQL Backups\"") or record['COMMAND_LINE'].contains("\"SQL Server (MSSQLSERVER)\"") or record['COMMAND_LINE'].contains("\"SQL Server (SQLEXPRESS)") or record['COMMAND_LINE'].contains("\"SQLsafe Backup Service\"") or record['COMMAND_LINE'].contains("\"SQLsafe Filter Service\"") or record['COMMAND_LINE'].contains("\"Symantec System Recovery\"") or record['COMMAND_LINE'].contains("\"Veeam Backup Catalog Data Service\"") or record['COMMAND_LINE'].contains("\"Veritas System Recovery\"") or record['COMMAND_LINE'].contains("\"Zoolz 2 Service\"") or record['COMMAND_LINE'].contains("“Avast Business Console Client Antivirus Service”") or record['COMMAND_LINE'].contains("“avast! Antivirus”") or record['COMMAND_LINE'].contains("“SQL Backups”") or record['COMMAND_LINE'].contains("“Zoolz 2 Service”") or record['COMMAND_LINE'].contains("143Svc") or record['COMMAND_LINE'].contains("AcronisAgent") or record['COMMAND_LINE'].contains("AcrSch2Svc") or record['COMMAND_LINE'].contains("Antivirus") or record['COMMAND_LINE'].contains("ARSM") or record['COMMAND_LINE'].contains("aswBcc") or record['COMMAND_LINE'].contains("AVP") or record['COMMAND_LINE'].contains("BackupExecAgentAccelerator") or record['COMMAND_LINE'].contains("BackupExecAgentBrowser") or record['COMMAND_LINE'].contains("BackupExecDeviceMediaService") or record['COMMAND_LINE'].contains("BackupExecJobEngine") or record['COMMAND_LINE'].contains("BackupExeclobEngine") or record['COMMAND_LINE'].contains("BackupExecManagementService") or record['COMMAND_LINE'].contains("BackupExecRPCService") or record['COMMAND_LINE'].contains("BackupExecVSSProvider") or record['COMMAND_LINE'].contains("bedbg") or record['COMMAND_LINE'].contains("BITS") or record['COMMAND_LINE'].contains("BrokerInfrastructure") or record['COMMAND_LINE'].contains("DCAgent") or record['COMMAND_LINE'].contains("EhttpSrv") or record['COMMAND_LINE'].contains("EhttpSry") or record['COMMAND_LINE'].contains("ekrn") or record['COMMAND_LINE'].contains("epag") or record['COMMAND_LINE'].contains("EPIntegrationService") or record['COMMAND_LINE'].contains("EPlntegrationService") or record['COMMAND_LINE'].contains("EPProtectedService") or record['COMMAND_LINE'].contains("EPRedline") or record['COMMAND_LINE'].contains("EPSecurityService") or record['COMMAND_LINE'].contains("EPUpdateService") or record['COMMAND_LINE'].contains("EraserSvc11710") or record['COMMAND_LINE'].contains("EsgShKernel") or record['COMMAND_LINE'].contains("ESHASRV") or record['COMMAND_LINE'].contains("FA_Scheduler") or record['COMMAND_LINE'].contains("HealthTLService") or record['COMMAND_LINE'].contains("HISSQLFDLauncherSSHAREPOINIT") or record['COMMAND_LINE'].contains("HMS") or record['COMMAND_LINE'].contains("IISAdmin") or record['COMMAND_LINE'].contains("IMANSVC") or record['COMMAND_LINE'].contains("IMAP4Svc") or record['COMMAND_LINE'].contains("KAVFS") or record['COMMAND_LINE'].contains("KAVFSGT") or record['COMMAND_LINE'].contains("kavfsslp") or record['COMMAND_LINE'].contains("klnagent") or record['COMMAND_LINE'].contains("LogProcessorService") or record['COMMAND_LINE'].contains("M8EndpointAgent") or record['COMMAND_LINE'].contains("macmnsvc") or record['COMMAND_LINE'].contains("masvc") or record['COMMAND_LINE'].contains("MBAMService") or record['COMMAND_LINE'].contains("MBEndpointAgent") or record['COMMAND_LINE'].contains("McAfeeEngineService") or record['COMMAND_LINE'].contains("MCAFEEEVENTPARSERSRV") or record['COMMAND_LINE'].contains("McAfeeFramework") or record['COMMAND_LINE'].contains("McAfeeFrameworkMcAfeeFramework") or record['COMMAND_LINE'].contains("MCAFEETOMCATSRV530") or record['COMMAND_LINE'].contains("McShield") or record['COMMAND_LINE'].contains("McTaskManager") or record['COMMAND_LINE'].contains("mfefire") or record['COMMAND_LINE'].contains("mfemms") or record['COMMAND_LINE'].contains("mfevto") or record['COMMAND_LINE'].contains("mfevtp") or record['COMMAND_LINE'].contains("mfewc") or record['COMMAND_LINE'].contains("MMS") or record['COMMAND_LINE'].contains("mozyprobackup") or record['COMMAND_LINE'].contains("MsDtsServer") or record['COMMAND_LINE'].contains("MsDtsServer100") or record['COMMAND_LINE'].contains("MsDtsServer110") or record['COMMAND_LINE'].contains("MsDtsServer130") or record['COMMAND_LINE'].contains("MSExchangeES") or record['COMMAND_LINE'].contains("MSExchangeIS") or record['COMMAND_LINE'].contains("MSExchangeMGMT") or record['COMMAND_LINE'].contains("MSExchangeMIA") or record['COMMAND_LINE'].contains("MSExchangeMTA") or record['COMMAND_LINE'].contains("MSExchangeSA") or record['COMMAND_LINE'].contains("MSExchangeSRS") or record['COMMAND_LINE'].contains("msftesq1SPROO") or record['COMMAND_LINE'].contains("msftesql$PROD") or record['COMMAND_LINE'].contains("MSOLAP$SQL_2008") or record['COMMAND_LINE'].contains("MSOLAP$SYSTEM_BGC") or record['COMMAND_LINE'].contains("MSOLAP$TPS") or record['COMMAND_LINE'].contains("MSOLAP$TPSAMA") or record['COMMAND_LINE'].contains("MSOLAPSTPS") or record['COMMAND_LINE'].contains("MSOLAPSTPSAMA") or record['COMMAND_LINE'].contains("MSSQ!I.SPROFXENGAGEMEHT") or record['COMMAND_LINE'].contains("MSSQ0SHAREPOINT") or record['COMMAND_LINE'].contains("MSSQ0SOPHOS") or record['COMMAND_LINE'].contains("MSSQL$BKUPEXEC") or record['COMMAND_LINE'].contains("MSSQL$ECWDB2") or record['COMMAND_LINE'].contains("MSSQL$EPOSERVER") or record['COMMAND_LINE'].contains("MSSQL$ITRIS") or record['COMMAND_LINE'].contains("MSSQL$PRACTICEMGT") or record['COMMAND_LINE'].contains("MSSQL$PRACTTICEBGC") or record['COMMAND_LINE'].contains("MSSQL$PROD") or record['COMMAND_LINE'].contains("MSSQL$PROFXENGAGEMENT") or record['COMMAND_LINE'].contains("MSSQL$SBSMONITORING") or record['COMMAND_LINE'].contains("MSSQL$SHAREPOINT") or record['COMMAND_LINE'].contains("MSSQL$SOPHOS") or record['COMMAND_LINE'].contains("MSSQL$SQL_2008") or record['COMMAND_LINE'].contains("MSSQL$SQLEXPRESS") or record['COMMAND_LINE'].contains("MSSQL$SYSTEM_BGC") or record['COMMAND_LINE'].contains("MSSQL$TPS") or record['COMMAND_LINE'].contains("MSSQL$TPSAMA") or record['COMMAND_LINE'].contains("MSSQL$VEEAMSQL2008R2") or record['COMMAND_LINE'].contains("MSSQL$VEEAMSQL2012") or record['COMMAND_LINE'].contains("MSSQLFDLauncher") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$ITRIS") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$PROFXENGAGEMENT") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$S8SMONITORING") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$SBSMONITORING") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$SHAREPOINT") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$SQL_2008") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$SYSTEM_BGC") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$TPS") or record['COMMAND_LINE'].contains("MSSQLFDLauncher$TPSAMA") or record['COMMAND_LINE'].contains("MSSQLFDLauncherSPROFXENGAGEMENT") or record['COMMAND_LINE'].contains("MSSQLFDLauncherSTPS") or record['COMMAND_LINE'].contains("MSSQLFDLauncherSTPSAMA") or record['COMMAND_LINE'].contains("MSSQLFOLauncherSSVSTEM_BGC") or record['COMMAND_LINE'].contains("MSSQLFOLavocher") or record['COMMAND_LINE'].contains("MSSQLLaunchpad$ITRIS") or record['COMMAND_LINE'].contains("MSSQLSBKUPEXEC") or record['COMMAND_LINE'].contains("MSSQLSECWDB2") or record['COMMAND_LINE'].contains("MSSQLSERVER") or record['COMMAND_LINE'].contains("MSSQLServerADHelper") or record['COMMAND_LINE'].contains("MSSQLServerADHelper100") or record['COMMAND_LINE'].contains("MSSQLServerOLAPService") or record['COMMAND_LINE'].contains("mSSQLSFRACTICEMGT") or record['COMMAND_LINE'].contains("MSSQLSPRACTTICEBGE") or record['COMMAND_LINE'].contains("MSSQLSPROO") or record['COMMAND_LINE'].contains("MSSQLSSBSMONITORIMG") or record['COMMAND_LINE'].contains("MSSQLSSQL_2008") or record['COMMAND_LINE'].contains("MSSQLSSQLEXPRESS") or record['COMMAND_LINE'].contains("MSSQLSSVSTEM_BGC") or record['COMMAND_LINE'].contains("MSSQLSTPS") or record['COMMAND_LINE'].contains("MSSQLSTPSAMA") or record['COMMAND_LINE'].contains("MSSQLSVEEAMSQL2012") or record['COMMAND_LINE'].contains("MSSQLSVIEAMSQL2008112") or record['COMMAND_LINE'].contains("MSSQLWEEAMSQL2008R2") or record['COMMAND_LINE'].contains("MySQL57") or record['COMMAND_LINE'].contains("MySQL80") or record['COMMAND_LINE'].contains("MySQLS7") or record['COMMAND_LINE'].contains("NetMsmqActivator") or record['COMMAND_LINE'].contains("ntrtscan") or record['COMMAND_LINE'].contains("OracleClientCache80") or record['COMMAND_LINE'].contains("PDVFSService") or record['COMMAND_LINE'].contains("POP3Svc") or record['COMMAND_LINE'].contains("POVFSService") or record['COMMAND_LINE'].contains("ReportServer") or record['COMMAND_LINE'].contains("ReportServer$SQL_2008") or record['COMMAND_LINE'].contains("ReportServer$SYSTEM_BGC") or record['COMMAND_LINE'].contains("ReportServer$TPS") or record['COMMAND_LINE'].contains("ReportServer$TPSAMA") or record['COMMAND_LINE'].contains("RESvc") or record['COMMAND_LINE'].contains("sacsvr") or record['COMMAND_LINE'].contains("SamSs") or record['COMMAND_LINE'].contains("SAVAdminService") or record['COMMAND_LINE'].contains("SAVService") or record['COMMAND_LINE'].contains("SDRSVC") or record['COMMAND_LINE'].contains("SentinelAgent") or record['COMMAND_LINE'].contains("SentinelHelperService") or record['COMMAND_LINE'].contains("SepMasterService") or record['COMMAND_LINE'].contains("ShMonitor") or record['COMMAND_LINE'].contains("Smcinst") or record['COMMAND_LINE'].contains("SmcService") or record['COMMAND_LINE'].contains("SMTPSvc") or record['COMMAND_LINE'].contains("SNAC") or record['COMMAND_LINE'].contains("SntpService") or record['COMMAND_LINE'].contains("sophossps") or record['COMMAND_LINE'].contains("SQ1SafeOLRService") or record['COMMAND_LINE'].contains("SQLAgent$BKUPEXEC") or record['COMMAND_LINE'].contains("SQLAgent$CITRIX_METAFRAME") or record['COMMAND_LINE'].contains("SQLAgent$CXDB") or record['COMMAND_LINE'].contains("SQLAgent$ECWDB2") or record['COMMAND_LINE'].contains("SQLAgent$EPOSERVER") or record['COMMAND_LINE'].contains("SQLAgent$ITRIS") or record['COMMAND_LINE'].contains("SQLAgent$PRACTTICEBGC") or record['COMMAND_LINE'].contains("SQLAgent$PRACTTICEMGT") or record['COMMAND_LINE'].contains("SQLAgent$PROD") or record['COMMAND_LINE'].contains("SQLAgent$PROFXENGAGEMENT") or record['COMMAND_LINE'].contains("SQLAgent$SBSMONITORING") or record['COMMAND_LINE'].contains("SQLAgent$SHAREPOINT") or record['COMMAND_LINE'].contains("SQLAgent$SOPHOS") or record['COMMAND_LINE'].contains("SQLAgent$SQL_2008") or record['COMMAND_LINE'].contains("SQLAgent$SQLEXPRESS") or record['COMMAND_LINE'].contains("SQLAgent$SVSTEM_BGC") or record['COMMAND_LINE'].contains("SQLAgent$SYSTEM_BGC") or record['COMMAND_LINE'].contains("SQLAgent$TPS") or record['COMMAND_LINE'].contains("SQLAgent$TPSAMA") or record['COMMAND_LINE'].contains("SQLAgent$VEEAMSQL2008R2") or record['COMMAND_LINE'].contains("SQLAgent$VEEAMSQL2012") or record['COMMAND_LINE'].contains("SQLAgentSCITRIX_METAFRAME") or record['COMMAND_LINE'].contains("SQLAgentSCXDB") or record['COMMAND_LINE'].contains("SQLAgentSPRACTTICEBGC") or record['COMMAND_LINE'].contains("SQLAgentSPROO") or record['COMMAND_LINE'].contains("SQLAgentSSBSMONITORING") or record['COMMAND_LINE'].contains("SQLAgentSSQL EXPRESS") or record['COMMAND_LINE'].contains("SQLAgentSTPS") or record['COMMAND_LINE'].contains("SQLAgentSTPSAMA") or record['COMMAND_LINE'].contains("SQLAgentSVEEAMSQL2008R2") or record['COMMAND_LINE'].contains("SQLBrowser") or record['COMMAND_LINE'].contains("SQLSafeOLRService") or record['COMMAND_LINE'].contains("SQLSERVERAGENT") or record['COMMAND_LINE'].contains("SQLTELEMETRY") or record['COMMAND_LINE'].contains("SQLTELEMETRY$ECWDB2") or record['COMMAND_LINE'].contains("SQLTELEMETRY$ITRIS") or record['COMMAND_LINE'].contains("SQLWriter") or record['COMMAND_LINE'].contains("SSISTELEMETRY130") or record['COMMAND_LINE'].contains("SstpSvc") or record['COMMAND_LINE'].contains("svcGenericHost") or record['COMMAND_LINE'].contains("svcienericHost") or record['COMMAND_LINE'].contains("swi_filter") or record['COMMAND_LINE'].contains("swi_service") or record['COMMAND_LINE'].contains("swi_update") or record['COMMAND_LINE'].contains("swi_update_64") or record['COMMAND_LINE'].contains("Telemetryserver") or record['COMMAND_LINE'].contains("ThreatLockerService") or record['COMMAND_LINE'].contains("TmCCSF") or record['COMMAND_LINE'].contains("tmlisten") or record['COMMAND_LINE'].contains("TmPfw") or record['COMMAND_LINE'].contains("TrueKey") or record['COMMAND_LINE'].contains("TruekeyScheduler") or record['COMMAND_LINE'].contains("TrueKeyServiceHelper") or record['COMMAND_LINE'].contains("UI0Detect") or record['COMMAND_LINE'].contains("UTODetect") or record['COMMAND_LINE'].contains("VeeamBackupSvc") or record['COMMAND_LINE'].contains("VeeamBrokerSvc") or record['COMMAND_LINE'].contains("VeeamCatalogSvc") or record['COMMAND_LINE'].contains("VeeamCloudSvc") or record['COMMAND_LINE'].contains("VeeamDeploymentService") or record['COMMAND_LINE'].contains("VeeamDeploySvc") or record['COMMAND_LINE'].contains("VeeamEnterpriseHanagerSvc") or record['COMMAND_LINE'].contains("VeeamEnterpriseManagerSvc") or record['COMMAND_LINE'].contains("VeeamHvIntegrationSvc") or record['COMMAND_LINE'].contains("VeeamMountSvc") or record['COMMAND_LINE'].contains("VeeamNFSSvc") or record['COMMAND_LINE'].contains("VeeamRESTSvc") or record['COMMAND_LINE'].contains("VeeamRISTSvc") or record['COMMAND_LINE'].contains("VeeamTransportSvc") or record['COMMAND_LINE'].contains("VeemaDep/oySvc") or record['COMMAND_LINE'].contains("VSS") or record['COMMAND_LINE'].contains("W3Svc") or record['COMMAND_LINE'].contains("wbengine") or record['COMMAND_LINE'].contains("WdNisSvc") or record['COMMAND_LINE'].contains("WeanClOudSve") or record['COMMAND_LINE'].contains("Weems JY") or record['COMMAND_LINE'].contains("WinDefend") or record['COMMAND_LINE'].contains("wozyprobackup") or record['COMMAND_LINE'].contains("WRSVC")) and ((((record['ORIGINAL_FILE_NAME'] == "sc.exe" or record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe") or (record['PROCESS_NAME'].endswith("\\sc.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe"))) and record['COMMAND_LINE'].contains("stop")) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("Stop-Service"))))

sigma_suspicious_stop_windows_service.sigma_meta = dict(
    level="high"
)

def sigma_command_line_path_traversal_evasion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_commandline_path_traversal_evasion.yml
    title: Command Line Path Traversal Evasion
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the attempt to evade or obfuscate the executed command on the CommandLine using bogus path traversal
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].contains("\\Windows") and (record['COMMAND_LINE'].contains("\\..\\Windows") or record['COMMAND_LINE'].contains("\\..\\System32") or record['COMMAND_LINE'].contains("\\..\\.."))) or record['COMMAND_LINE'].contains(".exe\\..")) and not ((record['COMMAND_LINE'].contains("\\Google\\Drive\\googledrivesync.exe\\..") or record['COMMAND_LINE'].contains("\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\.."))))

sigma_command_line_path_traversal_evasion.sigma_meta = dict(
    level="high"
)

def sigma_use_of_anydesk_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_anydesk.yml
    title: Use of Anydesk Remote Access Software
    fields: ['Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "AnyDesk" or record['PRODUCT_NAME'] == "AnyDesk" or record['COMPANY'] == "AnyDesk Software GmbH")

sigma_use_of_anydesk_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_bypass_uac_via_cmstp(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.yml
    title: Bypass UAC via CMSTP
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detect commandline usage of Microsoft Connection Manager Profile Installer (cmstp.exe) to install specially formatted local .INF files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmstp.exe") or record['ORIGINAL_FILE_NAME'] == "CMSTP.EXE") and (record['COMMAND_LINE'].contains("/s") or record['COMMAND_LINE'].contains("-s") or record['COMMAND_LINE'].contains("/au") or record['COMMAND_LINE'].contains("-au") or record['COMMAND_LINE'].contains("/ni") or record['COMMAND_LINE'].contains("-ni")))

sigma_bypass_uac_via_cmstp.sigma_meta = dict(
    level="high"
)

def sigma_inveigh_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_inveigh.yml
    title: Inveigh Hack Tool
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Description']
    level: critical
    description: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Inveigh.exe") or (record['ORIGINAL_FILE_NAME'] == "\\Inveigh.exe" or record['ORIGINAL_FILE_NAME'] == "\\Inveigh.dll") or record['DESCRIPTION'] == "Inveigh" or (record['COMMAND_LINE'].contains("-SpooferIP") or record['COMMAND_LINE'].contains("-ReplyToIPs") or record['COMMAND_LINE'].contains("-ReplyToDomains") or record['COMMAND_LINE'].contains("-ReplyToMACs") or record['COMMAND_LINE'].contains("-SnifferIP")))

sigma_inveigh_hack_tool.sigma_meta = dict(
    level="critical"
)

def sigma_gfxdownloadwrapper_exe_downloads_file_from_suspicious_url(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_file_download_via_gfxdownloadwrapper.yml
    title: GfxDownloadWrapper.exe Downloads File from Suspicious URL
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects when GfxDownloadWrapper.exe downloads file from non standard URL
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\GfxDownloadWrapper.exe") and not (record['COMMAND_LINE'].contains("gameplayapi.intel.com") and record['PARENT_NAME'].endswith("\\GfxDownloadWrapper.exe")))

sigma_gfxdownloadwrapper_exe_downloads_file_from_suspicious_url.sigma_meta = dict(
    level="medium"
)

def sigma_code_execution_via_pcwutl_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_pcwutl.yml
    title: Code Execution via Pcwutl.dll
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("pcwutl") and record['COMMAND_LINE'].contains("LaunchApplication"))

sigma_code_execution_via_pcwutl_dll.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_squirrel_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_squirrel.yml
    title: Use of Squirrel.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: The "Squirrel.exe" binary that is part of multiple software (Slack, Teams, Discord...etc) can be used as a LOLBIN
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\squirrel.exe") and (record['COMMAND_LINE'].contains("--download") or record['COMMAND_LINE'].contains("--update") or record['COMMAND_LINE'].contains("--updateRollback=")) and record['COMMAND_LINE'].contains("http"))

sigma_use_of_squirrel_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_new_service_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_new_service_creation.yml
    title: Suspicious New Service Creation
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\sc.exe") and record['COMMAND_LINE'].contains("create") and record['COMMAND_LINE'].contains("binPath=")) or (record['COMMAND_LINE'].contains("New-Service") and record['COMMAND_LINE'].contains("-BinaryPathName"))) and (record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("wscript") or record['COMMAND_LINE'].contains("cscript") or record['COMMAND_LINE'].contains("svchost") or record['COMMAND_LINE'].contains("dllhost") or record['COMMAND_LINE'].contains("cmd") or record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("C:\\Users\\Public") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") or record['COMMAND_LINE'].contains("C:\\Windows\\TEMP") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp")))

sigma_suspicious_new_service_creation.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_nmap_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_nmap.yml
    title: Suspicious Nmap Execution
    fields: ['OriginalFileName']
    level: high
    description: Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation
    logsource: category:process_creation - product:windows
    """
    return record['ORIGINAL_FILE_NAME'] == "nmap.exe"

sigma_suspicious_nmap_execution.sigma_meta = dict(
    level="high"
)

def sigma_taskmgr_as_local_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_taskmgr_localsystem.yml
    title: Taskmgr as LOCAL_SYSTEM
    fields: ['User', 'Image']
    level: high
    description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
    logsource: category:process_creation - product:windows
    """
    return ((record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")) and record['PROCESS_NAME'].endswith("\\taskmgr.exe"))

sigma_taskmgr_as_local_system.sigma_meta = dict(
    level="high"
)

def sigma_disable_of_etw_trace(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_etw_trace_evasion.yml
    title: Disable of ETW Trace
    fields: ['CommandLine']
    level: high
    description: Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("cl") and record['COMMAND_LINE'].contains("/Trace")) or (record['COMMAND_LINE'].contains("clear-log") and record['COMMAND_LINE'].contains("/Trace")) or (record['COMMAND_LINE'].contains("sl") and record['COMMAND_LINE'].contains("/e:false")) or (record['COMMAND_LINE'].contains("set-log") and record['COMMAND_LINE'].contains("/e:false")) or (record['COMMAND_LINE'].contains("logman") and record['COMMAND_LINE'].contains("update") and record['COMMAND_LINE'].contains("trace") and record['COMMAND_LINE'].contains("--p") and record['COMMAND_LINE'].contains("-ets")) or record['COMMAND_LINE'].contains("Remove-EtwTraceProvider") or (record['COMMAND_LINE'].contains("Set-EtwTraceProvider") and record['COMMAND_LINE'].contains("0x11")))

sigma_disable_of_etw_trace.sigma_meta = dict(
    level="high"
)

def sigma_control_panel_items(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_control_panel_item.yml
    title: Control Panel Items
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the malicious use of a control panel item
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and (record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("CurrentVersion\\Control Panel\\CPLs"))) or (record['COMMAND_LINE'].endswith(".cpl") and not (((record['COMMAND_LINE'].contains("\\System32") or record['COMMAND_LINE'].contains("%System%"))) or (record['COMMAND_LINE'].contains("regsvr32") and record['COMMAND_LINE'].contains("/s") and record['COMMAND_LINE'].contains("igfxCPL.cpl")))))

sigma_control_panel_items.sigma_meta = dict(
    level="high"
)

def sigma_dll_sideloading_by_vmware_xfer_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dll_sideload_vmware_xfer.yml
    title: DLL Sideloading by VMware Xfer Utility
    fields: ['Image']
    level: high
    description: Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\VMwareXferlogs.exe") and not (record['PROCESS_NAME'].startswith("C:\\Program Files\\VMware")))

sigma_dll_sideloading_by_vmware_xfer_utility.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_hwp_sub_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hwp_exploits.yml
    title: Suspicious HWP Sub Processes
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious Hangul Word Processor (Hanword) sub processes that could indicate an exploitation
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\Hwp.exe") and record['PROCESS_NAME'].endswith("\\gbb.exe"))

sigma_suspicious_hwp_sub_processes.sigma_meta = dict(
    level="high"
)

def sigma_run_once_task_execution_as_configured_in_registry(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_runonce_execution.yml
    title: Run Once Task Execution as Configured in Registry
    fields: ['CommandLine', 'Image', 'Description']
    level: low
    description: This rule detects the execution of Run Once task as configured in the registry
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\runonce.exe") or record['DESCRIPTION'] == "Run Once Wrapper") and record['COMMAND_LINE'].contains("/AlternateShellStartup"))

sigma_run_once_task_execution_as_configured_in_registry.sigma_meta = dict(
    level="low"
)

def sigma_too_long_powershell_commandlines(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_long_powershell_commandline.yml
    title: Too Long PowerShell Commandlines
    fields: ['CommandLine', 'Product', 'Description']
    level: low
    description: Detects Too long PowerShell command lines
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("pwsh")) or record['DESCRIPTION'] == "Windows Powershell" or record['PRODUCT_NAME'] == "PowerShell Core 6") and re.match('.{1000,}', record['COMMAND_LINE']))

sigma_too_long_powershell_commandlines.sigma_meta = dict(
    level="low"
)

def sigma_proxy_execution_via_explorer_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_explorer.yml
    title: Proxy Execution Via Explorer.exe
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: low
    description: Attackers can use explorer.exe for evading defense mechanisms
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\explorer.exe") and record['PARENT_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("explorer.exe"))

sigma_proxy_execution_via_explorer_exe.sigma_meta = dict(
    level="low"
)

def sigma_possible_privilege_escalation_via_weak_service_permissions(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_using_sc_to_change_sevice_image_path_by_non_admin.yml
    title: Possible Privilege Escalation via Weak Service Permissions
    fields: ['IntegrityLevel', 'Image', 'CommandLine']
    level: high
    description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sc.exe") and record['INTEGRITY_LEVEL'] == "Medium") and ((record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("binPath")) or (record['COMMAND_LINE'].contains("failure") and record['COMMAND_LINE'].contains("command"))))

sigma_possible_privilege_escalation_via_weak_service_permissions.sigma_meta = dict(
    level="high"
)

def sigma_devtoolslauncher_exe_executes_specified_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_devtoolslauncher.yml
    title: Devtoolslauncher.exe Executes Specified Binary
    fields: ['CommandLine', 'Image']
    level: high
    description: The Devtoolslauncher.exe executes other binary
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\devtoolslauncher.exe") and record['COMMAND_LINE'].contains("LaunchForDeploy"))

sigma_devtoolslauncher_exe_executes_specified_binary.sigma_meta = dict(
    level="high"
)

def sigma_formbook_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_formbook.yml
    title: Formbook Process Creation
    fields: ['CommandLine', 'ParentCommandLine']
    level: high
    description: Detects Formbook like process executions that inject code into a set of files in the System32 folder, which executes a special command command line to delete the dropper from the AppData Temp folder. We avoid false positives by excluding all parent process with command line parameters.
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_COMMAND_LINE'].startswith("C:\\Windows\\System32") or record['PARENT_COMMAND_LINE'].startswith("C:\\Windows\\SysWOW64")) and record['PARENT_COMMAND_LINE'].endswith(".exe")) and ((record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("del") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp")) or (record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("del") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\Desktop")) or (record['COMMAND_LINE'].contains("/C") and record['COMMAND_LINE'].contains("type nul >") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\Desktop"))) and record['COMMAND_LINE'].endswith(".exe"))

sigma_formbook_process_creation.sigma_meta = dict(
    level="high"
)

def sigma_obfuscated_command_line_using_special_unicode_characters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_char_in_cmd.yml
    title: Obfuscated Command Line Using Special Unicode Characters
    fields: ['CommandLine']
    level: high
    description: Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("â") or record['COMMAND_LINE'].contains("€") or record['COMMAND_LINE'].contains("£") or record['COMMAND_LINE'].contains("¯") or record['COMMAND_LINE'].contains("®") or record['COMMAND_LINE'].contains("µ") or record['COMMAND_LINE'].contains("¶"))

sigma_obfuscated_command_line_using_special_unicode_characters.sigma_meta = dict(
    level="high"
)

def sigma_equation_group_dll_u_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_equationgroup_dll_u_load.yml
    title: Equation Group DLL_U Load
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects a specific tool and export used by EquationGroup
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].endswith(",dll_u")) or record['COMMAND_LINE'].contains("-export dll_u"))

sigma_equation_group_dll_u_load.sigma_meta = dict(
    level="critical"
)

def sigma_use_of_gotoassist_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_gotoopener.yml
    title: Use of GoToAssist Remote Access Software
    fields: ['Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "GoTo Opener" or record['PRODUCT_NAME'] == "GoTo Opener" or record['COMPANY'] == "LogMeIn, Inc.")

sigma_use_of_gotoassist_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_minimized_msedge_start(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msedge_minimized_download.yml
    title: Suspicious Minimized MSEdge Start
    fields: ['CommandLine']
    level: high
    description: Detects the suspicious minimized start of MsEdge browser, which can be used to download files from the Internet
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("start /min msedge")

sigma_suspicious_minimized_msedge_start.sigma_meta = dict(
    level="high"
)

def sigma_nircmd_tool_execution_as_local_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tool_nircmd_as_system.yml
    title: NirCmd Tool Execution As LOCAL SYSTEM
    fields: ['CommandLine']
    level: high
    description: Detects the use of NirCmd tool for command execution as SYSTEM user
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("runassystem")

sigma_nircmd_tool_execution_as_local_system.sigma_meta = dict(
    level="high"
)

def sigma_wab_execution_from_non_default_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wab_execution_from_non_default_location.yml
    title: Wab Execution From Non Default Location
    fields: ['Image']
    level: high
    description: Detects execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wab.exe") or record['PROCESS_NAME'].endswith("\\wabmig.exe")) and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\WinSxS") or record['PROCESS_NAME'].startswith("C:\\Program Files\\Windows Mail") or record['PROCESS_NAME'].startswith("C:\\Program Files (x86)\\Windows Mail"))))

sigma_wab_execution_from_non_default_location.sigma_meta = dict(
    level="high"
)

def sigma_execute_arbitrary_commands_using_msdt_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msdt.yml
    title: Execute Arbitrary Commands Using MSDT.EXE
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects processes leveraging the "ms-msdt" handler or the "msdt.exe" binary to execute arbitrary commands as seen in the follina (CVE-2022-30190) vulnerability
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msdt.exe") or record['ORIGINAL_FILE_NAME'] == "msdt.exe") and (record['COMMAND_LINE'].contains("IT_BrowseForFile=") or (record['COMMAND_LINE'].contains("PCWDiagnostic") and (record['COMMAND_LINE'].contains("/af") or record['COMMAND_LINE'].contains("-af")))))

sigma_execute_arbitrary_commands_using_msdt_exe.sigma_meta = dict(
    level="high"
)

def sigma_malicious_base64_encoded_powershell_keywords_in_command_lines(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_hidden_b64_cmd.yml
    title: Malicious Base64 Encoded PowerShell Keywords in Command Lines
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects base64 encoded strings used in hidden malicious PowerShell command lines
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("hidden") and (record['COMMAND_LINE'].contains("AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA") or record['COMMAND_LINE'].contains("aXRzYWRtaW4gL3RyYW5zZmVy") or record['COMMAND_LINE'].contains("IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA") or record['COMMAND_LINE'].contains("JpdHNhZG1pbiAvdHJhbnNmZX") or record['COMMAND_LINE'].contains("YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg") or record['COMMAND_LINE'].contains("Yml0c2FkbWluIC90cmFuc2Zlc") or record['COMMAND_LINE'].contains("AGMAaAB1AG4AawBfAHMAaQB6AGUA") or record['COMMAND_LINE'].contains("JABjAGgAdQBuAGsAXwBzAGkAegBlA") or record['COMMAND_LINE'].contains("JGNodW5rX3Npem") or record['COMMAND_LINE'].contains("QAYwBoAHUAbgBrAF8AcwBpAHoAZQ") or record['COMMAND_LINE'].contains("RjaHVua19zaXpl") or record['COMMAND_LINE'].contains("Y2h1bmtfc2l6Z") or record['COMMAND_LINE'].contains("AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A") or record['COMMAND_LINE'].contains("kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg") or record['COMMAND_LINE'].contains("lPLkNvbXByZXNzaW9u") or record['COMMAND_LINE'].contains("SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA") or record['COMMAND_LINE'].contains("SU8uQ29tcHJlc3Npb2") or record['COMMAND_LINE'].contains("Ty5Db21wcmVzc2lvb") or record['COMMAND_LINE'].contains("AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ") or record['COMMAND_LINE'].contains("kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA") or record['COMMAND_LINE'].contains("lPLk1lbW9yeVN0cmVhb") or record['COMMAND_LINE'].contains("SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A") or record['COMMAND_LINE'].contains("SU8uTWVtb3J5U3RyZWFt") or record['COMMAND_LINE'].contains("Ty5NZW1vcnlTdHJlYW") or record['COMMAND_LINE'].contains("4ARwBlAHQAQwBoAHUAbgBrA") or record['COMMAND_LINE'].contains("5HZXRDaHVua") or record['COMMAND_LINE'].contains("AEcAZQB0AEMAaAB1AG4Aaw") or record['COMMAND_LINE'].contains("LgBHAGUAdABDAGgAdQBuAGsA") or record['COMMAND_LINE'].contains("LkdldENodW5r") or record['COMMAND_LINE'].contains("R2V0Q2h1bm") or record['COMMAND_LINE'].contains("AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A") or record['COMMAND_LINE'].contains("QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA") or record['COMMAND_LINE'].contains("RIUkVBRF9JTkZPNj") or record['COMMAND_LINE'].contains("SFJFQURfSU5GTzY0") or record['COMMAND_LINE'].contains("VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA") or record['COMMAND_LINE'].contains("VEhSRUFEX0lORk82N") or record['COMMAND_LINE'].contains("AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA") or record['COMMAND_LINE'].contains("cmVhdGVSZW1vdGVUaHJlYW") or record['COMMAND_LINE'].contains("MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA") or record['COMMAND_LINE'].contains("NyZWF0ZVJlbW90ZVRocmVhZ") or record['COMMAND_LINE'].contains("Q3JlYXRlUmVtb3RlVGhyZWFk") or record['COMMAND_LINE'].contains("QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA") or record['COMMAND_LINE'].contains("0AZQBtAG0AbwB2AGUA") or record['COMMAND_LINE'].contains("1lbW1vdm") or record['COMMAND_LINE'].contains("AGUAbQBtAG8AdgBlA") or record['COMMAND_LINE'].contains("bQBlAG0AbQBvAHYAZQ") or record['COMMAND_LINE'].contains("bWVtbW92Z") or record['COMMAND_LINE'].contains("ZW1tb3Zl")))

sigma_malicious_base64_encoded_powershell_keywords_in_command_lines.sigma_meta = dict(
    level="high"
)

def sigma_run_whoami_as_privileged_user(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_whoami_as_priv_user.yml
    title: Run Whoami as Privileged User
    fields: ['User', 'Image', 'OriginalFileName']
    level: high
    description: Detects a whoami.exe executed by privileged accounts that are often misused by threat actors
    logsource: category:process_creation - product:windows
    """
    return (record['USERNAME'].contains("TrustedInstaller") and (record['ORIGINAL_FILE_NAME'] == "whoami.exe" or record['PROCESS_NAME'].endswith("\\whoami.exe")))

sigma_run_whoami_as_privileged_user.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_usage_of_active_directory_diagnostic_tool_ntdsutil_exe_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ntdsutil_usage.yml
    title: Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe)
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects execution of ntdsutil.exe to perform different actions such as restoring snapshots...etc.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ntdsutil.exe") or record['ORIGINAL_FILE_NAME'] == "ntdsutil.exe") and ((record['COMMAND_LINE'].contains("snapshot") and record['COMMAND_LINE'].contains("mount")) or (record['COMMAND_LINE'].contains("ac") and record['COMMAND_LINE'].contains("i") and record['COMMAND_LINE'].contains("ntds"))))

sigma_suspicious_usage_of_active_directory_diagnostic_tool_ntdsutil_exe_.sigma_meta = dict(
    level="medium"
)

def sigma_stop_windows_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_service_stop.yml
    title: Stop Windows Service
    fields: ['CommandLine', 'User', 'Image', 'OriginalFileName']
    level: low
    description: Detects a windows service to be stopped
    logsource: category:process_creation - product:windows
    """
    return (((((record['ORIGINAL_FILE_NAME'] == "sc.exe" or record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe") or (record['PROCESS_NAME'].endswith("\\sc.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe"))) and record['COMMAND_LINE'].contains("stop")) and not (record['COMMAND_LINE'] == "sc  stop KSCWebConsoleMessageQueue" and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("Stop-Service")))

sigma_stop_windows_service.sigma_meta = dict(
    level="low"
)

def sigma_cobaltstrike_process_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cobaltstrike_process_patterns.yml
    title: CobaltStrike Process Patterns
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects process patterns found in Cobalt Strike beacon activity (see reference for more details) and also cases in which a China Chopper like webshell is used to run whoami
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("\\cmd.exe /C whoami") and record['PARENT_NAME'].startswith("C:\\Temp")) or ((record['COMMAND_LINE'].contains("cmd.exe /c echo") or record['COMMAND_LINE'].contains("> \\\\\\\\.\\\\pipe") or record['COMMAND_LINE'].contains("\\whoami.exe")) and record['PARENT_NAME'].endswith("\\dllhost.exe")) or (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['PARENT_NAME'].endswith("\\runonce.exe") and record['PARENT_COMMAND_LINE'].endswith("\\runonce.exe"))) or ((record['COMMAND_LINE'].contains("conhost.exe 0xffffffff -ForceV1") and (record['PARENT_COMMAND_LINE'].contains("/C whoami") or record['PARENT_COMMAND_LINE'].contains("cmd.exe /C echo") or record['PARENT_COMMAND_LINE'].contains("> \\\\\\\\.\\\\pipe"))) and not ((record['PARENT_COMMAND_LINE'].contains("C:\\Program Files (x86)\\Internet Download Manager\\IDMMsgHost.exe") or record['PARENT_COMMAND_LINE'].contains("chrome-extension://")))))

sigma_cobaltstrike_process_patterns.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rasdial_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rasdial_activity.yml
    title: Suspicious RASdial Activity
    fields: ['Image']
    level: medium
    description: Detects suspicious process related to rasdial.exe
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("rasdial.exe")

sigma_suspicious_rasdial_activity.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_iis_module_registration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_iis_module_registration.yml
    title: Suspicious IIS Module Registration
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("appcmd.exe add module") and record['PARENT_NAME'].endswith("\\w3wp.exe")) or (record['COMMAND_LINE'].contains("system.enterpriseservices.internal.publish") and record['PARENT_NAME'].endswith("\\w3wp.exe") and record['PROCESS_NAME'].endswith("\\powershell.exe")) or (record['COMMAND_LINE'].contains("\\\\gacutil.exe /I") and record['PARENT_NAME'].endswith("\\w3wp.exe")))

sigma_suspicious_iis_module_registration.sigma_meta = dict(
    level="high"
)

def sigma_darkside_ransomware_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_darkside_ransomware.yml
    title: DarkSide Ransomware Pattern
    fields: ['CommandLine', 'Image', 'ParentCommandLine']
    level: critical
    description: Detects DarkSide Ransomware and helpers
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("=[char][byte](\'0x\'+") or record['COMMAND_LINE'].contains("-work worker0 -path")) or (record['PARENT_COMMAND_LINE'].contains("DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}") and record['PROCESS_NAME'].contains("\\AppData\\Local\\Temp")))

sigma_darkside_ransomware_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_turla_group_commands_may_2020(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_turla_comrat_may20.yml
    title: Turla Group Commands May 2020
    fields: ['CommandLine']
    level: critical
    description: Detects commands used by Turla group as reported by ESET in May 2020
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("tracert -h 10 yahoo.com") or record['COMMAND_LINE'].contains(".WSqmCons))|iex;") or record['COMMAND_LINE'].contains("Fr`omBa`se6`4Str`ing")) or (record['COMMAND_LINE'].contains("net use https://docs.live.net") and record['COMMAND_LINE'].contains("@aol.co.uk")))

sigma_turla_group_commands_may_2020.sigma_meta = dict(
    level="critical"
)

def sigma_renamed_procdump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_procdump.yml
    title: Renamed ProcDump
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the execution of a renamed ProcDump executable often used by attackers or malware
    logsource: product:windows - category:process_creation
    """
    return ((record['ORIGINAL_FILE_NAME'] == "procdump" or ((record['COMMAND_LINE'].contains("-ma") or record['COMMAND_LINE'].contains("/ma")) and (record['COMMAND_LINE'].contains("-accepteula") or record['COMMAND_LINE'].contains("/accepteula")))) and not ((record['PROCESS_NAME'].endswith("\\procdump.exe") or record['PROCESS_NAME'].endswith("\\procdump64.exe"))))

sigma_renamed_procdump.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_mofcomp_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mofcomp_execution.yml
    title: Suspicious Mofcomp Execution
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a supsicious path in the commandline.
The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
Attackers abuse this utility to install malicious MOF scripts

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\mofcomp.exe") and ((record['PARENT_NAME'].endswith("\\cmd.exe") or record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\wsl.exe") or record['PARENT_NAME'].endswith("\\wscript.exe") or record['PARENT_NAME'].endswith("\\cscript.exe")) or (record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\WINDOWS\\Temp") or record['COMMAND_LINE'].contains("%temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("%appdata%"))))

sigma_suspicious_mofcomp_execution.sigma_meta = dict(
    level="medium"
)

def sigma_pchunter_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_pchunter.yml
    title: PCHunter Usage
    fields: ['Image', 'md5', 'imphash', 'Hashes', 'OriginalFileName', 'Description', 'sha1', 'sha256']
    level: high
    description: Detects suspicious use of PCHunter, a tool like Process Hacker to view and manipulate processes, kernel options and other low level stuff
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\PCHunter64.exe") or record['PROCESS_NAME'].endswith("\\PCHunter32.exe")) or record['ORIGINAL_FILE_NAME'] == "PCHunter.exe" or record['DESCRIPTION'] == "Epoolsoft Windows Information View Tools" or (record['HASHES'].contains("SHA1=5F1CBC3D99558307BC1250D084FA968521482025") or record['HASHES'].contains("MD5=987B65CD9B9F4E9A1AFD8F8B48CF64A7") or record['HASHES'].contains("SHA256=2B214BDDAAB130C274DE6204AF6DBA5AEEC7433DA99AA950022FA306421A6D32") or record['HASHES'].contains("IMPHASH=444D210CEA1FF8112F256A4997EED7FF") or record['HASHES'].contains("SHA1=3FB89787CB97D902780DA080545584D97FB1C2EB") or record['HASHES'].contains("MD5=228DD0C2E6287547E26FFBD973A40F14") or record['HASHES'].contains("SHA256=55F041BF4E78E9BFA6D4EE68BE40E496CE3A1353E1CA4306598589E19802522C") or record['HASHES'].contains("IMPHASH=0479F44DF47CFA2EF1CCC4416A538663")) or (record['MD5'] == "228dd0c2e6287547e26ffbd973a40f14" or record['MD5'] == "987b65cd9b9f4e9a1afd8f8b48cf64a7") or (record['SHA1'] == "5f1cbc3d99558307bc1250d084fa968521482025" or record['SHA1'] == "3fb89787cb97d902780da080545584d97fb1c2eb") or (record['SHA256'] == "2b214bddaab130c274de6204af6dba5aeec7433da99aa950022fa306421a6d32" or record['SHA256'] == "55f041bf4e78e9bfa6d4ee68be40e496ce3a1353e1ca4306598589e19802522c") or (record['IMPHASH'] == "444d210cea1ff8112f256a4997eed7ff" or record['IMPHASH'] == "0479f44df47cfa2ef1ccc4416a538663"))

sigma_pchunter_usage.sigma_meta = dict(
    level="high"
)

def sigma_modifies_the_registry_from_a_ads(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regini_ads.yml
    title: Modifies the Registry From a ADS
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regini.exe") or record['ORIGINAL_FILE_NAME'] == "REGINI.EXE") and re.match(':[^ \\\\]', record['COMMAND_LINE']))

sigma_modifies_the_registry_from_a_ads.sigma_meta = dict(
    level="high"
)

def sigma_cabinet_file_expansion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_expand_cabinet_files.yml
    title: Cabinet File Expansion
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Adversaries can use the inbuilt expand utility to decompress cab files as seen in recent Iranian MeteorExpress attack
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\expand.exe") and (record['COMMAND_LINE'].contains(".cab") or record['COMMAND_LINE'].contains("/F:") or record['COMMAND_LINE'].contains("-F:") or record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("C:\\Public") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("\\AppData\\Roaming\\Temp"))) and not ((record['PARENT_NAME'] == "C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe" and record['COMMAND_LINE'].contains("C:\\ProgramData\\Dell\\UpdateService\\Temp"))))

sigma_cabinet_file_expansion.sigma_meta = dict(
    level="medium"
)

def sigma_webshell_recon_detection_via_commandline_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webshell_recon_detection.yml
    title: Webshell Recon Detection Via CommandLine & Processes
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects processes spawned from web servers (php, tomcat, iis...etc) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\php-cgi.exe") or record['PARENT_NAME'].endswith("\\nginx.exe") or record['PARENT_NAME'].endswith("\\httpd.exe") or record['PARENT_NAME'].endswith("\\caddy.exe") or record['PARENT_NAME'].endswith("\\ws_tomcatservice.exe")) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['PARENT_NAME'].contains("-tomcat-") or record['PARENT_NAME'].contains("\\tomcat"))) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['COMMAND_LINE'].contains("catalina.jar") or record['COMMAND_LINE'].contains("CATALINA_HOME")))) and (record['COMMAND_LINE'].contains("perl --help") or record['COMMAND_LINE'].contains("python --help") or record['COMMAND_LINE'].contains("python -h") or record['COMMAND_LINE'].contains("python3 --help") or record['COMMAND_LINE'].contains("python3 -h") or record['COMMAND_LINE'].contains("wget --help") or record['COMMAND_LINE'].contains("perl -h")))

sigma_webshell_recon_detection_via_commandline_processes.sigma_meta = dict(
    level="high"
)

def sigma_cmstp_execution_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml
    title: CMSTP Execution Process Creation
    fields: ['ParentImage']
    level: high
    description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\cmstp.exe")

sigma_cmstp_execution_process_creation.sigma_meta = dict(
    level="high"
)

def sigma_impacket_lateralization_detection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_impacket_lateralization.yml
    title: Impacket Lateralization Detection
    fields: ['CommandLine', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\wmiprvse.exe") or record['PARENT_NAME'].endswith("\\mmc.exe") or record['PARENT_NAME'].endswith("\\explorer.exe") or record['PARENT_NAME'].endswith("\\services.exe")) and record['COMMAND_LINE'].contains("cmd.exe") and record['COMMAND_LINE'].contains("/Q") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("\\\\\\\\127.0.0.1") and record['COMMAND_LINE'].contains("&1")) or ((record['PARENT_COMMAND_LINE'].contains("svchost.exe -k netsvcs") or record['PARENT_COMMAND_LINE'].contains("taskeng.exe")) and record['COMMAND_LINE'].contains("cmd.exe") and record['COMMAND_LINE'].contains("/C") and record['COMMAND_LINE'].contains("Windows\\Temp") and record['COMMAND_LINE'].contains("&1")))

sigma_impacket_lateralization_detection.sigma_meta = dict(
    level="high"
)

def sigma_wmi_reconnaissance_list_remote_services(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_remote_service.yml
    title: WMI Reconnaissance List Remote Services
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: An adversary might use WMI to check if a certain Remote Service is running on a remote device.
When the test completes, a service information will be displayed on the screen if it exists.
A common feedback message is that "No instance(s) Available" if the service queried is not running.
A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreachable

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("/node:") and record['COMMAND_LINE'].contains("service")))

sigma_wmi_reconnaissance_list_remote_services.sigma_meta = dict(
    level="medium"
)

def sigma_frombase64string_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml
    title: FromBase64String Command Line
    fields: ['CommandLine']
    level: high
    description: Detects suspicious FromBase64String expressions in command line arguments
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("::FromBase64String(")

sigma_frombase64string_command_line.sigma_meta = dict(
    level="high"
)

def sigma_tasks_folder_evasion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_task_folder_evasion.yml
    title: Tasks Folder Evasion
    fields: ['CommandLine']
    level: high
    description: The Tasks folder in system32 and syswow64 are globally writable paths.
Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application 
in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr

    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("echo") or record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("type") or record['COMMAND_LINE'].contains("file createnew")) and (record['COMMAND_LINE'].contains("C:\\Windows\\System32\\Tasks") or record['COMMAND_LINE'].contains("C:\\Windows\\SysWow64\\Tasks")))

sigma_tasks_folder_evasion.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_wmic_execution_processcallcreate(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wmic_proc_create.yml
    title: Suspicious WMIC Execution - ProcessCallCreate
    fields: ['CommandLine']
    level: high
    description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32"...etc
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("process") and record['COMMAND_LINE'].contains("call") and record['COMMAND_LINE'].contains("create") and (record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("bitsadmin") or record['COMMAND_LINE'].contains("regsvr32") or record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd /r") or record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("pwsh") or record['COMMAND_LINE'].contains("certutil") or record['COMMAND_LINE'].contains("cscript") or record['COMMAND_LINE'].contains("wscript") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\Windows\\Temp") or record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("%temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("%ProgramData%") or record['COMMAND_LINE'].contains("%appdata%") or record['COMMAND_LINE'].contains("%comspec%") or record['COMMAND_LINE'].contains("%localappdata%")))

sigma_suspicious_wmic_execution_processcallcreate.sigma_meta = dict(
    level="high"
)

def sigma_bitsadmin_download_from_suspicious_domain(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_domain.yml
    title: Bitsadmin Download from Suspicious Domain
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of bitsadmin downloading a file from a suspicious domain
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/transfer") or record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and (record['COMMAND_LINE'].contains("raw.githubusercontent.com") or record['COMMAND_LINE'].contains("gist.githubusercontent.com") or record['COMMAND_LINE'].contains("pastebin.com") or record['COMMAND_LINE'].contains("cdn.discordapp.com/attachments/") or record['COMMAND_LINE'].contains("mediafire.com") or record['COMMAND_LINE'].contains("mega.nz") or record['COMMAND_LINE'].contains("ddns.net") or record['COMMAND_LINE'].contains(".paste.ee") or record['COMMAND_LINE'].contains(".hastebin.com") or record['COMMAND_LINE'].contains(".ghostbin.co/") or record['COMMAND_LINE'].contains("ufile.io") or record['COMMAND_LINE'].contains("storage.googleapis.com") or record['COMMAND_LINE'].contains("anonfiles.com") or record['COMMAND_LINE'].contains("send.exploit.in") or record['COMMAND_LINE'].contains("transfer.sh")))

sigma_bitsadmin_download_from_suspicious_domain.sigma_meta = dict(
    level="medium"
)

def sigma_bitsadmin_download_to_uncommon_target_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download_uncommon_targetfolder.yml
    title: Bitsadmin Download to Uncommon Target Folder
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of bitsadmin downloading a file to uncommon target folder
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/transfer") or record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and (record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("%temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("%ProgramData%") or record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("%AppData%")))

sigma_bitsadmin_download_to_uncommon_target_folder.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_webdav_client_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_webdav_client_execution.yml
    title: Suspicious WebDav Client Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: A General detection for svchost.exe spawning rundll32.exe with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie.
This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server).

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE") and record['COMMAND_LINE'].contains("C:\\windows\\system32\\davclnt.dll,DavSetCookie"))

sigma_suspicious_webdav_client_execution.sigma_meta = dict(
    level="medium"
)

def sigma_empire_monkey(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_empiremonkey.yml
    title: Empire Monkey
    fields: ['CommandLine', 'Image', 'Description']
    level: critical
    description: Detects EmpireMonkey APT reported Activity
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].endswith("/i:%APPDATA%\\logs.txt scrobj.dll") and record['PROCESS_NAME'].endswith("\\cutil.exe")) or (record['COMMAND_LINE'].endswith("/i:%APPDATA%\\logs.txt scrobj.dll") and record['DESCRIPTION'] == "Microsoft(C) Registerserver"))

sigma_empire_monkey.sigma_meta = dict(
    level="critical"
)

def sigma_wab_wabmig_unusual_parent_or_child_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wab_unusual_parents.yml
    title: Wab/Wabmig Unusual Parent Or Child Processes
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\WmiPrvSE.exe") or record['PARENT_NAME'].endswith("\\svchost.exe") or record['PARENT_NAME'].endswith("\\dllhost.exe")) and (record['PROCESS_NAME'].endswith("\\wab.exe") or record['PROCESS_NAME'].endswith("\\wabmig.exe"))) or (record['PARENT_NAME'].endswith("\\wab.exe") or record['PARENT_NAME'].endswith("\\wabmig.exe")))

sigma_wab_wabmig_unusual_parent_or_child_processes.sigma_meta = dict(
    level="high"
)

def sigma_powershell_download_from_url(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_download.yml
    title: PowerShell Download from URL
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects a Powershell process that contains download commands in its command line string
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("new-object") and record['COMMAND_LINE'].contains("net.webclient).") and record['COMMAND_LINE'].contains("download") and (record['COMMAND_LINE'].contains("string(") or record['COMMAND_LINE'].contains("file(")))

sigma_powershell_download_from_url.sigma_meta = dict(
    level="medium"
)

def sigma_dll_sideloading_via_deviceenroller_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_deviceenroller_evasion.yml
    title: DLL Sideloading via DeviceEnroller.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the use of the PhoneDeepLink parameter to potentially sideload a DLL file that doesnt exist. This non-existent DLL file is named "ShellChromeAPI.dll". 
Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\deviceenroller.exe") and record['COMMAND_LINE'].contains("/PhoneDeepLink"))

sigma_dll_sideloading_via_deviceenroller_exe.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_vsiisexelauncher_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_vsiisexelauncher.yml
    title: Use of VSIISExeLauncher.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\VSIISExeLauncher.exe") or record['ORIGINAL_FILE_NAME'] == "VSIISExeLauncher.exe") and (record['COMMAND_LINE'].contains("-p") or record['COMMAND_LINE'].contains("-a")))

sigma_use_of_vsiisexelauncher_exe.sigma_meta = dict(
    level="medium"
)

def sigma_uncommon_scheduled_task_once_00_00(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_schtasks_once_0000.yml
    title: Uncommon Scheduled Task Once 00:00
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\schtasks.exe") and (record['COMMAND_LINE'].contains("wscript") or record['COMMAND_LINE'].contains("vbscript") or record['COMMAND_LINE'].contains("cscript") or record['COMMAND_LINE'].contains("wmic") or record['COMMAND_LINE'].contains("wmic.exe") or record['COMMAND_LINE'].contains("regsvr32.exe") or record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("\\AppData"))) and ((record['COMMAND_LINE'].contains("once") and record['COMMAND_LINE'].contains("00:00")) or record['COMMAND_LINE'].contains("Joke")))

sigma_uncommon_scheduled_task_once_00_00.sigma_meta = dict(
    level="high"
)

def sigma_use_of_clip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_clip.yml
    title: Use of CLIP
    fields: ['Image', 'OriginalFileName']
    level: low
    description: Adversaries may collect data stored in the clipboard from users copying information within or between applications.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\clip.exe") or record['ORIGINAL_FILE_NAME'] == "clip.exe")

sigma_use_of_clip.sigma_meta = dict(
    level="low"
)

def sigma_redmimicry_winnti_playbook_execute(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_redmimicry_winnti_proc.yml
    title: RedMimicry Winnti Playbook Execute
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects actions caused by the RedMimicry Winnti playbook
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].contains("rundll32.exe") or record['PROCESS_NAME'].contains("cmd.exe")) and (record['COMMAND_LINE'].contains("gthread-3.6.dll") or record['COMMAND_LINE'].contains("\\Windows\\Temp\\tmp.bat") or record['COMMAND_LINE'].contains("sigcmm-2.4.dll")))

sigma_redmimicry_winnti_playbook_execute.sigma_meta = dict(
    level="high"
)

def sigma_dllhost_process_with_no_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_dllhost_no_cli.yml
    title: Dllhost Process With No CommandLine
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a "dllhost" spawning with no commandline arguments which is a very rare thing to happen and could indicate process injection activity or malware mimicking similar system processes
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].endswith("dllhost.exe") and record['PROCESS_NAME'].endswith("\\dllhost.exe"))

sigma_dllhost_process_with_no_commandline.sigma_meta = dict(
    level="high"
)

def sigma_run_whoami_showing_privileges(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_whoami_priv.yml
    title: Run Whoami Showing Privileges
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\whoami.exe") or record['ORIGINAL_FILE_NAME'] == "whoami.exe") and record['COMMAND_LINE'].contains("/priv"))

sigma_run_whoami_showing_privileges.sigma_meta = dict(
    level="high"
)

def sigma_lazarus_activity_dec20(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_lazarus_activity_dec20.yml
    title: Lazarus Activity Dec20
    fields: ['CommandLine']
    level: critical
    description: Detects different process creation events as described in various threat reports on Lazarus group activity
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("reg.exe save hklm\\sam %temp%\\~reg_sam.save") or record['COMMAND_LINE'].contains("1q2w3e4r@#$@#$@#$") or record['COMMAND_LINE'].contains("-hp1q2w3e4") or record['COMMAND_LINE'].contains(".dat data03 10000 -p")) or (record['COMMAND_LINE'].contains("process call create") and record['COMMAND_LINE'].contains("> %temp%\\~")) or (record['COMMAND_LINE'].contains("netstat -aon | find") and record['COMMAND_LINE'].contains("> %temp%\\~")) or record['COMMAND_LINE'].contains(".255 10 C:\\ProgramData"))

sigma_lazarus_activity_dec20.sigma_meta = dict(
    level="critical"
)

def sigma_base64_mz_header_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_inline_base64_mz_header.yml
    title: Base64 MZ Header In CommandLine
    fields: ['CommandLine']
    level: high
    description: Detects encoded base64 MZ header in the commandline
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("TVqQAAMAAAAEAAAA") or record['COMMAND_LINE'].contains("TVpQAAIAAAAEAA8A") or record['COMMAND_LINE'].contains("TVqAAAEAAAAEABAA") or record['COMMAND_LINE'].contains("TVoAAAAAAAAAAAAA") or record['COMMAND_LINE'].contains("TVpTAQEAAAAEAAAA"))

sigma_base64_mz_header_in_commandline.sigma_meta = dict(
    level="high"
)

def sigma_netsh_port_forwarding(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_port_fwd.yml
    title: Netsh Port Forwarding
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects netsh commands that configure a port forwarding (PortProxy)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("interface") and record['COMMAND_LINE'].contains("portproxy") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("v4tov4")) or (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("connectp") and record['COMMAND_LINE'].contains("listena") and record['COMMAND_LINE'].contains("c=")))

sigma_netsh_port_forwarding.sigma_meta = dict(
    level="medium"
)

def sigma_sharpersist_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_sharpersist.yml
    title: SharPersist Usage
    fields: ['CommandLine', 'Image', 'Product']
    level: high
    description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SharPersist.exe") or record['PRODUCT_NAME'] == "SharPersist" or (record['COMMAND_LINE'].contains("-t schtask -c") or record['COMMAND_LINE'].contains("-t startupfolder -c")) or (record['COMMAND_LINE'].contains("-t reg -c") and record['COMMAND_LINE'].contains("-m add")) or (record['COMMAND_LINE'].contains("-t service -c") and record['COMMAND_LINE'].contains("-m add")) or (record['COMMAND_LINE'].contains("-t schtask -c") and record['COMMAND_LINE'].contains("-m add")))

sigma_sharpersist_usage.sigma_meta = dict(
    level="high"
)

def sigma_gmer_rootkit_detector_and_remover_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_gmer_execution.yml
    title: GMER - Rootkit Detector and Remover Execution
    fields: ['Image', 'Hashes', 'SHA1', 'SHA256', 'MD5']
    level: high
    description: Detects the execution GMER tool based on image and hash fields.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\gmer.exe") or (record['HASHES'].contains("MD5=E9DC058440D321AA17D0600B3CA0AB04") or record['HASHES'].contains("SHA1=539C228B6B332F5AA523E5CE358C16647D8BBE57") or record['HASHES'].contains("SHA256=E8A3E804A96C716A3E9B69195DB6FFB0D33E2433AF871E4D4E1EAB3097237173")) or record['MD5'] == "e9dc058440d321aa17d0600b3ca0ab04" or record['SHA1'] == "539c228b6b332f5aa523e5ce358c16647d8bbe57" or record['SHA256'] == "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173")

sigma_gmer_rootkit_detector_and_remover_execution.sigma_meta = dict(
    level="high"
)

def sigma_base64_encoded_reflective_assembly_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_base64_reflective_assembly_load.yml
    title: Base64 Encoded Reflective Assembly Load
    fields: ['CommandLine']
    level: high
    description: Detects base64 encoded .NET reflective loading of Assembly
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA") or record['COMMAND_LINE'].contains("sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA") or record['COMMAND_LINE'].contains("bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA") or record['COMMAND_LINE'].contains("AFsAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiAC") or record['COMMAND_LINE'].contains("BbAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgAp") or record['COMMAND_LINE'].contains("AWwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAK") or record['COMMAND_LINE'].contains("WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAKQ") or record['COMMAND_LINE'].contains("sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiACkA") or record['COMMAND_LINE'].contains("bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgApA") or record['COMMAND_LINE'].contains("WwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA") or record['COMMAND_LINE'].contains("sAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA") or record['COMMAND_LINE'].contains("bAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA"))

sigma_base64_encoded_reflective_assembly_load.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_electron_application_child_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_electron_app_children.yml
    title: Suspicious Electron Application Child Processes
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious child processes of electron apps (teams, discord, slack...).
This could be a potential sign of ".asar" file tampering (See reference section for more information)

    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\Teams.exe") or record['PARENT_NAME'].endswith("\\slack.exe") or record['PARENT_NAME'].endswith("\\discord.exe")) and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe"))) and not (record['PARENT_NAME'].endswith("\\Discord.exe") and record['COMMAND_LINE'].contains("\\NVSMI\\nvidia-smi.exe")))

sigma_suspicious_electron_application_child_processes.sigma_meta = dict(
    level="medium"
)

def sigma_bypass_uac_via_wsreset_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.yml
    title: Bypass UAC via WSReset.exe
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\wsreset.exe") and not (record['PROCESS_NAME'].endswith("\\conhost.exe") or record['ORIGINAL_FILE_NAME'] == "CONHOST.EXE"))

sigma_bypass_uac_via_wsreset_exe.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_double_extension(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_double_extension.yml
    title: Suspicious Double Extension
    fields: ['Image']
    level: critical
    description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith(".doc.exe") or record['PROCESS_NAME'].endswith(".docx.exe") or record['PROCESS_NAME'].endswith(".xls.exe") or record['PROCESS_NAME'].endswith(".xlsx.exe") or record['PROCESS_NAME'].endswith(".ppt.exe") or record['PROCESS_NAME'].endswith(".pptx.exe") or record['PROCESS_NAME'].endswith(".rtf.exe") or record['PROCESS_NAME'].endswith(".pdf.exe") or record['PROCESS_NAME'].endswith(".txt.exe") or record['PROCESS_NAME'].endswith(".exe") or record['PROCESS_NAME'].endswith("______.exe"))

sigma_suspicious_double_extension.sigma_meta = dict(
    level="critical"
)

def sigma_squiblytwo_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bypass_squiblytwo.yml
    title: SquiblyTwo Execution
    fields: ['CommandLine', 'Image', 'Hashes', 'OriginalFileName', 'Imphash']
    level: medium
    description: Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wmic.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("wmic") and record['COMMAND_LINE'].contains("format") and record['COMMAND_LINE'].contains("http"))) or (((record['IMPHASH'] == "1B1A3F43BF37B5BFE60751F2EE2F326E" or record['IMPHASH'] == "37777A96245A3C74EB217308F3546F4C" or record['IMPHASH'] == "9D87C9D67CE724033C0B40CC4CA1B206") or (record['HASHES'].contains("IMPHASH=1B1A3F43BF37B5BFE60751F2EE2F326E") or record['HASHES'].contains("IMPHASH=37777A96245A3C74EB217308F3546F4C") or record['HASHES'].contains("IMPHASH=9D87C9D67CE724033C0B40CC4CA1B206"))) and (record['COMMAND_LINE'].contains("format:") and record['COMMAND_LINE'].contains("http"))))

sigma_squiblytwo_execution.sigma_meta = dict(
    level="medium"
)

def sigma_change_powershell_policies_to_an_insecure_level(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_set_policies_to_unsecure_level.yml
    title: Change PowerShell Policies to an Insecure Level
    fields: ['CommandLine']
    level: medium
    description: Detects use of executionpolicy option to set insecure policies
    logsource: product:windows - category:process_creation
    """
    return (((record['COMMAND_LINE'].contains("-executionpolicy") or record['COMMAND_LINE'].contains("-ep") or record['COMMAND_LINE'].contains("-exec")) and (record['COMMAND_LINE'].contains("Unrestricted") or record['COMMAND_LINE'].contains("bypass") or record['COMMAND_LINE'].contains("RemoteSigned"))) and not ((record['COMMAND_LINE'].contains("C:\\Program Files") or record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("\\AppData\\Roaming\\Code"))))

sigma_change_powershell_policies_to_an_insecure_level.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_splwow64_without_params(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_splwow64.yml
    title: Suspicious Splwow64 Without Params
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious Splwow64.exe process without any command line parameters
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\splwow64.exe") and record['COMMAND_LINE'].endswith("splwow64.exe"))

sigma_suspicious_splwow64_without_params.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_pkgmgr_and_dism(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_pkgmgr_dism.yml
    title: UAC Bypass Using PkgMgr and DISM
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\pkgmgr.exe") and record['PROCESS_NAME'].endswith("\\dism.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_pkgmgr_and_dism.sigma_meta = dict(
    level="high"
)

def sigma_cl_loadassembly_ps1_proxy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_cl_loadassembly.yml
    title: CL_LoadAssembly.ps1 Proxy Execution
    fields: ['CommandLine']
    level: medium
    description: Detects the use of a Microsoft signed script to execute commands and bypassing AppLocker.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\CL_LoadAssembly.ps1") or record['COMMAND_LINE'].contains("LoadAssemblyFromPath"))

sigma_cl_loadassembly_ps1_proxy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_chafer_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_chafer_mar18.yml
    title: Chafer Activity
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\Service.exe") and (record['COMMAND_LINE'].endswith("i") or record['COMMAND_LINE'].endswith("u"))) or (record['COMMAND_LINE'].endswith("\\microsoft\\Taskbar\\autoit3.exe") or record['COMMAND_LINE'].startswith("C:\\wsc.exe")) or (record['PROCESS_NAME'].contains("\\Windows\\Temp\\DB") and record['PROCESS_NAME'].endswith(".exe")) or (record['COMMAND_LINE'].contains("\\nslookup.exe") and record['COMMAND_LINE'].contains("-q=TXT") and record['PARENT_NAME'].contains("\\Autoit")))

sigma_chafer_activity.sigma_meta = dict(
    level="high"
)

def sigma_gallium_sha1_artefacts(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_gallium_sha1.yml
    title: GALLIUM Sha1 Artefacts
    fields: ['sha1']
    level: high
    description: Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.
    logsource: product:windows - category:process_creation
    """
    return (record['SHA1'] == "53a44c2396d15c3a03723fa5e5db54cafd527635" or record['SHA1'] == "9c5e496921e3bc882dc40694f1dcc3746a75db19" or record['SHA1'] == "aeb573accfd95758550cf30bf04f389a92922844" or record['SHA1'] == "79ef78a797403a4ed1a616c68e07fff868a8650a" or record['SHA1'] == "4f6f38b4cec35e895d91c052b1f5a83d665c2196" or record['SHA1'] == "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" or record['SHA1'] == "e841a63e47361a572db9a7334af459ddca11347a" or record['SHA1'] == "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" or record['SHA1'] == "2e94b305d6812a9f96e6781c888e48c7fb157b6b" or record['SHA1'] == "dd44133716b8a241957b912fa6a02efde3ce3025" or record['SHA1'] == "8793bf166cb89eb55f0593404e4e933ab605e803" or record['SHA1'] == "a39b57032dbb2335499a51e13470a7cd5d86b138" or record['SHA1'] == "41cc2b15c662bc001c0eb92f6cc222934f0beeea" or record['SHA1'] == "d209430d6af54792371174e70e27dd11d3def7a7" or record['SHA1'] == "1c6452026c56efd2c94cea7e0f671eb55515edb0" or record['SHA1'] == "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" or record['SHA1'] == "4923d460e22fbbf165bbbaba168e5a46b8157d9f" or record['SHA1'] == "f201504bd96e81d0d350c3a8332593ee1c9e09de" or record['SHA1'] == "ddd2db1127632a2a52943a2fe516a2e7d05d70d2")

sigma_gallium_sha1_artefacts.sigma_meta = dict(
    level="high"
)

def sigma_enabling_rdp_service_via_reg_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_enable_rdp.yml
    title: Enabling RDP Service via Reg.exe
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the execution of reg.exe and subsequent command line arguments for enabling RDP service on the host by tampering with the 'CurrentControlSet\Control\Terminal Server' subkeys
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("\\CurrentControlSet\\Control\\Terminal Server") and record['COMMAND_LINE'].contains("REG_DWORD") and record['COMMAND_LINE'].contains("/f")) and ((record['COMMAND_LINE'].contains("Licensing Core") and record['COMMAND_LINE'].contains("EnableConcurrentSessions")) or (record['COMMAND_LINE'].contains("WinStations\\RDP-Tcp") or record['COMMAND_LINE'].contains("MaxInstanceCount") or record['COMMAND_LINE'].contains("fEnableWinStation") or record['COMMAND_LINE'].contains("TSUserEnabled") or record['COMMAND_LINE'].contains("TSEnabled") or record['COMMAND_LINE'].contains("TSAppCompat") or record['COMMAND_LINE'].contains("IdleWinStationPoolCount") or record['COMMAND_LINE'].contains("TSAdvertise") or record['COMMAND_LINE'].contains("AllowTSConnections") or record['COMMAND_LINE'].contains("fSingleSessionPerUser") or record['COMMAND_LINE'].contains("fDenyTSConnections"))))

sigma_enabling_rdp_service_via_reg_exe.sigma_meta = dict(
    level="high"
)

def sigma_winnti_malware_hk_university_campaign(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_winnti_mal_hk_jan20.yml
    title: Winnti Malware HK University Campaign
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].contains("C:\\Windows\\Temp") or record['PARENT_NAME'].contains("\\hpqhvind.exe")) and record['PROCESS_NAME'].startswith("C:\\ProgramData\\DRM")) or (record['PARENT_NAME'].startswith("C:\\ProgramData\\DRM") and record['PROCESS_NAME'].endswith("\\wmplayer.exe")) or (record['PARENT_NAME'].endswith("\\Test.exe") and record['PROCESS_NAME'].endswith("\\wmplayer.exe")) or record['PROCESS_NAME'] == "C:\\ProgramData\\DRM\\CLR\\CLR.exe" or (record['PARENT_NAME'].startswith("C:\\ProgramData\\DRM\\Windows") and record['PROCESS_NAME'].endswith("\\SearchFilterHost.exe")))

sigma_winnti_malware_hk_university_campaign.sigma_meta = dict(
    level="critical"
)

def sigma_set_suspicious_files_as_system_files_using_attrib(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_attrib_system_susp_paths.yml
    title: Set Suspicious Files as System Files Using Attrib
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of attrib with "+s" option to set suspicious script or executable as system files to hide them from users and make them unable to delete with simple rights. The rule limit the search to specific extensions and directories to avoid FP's
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\attrib.exe") or record['ORIGINAL_FILE_NAME'] == "ATTRIB.EXE") and record['COMMAND_LINE'].contains("+s") and (record['COMMAND_LINE'].contains("%") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("\\ProgramData") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Windows\\Temp")) and (record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".ps1") or record['COMMAND_LINE'].contains(".vbe") or record['COMMAND_LINE'].contains(".vbs") or record['COMMAND_LINE'].contains(".exe"))) and not (record['COMMAND_LINE'].contains("\\Windows\\TEMP") and record['COMMAND_LINE'].contains(".exe")))

sigma_set_suspicious_files_as_system_files_using_attrib.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_compression_tool_parameters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_compression_params.yml
    title: Suspicious Compression Tool Parameters
    fields: ['CommandLine', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects suspicious command line arguments of common data compression tools
    logsource: category:process_creation - product:windows
    """
    return (((record['ORIGINAL_FILE_NAME'] == "7z*.exe" or record['ORIGINAL_FILE_NAME'].endswith("rar.exe") or record['ORIGINAL_FILE_NAME'].contains("Command*Line*RAR")) and (record['COMMAND_LINE'].contains("-p") or record['COMMAND_LINE'].contains("-ta") or record['COMMAND_LINE'].contains("-tb") or record['COMMAND_LINE'].contains("-sdel") or record['COMMAND_LINE'].contains("-dw") or record['COMMAND_LINE'].contains("-hp"))) and not (record['PARENT_NAME'].startswith("C:\\Program")))

sigma_suspicious_compression_tool_parameters.sigma_meta = dict(
    level="high"
)

def sigma_default_powersploit_and_empire_schtasks_persistence(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powersploit_empire_schtasks.yml
    title: Default PowerSploit and Empire Schtasks Persistence
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe")) and record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create") and record['COMMAND_LINE'].contains("/SC") and record['COMMAND_LINE'].contains("/TN") and record['COMMAND_LINE'].contains("Updater") and record['COMMAND_LINE'].contains("/TR") and record['COMMAND_LINE'].contains("powershell") and (record['COMMAND_LINE'].contains("ONLOGON") or record['COMMAND_LINE'].contains("DAILY") or record['COMMAND_LINE'].contains("ONIDLE") or record['COMMAND_LINE'].contains("Updater")))

sigma_default_powersploit_and_empire_schtasks_persistence.sigma_meta = dict(
    level="high"
)

def sigma_exfiltration_and_tunneling_tools_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exfiltration_and_tunneling_tools_execution.yml
    title: Exfiltration and Tunneling Tools Execution
    fields: ['Image']
    level: medium
    description: Execution of well known tools for data exfiltration and tunneling
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\plink.exe") or record['PROCESS_NAME'].endswith("\\socat.exe") or record['PROCESS_NAME'].endswith("\\stunnel.exe") or record['PROCESS_NAME'].endswith("\\httptunnel.exe"))

sigma_exfiltration_and_tunneling_tools_execution.sigma_meta = dict(
    level="medium"
)

def sigma_office_applications_spawning_wmi_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_applications_spawning_wmi_commandline.yml
    title: Office Applications Spawning Wmi Cli
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Initial execution of malicious document calls wmic to execute the file with regsvr32
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\wbem\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe")))

sigma_office_applications_spawning_wmi_cli.sigma_meta = dict(
    level="high"
)

def sigma_ntlm_coercion_via_certutil_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_certutil_ntlm_coercion.yml
    title: NTLM Coercion Via Certutil.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certutil.exe") or record['ORIGINAL_FILE_NAME'] == "CertUtil.exe") and (record['COMMAND_LINE'].contains("-syncwithWU") and record['COMMAND_LINE'].contains("")))

sigma_ntlm_coercion_via_certutil_exe.sigma_meta = dict(
    level="high"
)

def sigma_recon_activity_with_nltest(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_nltest_recon.yml
    title: Recon Activity with NLTEST
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects nltest commands that can be used for information discovery
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\nltest.exe") or record['ORIGINAL_FILE_NAME'] == "nltestrk.exe") and ((record['COMMAND_LINE'].contains("/server") and record['COMMAND_LINE'].contains("/query")) or (record['COMMAND_LINE'].contains("/dclist:") or record['COMMAND_LINE'].contains("/parentdomain") or record['COMMAND_LINE'].contains("/domain_trusts") or record['COMMAND_LINE'].contains("/trusted_domains") or record['COMMAND_LINE'].contains("/user"))))

sigma_recon_activity_with_nltest.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_powershell_with_base64(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_encode.yml
    title: Suspicious Execution of Powershell with Base64
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Commandline to launch powershell with a base64 payload
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("-en") or record['COMMAND_LINE'].contains("-enc") or record['COMMAND_LINE'].contains("-enco") or record['COMMAND_LINE'].contains("-ec"))) and not ((record['COMMAND_LINE'].contains("-Encoding")) or ((record['PARENT_NAME'].contains("C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows") or record['PARENT_NAME'].contains("\\gc_worker.exe")))))

sigma_suspicious_execution_of_powershell_with_base64.sigma_meta = dict(
    level="medium"
)

def sigma_explorer_nouaccheck_flag(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_explorer_nouaccheck.yml
    title: Explorer NOUACCHECK Flag
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\explorer.exe") and record['COMMAND_LINE'].contains("/NOUACCHECK")) and not ((record['PARENT_COMMAND_LINE'] == "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule" or record['PARENT_NAME'] == "C:\\Windows\\System32\\svchost.exe")))

sigma_explorer_nouaccheck_flag.sigma_meta = dict(
    level="high"
)

def sigma_mimikatz_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml
    title: Mimikatz Command Line
    fields: ['CommandLine', 'ParentImage']
    level: medium
    description: Detection well-known mimikatz command line arguments
    logsource: category:process_creation - product:windows
    """
    return ((((record['COMMAND_LINE'].contains("DumpCreds") or record['COMMAND_LINE'].contains("invoke-mimikatz")) or ((record['COMMAND_LINE'].contains("rpc") or record['COMMAND_LINE'].contains("token") or record['COMMAND_LINE'].contains("crypto") or record['COMMAND_LINE'].contains("dpapi") or record['COMMAND_LINE'].contains("sekurlsa") or record['COMMAND_LINE'].contains("kerberos") or record['COMMAND_LINE'].contains("lsadump") or record['COMMAND_LINE'].contains("privilege") or record['COMMAND_LINE'].contains("process") or record['COMMAND_LINE'].contains("vault")) and record['COMMAND_LINE'].contains("::"))) or ((record['COMMAND_LINE'].contains("aadcookie") or record['COMMAND_LINE'].contains("detours") or record['COMMAND_LINE'].contains("memssp") or record['COMMAND_LINE'].contains("mflt") or record['COMMAND_LINE'].contains("ncroutemon") or record['COMMAND_LINE'].contains("ngcsign") or record['COMMAND_LINE'].contains("printnightmare") or record['COMMAND_LINE'].contains("skeleton") or record['COMMAND_LINE'].contains("preshutdown") or record['COMMAND_LINE'].contains("mstsc") or record['COMMAND_LINE'].contains("multirdp")) and record['COMMAND_LINE'].contains("::"))) and not ((record['COMMAND_LINE'].contains("function Convert-GuidToCompressedGuid")) or (record['PARENT_NAME'].endswith("\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe") and record['COMMAND_LINE'].contains("/d /s /c") and record['COMMAND_LINE'].contains("checkfilenameiocs --ioc-path"))))

sigma_mimikatz_command_line.sigma_meta = dict(
    level="medium"
)

def sigma_psexec_paexec_flags(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexex_paexec_flags.yml
    title: PsExec/PAExec Flags
    fields: ['CommandLine']
    level: high
    description: Detects suspicious flags used by PsExec and PAExec but no usual program name in command line
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("-s cmd") or record['COMMAND_LINE'].contains("/s cmd") or record['COMMAND_LINE'].contains("-s -i cmd") or record['COMMAND_LINE'].contains("/s /i cmd") or record['COMMAND_LINE'].contains("/s -i cmd") or record['COMMAND_LINE'].contains("-s /i cmd") or record['COMMAND_LINE'].contains("-i -s cmd") or record['COMMAND_LINE'].contains("/i /s cmd") or record['COMMAND_LINE'].contains("-i /s cmd") or record['COMMAND_LINE'].contains("/i -s cmd") or record['COMMAND_LINE'].contains("-s pwsh") or record['COMMAND_LINE'].contains("/s pwsh") or record['COMMAND_LINE'].contains("-s -i pwsh") or record['COMMAND_LINE'].contains("/s /i pwsh") or record['COMMAND_LINE'].contains("/s -i pwsh") or record['COMMAND_LINE'].contains("-s /i pwsh") or record['COMMAND_LINE'].contains("-i -s pwsh") or record['COMMAND_LINE'].contains("/i /s pwsh") or record['COMMAND_LINE'].contains("-i /s pwsh") or record['COMMAND_LINE'].contains("/i -s pwsh") or record['COMMAND_LINE'].contains("-s powershell") or record['COMMAND_LINE'].contains("/s powershell") or record['COMMAND_LINE'].contains("-s -i powershell") or record['COMMAND_LINE'].contains("/s /i powershell") or record['COMMAND_LINE'].contains("/s -i powershell") or record['COMMAND_LINE'].contains("-s /i powershell") or record['COMMAND_LINE'].contains("-i -s powershell") or record['COMMAND_LINE'].contains("/i /s powershell") or record['COMMAND_LINE'].contains("-i /s powershell") or record['COMMAND_LINE'].contains("/i -s powershell")) or (record['COMMAND_LINE'].contains("accepteula") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p") and record['COMMAND_LINE'].contains(""))) and not ((record['COMMAND_LINE'].contains("paexec") or record['COMMAND_LINE'].contains("PsExec"))))

sigma_psexec_paexec_flags.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_usage_of_the_manage_bde_wsf_script(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_manage_bde_lolbas.yml
    title: Suspicious Usage of the Manage-bde.wsf Script
    fields: ['CommandLine']
    level: medium
    description: Detects a usage of the manage-bde.wsf script that may indicate an attempt of proxy execution from script
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cscript") and record['COMMAND_LINE'].contains("manage-bde.wsf"))

sigma_suspicious_usage_of_the_manage_bde_wsf_script.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_file_characteristics_due_to_missing_fields(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_file_characteristics.yml
    title: Suspicious File Characteristics Due to Missing Fields
    fields: ['Image', 'FileVersion', 'Company', 'Product', 'Description']
    level: medium
    description: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
    logsource: product:windows - category:process_creation
    """
    return ((((record['DESCRIPTION'] == "\\?" and record['FILE_VERSION'] == "\\?") or (record['DESCRIPTION'] == "\\?" and record['PRODUCT_NAME'] == "\\?")) or (record['DESCRIPTION'] == "\\?" and record['COMPANY'] == "\\?")) and record['PROCESS_NAME'].contains("\\Downloads"))

sigma_suspicious_file_characteristics_due_to_missing_fields.sigma_meta = dict(
    level="medium"
)

def sigma_conhost_parent_process_executions(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_conhost.yml
    title: Conhost Parent Process Executions
    fields: ['CommandLine', 'Image', 'ParentImage', 'Provider_Name', 'ParentCommandLine']
    level: medium
    description: Detects the conhost execution as parent process. Can be used to evaded defense mechanism.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\conhost.exe") and not ((record['PROVIDER__NAME'] == "SystemTraceProvider-Process") or (record['PROVIDER__NAME'] == "Microsoft-Windows-Kernel-Process" and record['PROCESS_NAME'].endswith("\\git.exe") and (record['PARENT_COMMAND_LINE'].contains("show --textconv") or record['PARENT_COMMAND_LINE'].contains("cat-file -s"))) or (record['PARENT_COMMAND_LINE'].contains("C:\\WINDOWS\\system32\\conhost.exe 0x4") and (record['COMMAND_LINE'].contains("show --textconv") or record['COMMAND_LINE'].contains("cat-file -s"))) or (record['PROVIDER__NAME'] == "Microsoft-Windows-Kernel-Process" and record['PARENT_COMMAND_LINE'].contains("cat-file -s") and record['PROCESS_NAME'] == "C:\\Windows\\System32\\conhost.exe") or ((record['PARENT_COMMAND_LINE'] == "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0x4" or record['PARENT_COMMAND_LINE'] == "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1") and record['PROCESS_NAME'] == "C:\\Windows\\System32\\conhost.exe") or (record['PARENT_COMMAND_LINE'] == "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1" and record['PROCESS_NAME'] == "C:\\Program Files\\Git\\mingw64\\bin\\git.exe" and record['COMMAND_LINE'].contains("show --textconv :"))))

sigma_conhost_parent_process_executions.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_download_from_office_domain(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_download_office_domain.yml
    title: Suspicious Download from Office Domain
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\curl.exe") or record['PROCESS_NAME'].endswith("\\wget.exe")) or (record['COMMAND_LINE'].contains("Invoke-WebRequest") or record['COMMAND_LINE'].contains("iwr") or record['COMMAND_LINE'].contains("curl") or record['COMMAND_LINE'].contains("wget") or record['COMMAND_LINE'].contains("Start-BitsTransfer") or record['COMMAND_LINE'].contains(".DownloadFile(") or record['COMMAND_LINE'].contains(".DownloadString("))) and (record['COMMAND_LINE'].contains("https://attachment.outlook.live.net/owa/") or record['COMMAND_LINE'].contains("https://onenoteonlinesync.onenote.com/onenoteonlinesync/")))

sigma_suspicious_download_from_office_domain.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_reg_add_open_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_reg_open_command.yml
    title: Suspicious Reg Add Open Command
    fields: ['CommandLine']
    level: medium
    description: Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("hkcu\\software\\classes\\ms-settings\\shell\\open\\command") and record['COMMAND_LINE'].contains("/ve") and record['COMMAND_LINE'].contains("/d")) or (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("hkcu\\software\\classes\\ms-settings\\shell\\open\\command") and record['COMMAND_LINE'].contains("/v") and record['COMMAND_LINE'].contains("DelegateExecute")) or (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("hkcu\\software\\classes\\ms-settings")))

sigma_suspicious_reg_add_open_command.sigma_meta = dict(
    level="medium"
)

def sigma_shells_spawned_by_web_servers(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webshell_spawn.yml
    title: Shells Spawned by Web Servers
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects web servers that spawn shell processes which could be the result of a successfully placed web shell or another attack
    logsource: category:process_creation - product:windows
    """
    return ((((record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\php.exe") or record['PARENT_NAME'].endswith("\\php-cgi.exe") or record['PARENT_NAME'].endswith("\\nginx.exe") or record['PARENT_NAME'].endswith("\\httpd.exe") or record['PARENT_NAME'].endswith("\\caddy.exe") or record['PARENT_NAME'].endswith("\\ws_TomcatService.exe") or record['PARENT_NAME'].endswith("\\tomcat.exe") or record['PARENT_NAME'].endswith("\\UMWorkerProcess.exe")) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['PARENT_NAME'].contains("-tomcat-") or record['PARENT_NAME'].contains("\\tomcat"))) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['PARENT_COMMAND_LINE'].contains("catalina.jar") or record['PARENT_COMMAND_LINE'].contains("CATALINA_HOME") or record['PARENT_COMMAND_LINE'].contains("catalina.home")))) and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\arp.exe") or record['PROCESS_NAME'].endswith("\\at.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\dsget.exe") or record['PROCESS_NAME'].endswith("\\dsquery.exe") or record['PROCESS_NAME'].endswith("\\find.exe") or record['PROCESS_NAME'].endswith("\\findstr.exe") or record['PROCESS_NAME'].endswith("\\fsutil.exe") or record['PROCESS_NAME'].endswith("\\hostname.exe") or record['PROCESS_NAME'].endswith("\\ipconfig.exe") or record['PROCESS_NAME'].endswith("\\nbtstat.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe") or record['PROCESS_NAME'].endswith("\\netdom.exe") or record['PROCESS_NAME'].endswith("\\netsh.exe") or record['PROCESS_NAME'].endswith("\\netstat.exe") or record['PROCESS_NAME'].endswith("\\nltest.exe") or record['PROCESS_NAME'].endswith("\\nslookup.exe") or record['PROCESS_NAME'].endswith("\\ntdutil.exe") or record['PROCESS_NAME'].endswith("\\pathping.exe") or record['PROCESS_NAME'].endswith("\\ping.exe") or record['PROCESS_NAME'].endswith("\\qprocess.exe") or record['PROCESS_NAME'].endswith("\\query.exe") or record['PROCESS_NAME'].endswith("\\qwinsta.exe") or record['PROCESS_NAME'].endswith("\\reg.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\sc.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\systeminfo.exe") or record['PROCESS_NAME'].endswith("\\tasklist.exe") or record['PROCESS_NAME'].endswith("\\tracert.exe") or record['PROCESS_NAME'].endswith("\\ver.exe") or record['PROCESS_NAME'].endswith("\\vssadmin.exe") or record['PROCESS_NAME'].endswith("\\wevtutil.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\wusa.exe"))) and not ((record['COMMAND_LINE'].endswith("Windows\\system32\\cmd.exe /c C:\\ManageEngine\\ADManager \"Plus\\ES\\bin\\elasticsearch.bat -Enode.name=RMP-NODE1 -pelasticsearch-pid.txt")) or (record['COMMAND_LINE'].contains("sc query") and record['COMMAND_LINE'].contains("ADManager Plus"))))

sigma_shells_spawned_by_web_servers.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msbuild_execution_by_uncommon_parent_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_msbuild.yml
    title: Suspicious Msbuild Execution By Uncommon Parent Process
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\MSBuild.exe") or record['ORIGINAL_FILE_NAME'] == "MSBuild.exe") and not ((record['PARENT_NAME'].endswith("\\devenv.exe") or record['PARENT_NAME'].endswith("\\cmd.exe") or record['PARENT_NAME'].endswith("\\msbuild.exe") or record['PARENT_NAME'].endswith("\\python.exe") or record['PARENT_NAME'].endswith("\\explorer.exe") or record['PARENT_NAME'].endswith("\\nuget.exe"))))

sigma_suspicious_msbuild_execution_by_uncommon_parent_process.sigma_meta = dict(
    level="medium"
)

def sigma_base64_encoded_listing_of_shadowcopy(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_base64_listing_shadowcopy.yml
    title: Base64 Encoded Listing of Shadowcopy
    fields: ['CommandLine']
    level: high
    description: Detects base64 encoded listing Win32_Shadowcopy
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("VwBpAG4AMwAyAF8AUwBoAGEAZABvAHcAYwBvAHAAeQAgAHwAIABGAG8AcgBFAGEAYwBoAC0ATwBiAGoAZQBjAHQA") or record['COMMAND_LINE'].contains("cAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0A") or record['COMMAND_LINE'].contains("XAGkAbgAzADIAXwBTAGgAYQBkAG8AdwBjAG8AcAB5ACAAfAAgAEYAbwByAEUAYQBjAGgALQBPAGIAagBlAGMAdA"))

sigma_base64_encoded_listing_of_shadowcopy.sigma_meta = dict(
    level="high"
)

def sigma_gpscript_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_gpscript.yml
    title: Gpscript Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects the execution of the LOLBIN gpscript, which executes logon or startup scripts configured in Group Policy
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\gpscript.exe") or record['ORIGINAL_FILE_NAME'] == "GPSCRIPT.EXE") and (record['COMMAND_LINE'].contains("/logon") or record['COMMAND_LINE'].contains("/startup")))

sigma_gpscript_execution.sigma_meta = dict(
    level="medium"
)

def sigma_replace_exe_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_replace.yml
    title: Replace.exe Usage
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the use of Replace.exe which can be used to replace file with another file
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\replace.exe") and (record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("-a")))

sigma_replace_exe_usage.sigma_meta = dict(
    level="medium"
)

def sigma_sdclt_child_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sdclt_child_process.yml
    title: Sdclt Child Processes
    fields: ['ParentImage']
    level: medium
    description: A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\sdclt.exe")

sigma_sdclt_child_processes.sigma_meta = dict(
    level="medium"
)

def sigma_lolbins_process_creation_with_wmiprvse(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbins_with_wmiprvse_parent_process.yml
    title: Lolbins Process Creation with WmiPrvse
    fields: ['Image', 'ParentImage']
    level: high
    description: This rule will monitor LOLBin process creations by wmiprvse. Add more LOLBins to rule logic if needed.
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\verclsid.exe")) and record['PARENT_NAME'].endswith("\\wbem\\WmiPrvSE.exe"))

sigma_lolbins_process_creation_with_wmiprvse.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_via_icmluautil(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_icmluautil.yml
    title: UAC Bypass via ICMLuaUtil
    fields: ['Image', 'ParentCommandLine', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using ICMLuaUtil Elevated COM interface
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\dllhost.exe") and (record['PARENT_COMMAND_LINE'].contains("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}") or record['PARENT_COMMAND_LINE'].contains("/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}"))) and not (record['PROCESS_NAME'].endswith("\\WerFault.exe") or record['ORIGINAL_FILE_NAME'] == "WerFault.exe"))

sigma_uac_bypass_via_icmluautil.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_wermgr_process_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wermgr.yml
    title: Suspicious WERMGR Process Patterns
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious Windows Error Reporting manager (wermgr.exe) process patterns - suspicious parents / children, execution folders, command lines etc.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wermgr.exe") and not ((record['PROCESS_NAME'].contains("C:\\Windows\\System32") or record['PROCESS_NAME'].contains("C:\\Windows\\SysWOW64")))) or (record['PARENT_NAME'].endswith("\\wermgr.exe") and (record['PROCESS_NAME'].endswith("\\nslookup.exe") or record['PROCESS_NAME'].endswith("\\ipconfig.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\netstat.exe") or record['PROCESS_NAME'].endswith("\\systeminfo.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe"))))

sigma_suspicious_wermgr_process_patterns.sigma_meta = dict(
    level="high"
)

def sigma_missing_space_characters_in_command_lines(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_missing_spaces.yml
    title: Missing Space Characters in Command Lines
    fields: ['CommandLine']
    level: high
    description: Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe.
This could be a sign of obfuscation of a fat finger problem (typo by the developer).

    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("cmd.exe/c") or record['COMMAND_LINE'].contains("\\cmd/c") or record['COMMAND_LINE'].contains("\"cmd/c") or record['COMMAND_LINE'].contains("cmd.exe/k") or record['COMMAND_LINE'].contains("\\cmd/k") or record['COMMAND_LINE'].contains("\"cmd/k") or record['COMMAND_LINE'].contains("cmd.exe/r") or record['COMMAND_LINE'].contains("\\cmd/r") or record['COMMAND_LINE'].contains("\"cmd/r")) or (record['COMMAND_LINE'].contains("/cwhoami") or record['COMMAND_LINE'].contains("/cpowershell") or record['COMMAND_LINE'].contains("/cschtasks") or record['COMMAND_LINE'].contains("/cbitsadmin") or record['COMMAND_LINE'].contains("/ccertutil") or record['COMMAND_LINE'].contains("/kwhoami") or record['COMMAND_LINE'].contains("/kpowershell") or record['COMMAND_LINE'].contains("/kschtasks") or record['COMMAND_LINE'].contains("/kbitsadmin") or record['COMMAND_LINE'].contains("/kcertutil")) or (record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd /r"))) and not (((record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd /r"))) or (record['COMMAND_LINE'].contains("AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules") or record['COMMAND_LINE'].endswith("cmd.exe/c .") or record['COMMAND_LINE'] == "cmd.exe /c")))

sigma_missing_space_characters_in_command_lines.sigma_meta = dict(
    level="high"
)

def sigma_compress_data_and_lock_with_password_for_exfiltration_with_7_zip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_7z.yml
    title: Compress Data and Lock With Password for Exfiltration With 7-ZIP
    fields: ['CommandLine']
    level: medium
    description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("7z.exe") or record['COMMAND_LINE'].contains("7za.exe")) and record['COMMAND_LINE'].contains("-p") and (record['COMMAND_LINE'].contains("a") or record['COMMAND_LINE'].contains("u")))

sigma_compress_data_and_lock_with_password_for_exfiltration_with_7_zip.sigma_meta = dict(
    level="medium"
)

def sigma_reg_add_run_key(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_add_run_key.yml
    title: Reg Add RUN Key
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious command line reg.exe tool adding key to RUN key in Registry
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("ADD") and record['COMMAND_LINE'].contains("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))

sigma_reg_add_run_key.sigma_meta = dict(
    level="medium"
)

def sigma_wmiexec_vbs_script(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_cloudhopper.yml
    title: WMIExec VBS Script
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects wmiexec vbs version execution by wscript or cscript
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe")) or (record['ORIGINAL_FILE_NAME'] == "cscript.exe" or record['ORIGINAL_FILE_NAME'] == "wscript.exe")) and (record['COMMAND_LINE'].contains(".vbs") and record['COMMAND_LINE'].contains("/shell")))

sigma_wmiexec_vbs_script.sigma_meta = dict(
    level="high"
)

def sigma_process_creation_with_renamed_browsercore_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_browsercore.yml
    title: Process Creation with Renamed BrowserCore.exe
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects process creation with a renamed BrowserCore.exe (used to extract Azure tokens)
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "BrowserCore.exe" and not ((record['PROCESS_NAME'].endswith("\\BrowserCore.exe"))))

sigma_process_creation_with_renamed_browsercore_exe.sigma_meta = dict(
    level="high"
)

def sigma_crackmapexec_process_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_crackmapexec_patterns.yml
    title: CrackMapExec Process Patterns
    fields: ['CommandLine', 'User']
    level: high
    description: Detects suspicious process patterns found in logs when CrackMapExec is used
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("tasklist /fi") and record['COMMAND_LINE'].contains("Imagename eq lsass.exe") and (record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /r") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /r") or record['COMMAND_LINE'].contains("cmd /k")) and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))) or (record['COMMAND_LINE'].contains("do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump") and record['COMMAND_LINE'].contains("\\Windows\\Temp") and record['COMMAND_LINE'].contains("full") and record['COMMAND_LINE'].contains("%%B")) or (record['COMMAND_LINE'].contains("tasklist /v /fo csv") and record['COMMAND_LINE'].contains("findstr /i \"lsass\"")))

sigma_crackmapexec_process_patterns.sigma_meta = dict(
    level="high"
)

def sigma_run_from_a_zip_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_run_from_zip.yml
    title: Run from a Zip File
    fields: ['Image']
    level: medium
    description: Payloads may be compressed, archived, or encrypted in order to avoid detection
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].contains(".zip")

sigma_run_from_a_zip_file.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_csi_exe_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_csi.yml
    title: Suspicious Csi.exe Usage
    fields: ['Image', 'OriginalFileName', 'Company']
    level: medium
    description: Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “Roslyn” Community Technology Preview was named 'rcsi.exe'
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\csi.exe") or record['PROCESS_NAME'].endswith("\\rcsi.exe")) or (record['ORIGINAL_FILE_NAME'] == "csi.exe" or record['ORIGINAL_FILE_NAME'] == "rcsi.exe")) and record['COMPANY'] == "Microsoft Corporation")

sigma_suspicious_csi_exe_usage.sigma_meta = dict(
    level="medium"
)

def sigma_local_accounts_discovery(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_local_system_owner_account_discovery.yml
    title: Local Accounts Discovery
    fields: ['CommandLine', 'Image']
    level: low
    description: Local accounts, System Owner/User discovery using operating systems utilities
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\whoami.exe") or (record['PROCESS_NAME'].endswith("\\wmic.exe") and record['COMMAND_LINE'].contains("useraccount") and record['COMMAND_LINE'].contains("get")) or (record['PROCESS_NAME'].endswith("\\quser.exe") or record['PROCESS_NAME'].endswith("\\qwinsta.exe")) or (record['PROCESS_NAME'].endswith("\\cmdkey.exe") and record['COMMAND_LINE'].contains("/l")) or (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("dir") and record['COMMAND_LINE'].contains("\\Users"))) and not (record['COMMAND_LINE'].contains("rmdir"))) or (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("user")) and not ((record['COMMAND_LINE'].contains("/domain") or record['COMMAND_LINE'].contains("/add") or record['COMMAND_LINE'].contains("/delete") or record['COMMAND_LINE'].contains("/active") or record['COMMAND_LINE'].contains("/expires") or record['COMMAND_LINE'].contains("/passwordreq") or record['COMMAND_LINE'].contains("/scriptpath") or record['COMMAND_LINE'].contains("/times") or record['COMMAND_LINE'].contains("/workstations")))))

sigma_local_accounts_discovery.sigma_meta = dict(
    level="low"
)

def sigma_lolbin_from_abnormal_drive(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_not_from_c_drive.yml
    title: LOLBIN From Abnormal Drive
    fields: ['CurrentDirectory']
    level: medium
    description: Detects LOLBINs executing from an abnormal drive such as a mounted ISO.
    logsource: category:process_creation - product:windows
    """
    return ((record['_raw'].contains("\\rundll32.exe") or record['_raw'].contains("\\calc.exe") or record['_raw'].contains("\\mshta.exe") or record['_raw'].contains("\\cscript.exe") or record['_raw'].contains("\\wscript.exe") or record['_raw'].contains("\\regsvr32.exe") or record['_raw'].contains("\\installutil.exe") or record['_raw'].contains("\\cmstp.exe")) and not ((record['PROCESS_PATH'].contains("C:") or record['PROCESS_PATH'] == "") or (record.get('PROCESS_PATH', None) == None)))

sigma_lolbin_from_abnormal_drive.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ultravnc_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_gamaredon_ultravnc.yml
    title: Suspicious UltraVNC Execution
    fields: ['CommandLine']
    level: high
    description: Detects suspicious UltraVNC command line flag combination that indicate a auto reconnect upon execution, e.g. startup (as seen being used by Gamaredon threat group)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-autoreconnect") and record['COMMAND_LINE'].contains("-connect") and record['COMMAND_LINE'].contains("-id:"))

sigma_suspicious_ultravnc_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_extrac32_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_extrac32.yml
    title: Suspicious Extrac32 Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Download or Copy file with Extrac32
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("extrac32.exe") or record['PROCESS_NAME'].endswith("\\extrac32.exe") or record['ORIGINAL_FILE_NAME'] == "extrac32.exe") and record['COMMAND_LINE'].contains(".cab") and (record['COMMAND_LINE'].contains("/C") or record['COMMAND_LINE'].contains("/Y") or record['COMMAND_LINE'].contains("")))

sigma_suspicious_extrac32_execution.sigma_meta = dict(
    level="medium"
)

def sigma_advanced_port_scanner(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_advanced_port_scanner.yml
    title: Advanced Port Scanner
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Description']
    level: medium
    description: Detects the use of Advanced Port Scanner.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\advanced_port_scanner") or record['ORIGINAL_FILE_NAME'].contains("advanced_port_scanner") or record['DESCRIPTION'].contains("Advanced Port Scanner")) or (record['COMMAND_LINE'].contains("/portable") and record['COMMAND_LINE'].contains("/lng")))

sigma_advanced_port_scanner.sigma_meta = dict(
    level="medium"
)

def sigma_imagingdevices_unusual_parent_or_child_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_imaging_devices_unusual_parents.yml
    title: ImagingDevices Unusual Parent Or Child Processes
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\WmiPrvSE.exe") or record['PARENT_NAME'].endswith("\\svchost.exe") or record['PARENT_NAME'].endswith("\\dllhost.exe")) and record['PROCESS_NAME'].endswith("\\ImagingDevices.exe")) or record['PARENT_NAME'].endswith("\\ImagingDevices.exe"))

sigma_imagingdevices_unusual_parent_or_child_processes.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_tasklist_discovery_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_tasklist_command.yml
    title: Suspicious Tasklist Discovery Command
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("tasklist") or record['PROCESS_NAME'].endswith("\\tasklist.exe") or record['ORIGINAL_FILE_NAME'] == "tasklist.exe")

sigma_suspicious_tasklist_discovery_command.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_service_dacl_modification_via_set_service_cmdlet(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_dacl_modification_set_service.yml
    title: Suspicious Service DACL Modification Via Set-Service Cmdlet
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['ORIGINAL_FILE_NAME'] == "pwsh.dll") and (record['COMMAND_LINE'].contains("-SecurityDescriptorSddl") or record['COMMAND_LINE'].contains("-sd")) and (record['COMMAND_LINE'].contains("Set-Service") and record['COMMAND_LINE'].contains("D;;") and (record['COMMAND_LINE'].contains(";;;IU") or record['COMMAND_LINE'].contains(";;;SU") or record['COMMAND_LINE'].contains(";;;BA") or record['COMMAND_LINE'].contains(";;;SY") or record['COMMAND_LINE'].contains(";;;WD"))))

sigma_suspicious_service_dacl_modification_via_set_service_cmdlet.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_characters_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_commandline_chars.yml
    title: Suspicious Characters in CommandLine
    fields: ['CommandLine']
    level: high
    description: Detects suspicious Unicode characters in the command line, which could be a sign of obfuscation or defense evasion
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("ˣ") or record['COMMAND_LINE'].contains("˪") or record['COMMAND_LINE'].contains("ˢ")) or (record['COMMAND_LINE'].contains("∕") or record['COMMAND_LINE'].contains("⁄")) or (record['COMMAND_LINE'].contains("―") or record['COMMAND_LINE'].contains("—")))

sigma_suspicious_characters_in_commandline.sigma_meta = dict(
    level="high"
)

def sigma_wmi_remote_command_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_remote_command.yml
    title: WMI Remote Command Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: An adversary might use WMI to execute commands on a remote system
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("/node:") and record['COMMAND_LINE'].contains("process") and record['COMMAND_LINE'].contains("call") and record['COMMAND_LINE'].contains("create")))

sigma_wmi_remote_command_execution.sigma_meta = dict(
    level="medium"
)

def sigma_blue_mockingbird(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_blue_mockingbird.yml
    title: Blue Mockingbird
    fields: ['CommandLine', 'Image']
    level: high
    description: Attempts to detect system changes made by Blue Mockingbird
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("sc config") and record['COMMAND_LINE'].contains("wercplsupporte.dll")) or (record['PROCESS_NAME'].endswith("\\wmic.exe") and record['COMMAND_LINE'].endswith("COR_PROFILER")))

sigma_blue_mockingbird.sigma_meta = dict(
    level="high"
)

def sigma_mmc_spawning_windows_shell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mmc_spawn_shell.yml
    title: MMC Spawning Windows Shell
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a Windows command line executable started from MMC
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\mmc.exe") and ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\reg.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe")) or record['PROCESS_NAME'].contains("\\BITSADMIN")))

sigma_mmc_spawning_windows_shell.sigma_meta = dict(
    level="high"
)

def sigma_cmd_stream_redirection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_redirect_to_stream.yml
    title: Cmd Stream Redirection
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the redirection of an alternate data stream (ADS) of / within a Windows command line session
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains(">") and record['COMMAND_LINE'].contains(":")) and not (record['COMMAND_LINE'].contains(":")))

sigma_cmd_stream_redirection.sigma_meta = dict(
    level="medium"
)

def sigma_microsoft_iis_service_account_password_dumped(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_iis_service_account_password_dumped.yml
    title: Microsoft IIS Service Account Password Dumped
    fields: ['CommandLine', 'OriginalFilename', 'Image']
    level: high
    description: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\appcmd.exe") or record['ORIGINAL_FILENAME'] == "appcmd.exe") and (record['COMMAND_LINE'].contains("/list") or record['COMMAND_LINE'].contains("list")) and (record['COMMAND_LINE'].contains("/text") and record['COMMAND_LINE'].contains("password")))

sigma_microsoft_iis_service_account_password_dumped.sigma_meta = dict(
    level="high"
)

def sigma_uninstall_crowdstrike_falcon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uninstall_crowdstrike_falcon.yml
    title: Uninstall Crowdstrike Falcon
    fields: ['CommandLine']
    level: medium
    description: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\WindowsSensor.exe") and record['COMMAND_LINE'].contains("/uninstall") and record['COMMAND_LINE'].contains("/quiet"))

sigma_uninstall_crowdstrike_falcon.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_shutdown_to_log_out(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_logoff.yml
    title: Suspicious Execution of Shutdown to Log Out
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the rare use of the command line tool shutdown to logoff a user
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\shutdown.exe") and record['COMMAND_LINE'].contains("/l"))

sigma_suspicious_execution_of_shutdown_to_log_out.sigma_meta = dict(
    level="medium"
)

def sigma_taidoor_rat_dll_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_taidoor.yml
    title: TAIDOOR RAT DLL Load
    fields: ['CommandLine']
    level: high
    description: Detects specific process characteristics of Chinese TAIDOOR RAT malware load
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("dll,MyStart") or record['COMMAND_LINE'].contains("dll MyStart")) or (record['COMMAND_LINE'].endswith("MyStart") and record['COMMAND_LINE'].contains("rundll32.exe")))

sigma_taidoor_rat_dll_load.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_rundll_launcher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_rundll.yml
    title: Invoke-Obfuscation RUNDLL LAUNCHER
    fields: ['CommandLine']
    level: medium
    description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("shell32.dll") and record['COMMAND_LINE'].contains("shellexec_rundll") and record['COMMAND_LINE'].contains("powershell"))

sigma_invoke_obfuscation_rundll_launcher.sigma_meta = dict(
    level="medium"
)

def sigma_microsoft_iis_connection_strings_decryption(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_iis_connection_strings_decryption.yml
    title: Microsoft IIS Connection Strings Decryption
    fields: ['CommandLine', 'OriginalFilename', 'Image']
    level: high
    description: Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\aspnet_regiis.exe") or record['ORIGINAL_FILENAME'] == "aspnet_regiis.exe") and (record['COMMAND_LINE'].contains("connectionStrings") and record['COMMAND_LINE'].contains("-pdf")))

sigma_microsoft_iis_connection_strings_decryption.sigma_meta = dict(
    level="high"
)

def sigma_launch_dirlister_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dirlister.yml
    title: Launch DirLister Executable
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detect use of DirLister.exe
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "DirLister.exe" or record['PROCESS_NAME'].endswith("\\dirlister.exe"))

sigma_launch_dirlister_executable.sigma_meta = dict(
    level="medium"
)

def sigma_createminidump_hacktool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hktl_createminidump.yml
    title: CreateMiniDump Hacktool
    fields: ['Image', 'Hashes', 'Imphash']
    level: high
    description: Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].contains("\\CreateMiniDump.exe") or record['IMPHASH'] == "4a07f944a83e8a7c2525efa35dd30e2f" or record['HASHES'].contains("IMPHASH=4a07f944a83e8a7c2525efa35dd30e2f"))

sigma_createminidump_hacktool.sigma_meta = dict(
    level="high"
)

def sigma_cscript_visual_basic_script_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cscript_vbs.yml
    title: Cscript Visual Basic Script Execution
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may abuse Visual Basic (VB) for execution
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cscript.exe") and record['COMMAND_LINE'].contains(".vbs"))

sigma_cscript_visual_basic_script_execution.sigma_meta = dict(
    level="medium"
)

def sigma_time_travel_debugging_utility_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_tttracer_mod_load.yml
    title: Time Travel Debugging Utility Usage
    fields: ['ParentImage']
    level: high
    description: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
    logsource: product:windows - category:process_creation
    """
    return record['PARENT_NAME'].endswith("\\tttracer.exe")

sigma_time_travel_debugging_utility_usage.sigma_meta = dict(
    level="high"
)

def sigma_imports_registry_key_from_a_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regedit_import_keys.yml
    title: Imports Registry Key From a File
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the import of the specified file to the registry with regedit.exe.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regedit.exe") and (record['COMMAND_LINE'].contains("/i") or record['COMMAND_LINE'].contains("/s") or record['COMMAND_LINE'].contains(".reg"))) and not (((record['COMMAND_LINE'].contains("/e") or record['COMMAND_LINE'].contains("/a") or record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("-e") or record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("-c"))) and (re.match(':[^ \\\\]', record['COMMAND_LINE']))))

sigma_imports_registry_key_from_a_file.sigma_meta = dict(
    level="medium"
)

def sigma_defrag_deactivation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_slingshot.yml
    title: Defrag Deactivation
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and (record['COMMAND_LINE'].contains("/delete") or record['COMMAND_LINE'].contains("/change")) and record['COMMAND_LINE'].contains("/TN") and record['COMMAND_LINE'].contains("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"))

sigma_defrag_deactivation.sigma_meta = dict(
    level="medium"
)

def sigma_remote_desktop_protocol_use_mstsc(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mstsc.yml
    title: Remote Desktop Protocol Use Mstsc
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
    logsource: category:process_creation - product:windows
    """
    return ((((record['PROCESS_NAME'].endswith("\\mstsc.exe") or record['ORIGINAL_FILE_NAME'] == "mstsc.exe") and record['COMMAND_LINE'].contains("/v:")) and not ((record['PARENT_NAME'] == "C:\\Windows\\System32\\lxss\\wslhost.exe" and record['COMMAND_LINE'].contains("C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp")))) or ((record['PROCESS_NAME'].endswith("\\cmdkey.exe") or record['ORIGINAL_FILE_NAME'] == "cmdkey.exe") and (record['COMMAND_LINE'].contains("/g") and record['COMMAND_LINE'].contains("/u") and record['COMMAND_LINE'].contains("/p"))))

sigma_remote_desktop_protocol_use_mstsc.sigma_meta = dict(
    level="medium"
)

def sigma_enumeration_for_credentials_in_registry(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_enumeration_for_credentials_in_registry.yml
    title: Enumeration for Credentials in Registry
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may search the Registry on compromised systems for insecurely stored credentials.
The Windows Registry stores configuration information that can be used by the system or other programs.
Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("query") and record['COMMAND_LINE'].contains("/t") and record['COMMAND_LINE'].contains("REG_SZ") and record['COMMAND_LINE'].contains("/s")) and ((record['COMMAND_LINE'].contains("/f") and record['COMMAND_LINE'].contains("HKLM")) or (record['COMMAND_LINE'].contains("/f") and record['COMMAND_LINE'].contains("HKCU")) or record['COMMAND_LINE'].contains("HKCU\\Software\\SimonTatham\\PuTTY\\Sessions")))

sigma_enumeration_for_credentials_in_registry.sigma_meta = dict(
    level="medium"
)

def sigma_fsutil_drive_enumeration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_fsutil_drive_enumeration.yml
    title: Fsutil Drive Enumeration
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Attackers may leverage fsutil to enumerated connected drives.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\fsutil.exe") or record['ORIGINAL_FILE_NAME'] == "fsutil.exe") and record['COMMAND_LINE'].contains("drives"))

sigma_fsutil_drive_enumeration.sigma_meta = dict(
    level="low"
)

def sigma_network_sniffing(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_network_sniffing.yml
    title: Network Sniffing
    fields: ['CommandLine', 'Image']
    level: low
    description: Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\tshark.exe") and record['COMMAND_LINE'].contains("-i")) or record['PROCESS_NAME'].endswith("\\windump.exe"))

sigma_network_sniffing.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_powercfg_execution_to_change_lock_screen_timeout(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powercfg.yml
    title: Suspicious Powercfg Execution To Change Lock Screen Timeout
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powercfg.exe") or record['ORIGINAL_FILE_NAME'] == "PowerCfg.exe") and ((record['COMMAND_LINE'].contains("/setacvalueindex") and record['COMMAND_LINE'].contains("SCHEME_CURRENT") and record['COMMAND_LINE'].contains("SUB_VIDEO") and record['COMMAND_LINE'].contains("VIDEOCONLOCK")) or (record['COMMAND_LINE'].contains("-change") and record['COMMAND_LINE'].contains("-standby-timeout-"))))

sigma_suspicious_powercfg_execution_to_change_lock_screen_timeout.sigma_meta = dict(
    level="medium"
)

def sigma_cve_2021_40444_process_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_control_cve_2021_40444.yml
    title: CVE-2021-40444 Process Pattern
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects a suspicious process pattern found in CVE-2021-40444 exploitation
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\control.exe") and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe") or record['PARENT_NAME'].endswith("\\excel.exe"))) and not ((record['COMMAND_LINE'].endswith("\\control.exe input.dll") or record['COMMAND_LINE'].endswith("\\control.exe\" input.dll"))))

sigma_cve_2021_40444_process_pattern.sigma_meta = dict(
    level="high"
)

def sigma_renamed_psexec_service_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexesvc_renamed.yml
    title: Renamed PsExec Service Execution
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "psexesvc.exe" and not (record['PROCESS_NAME'] == "C:\\Windows\\PSEXESVC.exe"))

sigma_renamed_psexec_service_execution.sigma_meta = dict(
    level="high"
)

def sigma_add_user_to_local_administrators(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_add_local_admin.yml
    title: Add User to Local Administrators
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious command line that adds an account to the local administrators/administrateurs group
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("localgroup") and record['COMMAND_LINE'].contains("/add")) or (record['COMMAND_LINE'].contains("Add-LocalGroupMember") and record['COMMAND_LINE'].contains("-Group"))) and (record['COMMAND_LINE'].contains("administrators") or record['COMMAND_LINE'].contains("administrateur")))

sigma_add_user_to_local_administrators.sigma_meta = dict(
    level="medium"
)

def sigma_wsf_jse_js_vba_vbe_file_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_script_execution.yml
    title: WSF/JSE/JS/VBA/VBE File Execution
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects suspicious file execution by wscript and cscript
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe")) and (record['COMMAND_LINE'].contains(".jse") or record['COMMAND_LINE'].contains(".vbe") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".vba")))

sigma_wsf_jse_js_vba_vbe_file_execution.sigma_meta = dict(
    level="medium"
)

def sigma_taskmgr_as_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_taskmgr_parent.yml
    title: Taskmgr as Parent
    fields: ['Image', 'ParentImage']
    level: low
    description: Detects the creation of a process from Windows task manager
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\taskmgr.exe") and not ((record['PROCESS_NAME'].endswith("\\resmon.exe") or record['PROCESS_NAME'].endswith("\\mmc.exe") or record['PROCESS_NAME'].endswith("\\taskmgr.exe"))))

sigma_taskmgr_as_parent.sigma_meta = dict(
    level="low"
)

def sigma_execution_of_renamed_plink_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_plink.yml
    title: Execution Of Renamed Plink Binary
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Execution of a renamed version of the Plink binary
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "Plink" or (record['COMMAND_LINE'].contains("-l forward") and record['COMMAND_LINE'].contains("-P") and record['COMMAND_LINE'].contains("-R"))) and not (record['PROCESS_NAME'].endswith("\\plink.exe")))

sigma_execution_of_renamed_plink_binary.sigma_meta = dict(
    level="high"
)

def sigma_bitsadmin_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml
    title: Bitsadmin Download
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of bitsadmin downloading a file
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and record['COMMAND_LINE'].contains("http")) or ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and record['COMMAND_LINE'].contains("/transfer")) or record['COMMAND_LINE'].contains("copy bitsadmin.exe"))

sigma_bitsadmin_download.sigma_meta = dict(
    level="medium"
)

def sigma_lazarus_loaders(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_lazarus_loader.yml
    title: Lazarus Loaders
    fields: ['CommandLine']
    level: critical
    description: Detects different loaders as described in various threat reports on Lazarus group activity
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("cmd.exe /c") and record['COMMAND_LINE'].contains("-p 0x") and (record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("C:\\RECYCLER"))) or (record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("C:\\ProgramData") and (record['COMMAND_LINE'].contains(".bin,") or record['COMMAND_LINE'].contains(".tmp,") or record['COMMAND_LINE'].contains(".dat,") or record['COMMAND_LINE'].contains(".io,") or record['COMMAND_LINE'].contains(".ini,") or record['COMMAND_LINE'].contains(".db,"))))

sigma_lazarus_loaders.sigma_meta = dict(
    level="critical"
)

def sigma_use_of_ultravnc_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ultravnc.yml
    title: Use of UltraVNC Remote Access Software
    fields: ['OriginalFileName', 'Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software,to establish an interactive command and control channel to target systems within networks
    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "VNCViewer" or record['PRODUCT_NAME'] == "UltraVNC VNCViewer" or record['COMPANY'] == "UltraVNC" or record['ORIGINAL_FILE_NAME'] == "VNCViewer.exe")

sigma_use_of_ultravnc_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_root_certificate_installed(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_root_certificate_installed.yml
    title: Root Certificate Installed
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certutil.exe") and record['COMMAND_LINE'].contains("-addstore") and record['COMMAND_LINE'].contains("root")) or (record['PROCESS_NAME'].endswith("\\CertMgr.exe") and record['COMMAND_LINE'].contains("/add") and record['COMMAND_LINE'].contains("root")))

sigma_root_certificate_installed.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_ftp_exe_binary_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_ftp.yml
    title: Renamed FTP.EXE Binary Execution
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects execution of renamed ftp.exe binary based on OriginalFileName field
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "ftp.exe" and not (record['PROCESS_NAME'].endswith("\\ftp.exe")))

sigma_renamed_ftp_exe_binary_execution.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_tools_using_computerdefaults(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tools_uac_bypass_computerdefaults.yml
    title: UAC Bypass Tools Using ComputerDefaults
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59)
    logsource: category:process_creation - product:windows
    """
    return (((record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and record['PROCESS_NAME'] == "C:\\Windows\\System32\\ComputerDefaults.exe") and not ((record['PARENT_NAME'].contains(":\\Windows\\System32") or record['PARENT_NAME'].contains(":\\Program Files"))))

sigma_uac_bypass_tools_using_computerdefaults.sigma_meta = dict(
    level="high"
)

def sigma_remote_code_execute_via_winrm_vbs(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_winrm_execution.yml
    title: Remote Code Execute via Winrm.vbs
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects an attempt to execute code or create service on remote host via winrm.vbs.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cscript.exe") or record['ORIGINAL_FILE_NAME'] == "cscript.exe") and (record['COMMAND_LINE'].contains("winrm") and record['COMMAND_LINE'].contains("invoke Create wmicimv2/Win32_") and record['COMMAND_LINE'].contains("-r:http")))

sigma_remote_code_execute_via_winrm_vbs.sigma_meta = dict(
    level="medium"
)

def sigma_remote_file_download_via_desktopimgdownldr_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_remote_file_download_desktopimgdownldr.yml
    title: Remote File Download via Desktopimgdownldr Utility
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\desktopimgdownldr.exe") and record['PARENT_NAME'].endswith("\\desktopimgdownldr.exe") and record['COMMAND_LINE'].contains("/lockscreenurl:http"))

sigma_remote_file_download_via_desktopimgdownldr_utility.sigma_meta = dict(
    level="medium"
)

def sigma_conti_ransomware_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_conti_cmd_ransomware.yml
    title: Conti Ransomware Execution
    fields: ['CommandLine']
    level: critical
    description: Conti ransomware command line ioc
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-m") and record['COMMAND_LINE'].contains("-net") and record['COMMAND_LINE'].contains("-size") and record['COMMAND_LINE'].contains("-nomutex") and record['COMMAND_LINE'].contains("-p ") and record['COMMAND_LINE'].contains("$"))

sigma_conti_ransomware_execution.sigma_meta = dict(
    level="critical"
)

def sigma_using_appvlp_to_circumvent_asr_file_path_rule(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_asr_bypass_via_appvlp_re.yml
    title: Using AppVLP To Circumvent ASR File Path Rule
    fields: ['CommandLine']
    level: medium
    description: Application Virtualization Utility is included with Microsoft Office. We are able to abuse "AppVLP" to execute shell commands.
Normally, this binary is used for Application Virtualization, but we can use it as an abuse binary to circumvent the ASR file path rule folder
or to mark a file as a system file.

    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("appvlp.exe") and (record['COMMAND_LINE'].contains("cmd.exe") or record['COMMAND_LINE'].contains("powershell.exe") or record['COMMAND_LINE'].contains("pwsh.exe")) and (record['COMMAND_LINE'].contains(".sh") or record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bin") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cmd") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".msh") or record['COMMAND_LINE'].contains(".reg") or record['COMMAND_LINE'].contains(".scr") or record['COMMAND_LINE'].contains(".ps") or record['COMMAND_LINE'].contains(".vb") or record['COMMAND_LINE'].contains(".jar") or record['COMMAND_LINE'].contains(".pl") or record['COMMAND_LINE'].contains(".inf")))

sigma_using_appvlp_to_circumvent_asr_file_path_rule.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_adfind_enumeration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_adfind_enumeration.yml
    title: Suspicious AdFind Enumeration
    fields: ['CommandLine']
    level: high
    description: Detects the execution of a AdFind for enumeration based on it's commadline flags
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("lockoutduration") or record['COMMAND_LINE'].contains("lockoutthreshold") or record['COMMAND_LINE'].contains("lockoutobservationwindow") or record['COMMAND_LINE'].contains("maxpwdage") or record['COMMAND_LINE'].contains("minpwdage") or record['COMMAND_LINE'].contains("minpwdlength") or record['COMMAND_LINE'].contains("pwdhistorylength") or record['COMMAND_LINE'].contains("pwdproperties")) or record['COMMAND_LINE'].contains("-sc admincountdmp") or record['COMMAND_LINE'].contains("-sc exchaddresses"))

sigma_suspicious_adfind_enumeration.sigma_meta = dict(
    level="high"
)

def sigma_ncat_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netcat_execution.yml
    title: Ncat Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ncat.exe") or record['PROCESS_NAME'].endswith("\\netcat.exe")) or (record['COMMAND_LINE'].contains("-lvp") or record['COMMAND_LINE'].contains("-lvnp") or record['COMMAND_LINE'].contains("-l -v -p") or record['COMMAND_LINE'].contains("-lv -p") or record['COMMAND_LINE'].contains("-l --proxy-type http") or record['COMMAND_LINE'].contains("--exec cmd.exe") or record['COMMAND_LINE'].contains("-vnl --exec")))

sigma_ncat_execution.sigma_meta = dict(
    level="high"
)

def sigma_possible_app_whitelisting_bypass_via_windbg_cdb_as_a_shellcode_runner(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cdb.yml
    title: Possible App Whitelisting Bypass via WinDbg/CDB as a Shellcode Runner
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Launch 64-bit shellcode from a debugger script file using cdb.exe.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cdb.exe") or record['ORIGINAL_FILE_NAME'] == "CDB.Exe") and (record['COMMAND_LINE'].contains("-c") or record['COMMAND_LINE'].contains("-cf")))

sigma_possible_app_whitelisting_bypass_via_windbg_cdb_as_a_shellcode_runner.sigma_meta = dict(
    level="medium"
)

def sigma_empire_powershell_uac_bypass(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_empire_uac_bypass.yml
    title: Empire PowerShell UAC Bypass
    fields: ['CommandLine']
    level: critical
    description: Detects some Empire PowerShell UAC bypass methods
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)") or record['COMMAND_LINE'].contains("-NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);"))

sigma_empire_powershell_uac_bypass.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_net_use_command_combo(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_net_use.yml
    title: Suspicious Net Use Command Combo
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects net use command combo which executes files from WebDAV server; seen in malicious LNK files
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].contains("\\cmd.exe") and record['COMMAND_LINE'].contains("net use http") and record['COMMAND_LINE'].contains("& start /b") and record['COMMAND_LINE'].contains("\\DavWWWRoot") and (record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".vbs") or record['COMMAND_LINE'].contains(".ps1")))

sigma_suspicious_net_use_command_combo.sigma_meta = dict(
    level="high"
)

def sigma_network_reconnaissance_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_recon_network_activity.yml
    title: Network Reconnaissance Activity
    fields: ['CommandLine']
    level: high
    description: Detects a set of suspicious network related commands often used in recon stages
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("nslookup") and record['COMMAND_LINE'].contains("_ldap._tcp.dc._msdcs."))

sigma_network_reconnaissance_activity.sigma_meta = dict(
    level="high"
)

def sigma_emotet_rundll32_process_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_emotet_rundll32_execution.yml
    title: Emotet RunDLL32 Process Creation
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,Control_RunDLL
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\rundll32.exe") and (record['COMMAND_LINE'].endswith(",RunDLL") or record['COMMAND_LINE'].endswith(",Control_RunDLL"))) and not (record['PARENT_NAME'].endswith("\\tracker.exe"))) and not ((record['COMMAND_LINE'].endswith(".dll,Control_RunDLL") or record['COMMAND_LINE'].endswith(".dll\",Control_RunDLL") or record['COMMAND_LINE'].endswith(".dll\',Control_RunDLL"))))

sigma_emotet_rundll32_process_creation.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_certreq_command_to_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_certreq_download.yml
    title: Suspicious Certreq Command to Download
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects a suspicious certreq execution taken from the LOLBAS examples, which can be abused to download (small) files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certreq.exe") or record['ORIGINAL_FILE_NAME'] == "CertReq.exe") and (record['COMMAND_LINE'].contains("-Post") and record['COMMAND_LINE'].contains("-config") and record['COMMAND_LINE'].contains("http") and record['COMMAND_LINE'].contains("C:\\windows\\win.ini")))

sigma_suspicious_certreq_command_to_download.sigma_meta = dict(
    level="high"
)

def sigma_detection_of_powershell_execution_via_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_dll_execution.yml
    title: Detection of PowerShell Execution via DLL
    fields: ['CommandLine', 'Image', 'Description']
    level: high
    description: Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['DESCRIPTION'].contains("Windows-Hostprozess (Rundll32)")) and (record['COMMAND_LINE'].contains("Default.GetString") or record['COMMAND_LINE'].contains("FromBase64String")))

sigma_detection_of_powershell_execution_via_dll.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_netsh_discovery_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_netsh_discovery_command.yml
    title: Suspicious Netsh Discovery Command
    fields: ['CommandLine']
    level: low
    description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("show") and record['COMMAND_LINE'].contains("firewall") and (record['COMMAND_LINE'].contains("config") or record['COMMAND_LINE'].contains("state") or record['COMMAND_LINE'].contains("rule") or record['COMMAND_LINE'].contains("name=all")))

sigma_suspicious_netsh_discovery_command.sigma_meta = dict(
    level="low"
)

def sigma_wusa_extracting_cab_files_from_suspicious_paths(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wusa_susp_cap_extraction_from_susp_paths.yml
    title: Wusa Extracting Cab Files From Suspicious Paths
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects usage of the "wusa.exe" (Windows Update Standalone Installer) utility to extract cab using the "/extract" argument from suspicious paths
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wusa.exe") and record['COMMAND_LINE'].contains("/extract:") and (record['COMMAND_LINE'].contains("C:\\Users\\Public") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Appdata\\Local\\Temp") or record['COMMAND_LINE'].contains("\\Windows\\Temp") or record['COMMAND_LINE'].contains("\\PerfLogs")))

sigma_wusa_extracting_cab_files_from_suspicious_paths.sigma_meta = dict(
    level="high"
)

def sigma_shadow_copies_deletion_using_operating_systems_utilities(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shadow_copies_deletion.yml
    title: Shadow Copies Deletion Using Operating Systems Utilities
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Shadow Copies deletion using operating systems utilities
    logsource: category:process_creation - product:windows
    """
    return (((((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\vssadmin.exe") or record['PROCESS_NAME'].endswith("\\diskshadow.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['ORIGINAL_FILE_NAME'] == "VSSADMIN.EXE" or record['ORIGINAL_FILE_NAME'] == "diskshadow.exe")) and (record['COMMAND_LINE'].contains("shadow") and record['COMMAND_LINE'].contains("delete"))) or ((record['PROCESS_NAME'].endswith("\\wbadmin.exe") or record['ORIGINAL_FILE_NAME'] == "WBADMIN.EXE") and (record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("catalog") and record['COMMAND_LINE'].contains("quiet")))) or ((record['PROCESS_NAME'].endswith("\\vssadmin.exe") or record['ORIGINAL_FILE_NAME'] == "VSSADMIN.EXE") and (record['COMMAND_LINE'].contains("resize") and record['COMMAND_LINE'].contains("shadowstorage") and (record['COMMAND_LINE'].contains("unbounded") or record['COMMAND_LINE'].contains("/MaxSize=")))))

sigma_shadow_copies_deletion_using_operating_systems_utilities.sigma_meta = dict(
    level="high"
)

def sigma_tropictrooper_campaign_november_2018(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_tropictrooper.yml
    title: TropicTrooper Campaign November 2018
    fields: ['CommandLine']
    level: high
    description: Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc")

sigma_tropictrooper_campaign_november_2018.sigma_meta = dict(
    level="high"
)

def sigma_delete_services_via_reg_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_delete_services.yml
    title: Delete Services Via Reg Utility
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of "reg.exe" commands with the "delete" flag on services registry key. Often used by attacker to remove AV software services
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("\\SYSTEM\\CurrentControlSet\\services"))

sigma_delete_services_via_reg_utility.sigma_meta = dict(
    level="high"
)

def sigma_bloodhound_and_sharphound_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_bloodhound.yml
    title: Bloodhound and Sharphound Hack Tool
    fields: ['CommandLine', 'Image', 'Company', 'Product', 'Description']
    level: high
    description: Detects command line parameters used by Bloodhound and Sharphound hack tools
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\Bloodhound.exe") or record['PROCESS_NAME'].contains("\\SharpHound.exe")) or (record['COMMAND_LINE'].contains("-CollectionMethod All") or record['COMMAND_LINE'].contains("--CollectionMethods Session") or record['COMMAND_LINE'].contains("--Loop --Loopduration") or record['COMMAND_LINE'].contains("--PortScanTimeout") or record['COMMAND_LINE'].contains(".exe -c All -d") or record['COMMAND_LINE'].contains("Invoke-Bloodhound") or record['COMMAND_LINE'].contains("Get-BloodHoundData")) or (record['COMMAND_LINE'].contains("-JsonFolder") and record['COMMAND_LINE'].contains("-ZipFileName")) or (record['COMMAND_LINE'].contains("DCOnly") and record['COMMAND_LINE'].contains("--NoSaveCache")) or (record['PRODUCT_NAME'].contains("SharpHound") or record['DESCRIPTION'].contains("SharpHound") or (record['COMPANY'].contains("SpecterOps") or record['COMPANY'].contains("evil corp"))))

sigma_bloodhound_and_sharphound_hack_tool.sigma_meta = dict(
    level="high"
)

def sigma_execute_from_alternate_data_streams(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_alternate_data_streams.yml
    title: Execute From Alternate Data Streams
    fields: ['CommandLine']
    level: medium
    description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("txt:") and ((record['COMMAND_LINE'].contains("type") and record['COMMAND_LINE'].contains(">")) or (record['COMMAND_LINE'].contains("makecab") and record['COMMAND_LINE'].contains(".cab")) or (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("export")) or (record['COMMAND_LINE'].contains("regedit") and record['COMMAND_LINE'].contains("/E")) or (record['COMMAND_LINE'].contains("esentutl") and record['COMMAND_LINE'].contains("/y") and record['COMMAND_LINE'].contains("/d") and record['COMMAND_LINE'].contains("/o"))))

sigma_execute_from_alternate_data_streams.sigma_meta = dict(
    level="medium"
)

def sigma_logon_scripts_userinitmprlogonscript_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_logon_scripts_userinitmprlogonscript_proc.yml
    title: Logon Scripts (UserInitMprLogonScript)
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects creation or execution of UserInitMprLogonScript persistence method
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\userinit.exe") and not (((record['PROCESS_NAME'].endswith("explorer.exe") or record['PROCESS_NAME'].endswith("\\proquota.exe"))) or ((record['COMMAND_LINE'].contains("netlogon*.bat") or record['COMMAND_LINE'].contains("UsrLogon.cmd") or record['COMMAND_LINE'].contains("C:\\WINDOWS\\Explorer.EXE"))) or (record['PROCESS_NAME'].endswith("\\Citrix\\System32\\icast.exe")))) or record['COMMAND_LINE'].contains("UserInitMprLogonScript"))

sigma_logon_scripts_userinitmprlogonscript_.sigma_meta = dict(
    level="high"
)

def sigma_safetykatz_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_safetykatz.yml
    title: SafetyKatz Hack Tool
    fields: ['Image', 'OriginalFileName', 'Description']
    level: critical
    description: Detects the execution of the hacktool SafetyKatz via PE information and default Image name
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SafetyKatz.exe") or record['ORIGINAL_FILE_NAME'] == "SafetyKatz.exe" or record['DESCRIPTION'] == "SafetyKatz")

sigma_safetykatz_hack_tool.sigma_meta = dict(
    level="critical"
)

def sigma_change_default_file_association(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_change_default_file_association.yml
    title: Change Default File Association
    fields: ['CommandLine']
    level: low
    description: When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("assoc") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/k") or record['COMMAND_LINE'].contains("/r")))

sigma_change_default_file_association.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_shells_spawn_by_java_utility_keytool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shell_spawn_by_java_keytool.yml
    title: Suspicious Shells Spawn by Java Utility Keytool
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\keytool.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\scrcons.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\mftrace.exe") or record['PROCESS_NAME'].endswith("\\AppVLP.exe")))

sigma_suspicious_shells_spawn_by_java_utility_keytool.sigma_meta = dict(
    level="high"
)

def sigma_root_certificate_installed_from_susp_locations(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_import_cert_susp_locations.yml
    title: Root Certificate Installed From Susp Locations
    fields: ['CommandLine']
    level: high
    description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Import-Certificate") and record['COMMAND_LINE'].contains("-File-Path") and record['COMMAND_LINE'].contains("Cert:\\LocalMachine\\Root") and (record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("C:\\Windows\\TEMP") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Perflogs") or record['COMMAND_LINE'].contains("C:\\Users\\Public")))

sigma_root_certificate_installed_from_susp_locations.sigma_meta = dict(
    level="high"
)

def sigma_advanced_ip_scanner(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_advanced_ip_scanner.yml
    title: Advanced IP Scanner
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Description']
    level: medium
    description: Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\advanced_ip_scanner") or record['ORIGINAL_FILE_NAME'].contains("advanced_ip_scanner") or record['DESCRIPTION'].contains("Advanced IP Scanner")) or (record['COMMAND_LINE'].contains("/portable") and record['COMMAND_LINE'].contains("/lng")))

sigma_advanced_ip_scanner.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_via_event_viewer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysmon_uac_bypass_eventvwr.yml
    title: UAC Bypass via Event Viewer
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects UAC bypass method using Windows event viewer
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\eventvwr.exe") and not ((record['PROCESS_NAME'].endswith("\\mmc.exe") or record['PROCESS_NAME'].endswith(":\\Windows\\SysWOW64\\WerFault.exe") or record['PROCESS_NAME'].endswith(":\\Windows\\System32\\WerFault.exe"))))

sigma_uac_bypass_via_event_viewer.sigma_meta = dict(
    level="high"
)

def sigma_abusing_ieexec_to_download_payloads(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_ieexec_download.yml
    title: Abusing IEExec To Download Payloads
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of the IEExec utility to download payloads
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\IEExec.exe") or record['ORIGINAL_FILE_NAME'] == "IEExec.exe") and (record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("http://")))

sigma_abusing_ieexec_to_download_payloads.sigma_meta = dict(
    level="high"
)

def sigma_dit_snapshot_viewer_use(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ditsnap.yml
    title: DIT Snapshot Viewer Use
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\ditsnap.exe") or record['COMMAND_LINE'].contains("ditsnap.exe"))

sigma_dit_snapshot_viewer_use.sigma_meta = dict(
    level="high"
)

def sigma_explorer_process_tree_break(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_explorer_break_proctree.yml
    title: Explorer Process Tree Break
    fields: ['CommandLine']
    level: medium
    description: Detects a command line process that uses explorer.exe to launch arbitrary commands or binaries,
which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer spawning from "svchost"

    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}") or (record['COMMAND_LINE'].contains("explorer.exe") and record['COMMAND_LINE'].contains("/root,")))

sigma_explorer_process_tree_break.sigma_meta = dict(
    level="medium"
)

def sigma_shell32_dll_execution_in_suspicious_directory(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_target_location_shell32.yml
    title: Shell32 DLL Execution in Suspicious Directory
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects shell32.dll executing a DLL in a suspicious directory
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("shell32.dll") and record['COMMAND_LINE'].contains("Control_RunDLL") and (record['COMMAND_LINE'].contains("%AppData%") or record['COMMAND_LINE'].contains("%LocalAppData%") or record['COMMAND_LINE'].contains("%Temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("\\AppData") or record['COMMAND_LINE'].contains("\\Temp") or record['COMMAND_LINE'].contains("\\Users\\Public")))

sigma_shell32_dll_execution_in_suspicious_directory.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_clsid_folder_name_in_suspicious_locations(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_clsid_foldername.yml
    title: Suspicious CLSID Folder Name In Suspicious Locations
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of a CLSID folder name located in a suspicious location from the commandline as seen being used in IcedID
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("\\AppData\\Roaming") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp")) and record['COMMAND_LINE'].contains("\\{") and record['COMMAND_LINE'].contains("}")) and not ((record['PROCESS_NAME'].contains("\\{") and record['PROCESS_NAME'].contains("}")) or (record.get('PROCESS_NAME', None) == None)))

sigma_suspicious_clsid_folder_name_in_suspicious_locations.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_nt_resource_kit_auditpol_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_nt_resource_kit_auditpol_usage.yml
    title: Suspicious NT Resource Kit Auditpol Usage
    fields: ['CommandLine']
    level: high
    description: Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability.
This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.

    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/logon:none") or record['COMMAND_LINE'].contains("/system:none") or record['COMMAND_LINE'].contains("/sam:none") or record['COMMAND_LINE'].contains("/privilege:none") or record['COMMAND_LINE'].contains("/object:none") or record['COMMAND_LINE'].contains("/process:none") or record['COMMAND_LINE'].contains("/policy:none"))

sigma_suspicious_nt_resource_kit_auditpol_usage.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_atbroker_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_atbroker.yml
    title: Suspicious Atbroker Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Atbroker executing non-deafualt Assistive Technology applications
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("AtBroker.exe") and record['COMMAND_LINE'].contains("start")) and not ((record['COMMAND_LINE'].contains("animations") or record['COMMAND_LINE'].contains("audiodescription") or record['COMMAND_LINE'].contains("caretbrowsing") or record['COMMAND_LINE'].contains("caretwidth") or record['COMMAND_LINE'].contains("colorfiltering") or record['COMMAND_LINE'].contains("cursorscheme") or record['COMMAND_LINE'].contains("filterkeys") or record['COMMAND_LINE'].contains("focusborderheight") or record['COMMAND_LINE'].contains("focusborderwidth") or record['COMMAND_LINE'].contains("highcontrast") or record['COMMAND_LINE'].contains("keyboardcues") or record['COMMAND_LINE'].contains("keyboardpref") or record['COMMAND_LINE'].contains("magnifierpane") or record['COMMAND_LINE'].contains("messageduration") or record['COMMAND_LINE'].contains("minimumhitradius") or record['COMMAND_LINE'].contains("mousekeys") or record['COMMAND_LINE'].contains("Narrator") or record['COMMAND_LINE'].contains("osk") or record['COMMAND_LINE'].contains("overlappedcontent") or record['COMMAND_LINE'].contains("showsounds") or record['COMMAND_LINE'].contains("soundsentry") or record['COMMAND_LINE'].contains("stickykeys") or record['COMMAND_LINE'].contains("togglekeys") or record['COMMAND_LINE'].contains("windowarranging") or record['COMMAND_LINE'].contains("windowtracking") or record['COMMAND_LINE'].contains("windowtrackingtimeout") or record['COMMAND_LINE'].contains("windowtrackingzorder"))))

sigma_suspicious_atbroker_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_execution_from_outlook(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_outlook.yml
    title: Suspicious Execution from Outlook
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects EnableUnsafeClientMailRules used for Script Execution from Outlook
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("EnableUnsafeClientMailRules") or (record['PARENT_NAME'].endswith("\\outlook.exe") and record['COMMAND_LINE'].contains("") and record['COMMAND_LINE'].contains("") and record['COMMAND_LINE'].contains(".exe")))

sigma_suspicious_execution_from_outlook.sigma_meta = dict(
    level="high"
)

def sigma_malicious_pe_execution_by_microsoft_visual_studio_debugger(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.yml
    title: Malicious PE Execution by Microsoft Visual Studio Debugger
    fields: ['Image', 'ParentImage']
    level: medium
    description: There is an option for a MS VS Just-In-Time Debugger "vsjitdebugger.exe" to launch specified executable and attach a debugger.
This option may be used adversaries to execute malicious code by signed verified binary.
The debugger is installed alongside with Microsoft Visual Studio package.

    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\vsjitdebugger.exe") and not ((record['PROCESS_NAME'].endswith("\\vsimmersiveactivatehelper*.exe") or record['PROCESS_NAME'].endswith("\\devenv.exe"))))

sigma_malicious_pe_execution_by_microsoft_visual_studio_debugger.sigma_meta = dict(
    level="medium"
)

def sigma_baby_shark_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_babyshark.yml
    title: Baby Shark Activity
    fields: ['CommandLine']
    level: high
    description: Detects activity that could be related to Baby Shark malware
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("reg query \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\"") or record['COMMAND_LINE'].contains("powershell.exe mshta.exe http") or record['COMMAND_LINE'].contains("cmd.exe /c taskkill /im cmd.exe"))

sigma_baby_shark_activity.sigma_meta = dict(
    level="high"
)

def sigma_possible_exfiltration_of_data_via_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exfil_data_via_cli.yml
    title: Possible Exfiltration Of Data Via CLI
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the use of various cli utility related to web request exfiltrating data
    logsource: category:process_creation - product:windows
    """
    return ((((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe")) and (record['COMMAND_LINE'].contains("Invoke-WebRequest") or record['COMMAND_LINE'].contains("iwr") or record['COMMAND_LINE'].contains("wget") or record['COMMAND_LINE'].contains("curl")) and record['COMMAND_LINE'].contains("-ur") and record['COMMAND_LINE'].contains("-me") and record['COMMAND_LINE'].contains("-b") and record['COMMAND_LINE'].contains("POST")) or (record['PROCESS_NAME'].endswith("\\curl.exe") and record['COMMAND_LINE'].contains("--ur") and (record['COMMAND_LINE'].contains("-d") or record['COMMAND_LINE'].contains("--data")))) and ((record['COMMAND_LINE'].contains("ToBase64String") or record['COMMAND_LINE'].contains("whoami") or record['COMMAND_LINE'].contains("nltest") or record['COMMAND_LINE'].contains("ifconfig") or record['COMMAND_LINE'].contains("hostname") or record['COMMAND_LINE'].contains("net view") or record['COMMAND_LINE'].contains("qprocess") or record['COMMAND_LINE'].contains("netstat") or record['COMMAND_LINE'].contains("systeminfo") or record['COMMAND_LINE'].contains("tasklist") or record['COMMAND_LINE'].contains("sc query")) or (record['COMMAND_LINE'].contains("type") and record['COMMAND_LINE'].contains(">") and record['COMMAND_LINE'].contains("C:"))))

sigma_possible_exfiltration_of_data_via_cli.sigma_meta = dict(
    level="high"
)

def sigma_zip_a_folder_with_powershell_for_staging_in_temp(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_zip_compress.yml
    title: Zip A Folder With PowerShell For Staging In Temp
    fields: ['CommandLine']
    level: medium
    description: Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("Compress-Archive") and record['COMMAND_LINE'].contains("-Path") and record['COMMAND_LINE'].contains("-DestinationPath") and record['COMMAND_LINE'].contains("$env:TEMP"))

sigma_zip_a_folder_with_powershell_for_staging_in_temp.sigma_meta = dict(
    level="medium"
)

def sigma_dinject_powershell_cradle_commandline_flags(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dinjector.yml
    title: DInject PowerShell Cradle CommandLine Flags
    fields: ['CommandLine', 'ParentImage']
    level: critical
    description: Detects the use of the Dinject PowerShell cradle based on the specific flags
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("/am51") or record['COMMAND_LINE'].contains("/password")) and not ((record['COMMAND_LINE'].contains("/PASSWORDCHG") or (record['PARENT_NAME'] == "C:\\Program Files\\CEETIS\\CEETIS_IDE.exe" or record['PARENT_NAME'] == "C:\\Program Files (x86)\\CEETIS\\CEETIS_IDE.exe"))))

sigma_dinject_powershell_cradle_commandline_flags.sigma_meta = dict(
    level="critical"
)

def sigma_3proxy_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_3proxy_usage.yml
    title: 3Proxy Usage
    fields: ['CommandLine', 'Image', 'Description']
    level: high
    description: Detects the use of 3proxy, a tiny free proxy server
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\3proxy.exe")

sigma_3proxy_usage.sigma_meta = dict(
    level="high"
)

def sigma_ps_exe_renamed_sysinternals_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_ta17_293a_ps.yml
    title: Ps.exe Renamed SysInternals Tool
    fields: ['CommandLine']
    level: high
    description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'] == "ps.exe -accepteula"

sigma_ps_exe_renamed_sysinternals_tool.sigma_meta = dict(
    level="high"
)

def sigma_curl_usage_on_windows(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_curl_download.yml
    title: Curl Usage on Windows
    fields: ['Image', 'Product']
    level: low
    description: Detects a curl process start on Windows, which indicates a file download from a remote location or a simple web request to a remote server
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\curl.exe") or record['PRODUCT_NAME'] == "The curl executable")

sigma_curl_usage_on_windows.sigma_meta = dict(
    level="low"
)

def sigma_discover_private_keys(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_discover_private_keys.yml
    title: Discover Private Keys
    fields: ['CommandLine']
    level: medium
    description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("dir") or record['COMMAND_LINE'].contains("findstr")) and (record['COMMAND_LINE'].contains(".key") or record['COMMAND_LINE'].contains(".pgp") or record['COMMAND_LINE'].contains(".gpg") or record['COMMAND_LINE'].contains(".ppk") or record['COMMAND_LINE'].contains(".p12") or record['COMMAND_LINE'].contains(".pem") or record['COMMAND_LINE'].contains(".pfx") or record['COMMAND_LINE'].contains(".cer") or record['COMMAND_LINE'].contains(".p7b") or record['COMMAND_LINE'].contains(".asc")))

sigma_discover_private_keys.sigma_meta = dict(
    level="medium"
)

def sigma_crackmapexec_command_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_crackmapexec_execution.yml
    title: CrackMapExec Command Execution
    fields: ['CommandLine']
    level: high
    description: Detect various execution methods of the CrackMapExec pentesting framework
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].endswith("cmd.exe /Q /c * 1> \\\\\\\\*\\\\*\\\\* 2>&1") or record['COMMAND_LINE'].endswith("cmd.exe /C * > \\\\\\\\*\\\\*\\\\* 2>&1") or record['COMMAND_LINE'].endswith("cmd.exe /C * > *\\\\Temp\\\\* 2>&1")) and (record['COMMAND_LINE'].contains("powershell.exe -exec bypass -noni -nop -w 1 -C \"") or record['COMMAND_LINE'].contains("powershell.exe -noni -nop -w 1 -enc")))

sigma_crackmapexec_command_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msiexec_execute_arbitrary_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msiexec_execute_dll.yml
    title: Suspicious Msiexec Execute Arbitrary DLL
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msiexec.exe") and (record['COMMAND_LINE'].contains("/y") or record['COMMAND_LINE'].contains("-y"))) and not (((record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y \"C:\\Program Files\\Bonjour\\mdnsNSP.dll") or record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Bonjour\\mdnsNSP.dll") or record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Apple Software Update\\ScriptingObjectModel.dll") or record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Apple Software Update\\SoftwareUpdateAdmin.dll") or record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y \"C:\\Windows\\CCM") or record['COMMAND_LINE'].contains("\\MsiExec.exe\" /Y C:\\Windows\\CCM")))))

sigma_suspicious_msiexec_execute_arbitrary_dll.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_using_ntfs_reparse_point_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_ntfs_reparse_point.yml
    title: UAC Bypass Using NTFS Reparse Point - Process
    fields: ['CommandLine', 'IntegrityLevel', 'ParentCommandLine', 'Image']
    level: high
    description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].startswith("\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users") and record['COMMAND_LINE'].endswith("\\AppData\\Local\\Temp\\update.msu") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System")) or (record['PARENT_COMMAND_LINE'] == "\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck" and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") and record['COMMAND_LINE'].contains("\\dismhost.exe {") and record['PROCESS_NAME'].endswith("\\DismHost.exe")))

sigma_uac_bypass_using_ntfs_reparse_point_process.sigma_meta = dict(
    level="high"
)

def sigma_sensitive_registry_access_via_volume_shadow_copy(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_conti_shadowcopy.yml
    title: Sensitive Registry Access via Volume Shadow Copy
    fields: ['CommandLine']
    level: high
    description: Detects a command that accesses password storing registry hives via volume shadow backups
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\\\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy") and (record['COMMAND_LINE'].contains("\\\\NTDS.dit") or record['COMMAND_LINE'].contains("\\\\SYSTEM") or record['COMMAND_LINE'].contains("\\\\SECURITY") or record['COMMAND_LINE'].contains("C:\\\\tmp\\\\log")))

sigma_sensitive_registry_access_via_volume_shadow_copy.sigma_meta = dict(
    level="high"
)

def sigma_shadow_copies_access_via_symlink(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shadow_copies_access_symlink.yml
    title: Shadow Copies Access via Symlink
    fields: ['CommandLine']
    level: medium
    description: Shadow Copies storage symbolic link creation using operating systems utilities
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("mklink") and record['COMMAND_LINE'].contains("HarddiskVolumeShadowCopy"))

sigma_shadow_copies_access_via_symlink.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_screenconnect_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_screenconnect.yml
    title: Use of ScreenConnect Remote Access Software
    fields: ['Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "ScreenConnect Service" or record['PRODUCT_NAME'] == "ScreenConnect" or record['COMPANY'] == "ScreenConnect Software")

sigma_use_of_screenconnect_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_sharpevtmute_evtmutehook_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysmon_disable_sharpevtmute.yml
    title: SharpEvtMute EvtMuteHook Load
    fields: ['CommandLine', 'Image', 'Description']
    level: high
    description: Detects the use of SharpEvtHook, a tool to tamper with Windows event logs
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\SharpEvtMute.exe") or record['DESCRIPTION'] == "SharpEvtMute" or (record['COMMAND_LINE'].contains("--Filter \"rule") or record['COMMAND_LINE'].contains("--Encoded --Filter \\\"")))

sigma_sharpevtmute_evtmutehook_load.sigma_meta = dict(
    level="high"
)

def sigma_cve_2021_26857_exchange_exploitation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cve_2021_26857_msexchange.yml
    title: CVE-2021-26857 Exchange Exploitation
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects possible successful exploitation for vulnerability described in CVE-2021-26857 by looking for | abnormal subprocesses spawning by Exchange Server's Unified Messaging service
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("UMWorkerProcess.exe") and not ((record['PROCESS_NAME'].endswith("wermgr.exe") or record['PROCESS_NAME'].endswith("WerFault.exe"))))

sigma_cve_2021_26857_exchange_exploitation.sigma_meta = dict(
    level="high"
)

def sigma_webshell_detection_with_command_line_keywords(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webshell_detection.yml
    title: Webshell Detection With Command Line Keywords
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects certain command line parameters often used during reconnaissance activity via web shells
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\php-cgi.exe") or record['PARENT_NAME'].endswith("\\nginx.exe") or record['PARENT_NAME'].endswith("\\httpd.exe") or record['PARENT_NAME'].endswith("\\caddy.exe") or record['PARENT_NAME'].endswith("\\ws_tomcatservice.exe")) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['PARENT_NAME'].contains("-tomcat-") or record['PARENT_NAME'].contains("\\tomcat"))) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['COMMAND_LINE'].contains("catalina.jar") or record['COMMAND_LINE'].contains("CATALINA_HOME")))) and (((record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe") and (record['COMMAND_LINE'].contains("user") or record['COMMAND_LINE'].contains("use") or record['COMMAND_LINE'].contains("group"))) or (record['ORIGINAL_FILE_NAME'] == "ping.exe" and record['COMMAND_LINE'].contains("-n")) or (record['COMMAND_LINE'].contains("&cd&echo") or record['COMMAND_LINE'].contains("cd /d")) or (record['ORIGINAL_FILE_NAME'] == "wmic.exe" and record['COMMAND_LINE'].contains("/node:")) or ((record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\systeminfo.exe") or record['PROCESS_NAME'].endswith("\\quser.exe") or record['PROCESS_NAME'].endswith("\\ipconfig.exe") or record['PROCESS_NAME'].endswith("\\pathping.exe") or record['PROCESS_NAME'].endswith("\\tracert.exe") or record['PROCESS_NAME'].endswith("\\netstat.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\vssadmin.exe") or record['PROCESS_NAME'].endswith("\\wevtutil.exe") or record['PROCESS_NAME'].endswith("\\tasklist.exe")) or (record['ORIGINAL_FILE_NAME'] == "whoami.exe" or record['ORIGINAL_FILE_NAME'] == "sysinfo.exe" or record['ORIGINAL_FILE_NAME'] == "quser.exe" or record['ORIGINAL_FILE_NAME'] == "ipconfig.exe" or record['ORIGINAL_FILE_NAME'] == "pathping.exe" or record['ORIGINAL_FILE_NAME'] == "tracert.exe" or record['ORIGINAL_FILE_NAME'] == "netstat.exe" or record['ORIGINAL_FILE_NAME'] == "schtasks.exe" or record['ORIGINAL_FILE_NAME'] == "VSSADMIN.EXE" or record['ORIGINAL_FILE_NAME'] == "wevtutil.exe" or record['ORIGINAL_FILE_NAME'] == "tasklist.exe")) or (record['COMMAND_LINE'].contains("Test-NetConnection") or record['COMMAND_LINE'].contains("dir "))))

sigma_webshell_detection_with_command_line_keywords.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_copy_from_or_to_system32(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_copy_system32.yml
    title: Suspicious Copy From or To System32
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects a suspicious copy operation that tries to copy a program from a system (System32 or SysWOW64) directory to another on disk.
Often used to move LOLBINs such as 'certutil' or 'desktopimgdownldr' to a different location with a different name in order to bypass detections based on locations

    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("copy")) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("copy-item") or record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("cpi") or record['COMMAND_LINE'].contains("cp"))) or (record['PROCESS_NAME'].endswith("\\robocopy.exe") or record['PROCESS_NAME'].endswith("\\xcopy.exe"))) and (record['COMMAND_LINE'].contains("\\System32") or record['COMMAND_LINE'].contains("\\SysWOW64")))

sigma_suspicious_copy_from_or_to_system32.sigma_meta = dict(
    level="medium"
)

def sigma_use_ntfs_short_name_in_image(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ntfs_short_name_use_image.yml
    title: Use NTFS Short Name in Image
    fields: ['Image', 'ParentImage']
    level: high
    description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("~1.exe") or record['PROCESS_NAME'].contains("~1.bat") or record['PROCESS_NAME'].contains("~1.msi") or record['PROCESS_NAME'].contains("~1.vbe") or record['PROCESS_NAME'].contains("~1.vbs") or record['PROCESS_NAME'].contains("~1.dll") or record['PROCESS_NAME'].contains("~1.ps1") or record['PROCESS_NAME'].contains("~1.js") or record['PROCESS_NAME'].contains("~1.hta") or record['PROCESS_NAME'].contains("~2.exe") or record['PROCESS_NAME'].contains("~2.bat") or record['PROCESS_NAME'].contains("~2.msi") or record['PROCESS_NAME'].contains("~2.vbe") or record['PROCESS_NAME'].contains("~2.vbs") or record['PROCESS_NAME'].contains("~2.dll") or record['PROCESS_NAME'].contains("~2.ps1") or record['PROCESS_NAME'].contains("~2.js") or record['PROCESS_NAME'].contains("~2.hta")) and not ((record['PARENT_NAME'].endswith("\\WebEx\\WebexHost.exe") or record['PARENT_NAME'].endswith("\\thor\\thor64.exe") or record['PARENT_NAME'].endswith("-installer.exe")) or record['PROCESS_NAME'].contains("\\vcredi")))

sigma_use_ntfs_short_name_in_image.sigma_meta = dict(
    level="high"
)

def sigma_use_radmin_viewer_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_radmin.yml
    title: Use Radmin Viewer Utility
    fields: ['OriginalFileName', 'Product', 'Description']
    level: high
    description: An adversary may use Radmin Viewer Utility to remotely control Windows device
    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "Radmin Viewer" or record['PRODUCT_NAME'] == "Radmin Viewer" or record['ORIGINAL_FILE_NAME'] == "Radmin.exe")

sigma_use_radmin_viewer_utility.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_usage_of_shellexec_rundll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shellexec_rundll_usage.yml
    title: Suspicious Usage Of ShellExec_RunDLL
    fields: ['CommandLine']
    level: high
    description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("ShellExec_RunDLL") and (record['COMMAND_LINE'].contains("regsvr32") or record['COMMAND_LINE'].contains("msiexec") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("odbcconf") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Temp")))

sigma_suspicious_usage_of_shellexec_rundll.sigma_meta = dict(
    level="high"
)

def sigma_powershell_reverse_shell_connection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.yml
    title: Powershell Reverse Shell Connection
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the Nishang Invoke-PowerShellTcpOneLine reverse shell
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("new-object system.net.sockets.tcpclient"))

sigma_powershell_reverse_shell_connection.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_var_launcher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_var.yml
    title: Invoke-Obfuscation VAR+ Launcher
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated use of Environment Variables to execute PowerShell
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("\"set") and record['COMMAND_LINE'].contains("-f") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/r")))

sigma_invoke_obfuscation_var_launcher.sigma_meta = dict(
    level="high"
)

def sigma_netsh_rdp_port_forwarding(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_port_fwd_3389.yml
    title: Netsh RDP Port Forwarding
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("i") and record['COMMAND_LINE'].contains("p") and record['COMMAND_LINE'].contains("=3389") and record['COMMAND_LINE'].contains("c"))

sigma_netsh_rdp_port_forwarding.sigma_meta = dict(
    level="high"
)

def sigma_redirect_output_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmd_redirect.yml
    title: Redirect Output in CommandLine
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Use ">" to redicrect information in commandline
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['PROCESS_NAME'].endswith("\\cmd.exe")) and record['COMMAND_LINE'].contains(">"))

sigma_redirect_output_in_commandline.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_key_manager_access(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_keymgr.yml
    title: Suspicious Key Manager Access
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].contains("keymgr") and record['COMMAND_LINE'].contains("KRShowKeyMgr"))

sigma_suspicious_key_manager_access.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rdp_redirect_using_tscon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_tscon_rdp_redirect.yml
    title: Suspicious RDP Redirect Using TSCON
    fields: ['CommandLine']
    level: high
    description: Detects a suspicious RDP session redirect using tscon.exe
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("/dest:rdp-tcp:")

sigma_suspicious_rdp_redirect_using_tscon.sigma_meta = dict(
    level="high"
)

def sigma_execute_code_with_pester_bat_as_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_pester_parent.yml
    title: Execute Code with Pester.bat as Parent
    fields: ['ParentCommandLine', 'ParentImage']
    level: medium
    description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe")) and record['PARENT_COMMAND_LINE'].contains("\\WindowsPowerShell\\Modules\\Pester") and (record['PARENT_COMMAND_LINE'].contains("{ Invoke-Pester -EnableExit ;") or record['PARENT_COMMAND_LINE'].contains("{ Get-Help \"")))

sigma_execute_code_with_pester_bat_as_parent.sigma_meta = dict(
    level="medium"
)

def sigma_non_interactive_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_non_interactive_powershell.yml
    title: Non Interactive PowerShell
    fields: ['Image', 'ParentImage']
    level: low
    description: Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\powershell.exe") and not (((record['PARENT_NAME'].endswith("\\explorer.exe") or record['PARENT_NAME'].endswith("\\CompatTelRunner.exe")) or record['PARENT_NAME'] == "C:\\$WINDOWS.~BT\\Sources\\SetupHost.exe")))

sigma_non_interactive_powershell.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_debugger_registration_cmdline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_install_reg_debugger_backdoor.yml
    title: Suspicious Debugger Registration Cmdline
    fields: ['CommandLine']
    level: high
    description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\CurrentVersion\\Image File Execution Options") and (record['COMMAND_LINE'].contains("sethc.exe") or record['COMMAND_LINE'].contains("utilman.exe") or record['COMMAND_LINE'].contains("osk.exe") or record['COMMAND_LINE'].contains("magnify.exe") or record['COMMAND_LINE'].contains("narrator.exe") or record['COMMAND_LINE'].contains("displayswitch.exe") or record['COMMAND_LINE'].contains("atbroker.exe") or record['COMMAND_LINE'].contains("HelpPane.exe")))

sigma_suspicious_debugger_registration_cmdline.sigma_meta = dict(
    level="high"
)

def sigma_tamper_windows_defender_remove_mppreference(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tamper_defender_remove_mppreference.yml
    title: Tamper Windows Defender Remove-MpPreference
    fields: ['CommandLine']
    level: high
    description: Detects attempts to remove windows defender configuration using the 'MpPreference' cmdlet
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("Remove-MpPreference") and (record['COMMAND_LINE'].contains("-ControlledFolderAccessProtectedFolders") or record['COMMAND_LINE'].contains("-AttackSurfaceReductionRules_Ids") or record['COMMAND_LINE'].contains("-AttackSurfaceReductionRules_Actions") or record['COMMAND_LINE'].contains("-CheckForSignaturesBeforeRunningScan")))

sigma_tamper_windows_defender_remove_mppreference.sigma_meta = dict(
    level="high"
)

def sigma_ms_office_product_spawning_exe_in_user_dir(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_spawn_exe_from_users_directory.yml
    title: MS Office Product Spawning Exe in User Dir
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\WINWORD.EXE") or record['PARENT_NAME'].endswith("\\EXCEL.EXE") or record['PARENT_NAME'].endswith("\\POWERPNT.exe") or record['PARENT_NAME'].endswith("\\MSPUB.exe") or record['PARENT_NAME'].endswith("\\VISIO.exe") or record['PARENT_NAME'].endswith("\\MSACCESS.exe") or record['PARENT_NAME'].endswith("\\EQNEDT32.exe")) and record['PROCESS_NAME'].startswith("C:\\users") and record['PROCESS_NAME'].endswith(".exe")) and not (record['PROCESS_NAME'].endswith("\\Teams.exe")))

sigma_ms_office_product_spawning_exe_in_user_dir.sigma_meta = dict(
    level="high"
)

def sigma_application_whitelisting_bypass_via_presentationhost_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_presentationhost.yml
    title: Application Whitelisting Bypass via PresentationHost.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files. It can be abused to run malicious ".xbap" files any bypass AWL
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\presentationhost.exe") or record['ORIGINAL_FILE_NAME'] == "PresentationHost.exe") and record['COMMAND_LINE'].contains(".xbap")) and not ((record['COMMAND_LINE'].contains("C:\\Windows") or record['COMMAND_LINE'].contains("C:\\Program Files"))))

sigma_application_whitelisting_bypass_via_presentationhost_exe.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_tool_uacme_akagi(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hktl_uacme_uac_bypass.yml
    title: UAC Bypass Tool UACMe Akagi
    fields: ['Image', 'Company', 'OriginalFileName', 'Product', 'Hashes', 'Description', 'Imphash']
    level: high
    description: Detects execution of UACMe (a tool used for UAC bypass) via default PE metadata
    logsource: category:process_creation - product:windows
    """
    return (record['PRODUCT_NAME'] == "UACMe" or (record['COMPANY'] == "REvol Corp" or record['COMPANY'] == "APT 92" or record['COMPANY'] == "UG North" or record['COMPANY'] == "Hazardous Environments" or record['COMPANY'] == "CD Project Rekt") or (record['DESCRIPTION'] == "UACMe main module" or record['DESCRIPTION'] == "Pentesting utility") or (record['ORIGINAL_FILE_NAME'] == "Akagi.exe" or record['ORIGINAL_FILE_NAME'] == "Akagi64.exe") or (record['PROCESS_NAME'].endswith("\\Akagi64.exe") or record['PROCESS_NAME'].endswith("\\Akagi.exe")) or (record['HASHES'].contains("IMPHASH=767637C23BB42CD5D7397CF58B0BE688") or record['HASHES'].contains("IMPHASH=14C4E4C72BA075E9069EE67F39188AD8") or record['HASHES'].contains("IMPHASH=3C782813D4AFCE07BBFC5A9772ACDBDC") or record['HASHES'].contains("IMPHASH=7D010C6BB6A3726F327F7E239166D127") or record['HASHES'].contains("IMPHASH=89159BA4DD04E4CE5559F132A9964EB3") or record['HASHES'].contains("IMPHASH=6F33F4A5FC42B8CEC7314947BD13F30F") or record['HASHES'].contains("IMPHASH=5834ED4291BDEB928270428EBBAF7604") or record['HASHES'].contains("IMPHASH=5A8A8A43F25485E7EE1B201EDCBC7A38") or record['HASHES'].contains("IMPHASH=DC7D30B90B2D8ABF664FBED2B1B59894") or record['HASHES'].contains("IMPHASH=41923EA1F824FE63EA5BEB84DB7A3E74") or record['HASHES'].contains("IMPHASH=3DE09703C8E79ED2CA3F01074719906B")) or (record['IMPHASH'] == "767637c23bb42cd5d7397cf58b0be688" or record['IMPHASH'] == "14c4e4c72ba075e9069ee67f39188ad8" or record['IMPHASH'] == "3c782813d4afce07bbfc5a9772acdbdc" or record['IMPHASH'] == "7d010c6bb6a3726f327f7e239166d127" or record['IMPHASH'] == "89159ba4dd04e4ce5559f132a9964eb3" or record['IMPHASH'] == "6f33f4a5fc42b8cec7314947bd13f30f" or record['IMPHASH'] == "5834ed4291bdeb928270428ebbaf7604" or record['IMPHASH'] == "5a8a8a43f25485e7ee1b201edcbc7a38" or record['IMPHASH'] == "dc7d30b90b2d8abf664fbed2b1b59894" or record['IMPHASH'] == "41923ea1f824fe63ea5beb84db7a3e74" or record['IMPHASH'] == "3de09703c8e79ed2ca3f01074719906b"))

sigma_uac_bypass_tool_uacme_akagi.sigma_meta = dict(
    level="high"
)

def sigma_execution_via_stordiag_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_stordiag_execution.yml
    title: Execution via stordiag.exe
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\stordiag.exe") and (record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\systeminfo.exe") or record['PROCESS_NAME'].endswith("\\fltmc.exe"))) and not ((record['PARENT_NAME'].startswith("c:\\windows\\system32") or record['PARENT_NAME'].startswith("c:\\windows\\syswow64"))))

sigma_execution_via_stordiag_exe.sigma_meta = dict(
    level="high"
)

def sigma_disable_or_delete_windows_eventlog(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_disable_eventlog.yml
    title: Disable or Delete Windows Eventlog
    fields: ['CommandLine']
    level: high
    description: Detects command that is used to disable or delete Windows eventlog via logman Windows utility
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("logman") and (record['COMMAND_LINE'].contains("stop") or record['COMMAND_LINE'].contains("delete")) and record['COMMAND_LINE'].contains("EventLog-System"))

sigma_disable_or_delete_windows_eventlog.sigma_meta = dict(
    level="high"
)

def sigma_esentutl_steals_browser_information(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_esentutl_webcache.yml
    title: Esentutl Steals Browser Information
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\esentutl.exe") or record['ORIGINAL_FILE_NAME'] == "esentutl.exe") and (record['COMMAND_LINE'].contains("/r") or record['COMMAND_LINE'].contains("-r")) and record['COMMAND_LINE'].contains("\\Windows\\WebCache"))

sigma_esentutl_steals_browser_information.sigma_meta = dict(
    level="medium"
)

def sigma_windows_shell_spawning_suspicious_program(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_shell_spawn_susp_program.yml
    title: Windows Shell Spawning Suspicious Program
    fields: ['CommandLine', 'Image', 'ParentImage', 'CurrentDirectory', 'ParentCommandLine']
    level: high
    description: Detects a suspicious child process of a Windows shell
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\mshta.exe") or record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\rundll32.exe") or record['PARENT_NAME'].endswith("\\cscript.exe") or record['PARENT_NAME'].endswith("\\wscript.exe") or record['PARENT_NAME'].endswith("\\wmiprvse.exe") or record['PARENT_NAME'].endswith("\\regsvr32.exe")) and (record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\nslookup.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe"))) and not ((record['PROCESS_PATH'].contains("\\ccmcache")) or ((record['PARENT_COMMAND_LINE'].contains("\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\setup-scheduledtask.ps1") or record['PARENT_COMMAND_LINE'].contains("\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\set-selfhealing.ps1") or record['PARENT_COMMAND_LINE'].contains("\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\check-workspacehealth.ps1") or record['PARENT_COMMAND_LINE'].contains("\\nessus_"))) or (record['COMMAND_LINE'].contains("\\nessus_"))))

sigma_windows_shell_spawning_suspicious_program.sigma_meta = dict(
    level="high"
)

def sigma_wmi_uninstall_an_application(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_remove_application.yml
    title: WMI Uninstall An Application
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Uninstall an application with wmic
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and record['COMMAND_LINE'].contains("call uninstall"))

sigma_wmi_uninstall_an_application.sigma_meta = dict(
    level="medium"
)

def sigma_turla_group_lateral_movement(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_turla_commands_critical.yml
    title: Turla Group Lateral Movement
    fields: ['CommandLine']
    level: critical
    description: Detects automated lateral movement by Turla group
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].startswith("net use \\\\\\\\%DomainController%\\C$ \"P@ssw0rd\"") or record['COMMAND_LINE'] == "dir c:\\\\*.doc* /s" or record['COMMAND_LINE'] == "dir %TEMP%\\\\*.exe")

sigma_turla_group_lateral_movement.sigma_meta = dict(
    level="critical"
)

def sigma_unc2452_powershell_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_unc2452_ps.yml
    title: UNC2452 PowerShell Pattern
    fields: ['CommandLine']
    level: critical
    description: Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Invoke-WMIMethod win32_process -name create -argumentlist") and record['COMMAND_LINE'].contains("rundll32 c:\\windows")) or (record['COMMAND_LINE'].contains("wmic /node:") and record['COMMAND_LINE'].contains("process call create \"rundll32 c:\\windows")))

sigma_unc2452_powershell_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_delete_all_scheduled_tasks(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_delete_all.yml
    title: Delete All Scheduled Tasks
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the usage of schtasks with the delete flag and the asterisk symbole to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/delete") and record['COMMAND_LINE'].contains("/tn ") and record['COMMAND_LINE'].contains("/f"))

sigma_delete_all_scheduled_tasks.sigma_meta = dict(
    level="high"
)

def sigma_always_install_elevated_msi_spawned_cmd_and_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_always_install_elevated_msi_spawned_cmd_powershell.yml
    title: Always Install Elevated MSI Spawned Cmd And Powershell
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll")) and (record['PARENT_NAME'].contains("\\Windows\\Installer") and record['PARENT_NAME'].contains("msi") and record['PARENT_NAME'].endswith("tmp")))

sigma_always_install_elevated_msi_spawned_cmd_and_powershell.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_service_dacl_modification(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_dacl_modification.yml
    title: Suspicious Service DACL Modification
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious DACL modifications that can  be used to hide services or make them unstopable
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sc.exe") or record['ORIGINAL_FILE_NAME'] == "sc.exe") and (record['COMMAND_LINE'].contains("sdset") and record['COMMAND_LINE'].contains("D;;") and (record['COMMAND_LINE'].contains(";;;IU") or record['COMMAND_LINE'].contains(";;;SU") or record['COMMAND_LINE'].contains(";;;BA") or record['COMMAND_LINE'].contains(";;;SY") or record['COMMAND_LINE'].contains(";;;WD"))))

sigma_suspicious_service_dacl_modification.sigma_meta = dict(
    level="high"
)

def sigma_bitsadmin_download_file_from_ip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_ip.yml
    title: Bitsadmin Download File from IP
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of bitsadmin downloading a file using an URL that contains an IP
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['ORIGINAL_FILE_NAME'] == "bitsadmin.exe") and (record['COMMAND_LINE'].contains("/transfer") or record['COMMAND_LINE'].contains("/create") or record['COMMAND_LINE'].contains("/addfile")) and (record['COMMAND_LINE'].contains("http://1") or record['COMMAND_LINE'].contains("http://2") or record['COMMAND_LINE'].contains("http://3") or record['COMMAND_LINE'].contains("http://4") or record['COMMAND_LINE'].contains("http://5") or record['COMMAND_LINE'].contains("http://6") or record['COMMAND_LINE'].contains("http://7") or record['COMMAND_LINE'].contains("http://8") or record['COMMAND_LINE'].contains("http://9") or record['COMMAND_LINE'].contains("https://1") or record['COMMAND_LINE'].contains("https://2") or record['COMMAND_LINE'].contains("https://3") or record['COMMAND_LINE'].contains("https://4") or record['COMMAND_LINE'].contains("https://5") or record['COMMAND_LINE'].contains("https://6") or record['COMMAND_LINE'].contains("https://7") or record['COMMAND_LINE'].contains("https://8") or record['COMMAND_LINE'].contains("https://9")))

sigma_bitsadmin_download_file_from_ip.sigma_meta = dict(
    level="high"
)

def sigma_findstr_gpp_passwords(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_findstr_gpp_passwords.yml
    title: Findstr GPP Passwords
    fields: ['CommandLine', 'Image']
    level: high
    description: Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\findstr.exe") and record['COMMAND_LINE'].contains("cpassword") and record['COMMAND_LINE'].contains("\\sysvol") and record['COMMAND_LINE'].contains(".xml"))

sigma_findstr_gpp_passwords.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_office_token_search_via_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_office_token_search.yml
    title: Suspicious Office Token Search Via CLI
    fields: ['CommandLine']
    level: medium
    description: Detects possible search for office tokens via CLI by looking for the string "eyJ0eX". This string is used as an anchor to look for the start of the JWT token used by office and similar apps.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("eyJ0eXAiOi") or record['COMMAND_LINE'].contains("eyJ0eX") or record['COMMAND_LINE'].contains("\"eyJ0eX\"") or record['COMMAND_LINE'].contains("\'eyJ0eX\'"))

sigma_suspicious_office_token_search_via_cli.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_invoke_webrequest_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_invoke_webrequest_download.yml
    title: Suspicious Invoke-WebRequest Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe")) and (record['COMMAND_LINE'].contains("Invoke-WebRequest") or record['COMMAND_LINE'].contains("iwr") or record['COMMAND_LINE'].contains("wget") or record['COMMAND_LINE'].contains("curl")) and (record['COMMAND_LINE'].contains("-ur") or record['COMMAND_LINE'].contains("-o")) and (record['COMMAND_LINE'].contains("\\AppData") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\Temp") or record['COMMAND_LINE'].contains("%AppData%") or record['COMMAND_LINE'].contains("%Temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("%Public%") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("C:\\Windows")))

sigma_suspicious_invoke_webrequest_usage.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_add_scheduled_task_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_parent.yml
    title: Suspicious Add Scheduled Task Parent
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious scheduled task creations from a parent stored in a temporary folder
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create") and (record['PARENT_NAME'].contains("\\AppData\\Local") or record['PARENT_NAME'].contains("\\AppData\\Roaming") or record['PARENT_NAME'].contains("\\Temporary Internet") or record['PARENT_NAME'].contains("\\Users\\Public"))) and not (((record['COMMAND_LINE'].contains("update_task.xml") or record['COMMAND_LINE'].contains("unattended.ini")))))

sigma_suspicious_add_scheduled_task_parent.sigma_meta = dict(
    level="medium"
)

def sigma_registry_disabling_lsass_ppl(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_lsass_ppl.yml
    title: Registry Disabling LSASS PPL
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects reg command lines that disables PPL on the LSA process
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("SYSTEM\\CurrentControlSet\\Control\\Lsa") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("/d 0") and record['COMMAND_LINE'].contains("/v RunAsPPL") and (record['COMMAND_LINE'].contains("Real-Time Protection") or record['COMMAND_LINE'].contains("TamperProtection")))

sigma_registry_disabling_lsass_ppl.sigma_meta = dict(
    level="high"
)

def sigma_usage_of_sysinternals_tools(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysinternals_eula_accepted.yml
    title: Usage of Sysinternals Tools
    fields: ['CommandLine']
    level: low
    description: Detects the usage of Sysinternals Tools due to accepteula option being seen in the command line.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-accepteula") or record['COMMAND_LINE'].contains("/accepteula"))

sigma_usage_of_sysinternals_tools.sigma_meta = dict(
    level="low"
)

def sigma_node_process_executions(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_creative_cloud_node_abuse.yml
    title: Node Process Executions
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Adobe Creative Cloud Experience\\libs\\node.exe") and not (record['COMMAND_LINE'].contains("Adobe Creative Cloud Experience\\js")))

sigma_node_process_executions.sigma_meta = dict(
    level="medium"
)

def sigma_malicious_payload_download_via_office_binaries(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_msoffice.yml
    title: Malicious Payload Download via Office Binaries
    fields: ['CommandLine', 'Image']
    level: high
    description: Downloads payload from remote server
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powerpnt.exe") or record['PROCESS_NAME'].endswith("\\winword.exe") or record['PROCESS_NAME'].endswith("\\excel.exe")) and record['COMMAND_LINE'].contains("http"))

sigma_malicious_payload_download_via_office_binaries.sigma_meta = dict(
    level="high"
)

def sigma_suspect_svchost_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_svchost_no_cli.yml
    title: Suspect Svchost Activity
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].endswith("svchost.exe") and record['PROCESS_NAME'].endswith("\\svchost.exe")) and not ((record['PARENT_NAME'].endswith("\\rpcnet.exe") or record['PARENT_NAME'].endswith("\\rpcnetp.exe")) or record.get('COMMAND_LINE', None) == None))

sigma_suspect_svchost_activity.sigma_meta = dict(
    level="high"
)

def sigma_reg_disable_security_service(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_reg_disable_sec_services.yml
    title: Reg Disable Security Service
    fields: ['CommandLine']
    level: high
    description: Detects a suspicious reg.exe invocation that looks as if it would disable an important security service
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add")) and ((record['COMMAND_LINE'].contains("/d 4") and record['COMMAND_LINE'].contains("/v Start") and (record['COMMAND_LINE'].contains("\\Sense") or record['COMMAND_LINE'].contains("\\WinDefend") or record['COMMAND_LINE'].contains("\\MsMpSvc") or record['COMMAND_LINE'].contains("\\NisSrv") or record['COMMAND_LINE'].contains("\\WdBoot") or record['COMMAND_LINE'].contains("\\WdNisDrv") or record['COMMAND_LINE'].contains("\\WdNisSvc") or record['COMMAND_LINE'].contains("\\wscsvc") or record['COMMAND_LINE'].contains("\\SecurityHealthService") or record['COMMAND_LINE'].contains("\\wuauserv") or record['COMMAND_LINE'].contains("\\UsoSvc") or record['COMMAND_LINE'].contains("\\WdFilter") or record['COMMAND_LINE'].contains("\\AppIDSvc"))) or (record['COMMAND_LINE'].contains("/d 1") and record['COMMAND_LINE'].contains("Windows Defender") and (record['COMMAND_LINE'].contains("DisableIOAVProtection") or record['COMMAND_LINE'].contains("DisableOnAccessProtection") or record['COMMAND_LINE'].contains("DisableRoutinelyTakingAction") or record['COMMAND_LINE'].contains("DisableScanOnRealtimeEnable") or record['COMMAND_LINE'].contains("DisableBlockAtFirstSeen") or record['COMMAND_LINE'].contains("DisableBehaviorMonitoring") or record['COMMAND_LINE'].contains("DisableEnhancedNotifications") or record['COMMAND_LINE'].contains("DisableAntiSpyware") or record['COMMAND_LINE'].contains("DisableAntiSpywareRealtimeProtection") or record['COMMAND_LINE'].contains("DisableConfig") or record['COMMAND_LINE'].contains("DisablePrivacyMode") or record['COMMAND_LINE'].contains("SignatureDisableUpdateOnStartupWithoutEngine") or record['COMMAND_LINE'].contains("DisableArchiveScanning") or record['COMMAND_LINE'].contains("DisableIntrusionPreventionSystem") or record['COMMAND_LINE'].contains("DisableScriptScanning")))))

sigma_reg_disable_security_service.sigma_meta = dict(
    level="high"
)

def sigma_browser_started_with_remote_debugging(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_browser_remote_debugging.yml
    title: Browser Started with Remote Debugging
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("--remote-debugging-") or (record['PROCESS_NAME'].endswith("\\firefox.exe") and record['COMMAND_LINE'].contains("-start-debugger-server")))

sigma_browser_started_with_remote_debugging.sigma_meta = dict(
    level="medium"
)

def sigma_regasm_regsvcs_suspicious_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_regasm.yml
    title: Regasm/Regsvcs Suspicious Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious execution of Regasm/Regsvcs utilities
    logsource: category:process_creation - product:windows
    """
    return ((((record['PROCESS_NAME'].endswith("\\Regsvcs.exe") or record['PROCESS_NAME'].endswith("\\Regasm.exe")) or (record['ORIGINAL_FILE_NAME'] == "RegSvcs.exe" or record['ORIGINAL_FILE_NAME'] == "RegAsm.exe")) and (record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("\\Desktop") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\PerfLogs") or record['COMMAND_LINE'].contains("\\Windows\\Temp") or record['COMMAND_LINE'].contains("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"))) or (((record['PROCESS_NAME'].endswith("\\Regsvcs.exe") or record['PROCESS_NAME'].endswith("\\Regasm.exe")) or (record['ORIGINAL_FILE_NAME'] == "RegSvcs.exe" or record['ORIGINAL_FILE_NAME'] == "RegAsm.exe")) and not (record['COMMAND_LINE'].contains(".dll"))))

sigma_regasm_regsvcs_suspicious_execution.sigma_meta = dict(
    level="high"
)

def sigma_read_and_execute_a_file_via_cmd_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmd_read_contents.yml
    title: Read and Execute a File Via Cmd.exe
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'OriginalFileName']
    level: medium
    description: Detect use of "/R <" to read and execute a file via cmd.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['PROCESS_NAME'].endswith("\\cmd.exe")) and ((record['PARENT_COMMAND_LINE'].contains("cmd") and record['PARENT_COMMAND_LINE'].contains("/r") and record['PARENT_COMMAND_LINE'].contains("<")) or (record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("/r") and record['COMMAND_LINE'].contains("<"))))

sigma_read_and_execute_a_file_via_cmd_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ssh_usage_rdp_tunneling(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ssh_usage.yml
    title: Suspicious SSH Usage RDP Tunneling
    fields: ['CommandLine', 'Image']
    level: high
    description: Execution of ssh.exe to perform data exfiltration and tunneling through RDP
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ssh.exe") and record['COMMAND_LINE'].contains(":127.0.0.1:3389")) or (record['PROCESS_NAME'].endswith("\\ssh.exe") and record['COMMAND_LINE'].contains(":3389")))

sigma_suspicious_ssh_usage_rdp_tunneling.sigma_meta = dict(
    level="high"
)

def sigma_judgement_panda_exfil_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_judgement_panda_gtr19.yml
    title: Judgement Panda Exfil Activity
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects Judgement Panda activity as described in Global Threat Report 2019 by Crowdstrike
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].endswith("eprod.ldf") or (record['COMMAND_LINE'].contains("\\ldifde.exe -f -n") or record['COMMAND_LINE'].contains("\\7za.exe a 1.7z") or record['COMMAND_LINE'].contains("\\aaaa\\procdump64.exe") or record['COMMAND_LINE'].contains("\\aaaa\\netsess.exe") or record['COMMAND_LINE'].contains("\\aaaa\\7za.exe") or record['COMMAND_LINE'].contains("copy .\\1.7z ") or record['COMMAND_LINE'].contains("copy \\\\client\\c$\\aaaa")) or record['PROCESS_NAME'] == "C:\\Users\\Public\\7za.exe")

sigma_judgement_panda_exfil_activity.sigma_meta = dict(
    level="critical"
)

def sigma_write_protect_for_storage_disabled(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_write_protect_for_storage_disabled.yml
    title: Write Protect For Storage Disabled
    fields: ['CommandLine']
    level: medium
    description: Looks for changes to registry to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("reg add") and record['COMMAND_LINE'].contains("\\system\\currentcontrolset\\control") and record['COMMAND_LINE'].contains("write protection") and record['COMMAND_LINE'].contains("0") and (record['COMMAND_LINE'].contains("storage") or record['COMMAND_LINE'].contains("storagedevicepolicies")))

sigma_write_protect_for_storage_disabled.sigma_meta = dict(
    level="medium"
)

def sigma_dns_exfiltration_and_tunneling_tools_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dns_exfiltration_tools_execution.yml
    title: DNS Exfiltration and Tunneling Tools Execution
    fields: ['Image']
    level: high
    description: Well-known DNS Exfiltration tools execution
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\iodine.exe") or record['PROCESS_NAME'].contains("\\dnscat2"))

sigma_dns_exfiltration_and_tunneling_tools_execution.sigma_meta = dict(
    level="high"
)

def sigma_excel_proxy_executing_regsvr32_with_payload(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_from_proxy_executing_regsvr32_payload.yml
    title: Excel Proxy Executing Regsvr32 With Payload
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Excel called wmic to finally proxy execute regsvr32 with the payload.
An attacker wanted to break suspicious parent-child chain (Office app spawns LOLBin).
But we have command-line in the event which allow us to "restore" this suspicious parent-child chain and detect it.
Monitor process creation with "wmic process call create" and LOLBins in command-line with parent Office application processes.

    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\wbem\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and ((record['COMMAND_LINE'].contains("regsvr32") or record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("msiexec") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("verclsid")) and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe")) and record['COMMAND_LINE'].contains("process") and record['COMMAND_LINE'].contains("create") and record['COMMAND_LINE'].contains("call")))

sigma_excel_proxy_executing_regsvr32_with_payload.sigma_meta = dict(
    level="high"
)

def sigma_conhost_exe_commandline_path_traversal(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_conhost_path_traversal.yml
    title: Conhost.exe CommandLine Path Traversal
    fields: ['CommandLine', 'ParentCommandLine']
    level: high
    description: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_COMMAND_LINE'].contains("conhost") and record['COMMAND_LINE'].contains("/../../"))

sigma_conhost_exe_commandline_path_traversal.sigma_meta = dict(
    level="high"
)

def sigma_usage_of_web_request_commands_and_cmdlets(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_web_request_cmd_and_cmdlets.yml
    title: Usage Of Web Request Commands And Cmdlets
    fields: ['CommandLine']
    level: medium
    description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Invoke-WebRequest") or record['COMMAND_LINE'].contains("iwr") or record['COMMAND_LINE'].contains("wget") or record['COMMAND_LINE'].contains("curl") or record['COMMAND_LINE'].contains("Net.WebClient") or record['COMMAND_LINE'].contains("Start-BitsTransfer"))

sigma_usage_of_web_request_commands_and_cmdlets.sigma_meta = dict(
    level="medium"
)

def sigma_change_default_file_association_to_executable(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_change_default_file_assoc_susp.yml
    title: Change Default File Association To Executable
    fields: ['CommandLine']
    level: high
    description: Detects when a program changes the default file association of any extension to an executable
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("assoc") and record['COMMAND_LINE'].contains("exefile") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/r") or record['COMMAND_LINE'].contains("/k"))) and not (record['COMMAND_LINE'].contains(".exe=exefile")))

sigma_change_default_file_association_to_executable.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_via_use_clip(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_clip.yml
    title: Invoke-Obfuscation Via Use Clip
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated Powershell via use Clip.exe in Scripts
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains("clip") and record['COMMAND_LINE'].contains("&&") and (record['COMMAND_LINE'].contains("clipboard") or record['COMMAND_LINE'].contains("invoke") or record['COMMAND_LINE'].contains("i`") or record['COMMAND_LINE'].contains("n`") or record['COMMAND_LINE'].contains("v`") or record['COMMAND_LINE'].contains("o`") or record['COMMAND_LINE'].contains("k`") or record['COMMAND_LINE'].contains("e`")))

sigma_invoke_obfuscation_via_use_clip.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_execution_of_adidnsdump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_adidnsdump.yml
    title: Suspicious Execution of Adidnsdump
    fields: ['CommandLine', 'Image']
    level: low
    description: This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\python.exe") and record['COMMAND_LINE'].contains("adidnsdump"))

sigma_suspicious_execution_of_adidnsdump.sigma_meta = dict(
    level="low"
)

def sigma_launch_vsdevshell_ps1_proxy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.yml
    title: Launch-VsDevShell.PS1 Proxy Execution
    fields: ['CommandLine']
    level: medium
    description: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Launch-VsDevShell.ps1") and (record['COMMAND_LINE'].contains("VsWherePath") or record['COMMAND_LINE'].contains("VsInstallationPath")))

sigma_launch_vsdevshell_ps1_proxy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_executable_used_by_plugx_in_uncommon_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_plugx_susp_exe_locations.yml
    title: Executable Used by PlugX in Uncommon Location
    fields: ['Image']
    level: high
    description: Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location
    logsource: category:process_creation - product:windows
    """
    return ((((((((((((record['PROCESS_NAME'].endswith("\\CamMute.exe") and not ((record['PROCESS_NAME'].contains("\\Lenovo\\Communication Utility") or record['PROCESS_NAME'].contains("\\Lenovo\\Communications Utility")))) or (record['PROCESS_NAME'].endswith("\\chrome_frame_helper.exe") and not (record['PROCESS_NAME'].contains("\\Google\\Chrome\\application")))) or (record['PROCESS_NAME'].endswith("\\dvcemumanager.exe") and not (record['PROCESS_NAME'].contains("\\Microsoft Device Emulator")))) or (record['PROCESS_NAME'].endswith("\\Gadget.exe") and not (record['PROCESS_NAME'].contains("\\Windows Media Player")))) or (record['PROCESS_NAME'].endswith("\\hcc.exe") and not (record['PROCESS_NAME'].contains("\\HTML Help Workshop")))) or (record['PROCESS_NAME'].endswith("\\hkcmd.exe") and not ((record['PROCESS_NAME'].contains("\\System32") or record['PROCESS_NAME'].contains("\\SysNative") or record['PROCESS_NAME'].contains("\\SysWow64"))))) or (record['PROCESS_NAME'].endswith("\\Mc.exe") and not ((record['PROCESS_NAME'].contains("\\Microsoft Visual Studio") or record['PROCESS_NAME'].contains("\\Microsoft SDK") or record['PROCESS_NAME'].contains("\\Windows Kit"))))) or (record['PROCESS_NAME'].endswith("\\MsMpEng.exe") and not ((record['PROCESS_NAME'].contains("\\Microsoft Security Client") or record['PROCESS_NAME'].contains("\\Windows Defender") or record['PROCESS_NAME'].contains("\\AntiMalware"))))) or (record['PROCESS_NAME'].endswith("\\msseces.exe") and not ((record['PROCESS_NAME'].contains("\\Microsoft Security Center") or record['PROCESS_NAME'].contains("\\Microsoft Security Client") or record['PROCESS_NAME'].contains("\\Microsoft Security Essentials"))))) or (record['PROCESS_NAME'].endswith("\\OInfoP11.exe") and not (record['PROCESS_NAME'].contains("\\Common Files\\Microsoft Shared")))) or (record['PROCESS_NAME'].endswith("\\OleView.exe") and not ((record['PROCESS_NAME'].contains("\\Microsoft Visual Studio") or record['PROCESS_NAME'].contains("\\Microsoft SDK") or record['PROCESS_NAME'].contains("\\Windows Kit") or record['PROCESS_NAME'].contains("\\Windows Resource Kit"))))) or (record['PROCESS_NAME'].endswith("\\rc.exe") and not ((record['PROCESS_NAME'].contains("\\Microsoft Visual Studio") or record['PROCESS_NAME'].contains("\\Microsoft SDK") or record['PROCESS_NAME'].contains("\\Windows Kit") or record['PROCESS_NAME'].contains("\\Windows Resource Kit") or record['PROCESS_NAME'].contains("\\Microsoft.NET")))))

sigma_executable_used_by_plugx_in_uncommon_location.sigma_meta = dict(
    level="high"
)

def sigma_windows_processes_suspicious_parent_directory(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_proc_wrong_parent.yml
    title: Windows Processes Suspicious Parent Directory
    fields: ['Image', 'ParentImage']
    level: low
    description: Detect suspicious parent processes of well-known Windows processes
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\svchost.exe") or record['PROCESS_NAME'].endswith("\\taskhost.exe") or record['PROCESS_NAME'].endswith("\\lsm.exe") or record['PROCESS_NAME'].endswith("\\lsass.exe") or record['PROCESS_NAME'].endswith("\\services.exe") or record['PROCESS_NAME'].endswith("\\lsaiso.exe") or record['PROCESS_NAME'].endswith("\\csrss.exe") or record['PROCESS_NAME'].endswith("\\wininit.exe") or record['PROCESS_NAME'].endswith("\\winlogon.exe")) and not (((record['PARENT_NAME'].endswith("\\SavService.exe") or record['PARENT_NAME'].endswith("\\ngen.exe")) or (record['PARENT_NAME'].contains("\\System32") or record['PARENT_NAME'].contains("\\SysWOW64"))) or ((record['PARENT_NAME'].contains("\\Windows Defender") or record['PARENT_NAME'].contains("\\Microsoft Security Client")) and record['PARENT_NAME'].endswith("\\MsMpEng.exe")) or (record.get('PARENT_NAME', None) == None or record['PARENT_NAME'] == "-")))

sigma_windows_processes_suspicious_parent_directory.sigma_meta = dict(
    level="low"
)

def sigma_ngrok_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ngrok_pua.yml
    title: Ngrok Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
Involved domains are bin.equinox.io for download and *.ngrok.io for connections.

    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("tcp 139") or record['COMMAND_LINE'].contains("tcp 445") or record['COMMAND_LINE'].contains("tcp 3389") or record['COMMAND_LINE'].contains("tcp 5985") or record['COMMAND_LINE'].contains("tcp 5986")) or (record['COMMAND_LINE'].contains("start") and record['COMMAND_LINE'].contains("--all") and record['COMMAND_LINE'].contains("--config") and record['COMMAND_LINE'].contains(".yml")) or (record['PROCESS_NAME'].endswith("ngrok.exe") and (record['COMMAND_LINE'].contains("tcp") or record['COMMAND_LINE'].contains("http") or record['COMMAND_LINE'].contains("authtoken"))))

sigma_ngrok_usage.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_regsvr32_execution_with_image_extension(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_image.yml
    title: Suspicious Regsvr32 Execution With Image Extension
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of REGSVR32.exe with DLL masquerading as image files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['ORIGINAL_FILE_NAME'] == "\\REGSVR32.EXE") and (record['COMMAND_LINE'].endswith(".jpg") or record['COMMAND_LINE'].endswith(".jpeg") or record['COMMAND_LINE'].endswith(".gif") or record['COMMAND_LINE'].endswith(".png") or record['COMMAND_LINE'].endswith(".ico") or record['COMMAND_LINE'].endswith(".bmp") or record['COMMAND_LINE'].endswith(".tif") or record['COMMAND_LINE'].endswith(".tiff") or record['COMMAND_LINE'].endswith(".eps") or record['COMMAND_LINE'].endswith(".raw") or record['COMMAND_LINE'].endswith(".cr2") or record['COMMAND_LINE'].endswith(".nef") or record['COMMAND_LINE'].endswith(".orf") or record['COMMAND_LINE'].endswith(".sr2")))

sigma_suspicious_regsvr32_execution_with_image_extension.sigma_meta = dict(
    level="high"
)

def sigma_dll_injection_with_tracker_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_tracker_execution.yml
    title: DLL Injection with Tracker.exe
    fields: ['CommandLine', 'Image', 'ParentImage', 'Description']
    level: medium
    description: This rule detects DLL injection and execution via LOLBAS - Tracker.exe
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\tracker.exe") or record['DESCRIPTION'] == "Tracker") and (record['COMMAND_LINE'].contains("/d") or record['COMMAND_LINE'].contains("/c"))) and not ((record['COMMAND_LINE'].contains("/ERRORREPORT:PROMPT")) or (record['PARENT_NAME'].endswith("\\Msbuild\\Current\\Bin\\MSBuild.exe") and record['COMMAND_LINE'].contains("\\VC\\Tools\\MSVC") and record['COMMAND_LINE'].contains("\\bin\\HostX86\\x64"))))

sigma_dll_injection_with_tracker_exe.sigma_meta = dict(
    level="medium"
)

def sigma_monitoring_for_persistence_via_bits(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_monitoring_for_persistence_via_bits.yml
    title: Monitoring For Persistence Via BITS
    fields: ['CommandLine']
    level: medium
    description: BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished. When the job runs on the system the command specified in the BITS job will be executed. This can be abused by actors to create a backdoor within the system and for persistence. It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("bitsadmin") and record['COMMAND_LINE'].contains("/SetNotifyCmdLine") and (record['COMMAND_LINE'].contains("%COMSPEC%") or record['COMMAND_LINE'].contains("cmd.exe") or record['COMMAND_LINE'].contains("regsvr32.exe"))) or (record['COMMAND_LINE'].contains("bitsadmin") and record['COMMAND_LINE'].contains("/Addfile") and (record['COMMAND_LINE'].contains("http:") or record['COMMAND_LINE'].contains("https:") or record['COMMAND_LINE'].contains("ftp:") or record['COMMAND_LINE'].contains("ftps:"))))

sigma_monitoring_for_persistence_via_bits.sigma_meta = dict(
    level="medium"
)

def sigma_schtasks_creation_or_modification_with_system_privileges(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_schtasks_system.yml
    title: Schtasks Creation Or Modification With SYSTEM Privileges
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") and (record['COMMAND_LINE'].contains("/change") or record['COMMAND_LINE'].contains("/create")) and record['COMMAND_LINE'].contains("/ru") and (record['COMMAND_LINE'].contains("NT AUT") or record['COMMAND_LINE'].contains("SYSTEM"))) and not (record['PARENT_NAME'].contains("\\AppData\\Local\\Temp") and record['PARENT_NAME'].contains("TeamViewer_.exe") and record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/TN TVInstallRestore")))

sigma_schtasks_creation_or_modification_with_system_privileges.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_wmic_activescripteventconsumer_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wmic_eventconsumer_create.yml
    title: Suspicious WMIC ActiveScriptEventConsumer Creation
    fields: ['CommandLine']
    level: high
    description: Detects WMIC executions in which a event consumer gets created in order to establish persistence
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("ActiveScriptEventConsumer") and record['COMMAND_LINE'].contains("CREATE"))

sigma_suspicious_wmic_activescripteventconsumer_creation.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_driver_install_by_pnputil_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_driver_installed_by_pnputil.yml
    title: Suspicious Driver Install by pnputil.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects when a possible suspicious driver is being installed via pnputil.exe lolbin
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-i") or record['COMMAND_LINE'].contains("/install") or record['COMMAND_LINE'].contains("-a") or record['COMMAND_LINE'].contains("/add-driver") or record['COMMAND_LINE'].contains(".inf")) and record['PROCESS_NAME'].endswith("\\pnputil.exe"))

sigma_suspicious_driver_install_by_pnputil_exe.sigma_meta = dict(
    level="medium"
)

def sigma_register_app_vbs_proxy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_register_app.yml
    title: REGISTER_APP.VBS Proxy Execution
    fields: ['CommandLine']
    level: medium
    description: Detects the use of a Microsoft signed script 'REGISTER_APP.VBS' to register a VSS/VDS Provider as a COM+ application.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\register_app.vbs") and record['COMMAND_LINE'].contains("-register"))

sigma_register_app_vbs_proxy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_ie4uinit_lolbin_use_from_invalid_path(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_ie4uinit.yml
    title: Ie4uinit Lolbin Use From Invalid Path
    fields: ['Image', 'OriginalFileName', 'CurrentDirectory']
    level: medium
    description: Detect use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\ie4uinit.exe") or record['ORIGINAL_FILE_NAME'] == "IE4UINIT.EXE") and not (((record['PROCESS_PATH'] == "c:\\windows\\system32" or record['PROCESS_PATH'] == "c:\\windows\\sysWOW64")) or (record.get('PROCESS_PATH', None) == None)))

sigma_ie4uinit_lolbin_use_from_invalid_path.sigma_meta = dict(
    level="medium"
)

def sigma_cmdkey_cached_credentials_recon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmdkey_recon.yml
    title: Cmdkey Cached Credentials Recon
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects usage of cmdkey to look for cached credentials
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmdkey.exe") or record['ORIGINAL_FILE_NAME'] == "cmdkey.exe") and (record['COMMAND_LINE'].contains("/l") or record['COMMAND_LINE'].contains("-l")))

sigma_cmdkey_cached_credentials_recon.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_using_idiagnostic_profile(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_idiagnostic_profile.yml
    title: UAC Bypass Using IDiagnostic Profile
    fields: ['IntegrityLevel', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects the "IDiagnosticProfileUAC" UAC bypass technique
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\DllHost.exe") and record['PARENT_COMMAND_LINE'].contains("/Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_idiagnostic_profile.sigma_meta = dict(
    level="high"
)

def sigma_registry_parse_with_pypykatz(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pypykatz.yml
    title: Registry Parse with Pypykatz
    fields: ['CommandLine', 'Image']
    level: high
    description: Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through Windows Registry where the SAM database is stored
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\pypykatz.exe") or record['PROCESS_NAME'].endswith("\\python.exe")) and record['COMMAND_LINE'].contains("live") and record['COMMAND_LINE'].contains("registry"))

sigma_registry_parse_with_pypykatz.sigma_meta = dict(
    level="high"
)

def sigma_powershell_downgrade_attack(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_downgrade_attack.yml
    title: PowerShell Downgrade Attack
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("-version 2") or record['COMMAND_LINE'].contains("-versio 2") or record['COMMAND_LINE'].contains("-versi 2") or record['COMMAND_LINE'].contains("-vers 2") or record['COMMAND_LINE'].contains("-ver 2") or record['COMMAND_LINE'].contains("-ve 2")))

sigma_powershell_downgrade_attack.sigma_meta = dict(
    level="medium"
)

def sigma_execute_code_with_pester_bat(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_pester.yml
    title: Execute Code with Pester.bat
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("Pester") and record['COMMAND_LINE'].contains("Get-Help")) or (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("pester") and record['COMMAND_LINE'].contains(";") and (record['COMMAND_LINE'].contains("help") or record['COMMAND_LINE'].contains("?"))))

sigma_execute_code_with_pester_bat.sigma_meta = dict(
    level="medium"
)

def sigma_bad_opsec_defaults_sacrificial_processes_with_improper_arguments(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bad_opsec_sacrificial_processes.yml
    title: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects attackers using tooling with bad opsec defaults e.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run, one trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\WerFault.exe") and record['COMMAND_LINE'].endswith("WerFault.exe")) or (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].endswith("rundll32.exe")) or (record['PROCESS_NAME'].endswith("\\regsvcs.exe") and record['COMMAND_LINE'].endswith("regsvcs.exe")) or (record['PROCESS_NAME'].endswith("\\regasm.exe") and record['COMMAND_LINE'].endswith("regasm.exe")) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['COMMAND_LINE'].endswith("regsvr32.exe")))

sigma_bad_opsec_defaults_sacrificial_processes_with_improper_arguments.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_reconnaissance_activity_using_net(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_recon.yml
    title: Suspicious Reconnaissance Activity Using Net
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) or (record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe")) and (((record['COMMAND_LINE'].contains("group") or record['COMMAND_LINE'].contains("localgroup")) and (record['COMMAND_LINE'].contains("domain admins") or record['COMMAND_LINE'].contains("administrator") or record['COMMAND_LINE'].contains("administrateur") or record['COMMAND_LINE'].contains("enterprise admins") or record['COMMAND_LINE'].contains("Exchange Trusted Subsystem") or record['COMMAND_LINE'].contains("Remote Desktop Users") or record['COMMAND_LINE'].contains("Utilisateurs du Bureau à distance") or record['COMMAND_LINE'].contains("Usuarios de escritorio remoto") or record['COMMAND_LINE'].contains("/do"))) or (record['COMMAND_LINE'].contains("accounts") and record['COMMAND_LINE'].contains("/do"))))

sigma_suspicious_reconnaissance_activity_using_net.sigma_meta = dict(
    level="medium"
)

def sigma_psexec_service_execution_as_local_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexesvc_as_system.yml
    title: PsExec Service Execution as LOCAL SYSTEM
    fields: ['User', 'ParentImage']
    level: high
    description: Detects suspicious launch of the PSEXESVC service on this system and a sub process run as LOCAL_SYSTEM (-s), which means that someone remotely started a command on this system running it with highest privileges and not only the privileges of the login user account (e.g. the administrator account)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'] == "C:\\Windows\\PSEXESVC.exe" and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")))

sigma_psexec_service_execution_as_local_system.sigma_meta = dict(
    level="high"
)

def sigma_revil_kaseya_incident_malware_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_revil_kaseya.yml
    title: REvil Kaseya Incident Malware Patterns
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects process command line patterns and locations used by REvil group in Kaseya incident (can also match on other malware)
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("C:\\Windows\\cert.exe") or record['COMMAND_LINE'].contains("del /q /f c:\\kworking\\agent.crt") or record['COMMAND_LINE'].contains("Kaseya VSA Agent Hot-fix") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp\\MsMpEng.exe") or record['COMMAND_LINE'].contains("rmdir /s /q %SystemDrive%\\inetpub\\logs") or record['COMMAND_LINE'].contains("del /s /q /f %SystemDrive%\\\\*.log") or record['COMMAND_LINE'].contains("c:\\kworking1\\agent.exe") or record['COMMAND_LINE'].contains("c:\\kworking1\\agent.crt")) or (record['PROCESS_NAME'] == "C:\\Windows\\MsMpEng.exe" or record['PROCESS_NAME'] == "C:\\Windows\\cert.exe" or record['PROCESS_NAME'] == "C:\\kworking\\agent.exe" or record['PROCESS_NAME'] == "C:\\kworking1\\agent.exe") or (record['COMMAND_LINE'].contains("del /s /q /f") and record['COMMAND_LINE'].contains("WebPages\\Errors\\webErrorLog.txt")))

sigma_revil_kaseya_incident_malware_patterns.sigma_meta = dict(
    level="critical"
)

def sigma_netsh_allow_group_policy_on_microsoft_defender_firewall(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_fw_enable_group_rule.yml
    title: Netsh Allow Group Policy on Microsoft Defender Firewall
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may  modify system firewalls in order to bypass controls limiting network usage
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("advfirewall") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("rule") and record['COMMAND_LINE'].contains("group=") and record['COMMAND_LINE'].contains("new") and record['COMMAND_LINE'].contains("enable=Yes"))

sigma_netsh_allow_group_policy_on_microsoft_defender_firewall.sigma_meta = dict(
    level="medium"
)

def sigma_dumpert_process_dumper(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_dumpert.yml
    title: Dumpert Process Dumper
    fields: ['Hashes']
    level: critical
    description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
    logsource: category:process_creation - product:windows
    """
    return record['HASHES'].contains("09D278F9DE118EF09163C6140255C690")

sigma_dumpert_process_dumper.sigma_meta = dict(
    level="critical"
)

def sigma_mounted_windows_admin_shares_with_net_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_use_admin_share.yml
    title: Mounted Windows Admin Shares with net.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects when an admin share is mounted using net.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("use") and record['COMMAND_LINE'].contains("\\\\\\*\\\\*$"))

sigma_mounted_windows_admin_shares_with_net_exe.sigma_meta = dict(
    level="medium"
)

def sigma_highly_relevant_renamed_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml
    title: Highly Relevant Renamed Binary
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "powershell.exe" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "powershell_ise.exe" or record['ORIGINAL_FILE_NAME'] == "psexec.exe" or record['ORIGINAL_FILE_NAME'] == "psexec.c" or record['ORIGINAL_FILE_NAME'] == "cscript.exe" or record['ORIGINAL_FILE_NAME'] == "wscript.exe" or record['ORIGINAL_FILE_NAME'] == "mshta.exe" or record['ORIGINAL_FILE_NAME'] == "regsvr32.exe" or record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['ORIGINAL_FILE_NAME'] == "certutil.exe" or record['ORIGINAL_FILE_NAME'] == "rundll32.exe" or record['ORIGINAL_FILE_NAME'] == "cmstp.exe" or record['ORIGINAL_FILE_NAME'] == "msiexec.exe") and not ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe") or record['PROCESS_NAME'].endswith("\\psexec.exe") or record['PROCESS_NAME'].endswith("\\psexec64.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\cmstp.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe"))))

sigma_highly_relevant_renamed_binary.sigma_meta = dict(
    level="high"
)

def sigma_koadic_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_koadic.yml
    title: Koadic Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects command line parameters used by Koadic hack tool
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['COMMAND_LINE'].contains("/q") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("chcp"))

sigma_koadic_execution.sigma_meta = dict(
    level="high"
)

def sigma_monitoring_winget_for_lolbin_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_execution_via_winget.yml
    title: Monitoring Winget For LOLbin Execution
    fields: ['CommandLine']
    level: medium
    description: Adversaries can abuse winget to download payloads remotely and execute them without touching disk. Winget will be included by default in Windows 10 and is already available in Windows 10 insider programs. The manifest option enables you to install an application by passing in a YAML file directly to the client. Winget can be used to download and install exe's, msi, msix files later.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("winget") and record['COMMAND_LINE'].contains("install") and (record['COMMAND_LINE'].contains("-m") or record['COMMAND_LINE'].contains("--manifest")))

sigma_monitoring_winget_for_lolbin_execution.sigma_meta = dict(
    level="medium"
)

def sigma_sc_or_set_service_cmdlet_execution_to_disable_services(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_disable_service.yml
    title: Sc Or Set-Service Cmdlet Execution to Disable Services
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects when attackers use "sc.exe" or the powershell "Set-Service" cmdlet to change the startup type of a service to "disabled"
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\sc.exe") or record['ORIGINAL_FILE_NAME'] == "sc.exe") and (record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("start") and (record['COMMAND_LINE'].contains("disabled") or record['COMMAND_LINE'].contains("demand")))) or (record['COMMAND_LINE'].contains("Set-Service") and record['COMMAND_LINE'].contains("-StartupType") and (record['COMMAND_LINE'].contains("Disabled") or record['COMMAND_LINE'].contains("Manual"))))

sigma_sc_or_set_service_cmdlet_execution_to_disable_services.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_wmic_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wmic_execution.yml
    title: Suspicious WMIC Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects WMIC executing suspicious or recon commands
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wmic.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("process") and record['COMMAND_LINE'].contains("call") and record['COMMAND_LINE'].contains("create"))) or ((record['PROCESS_NAME'].endswith("\\wmic.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("path") and (record['COMMAND_LINE'].contains("AntiVirus") or record['COMMAND_LINE'].contains("Firewall")) and record['COMMAND_LINE'].contains("Product") and record['COMMAND_LINE'].contains("get") and record['COMMAND_LINE'].contains("wmic csproduct get name"))))

sigma_suspicious_wmic_execution.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_process_start_locations(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_run_locations.yml
    title: Suspicious Process Start Locations
    fields: ['Image']
    level: medium
    description: Detects suspicious process run from unusual locations
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains(":\\RECYCLER") or record['PROCESS_NAME'].contains(":\\SystemVolumeInformation")) or (record['PROCESS_NAME'].startswith("C:\\Windows\\Tasks") or record['PROCESS_NAME'].startswith("C:\\Windows\\debug") or record['PROCESS_NAME'].startswith("C:\\Windows\\fonts") or record['PROCESS_NAME'].startswith("C:\\Windows\\help") or record['PROCESS_NAME'].startswith("C:\\Windows\\drivers") or record['PROCESS_NAME'].startswith("C:\\Windows\\addins") or record['PROCESS_NAME'].startswith("C:\\Windows\\cursors") or record['PROCESS_NAME'].startswith("C:\\Windows\\system32\\tasks")))

sigma_suspicious_process_start_locations.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_command_with_teams_objects_pathes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_teams_suspicious_command_line_cred_access.yml
    title: Suspicious Command With Teams Objects Pathes
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("\\Microsoft\\Teams\\Cookies") or record['COMMAND_LINE'].contains("\\Microsoft\\Teams\\Local Storage\\leveldb")) and not (record['PROCESS_NAME'].endswith("\\Microsoft\\Teams\\current\\Teams.exe")))

sigma_suspicious_command_with_teams_objects_pathes.sigma_meta = dict(
    level="high"
)

def sigma_whoami_execution_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_whoami_anomaly.yml
    title: Whoami Execution Anomaly
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects the execution of whoami with suspicious parents or parameters
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\whoami.exe") or record['ORIGINAL_FILE_NAME'] == "whoami.exe") and not (((record['PARENT_NAME'].endswith("\\cmd.exe") or record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\powershell_ise.exe"))) or ((record['PARENT_NAME'] == "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe" or record['PARENT_NAME'] == "")) or (record.get('PARENT_NAME', None) == None))) or (record['COMMAND_LINE'].contains("whoami -all") or record['COMMAND_LINE'].contains("whoami /all") or record['COMMAND_LINE'].contains("whoami.exe -all") or record['COMMAND_LINE'].contains("whoami.exe /all") or record['COMMAND_LINE'].contains("whoami.exe >") or record['COMMAND_LINE'].contains("whoami >")))

sigma_whoami_execution_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_abused_debug_privilege_by_arbitrary_parent_processes(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_abusing_debug_privilege.yml
    title: Abused Debug Privilege by Arbitrary Parent Processes
    fields: ['CommandLine', 'Image', 'ParentImage', 'OriginalFileName', 'User']
    level: high
    description: Detection of unusual child processes by different system processes
    logsource: product:windows - category:process_creation
    """
    return ((((record['PARENT_NAME'].endswith("\\winlogon.exe") or record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\lsass.exe") or record['PARENT_NAME'].endswith("\\csrss.exe") or record['PARENT_NAME'].endswith("\\smss.exe") or record['PARENT_NAME'].endswith("\\wininit.exe") or record['PARENT_NAME'].endswith("\\spoolsv.exe") or record['PARENT_NAME'].endswith("\\searchindexer.exe")) and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))) and ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "Cmd.Exe"))) and not (record['COMMAND_LINE'].contains("route") and record['COMMAND_LINE'].contains("ADD")))

sigma_abused_debug_privilege_by_arbitrary_parent_processes.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_base64_encoded_powershell_invoke(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_base64_invoke.yml
    title: Suspicious Base64 Encoded Powershell Invoke
    fields: ['CommandLine']
    level: high
    description: Detects base64 encoded powershell 'Invoke-' call
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQ") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0A") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtA")) and not (((record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBCAGwAbwBvAGQASABvAHUAbgBkA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0AQgBsAG8AbwBkAEgAbwB1AG4AZA") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAEIAbABvAG8AZABIAG8AdQBuAGQA") or record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6A") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAeg") or record['COMMAND_LINE'].contains("SQBuAHYAbwBrAGUALQBXAE0ASQBFAHgAZQBjA") or record['COMMAND_LINE'].contains("kAbgB2AG8AawBlAC0AVwBNAEkARQB4AGUAYw") or record['COMMAND_LINE'].contains("JAG4AdgBvAGsAZQAtAFcATQBJAEUAeABlAGMA")))))

sigma_suspicious_base64_encoded_powershell_invoke.sigma_meta = dict(
    level="high"
)

def sigma_sql_client_tools_powershell_session_detection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_use_of_sqltoolsps_bin.yml
    title: SQL Client Tools PowerShell Session Detection
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio.
Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sqltoolsps.exe") or record['PARENT_NAME'].endswith("\\sqltoolsps.exe") or record['ORIGINAL_FILE_NAME'] == "\\sqltoolsps.exe") and not (record['PARENT_NAME'].endswith("\\smss.exe")))

sigma_sql_client_tools_powershell_session_detection.sigma_meta = dict(
    level="medium"
)

def sigma_dns_rce_cve_2020_1350(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2020_1350.yml
    title: DNS RCE CVE-2020-1350
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects exploitation of DNS RCE bug reported in CVE-2020-1350 by the detection of suspicious sub process
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\System32\\dns.exe") and not ((record['PROCESS_NAME'].endswith("\\System32\\werfault.exe") or record['PROCESS_NAME'].endswith("\\System32\\conhost.exe") or record['PROCESS_NAME'].endswith("\\System32\\dnscmd.exe") or record['PROCESS_NAME'].endswith("\\System32\\dns.exe"))))

sigma_dns_rce_cve_2020_1350.sigma_meta = dict(
    level="critical"
)

def sigma_krbrelayup_hack_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_krbrelayup.yml
    title: KrbRelayUp Hack Tool
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\KrbRelayUp.exe") or record['ORIGINAL_FILE_NAME'] == "KrbRelayUp.exe" or (record['COMMAND_LINE'].contains("relay") and record['COMMAND_LINE'].contains("-Domain") and record['COMMAND_LINE'].contains("-ComputerName")) or (record['COMMAND_LINE'].contains("krbscm") and record['COMMAND_LINE'].contains("-sc")) or (record['COMMAND_LINE'].contains("spawn") and record['COMMAND_LINE'].contains("-d") and record['COMMAND_LINE'].contains("-cn") and record['COMMAND_LINE'].contains("-cp")))

sigma_krbrelayup_hack_tool.sigma_meta = dict(
    level="high"
)

def sigma_process_creation_using_sysnative_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sysnative.yml
    title: Process Creation Using Sysnative Folder
    fields: ['CommandLine']
    level: medium
    description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].startswith("C:\\Windows\\Sysnative")

sigma_process_creation_using_sysnative_folder.sigma_meta = dict(
    level="medium"
)

def sigma_fsutil_suspicious_invocation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_fsutil_usage.yml
    title: Fsutil Suspicious Invocation
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size, etc).
Might be used by ransomwares during the attack (seen by NotPetya and others).

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\fsutil.exe") or record['ORIGINAL_FILE_NAME'] == "fsutil.exe") and (record['COMMAND_LINE'].contains("deletejournal") or record['COMMAND_LINE'].contains("createjournal")))

sigma_fsutil_suspicious_invocation.sigma_meta = dict(
    level="high"
)

def sigma_adwind_rat_jrat(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mal_adwind.yml
    title: Adwind RAT / JRAT
    fields: ['CommandLine']
    level: high
    description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\AppData\\Roaming\\Oracle") and record['COMMAND_LINE'].contains("\\java") and record['COMMAND_LINE'].contains(".exe")) or (record['COMMAND_LINE'].contains("cscript.exe") and record['COMMAND_LINE'].contains("Retrive") and record['COMMAND_LINE'].contains(".vbs")))

sigma_adwind_rat_jrat.sigma_meta = dict(
    level="high"
)

def sigma_screenconnect_backstage_mode_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_screenconnect_anomaly.yml
    title: ScreenConnect Backstage Mode Anomaly
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious sub processes started by the ScreenConnect client service, which indicates the use of the so-called Backstage mode
    logsource: product:windows - category:process_creation
    """
    return (record['PARENT_NAME'].endswith("ScreenConnect.ClientService.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")))

sigma_screenconnect_backstage_mode_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_trickbot_malware_recon_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_trickbot_recon_activity.yml
    title: Trickbot Malware Recon Activity
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Trickbot enumerates domain/network topology and executes certain commands automatically every few minutes. This detectors attempts to identify that activity based off a command rarely observed in an enterprise network.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\cmd.exe") and record['PROCESS_NAME'].endswith("\\nltest.exe") and record['COMMAND_LINE'].contains("/domain_trusts /all_trusts"))

sigma_trickbot_malware_recon_activity.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_spool_service_child_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_spoolsv_child_processes.yml
    title: Suspicious Spool Service Child Process
    fields: ['IntegrityLevel', 'Image', 'ParentImage', 'CommandLine']
    level: high
    description: Detects suspicious print spool service (spoolsv.exe) child processes.
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\spoolsv.exe") and record['INTEGRITY_LEVEL'] == "System") and ((((((record['PROCESS_NAME'].endswith("\\gpupdate.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe") or record['PROCESS_NAME'].endswith("\\nltest.exe") or record['PROCESS_NAME'].endswith("\\taskkill.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\taskmgr.exe") or record['PROCESS_NAME'].endswith("\\sc.exe") or record['PROCESS_NAME'].endswith("\\findstr.exe") or record['PROCESS_NAME'].endswith("\\curl.exe") or record['PROCESS_NAME'].endswith("\\wget.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\accesschk.exe") or record['PROCESS_NAME'].endswith("\\wevtutil.exe") or record['PROCESS_NAME'].endswith("\\bcdedit.exe") or record['PROCESS_NAME'].endswith("\\fsutil.exe") or record['PROCESS_NAME'].endswith("\\cipher.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\write.exe") or record['PROCESS_NAME'].endswith("\\wuauclt.exe")) or (record['PROCESS_NAME'].endswith("\\net.exe") and not (record['COMMAND_LINE'].contains("start")))) or (record['PROCESS_NAME'].endswith("\\cmd.exe") and not ((record['COMMAND_LINE'].contains(".spl") or record['COMMAND_LINE'].contains("route add") or record['COMMAND_LINE'].contains("program files"))))) or (record['PROCESS_NAME'].endswith("\\netsh.exe") and not ((record['COMMAND_LINE'].contains("add portopening") or record['COMMAND_LINE'].contains("rule name"))))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and not (record['COMMAND_LINE'].contains(".spl")))) or (record['PROCESS_NAME'].endswith("\\rundll32.exe") and record['COMMAND_LINE'].endswith("rundll32.exe"))))

sigma_suspicious_spool_service_child_process.sigma_meta = dict(
    level="high"
)

def sigma_awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_winrm_awl_bypass.yml
    title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("winrm") and (record['COMMAND_LINE'].contains("format:pretty") or record['COMMAND_LINE'].contains("format:\"pretty\"") or record['COMMAND_LINE'].contains("format:\"text\"") or record['COMMAND_LINE'].contains("format:text")) and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64"))))

sigma_awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl.sigma_meta = dict(
    level="medium"
)

def sigma_net_webclient_casing_anomalies(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_webclient_casing.yml
    title: Net WebClient Casing Anomalies
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects PowerShell command line contents that include a suspicious abnormal casing in the Net.Webclient (e.g. nEt.WEbCliEnT) string as used in obfuscation techniques
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("TgBlAFQALgB3AEUAQg") or record['COMMAND_LINE'].contains("4AZQBUAC4AdwBFAEIA") or record['COMMAND_LINE'].contains("OAGUAVAAuAHcARQBCA") or record['COMMAND_LINE'].contains("bgBFAHQALgB3AGUAYg") or record['COMMAND_LINE'].contains("4ARQB0AC4AdwBlAGIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAHcAZQBiA") or record['COMMAND_LINE'].contains("TgBFAHQALgB3AGUAYg") or record['COMMAND_LINE'].contains("OAEUAdAAuAHcAZQBiA") or record['COMMAND_LINE'].contains("bgBlAFQALgB3AGUAYg") or record['COMMAND_LINE'].contains("4AZQBUAC4AdwBlAGIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAHcAZQBiA") or record['COMMAND_LINE'].contains("TgBlAFQALgB3AGUAYg") or record['COMMAND_LINE'].contains("OAGUAVAAuAHcAZQBiA") or record['COMMAND_LINE'].contains("bgBFAFQALgB3AGUAYg") or record['COMMAND_LINE'].contains("4ARQBUAC4AdwBlAGIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAHcAZQBiA") or record['COMMAND_LINE'].contains("bgBlAHQALgBXAGUAYg") or record['COMMAND_LINE'].contains("4AZQB0AC4AVwBlAGIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("bgBFAHQALgBXAGUAYg") or record['COMMAND_LINE'].contains("4ARQB0AC4AVwBlAGIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("TgBFAHQALgBXAGUAYg") or record['COMMAND_LINE'].contains("OAEUAdAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("bgBlAFQALgBXAGUAYg") or record['COMMAND_LINE'].contains("4AZQBUAC4AVwBlAGIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("TgBlAFQALgBXAGUAYg") or record['COMMAND_LINE'].contains("OAGUAVAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("bgBFAFQALgBXAGUAYg") or record['COMMAND_LINE'].contains("4ARQBUAC4AVwBlAGIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAFcAZQBiA") or record['COMMAND_LINE'].contains("bgBlAHQALgB3AEUAYg") or record['COMMAND_LINE'].contains("4AZQB0AC4AdwBFAGIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAHcARQBiA") or record['COMMAND_LINE'].contains("TgBlAHQALgB3AEUAYg") or record['COMMAND_LINE'].contains("OAGUAdAAuAHcARQBiA") or record['COMMAND_LINE'].contains("bgBFAHQALgB3AEUAYg") or record['COMMAND_LINE'].contains("4ARQB0AC4AdwBFAGIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAHcARQBiA") or record['COMMAND_LINE'].contains("TgBFAHQALgB3AEUAYg") or record['COMMAND_LINE'].contains("OAEUAdAAuAHcARQBiA") or record['COMMAND_LINE'].contains("bgBlAFQALgB3AEUAYg") or record['COMMAND_LINE'].contains("4AZQBUAC4AdwBFAGIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAHcARQBiA") or record['COMMAND_LINE'].contains("TgBlAFQALgB3AEUAYg") or record['COMMAND_LINE'].contains("OAGUAVAAuAHcARQBiA") or record['COMMAND_LINE'].contains("bgBFAFQALgB3AEUAYg") or record['COMMAND_LINE'].contains("4ARQBUAC4AdwBFAGIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAHcARQBiA") or record['COMMAND_LINE'].contains("TgBFAFQALgB3AEUAYg") or record['COMMAND_LINE'].contains("OAEUAVAAuAHcARQBiA") or record['COMMAND_LINE'].contains("bgBlAHQALgBXAEUAYg") or record['COMMAND_LINE'].contains("4AZQB0AC4AVwBFAGIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAFcARQBiA") or record['COMMAND_LINE'].contains("TgBlAHQALgBXAEUAYg") or record['COMMAND_LINE'].contains("OAGUAdAAuAFcARQBiA") or record['COMMAND_LINE'].contains("bgBFAHQALgBXAEUAYg") or record['COMMAND_LINE'].contains("4ARQB0AC4AVwBFAGIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAFcARQBiA") or record['COMMAND_LINE'].contains("TgBFAHQALgBXAEUAYg") or record['COMMAND_LINE'].contains("OAEUAdAAuAFcARQBiA") or record['COMMAND_LINE'].contains("bgBlAFQALgBXAEUAYg") or record['COMMAND_LINE'].contains("4AZQBUAC4AVwBFAGIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAFcARQBiA") or record['COMMAND_LINE'].contains("TgBlAFQALgBXAEUAYg") or record['COMMAND_LINE'].contains("OAGUAVAAuAFcARQBiA") or record['COMMAND_LINE'].contains("bgBFAFQALgBXAEUAYg") or record['COMMAND_LINE'].contains("4ARQBUAC4AVwBFAGIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAFcARQBiA") or record['COMMAND_LINE'].contains("TgBFAFQALgBXAEUAYg") or record['COMMAND_LINE'].contains("OAEUAVAAuAFcARQBiA") or record['COMMAND_LINE'].contains("bgBlAHQALgB3AGUAQg") or record['COMMAND_LINE'].contains("4AZQB0AC4AdwBlAEIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("TgBlAHQALgB3AGUAQg") or record['COMMAND_LINE'].contains("OAGUAdAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("bgBFAHQALgB3AGUAQg") or record['COMMAND_LINE'].contains("4ARQB0AC4AdwBlAEIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("TgBFAHQALgB3AGUAQg") or record['COMMAND_LINE'].contains("OAEUAdAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("bgBlAFQALgB3AGUAQg") or record['COMMAND_LINE'].contains("4AZQBUAC4AdwBlAEIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("TgBlAFQALgB3AGUAQg") or record['COMMAND_LINE'].contains("OAGUAVAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("bgBFAFQALgB3AGUAQg") or record['COMMAND_LINE'].contains("4ARQBUAC4AdwBlAEIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("TgBFAFQALgB3AGUAQg") or record['COMMAND_LINE'].contains("OAEUAVAAuAHcAZQBCA") or record['COMMAND_LINE'].contains("bgBlAHQALgBXAGUAQg") or record['COMMAND_LINE'].contains("4AZQB0AC4AVwBlAEIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("TgBlAHQALgBXAGUAQg") or record['COMMAND_LINE'].contains("OAGUAdAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("bgBFAHQALgBXAGUAQg") or record['COMMAND_LINE'].contains("4ARQB0AC4AVwBlAEIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("TgBFAHQALgBXAGUAQg") or record['COMMAND_LINE'].contains("OAEUAdAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("bgBlAFQALgBXAGUAQg") or record['COMMAND_LINE'].contains("4AZQBUAC4AVwBlAEIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("TgBlAFQALgBXAGUAQg") or record['COMMAND_LINE'].contains("OAGUAVAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("bgBFAFQALgBXAGUAQg") or record['COMMAND_LINE'].contains("4ARQBUAC4AVwBlAEIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("TgBFAFQALgBXAGUAQg") or record['COMMAND_LINE'].contains("OAEUAVAAuAFcAZQBCA") or record['COMMAND_LINE'].contains("bgBlAHQALgB3AEUAQg") or record['COMMAND_LINE'].contains("4AZQB0AC4AdwBFAEIA") or record['COMMAND_LINE'].contains("uAGUAdAAuAHcARQBCA") or record['COMMAND_LINE'].contains("TgBlAHQALgB3AEUAQg") or record['COMMAND_LINE'].contains("OAGUAdAAuAHcARQBCA") or record['COMMAND_LINE'].contains("bgBFAHQALgB3AEUAQg") or record['COMMAND_LINE'].contains("4ARQB0AC4AdwBFAEIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAHcARQBCA") or record['COMMAND_LINE'].contains("TgBFAHQALgB3AEUAQg") or record['COMMAND_LINE'].contains("OAEUAdAAuAHcARQBCA") or record['COMMAND_LINE'].contains("bgBlAFQALgB3AEUAQg") or record['COMMAND_LINE'].contains("uAGUAVAAuAHcARQBCA") or record['COMMAND_LINE'].contains("bgBFAFQALgB3AEUAQg") or record['COMMAND_LINE'].contains("4ARQBUAC4AdwBFAEIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAHcARQBCA") or record['COMMAND_LINE'].contains("TgBFAFQALgB3AEUAQg") or record['COMMAND_LINE'].contains("OAEUAVAAuAHcARQBCA") or record['COMMAND_LINE'].contains("TgBlAHQALgBXAEUAQg") or record['COMMAND_LINE'].contains("4AZQB0AC4AVwBFAEIA") or record['COMMAND_LINE'].contains("OAGUAdAAuAFcARQBCA") or record['COMMAND_LINE'].contains("bgBFAHQALgBXAEUAQg") or record['COMMAND_LINE'].contains("4ARQB0AC4AVwBFAEIA") or record['COMMAND_LINE'].contains("uAEUAdAAuAFcARQBCA") or record['COMMAND_LINE'].contains("TgBFAHQALgBXAEUAQg") or record['COMMAND_LINE'].contains("OAEUAdAAuAFcARQBCA") or record['COMMAND_LINE'].contains("bgBlAFQALgBXAEUAQg") or record['COMMAND_LINE'].contains("4AZQBUAC4AVwBFAEIA") or record['COMMAND_LINE'].contains("uAGUAVAAuAFcARQBCA") or record['COMMAND_LINE'].contains("TgBlAFQALgBXAEUAQg") or record['COMMAND_LINE'].contains("OAGUAVAAuAFcARQBCA") or record['COMMAND_LINE'].contains("bgBFAFQALgBXAEUAQg") or record['COMMAND_LINE'].contains("4ARQBUAC4AVwBFAEIA") or record['COMMAND_LINE'].contains("uAEUAVAAuAFcARQBCA")))

sigma_net_webclient_casing_anomalies.sigma_meta = dict(
    level="high"
)

def sigma_new_network_provider_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_new_network_provider.yml
    title: New Network Provider - CommandLine
    fields: ['CommandLine']
    level: high
    description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\System\\CurrentControlSet\\Services") and record['COMMAND_LINE'].contains("\\NetworkProvider")) and not ((record['COMMAND_LINE'].contains("\\System\\CurrentControlSet\\Services\\WebClient\\NetworkProvider") or record['COMMAND_LINE'].contains("\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\NetworkProvider") or record['COMMAND_LINE'].contains("\\System\\CurrentControlSet\\Services\\RDPNP\\NetworkProvider"))))

sigma_new_network_provider_commandline.sigma_meta = dict(
    level="high"
)

def sigma_use_of_remote_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_remote.yml
    title: Use of Remote.exe
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Remote.exe is part of WinDbg in the Windows SDK and can be used for AWL bypass and running remote files.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\remote.exe") or record['ORIGINAL_FILE_NAME'] == "remote.exe")

sigma_use_of_remote_exe.sigma_meta = dict(
    level="medium"
)

def sigma_screenconnect_remote_access(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_screenconnect_access.yml
    title: ScreenConnect Remote Access
    fields: ['CommandLine']
    level: high
    description: Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("e=Access&") and record['COMMAND_LINE'].contains("y=Guest&") and record['COMMAND_LINE'].contains("&p=") and record['COMMAND_LINE'].contains("&c=") and record['COMMAND_LINE'].contains("&k="))

sigma_screenconnect_remote_access.sigma_meta = dict(
    level="high"
)

def sigma_email_exifiltration_via_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_email_exfil_via_powershell.yml
    title: Email Exifiltration Via Powershell
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects email exfiltration via powershell cmdlets
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("Add-PSSnapin") and record['COMMAND_LINE'].contains("Get-Recipient") and record['COMMAND_LINE'].contains("-ExpandProperty") and record['COMMAND_LINE'].contains("EmailAddresses") and record['COMMAND_LINE'].contains("SmtpAddress") and record['COMMAND_LINE'].contains("-hidetableheaders"))

sigma_email_exifiltration_via_powershell.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_regsvr32_execution_from_remote_share(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_remote_share.yml
    title: Suspicious Regsvr32 Execution From Remote Share
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects REGSVR32.exe to execute DLL hosted on remote shares
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['ORIGINAL_FILE_NAME'] == "\\REGSVR32.EXE") and record['COMMAND_LINE'].contains(""))

sigma_suspicious_regsvr32_execution_from_remote_share.sigma_meta = dict(
    level="high"
)

def sigma_detect_execution_of_winpeas(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_winpeas_tool.yml
    title: Detect Execution of winPEAS
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on book.hacktricks.xyz
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\winPEASany.exe") or record['PROCESS_NAME'].endswith("\\winPEASany_ofs.exe") or record['PROCESS_NAME'].endswith("\\winPEASx64.exe") or record['PROCESS_NAME'].endswith("\\winPEASx64_ofs.exe") or record['PROCESS_NAME'].endswith("\\winPEASx86.exe") or record['PROCESS_NAME'].endswith("\\winPEASx86_ofs.exe")) or record['ORIGINAL_FILE_NAME'] == "winPEAS.exe" or (record['COMMAND_LINE'].endswith("serviceinfo") or record['COMMAND_LINE'].endswith("applicationsinfo") or record['COMMAND_LINE'].endswith("windowscreds") or record['COMMAND_LINE'].endswith("browserinfo") or record['COMMAND_LINE'].endswith("fileanalysis")) or record['COMMAND_LINE'].contains(".exe browserinfo"))

sigma_detect_execution_of_winpeas.sigma_meta = dict(
    level="high"
)

def sigma_powershell_amsi_bypass_via_net_reflection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_amsi_bypass.yml
    title: Powershell AMSI Bypass via .NET Reflection
    fields: ['CommandLine']
    level: high
    description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("System.Management.Automation.AmsiUtils") or record['COMMAND_LINE'].contains("amsiInitFailed"))

sigma_powershell_amsi_bypass_via_net_reflection.sigma_meta = dict(
    level="high"
)

def sigma_capture_a_network_trace_with_netsh_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_packet_capture.yml
    title: Capture a Network Trace with netsh.exe
    fields: ['CommandLine']
    level: medium
    description: Detects capture a network trace via netsh.exe trace functionality
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("trace") and record['COMMAND_LINE'].contains("start"))

sigma_capture_a_network_trace_with_netsh_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_regsvr32_http_ip_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_http_pattern.yml
    title: Suspicious Regsvr32 HTTP IP Pattern
    fields: ['CommandLine']
    level: high
    description: Detects a certain command line flag combination used by regsvr32 when used to download and register a DLL from a remote address which uses HTTP (not HTTPS) and a IP address and not FQDN
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/s") and record['COMMAND_LINE'].contains("/u") and (record['COMMAND_LINE'].contains("/i:http://1") or record['COMMAND_LINE'].contains("/i:http://2") or record['COMMAND_LINE'].contains("/i:http://3") or record['COMMAND_LINE'].contains("/i:http://4") or record['COMMAND_LINE'].contains("/i:http://5") or record['COMMAND_LINE'].contains("/i:http://6") or record['COMMAND_LINE'].contains("/i:http://7") or record['COMMAND_LINE'].contains("/i:http://8") or record['COMMAND_LINE'].contains("/i:http://9")))

sigma_suspicious_regsvr32_http_ip_pattern.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_cmdline_special_characters.yml
    title: Suspicious PowerShell Command Line
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects the PowerShell command lines with special characters
    logsource: category:process_creation - product:windows
    """
    return ((((((((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*\+.*', record['COMMAND_LINE'])) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*\{.*\{.*\{.*\{.*\{.*\{.*\{.*\{.*\{.*\{.*', record['COMMAND_LINE']))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*\{.*\{.*\{.*\{.*\{.*', record['COMMAND_LINE']))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*\^.*\^.*\^.*\^.*\^.*', record['COMMAND_LINE']))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*`.*`.*`.*`.*`.*', record['COMMAND_LINE']))) and not (record['PARENT_NAME'] == "C:\\Program Files\\Amazon\\SSM\\ssm-document-worker.exe")) and not (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and re.match('.*\{.*\{.*\{.*\{.*\{.*', record['COMMAND_LINE']) and (record['COMMAND_LINE'].contains("new EventSource(\"Microsoft.Windows.Sense.Client.Management\"") or record['COMMAND_LINE'].contains("public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);")))))

sigma_suspicious_powershell_command_line.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_cmd_shell_redirect(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmd_redirection_susp_folder.yml
    title: Suspicious CMD Shell Redirect
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects inline windows shell commands redirecting output via the ">" symbol to a suspicious location
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['ORIGINAL_FILE_NAME'] == "Cmd.Exe") and (record['COMMAND_LINE'].contains("> %USERPROFILE%") and record['COMMAND_LINE'].contains("> %APPDATA%") and record['COMMAND_LINE'].contains("> \\Users\\Public") and record['COMMAND_LINE'].contains("> C:\\Users\\Public") and record['COMMAND_LINE'].contains("> %TEMP%") and record['COMMAND_LINE'].contains("> %TMP%")))

sigma_suspicious_cmd_shell_redirect.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_razerinstaller_explorer_subprocess(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_razorinstaller_explorer.yml
    title: Suspicious RazerInstaller Explorer Subprocess
    fields: ['IntegrityLevel', 'Image', 'ParentImage']
    level: high
    description: Detects a explorer.exe sub process of the RazerInstaller software which can be invoked from the installer to select a different installation folder but can also be exploited to escalate privileges to LOCAL SYSTEM
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\RazerInstaller.exe") and record['INTEGRITY_LEVEL'] == "System") and not (record['PROCESS_NAME'].startswith("C:\\Windows\\Installer\\Razer\\Installer")))

sigma_suspicious_razerinstaller_explorer_subprocess.sigma_meta = dict(
    level="high"
)

def sigma_execution_of_renamed_paexec(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_paexec.yml
    title: Execution of Renamed PaExec
    fields: ['Image', 'Hashes', 'Imphash', 'Product']
    level: medium
    description: Detects execution of renamed paexec via imphash and executable product string
    logsource: category:process_creation - product:windows
    """
    return ((record['PRODUCT_NAME'].contains("PAExec") and ((record['IMPHASH'] == "11D40A7B7876288F919AB819CC2D9802" or record['IMPHASH'] == "6444f8a34e99b8f7d9647de66aabe516" or record['IMPHASH'] == "dfd6aa3f7b2b1035b76b718f1ddc689f" or record['IMPHASH'] == "1a6cca4d5460b1710a12dea39e4a592c") or (record['HASHES'].contains("IMPHASH=11D40A7B7876288F919AB819CC2D9802") or record['HASHES'].contains("IMPHASH=6444f8a34e99b8f7d9647de66aabe516") or record['HASHES'].contains("IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f") or record['HASHES'].contains("IMPHASH=1a6cca4d5460b1710a12dea39e4a592c")))) and not (record['PROCESS_NAME'].contains("paexec")))

sigma_execution_of_renamed_paexec.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_curl_usage_on_windows(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_curl_download.yml
    title: Suspicious Curl Usage on Windows
    fields: ['CommandLine', 'Image', 'Product', 'ParentImage']
    level: high
    description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\curl.exe") or record['PRODUCT_NAME'] == "The curl executable") and ((record['COMMAND_LINE'].contains("\\AppData") or record['COMMAND_LINE'].contains("\\Users\\Public") or record['COMMAND_LINE'].contains("\\Temp") or record['COMMAND_LINE'].contains("%AppData%") or record['COMMAND_LINE'].contains("%Temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("%Public%") or record['COMMAND_LINE'].contains("\\Desktop")) or (record['COMMAND_LINE'].endswith(".jpg") or record['COMMAND_LINE'].endswith(".jpeg") or record['COMMAND_LINE'].endswith(".png") or record['COMMAND_LINE'].endswith(".gif") or record['COMMAND_LINE'].endswith(".tmp") or record['COMMAND_LINE'].endswith(".temp") or record['COMMAND_LINE'].endswith(".txt")) or (record['COMMAND_LINE'].contains("-O") or record['COMMAND_LINE'].contains("--remote-name") or record['COMMAND_LINE'].contains("--output")))) and not ((record['PARENT_NAME'] == "C:\\Program Files\\Git\\usr\\bin\\sh.exe" and record['PROCESS_NAME'] == "C:\\Program Files\\Git\\mingw64\\bin\\curl.exe" and record['COMMAND_LINE'].contains("--silent --show-error --output") and record['COMMAND_LINE'].contains("gfw-httpget-"))))

sigma_suspicious_curl_usage_on_windows.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_curl_change_user_agents(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_curl_useragent.yml
    title: Suspicious Curl Change User Agents
    fields: ['CommandLine', 'Image', 'Product']
    level: medium
    description: Detects a suspicious curl process start on Windows with set useragent options
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\curl.exe") or record['PRODUCT_NAME'] == "The curl executable") and (record['COMMAND_LINE'].contains("-A") or record['COMMAND_LINE'].contains("--user-agent")))

sigma_suspicious_curl_change_user_agents.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_lsass_process_clone(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_lsass_clone.yml
    title: Suspicious LSASS Process Clone
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects a suspicious LSASS process process clone that could be a sign of process dumping activity
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Windows\\System32\\lsass.exe") and record['PARENT_NAME'].endswith("\\Windows\\System32\\lsass.exe"))

sigma_suspicious_lsass_process_clone.sigma_meta = dict(
    level="critical"
)

def sigma_registry_dump_of_sam_creds_and_secrets(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_dump_sam.yml
    title: Registry Dump of SAM Creds and Secrets
    fields: ['CommandLine']
    level: high
    description: Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through Windows Registry where the SAM database is stored
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("save") and (record['COMMAND_LINE'].contains("HKLM\\sam") or record['COMMAND_LINE'].contains("HKLM\\system") or record['COMMAND_LINE'].contains("HKLM\\security")))

sigma_registry_dump_of_sam_creds_and_secrets.sigma_meta = dict(
    level="high"
)

def sigma_regsvr32_flags_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_flags_anomaly.yml
    title: Regsvr32 Flags Anomaly
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['COMMAND_LINE'].contains("/i:")) and not (record['COMMAND_LINE'].contains("/n")))

sigma_regsvr32_flags_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_add_safeboot_keys_via_reg_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_add_safeboot.yml
    title: Add SafeBoot Keys Via Reg Utility
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of "reg.exe" commands with the "add" or "copy" flags on safe boot registry keys. Often used by attacker to allow the ransomware to work in safe mode as some security products do not
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and record['COMMAND_LINE'].contains("\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot") and (record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("add")))

sigma_add_safeboot_keys_via_reg_utility.sigma_meta = dict(
    level="high"
)

def sigma_uac_bypass_wsreset(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset_integrity_level.yml
    title: UAC Bypass WSReset
    fields: ['IntegrityLevel', 'Image']
    level: high
    description: Detects the pattern of UAC Bypass via WSReset usable by default sysmon-config
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wsreset.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_wsreset.sigma_meta = dict(
    level="high"
)

def sigma_wscript_shell_run_in_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wscript_shell_cli.yml
    title: Wscript Shell Run In CommandLine
    fields: ['CommandLine']
    level: high
    description: Detects the presence of the keywords "Wscript", "Shell" and "Run" in the command, which could indicate a suspicious activity
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Wscript.") and record['COMMAND_LINE'].contains(".Shell") and record['COMMAND_LINE'].contains(".Run"))

sigma_wscript_shell_run_in_commandline.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_network_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_network_command.yml
    title: Suspicious Network Command
    fields: ['CommandLine']
    level: low
    description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("ipconfig /all") or record['COMMAND_LINE'].contains("netsh interface show interface") or record['COMMAND_LINE'].contains("arp -a") or record['COMMAND_LINE'].contains("nbtstat -n") or record['COMMAND_LINE'].contains("net config") or record['COMMAND_LINE'].contains("route print"))

sigma_suspicious_network_command.sigma_meta = dict(
    level="low"
)

def sigma_dll_execution_via_register_cimprovider_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_register_cimprovider.yml
    title: DLL Execution Via Register-cimprovider.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects using register-cimprovider.exe to execute arbitrary dll file.
    logsource: category:process_creation - product:windows - definition:Requirements: Sysmon ProcessCreation logging must be activated and Windows audit msut Include command line in process creation events
    """
    return (record['PROCESS_NAME'].endswith("\\register-cimprovider.exe") and record['COMMAND_LINE'].contains("-path") and record['COMMAND_LINE'].contains("dll"))

sigma_dll_execution_via_register_cimprovider_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_sysvol_domain_group_policy_access(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_sysvol_access.yml
    title: Suspicious SYSVOL Domain Group Policy Access
    fields: ['CommandLine']
    level: medium
    description: Detects Access to Domain Group Policies stored in SYSVOL
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\SYSVOL") and record['COMMAND_LINE'].contains("\\policies"))

sigma_suspicious_sysvol_domain_group_policy_access.sigma_meta = dict(
    level="medium"
)

def sigma_execute_pcwrun_exe_to_leverage_follina(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_pcwrun_follina.yml
    title: Execute Pcwrun.EXE To Leverage Follina
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\pcwrun.exe") and record['COMMAND_LINE'].contains("../"))

sigma_execute_pcwrun_exe_to_leverage_follina.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_advancedrun_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_advancedrun.yml
    title: Suspicious AdvancedRun Execution
    fields: ['CommandLine', 'OriginalFileName']
    level: medium
    description: Detects the execution of AdvancedRun utility
    logsource: product:windows - category:process_creation
    """
    return (record['ORIGINAL_FILE_NAME'] == "AdvancedRun.exe" or (record['COMMAND_LINE'].contains("/EXEFilename") and record['COMMAND_LINE'].contains("/Run")) or (record['COMMAND_LINE'].contains("/WindowState 0") and record['COMMAND_LINE'].contains("/RunAs") and record['COMMAND_LINE'].contains("/CommandLine")))

sigma_suspicious_advancedrun_execution.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_manipulation_of_default_accounts(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_default_accounts_manipulation.yml
    title: Suspicious Manipulation Of Default Accounts
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("user") and (record['COMMAND_LINE'].contains("Järjestelmänvalvoja") or record['COMMAND_LINE'].contains("Rendszergazda") or record['COMMAND_LINE'].contains("Администратор") or record['COMMAND_LINE'].contains("Administrateur") or record['COMMAND_LINE'].contains("Administrador") or record['COMMAND_LINE'].contains("Administratör") or record['COMMAND_LINE'].contains("Administrator") or record['COMMAND_LINE'].contains("guest") or record['COMMAND_LINE'].contains("DefaultAccount") or record['COMMAND_LINE'].contains("\"Järjestelmänvalvoja\"") or record['COMMAND_LINE'].contains("\"Rendszergazda\"") or record['COMMAND_LINE'].contains("\"Администратор\"") or record['COMMAND_LINE'].contains("\"Administrateur\"") or record['COMMAND_LINE'].contains("\"Administrador\"") or record['COMMAND_LINE'].contains("\"Administratör\"") or record['COMMAND_LINE'].contains("\"Administrator\"") or record['COMMAND_LINE'].contains("\"guest\"") or record['COMMAND_LINE'].contains("\"DefaultAccount\"") or record['COMMAND_LINE'].contains("\'Järjestelmänvalvoja\'") or record['COMMAND_LINE'].contains("\'Rendszergazda\'") or record['COMMAND_LINE'].contains("\'Администратор\'") or record['COMMAND_LINE'].contains("\'Administrateur\'") or record['COMMAND_LINE'].contains("\'Administrador\'") or record['COMMAND_LINE'].contains("\'Administratör\'") or record['COMMAND_LINE'].contains("\'Administrator\'") or record['COMMAND_LINE'].contains("\'guest\'") or record['COMMAND_LINE'].contains("\'DefaultAccount\'"))) and not (record['COMMAND_LINE'].contains("guest") and record['COMMAND_LINE'].contains("/active no")))

sigma_suspicious_manipulation_of_default_accounts.sigma_meta = dict(
    level="high"
)

def sigma_shimcache_flush(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shimcache_flush.yml
    title: ShimCache Flush
    fields: ['CommandLine']
    level: high
    description: Detects actions that clear the local ShimCache and remove forensic evidence
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("apphelp.dll") and (record['COMMAND_LINE'].contains("ShimFlushCache") or record['COMMAND_LINE'].contains("#250"))) or (record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("kernel32.dll") and (record['COMMAND_LINE'].contains("BaseFlushAppcompatCache") or record['COMMAND_LINE'].contains("#46"))))

sigma_shimcache_flush.sigma_meta = dict(
    level="high"
)

def sigma_dns_tunnel_technique_from_muddywater(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_muddywater_dnstunnel.yml
    title: DNS Tunnel Technique from MuddyWater
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detecting DNS tunnel activity for Muddywater actor
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['PARENT_NAME'].endswith("\\excel.exe") and record['COMMAND_LINE'].contains("DataExchange.dll"))

sigma_dns_tunnel_technique_from_muddywater.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_query_of_machineguid(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_machineguid.yml
    title: Suspicious Query of MachineGUID
    fields: ['CommandLine', 'Image']
    level: low
    description: Use of reg to get MachineGuid information
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("SOFTWARE\\Microsoft\\Cryptography") and record['COMMAND_LINE'].contains("/v") and record['COMMAND_LINE'].contains("MachineGuid"))

sigma_suspicious_query_of_machineguid.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_netsh_dll_persistence(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_netsh_dll_persistence.yml
    title: Suspicious Netsh DLL Persistence
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects persitence via netsh helper
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("helper"))

sigma_suspicious_netsh_dll_persistence.sigma_meta = dict(
    level="high"
)

def sigma_winword_lolbin_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_winword.yml
    title: Winword LOLBIN Usage
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects Winword process loading custmom dlls via the '/l' switch.
Winword can be abused as a LOLBIN to download arbitrary file or load arbitrary DLLs.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\WINWORD.exe") or record['ORIGINAL_FILE_NAME'] == "WinWord.exe") and (record['COMMAND_LINE'].contains("/l") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://")))

sigma_winword_lolbin_usage.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_conhost_legacy_option(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_conhost_option.yml
    title: Suspicious Conhost Legacy Option
    fields: ['CommandLine']
    level: informational
    description: ForceV1 asks for information directly from the kernel space. Conhost connects to the console application
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("conhost.exe") and record['COMMAND_LINE'].contains("0xffffffff") and record['COMMAND_LINE'].contains("-ForceV1"))

sigma_suspicious_conhost_legacy_option.sigma_meta = dict(
    level="informational"
)

def sigma_schtasks_from_suspicious_folders(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_folder_combos.yml
    title: Schtasks From Suspicious Folders
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects scheduled task creations that have suspicious action command and folder combinations
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['ORIGINAL_FILE_NAME'] == "schtasks.exe") and record['COMMAND_LINE'].contains("/create") and (record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("pwsh") or record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("cmd /r") or record['COMMAND_LINE'].contains("cmd.exe /c") or record['COMMAND_LINE'].contains("cmd.exe /k") or record['COMMAND_LINE'].contains("cmd.exe /r")) and (record['COMMAND_LINE'].contains("C:\\ProgramData") or record['COMMAND_LINE'].contains("%ProgramData%")))

sigma_schtasks_from_suspicious_folders.sigma_meta = dict(
    level="high"
)

def sigma_mmc20_lateral_movement(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_mmc20_lateral_movement.yml
    title: MMC20 Lateral Movement
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\svchost.exe") and record['PROCESS_NAME'].endswith("\\mmc.exe") and record['COMMAND_LINE'].contains("-Embedding"))

sigma_mmc20_lateral_movement.sigma_meta = dict(
    level="high"
)

def sigma_custom_class_execution_via_xwizard(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_class_exec_xwizard.yml
    title: Custom Class Execution via Xwizard
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the execution of Xwizard tool with specific arguments which utilized to run custom class properties.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\xwizard.exe") and re.match('\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}', record['COMMAND_LINE']))

sigma_custom_class_execution_via_xwizard.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_code_page_switch(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_codepage_switch.yml
    title: Suspicious Code Page Switch
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects a code page switch in command line or batch scripts to a rare language
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\chcp.com") and (record['COMMAND_LINE'].endswith("936") or record['COMMAND_LINE'].endswith("1258")))

sigma_suspicious_code_page_switch.sigma_meta = dict(
    level="medium"
)

def sigma_new_service_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_new_service_creation.yml
    title: New Service Creation
    fields: ['CommandLine', 'Image']
    level: low
    description: Detects creation of a new service.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sc.exe") and record['COMMAND_LINE'].contains("create") and record['COMMAND_LINE'].contains("binPath")) or (record['COMMAND_LINE'].contains("New-Service") and record['COMMAND_LINE'].contains("-BinaryPathName")))

sigma_new_service_creation.sigma_meta = dict(
    level="low"
)

def sigma_office_applications_spawning_wmi_cli_alternate(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_spawning_wmi_commandline.yml
    title: Office Applications Spawning Wmi Cli Alternate
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Initial execution of malicious document calls wmic to execute the file with regsvr32
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\wbem\\WMIC.exe") or record['COMMAND_LINE'].contains("wmic")) and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe") or record['PARENT_NAME'].endswith("\\msaccess.exe") or record['PARENT_NAME'].endswith("\\mspub.exe") or record['PARENT_NAME'].endswith("\\eqnedt32.exe") or record['PARENT_NAME'].endswith("\\visio.exe")))

sigma_office_applications_spawning_wmi_cli_alternate.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_recursive_takeown(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_takeown.yml
    title: Suspicious Recursive Takeown
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\takeown.exe") and record['COMMAND_LINE'].contains("/f") and record['COMMAND_LINE'].contains("/r"))

sigma_suspicious_recursive_takeown.sigma_meta = dict(
    level="medium"
)

def sigma_detect_virtualbox_driver_installation_or_starting_of_vms(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_run_virtualbox.yml
    title: Detect Virtualbox Driver Installation OR Starting Of VMs
    fields: ['CommandLine']
    level: low
    description: Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("VBoxRT.dll,RTR3Init") or record['COMMAND_LINE'].contains("VBoxC.dll") or record['COMMAND_LINE'].contains("VBoxDrv.sys")) or (record['COMMAND_LINE'].contains("startvm") or record['COMMAND_LINE'].contains("controlvm")))

sigma_detect_virtualbox_driver_installation_or_starting_of_vms.sigma_meta = dict(
    level="low"
)

def sigma_procdump_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_procdump.yml
    title: Procdump Usage
    fields: ['Image']
    level: medium
    description: Detects usage of the SysInternals Procdump utility
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\procdump.exe") or record['PROCESS_NAME'].endswith("\\procdump64.exe"))

sigma_procdump_usage.sigma_meta = dict(
    level="medium"
)

def sigma_cmstp_uac_bypass_via_com_object_access(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cmstp_com_object_access.yml
    title: CMSTP UAC Bypass via COM Object Access
    fields: ['IntegrityLevel', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects (e.g. UACMe ID of 41, 43, 58 or 65)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\DllHost.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System") and (record['PARENT_COMMAND_LINE'].contains("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}") or record['PARENT_COMMAND_LINE'].contains("/Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}") or record['PARENT_COMMAND_LINE'].contains("/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}") or record['PARENT_COMMAND_LINE'].contains("/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") or record['PARENT_COMMAND_LINE'].contains("/Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}")))

sigma_cmstp_uac_bypass_via_com_object_access.sigma_meta = dict(
    level="high"
)

def sigma_winrm_access_with_evil_winrm(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_evil_winrm.yml
    title: WinRM Access with Evil-WinRM
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\ruby.exe") and record['COMMAND_LINE'].contains("-i") and record['COMMAND_LINE'].contains("-u") and record['COMMAND_LINE'].contains("-p"))

sigma_winrm_access_with_evil_winrm.sigma_meta = dict(
    level="medium"
)

def sigma_invoke_obfuscation_via_stdin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_stdin.yml
    title: Invoke-Obfuscation Via Stdin
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated Powershell via Stdin in Scripts
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("&&") and (record['COMMAND_LINE'].contains("environment") or record['COMMAND_LINE'].contains("invoke") or record['COMMAND_LINE'].contains("input")))

sigma_invoke_obfuscation_via_stdin.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_runas_like_flag_combination(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_command_flag_pattern.yml
    title: Suspicious RunAs-Like Flag Combination
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("-u system") or record['COMMAND_LINE'].contains("--user system") or record['COMMAND_LINE'].contains("-u NT") or record['COMMAND_LINE'].contains("-u \"NT") or record['COMMAND_LINE'].contains("-u \'NT") or record['COMMAND_LINE'].contains("--system") or record['COMMAND_LINE'].contains("-u administrator")) and (record['COMMAND_LINE'].contains("-c cmd") or record['COMMAND_LINE'].contains("-c \"cmd") or record['COMMAND_LINE'].contains("-c powershell") or record['COMMAND_LINE'].contains("-c \"powershell") or record['COMMAND_LINE'].contains("--command cmd") or record['COMMAND_LINE'].contains("--command powershell") or record['COMMAND_LINE'].contains("-c whoami") or record['COMMAND_LINE'].contains("-c wscript") or record['COMMAND_LINE'].contains("-c cscript")))

sigma_suspicious_runas_like_flag_combination.sigma_meta = dict(
    level="medium"
)

def sigma_windows_10_scheduled_task_sandboxescaper_0_day(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_win10_sched_task_0day.yml
    title: Windows 10 Scheduled Task SandboxEscaper 0-day
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects Task Scheduler .job import arbitrary DACL write\par
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['ORIGINAL_FILE_NAME'] == "schtasks.exe" and record['COMMAND_LINE'].contains("/change") and record['COMMAND_LINE'].contains("/TN") and record['COMMAND_LINE'].contains("/RU") and record['COMMAND_LINE'].contains("/RP"))

sigma_windows_10_scheduled_task_sandboxescaper_0_day.sigma_meta = dict(
    level="high"
)

def sigma_rundll32_unc_path_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml
    title: Rundll32 UNC Path Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects rundll32 execution where the DLL is located on a remote location (share)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" or record['COMMAND_LINE'].contains("rundll32")) and record['COMMAND_LINE'].contains(""))

sigma_rundll32_unc_path_execution.sigma_meta = dict(
    level="high"
)

def sigma_high_integrity_sdclt_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_high_integrity_sdclt.yml
    title: High Integrity Sdclt Process
    fields: ['IntegrityLevel', 'Image']
    level: medium
    description: A General detection for sdclt being spawned as an elevated process. This could be an indicator of sdclt being used for bypass UAC techniques.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("sdclt.exe") and record['INTEGRITY_LEVEL'] == "High")

sigma_high_integrity_sdclt_process.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_get_computersystem_information_with_wmic(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_computersystem_recon.yml
    title: Suspicious Get ComputerSystem Information with WMIC
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model...etc.
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\wmic.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("computersystem") and record['COMMAND_LINE'].contains("get")))

sigma_suspicious_get_computersystem_information_with_wmic.sigma_meta = dict(
    level="medium"
)

def sigma_conti_backup_database(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_conti_sqlcmd.yml
    title: Conti Backup Database
    fields: ['CommandLine']
    level: high
    description: Detects a command used by conti to dump database
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("sqlcmd") or record['COMMAND_LINE'].contains("sqlcmd.exe")) and record['COMMAND_LINE'].contains("-S localhost") and (record['COMMAND_LINE'].contains("sys.sysprocesses") or record['COMMAND_LINE'].contains("master.dbo.sysdatabases") or record['COMMAND_LINE'].contains("BACKUP DATABASE")))

sigma_conti_backup_database.sigma_meta = dict(
    level="high"
)

def sigma_sharpup_privesc_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sharpup.yml
    title: SharpUp PrivEsc Tool
    fields: ['CommandLine', 'Image', 'Description']
    level: critical
    description: Detects the use of SharpUp, a tool for local privilege escalation
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SharpUp.exe") or record['DESCRIPTION'] == "SharpUp" or (record['COMMAND_LINE'].contains("HijackablePaths") or record['COMMAND_LINE'].contains("UnquotedServicePath") or record['COMMAND_LINE'].contains("ProcessDLLHijack") or record['COMMAND_LINE'].contains("ModifiableServiceBinaries") or record['COMMAND_LINE'].contains("ModifiableScheduledTask") or record['COMMAND_LINE'].contains("DomainGPPPassword") or record['COMMAND_LINE'].contains("CachedGPPPassword")))

sigma_sharpup_privesc_tool.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_schtasks_schedule_type_with_high_privileges(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_schedule_type_system.yml
    title: Suspicious Schtasks Schedule Type With High Privileges
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['ORIGINAL_FILE_NAME'] == "schtasks.exe") and (record['COMMAND_LINE'].contains("ONLOGON") or record['COMMAND_LINE'].contains("ONSTART") or record['COMMAND_LINE'].contains("ONCE") or record['COMMAND_LINE'].contains("ONIDLE")) and (record['COMMAND_LINE'].contains("NT AUT") or record['COMMAND_LINE'].contains("SYSTEM") or record['COMMAND_LINE'].contains("HIGHEST")))

sigma_suspicious_schtasks_schedule_type_with_high_privileges.sigma_meta = dict(
    level="medium"
)

def sigma_scheduled_task_executing_powershell_encoded_payload_from_registry(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_schtasks_reg_loader.yml
    title: Scheduled Task Executing Powershell Encoded Payload from Registry
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the creation of a schtask that executes a base64 encoded payload stored in the Windows Registry using PowerShell.
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create") and record['COMMAND_LINE'].contains("/SC") and record['COMMAND_LINE'].contains("FromBase64String") and record['COMMAND_LINE'].contains("Get-ItemProperty") and (record['COMMAND_LINE'].contains("HKCU:") or record['COMMAND_LINE'].contains("HKLM:") or record['COMMAND_LINE'].contains("registry::") or record['COMMAND_LINE'].contains("HKEY_")))

sigma_scheduled_task_executing_powershell_encoded_payload_from_registry.sigma_meta = dict(
    level="high"
)

def sigma_dll_sideloading_by_microsoft_defender(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_dll_sideload_defender.yml
    title: DLL Sideloading by Microsoft Defender
    fields: ['Image']
    level: high
    description: Detects execution of Microsoft Defender's CLI process (MpCmdRun.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\MpCmdRun.exe") and not ((record['PROCESS_NAME'].startswith("C:\\Program Files\\Windows Defender") or record['PROCESS_NAME'].startswith("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform") or record['PROCESS_NAME'].startswith("C:\\Windows\\winsxs") or record['PROCESS_NAME'].startswith("C:\\Program Files\\Microsoft Security Client\\MpCmdRun.exe"))))

sigma_dll_sideloading_by_microsoft_defender.sigma_meta = dict(
    level="high"
)

def sigma_use_of_netsupport_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsupport.yml
    title: Use of NetSupport Remote Access Software
    fields: ['OriginalFileName', 'Product', 'Company', 'Description']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['DESCRIPTION'] == "NetSupport Client Configurator" or record['PRODUCT_NAME'] == "NetSupport Remote Control" or record['COMPANY'] == "NetSupport Ltd" or record['ORIGINAL_FILE_NAME'] == "PCICFGUI.EXE")

sigma_use_of_netsupport_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_detecting_fake_instances_of_hxtsr_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_detecting_fake_instances_of_hxtsr.yml
    title: Detecting Fake Instances Of Hxtsr.exe
    fields: ['Image', 'CurrentDirectory']
    level: medium
    description: HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files". Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe". Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'] == "hxtsr.exe" and not (record['PROCESS_PATH'].startswith("C:\\program files\\windowsapps\\microsoft.windowscommunicationsapps_") and record['PROCESS_PATH'].endswith("\\hxtsr.exe")))

sigma_detecting_fake_instances_of_hxtsr_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_scheduled_task_name_as_guid(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_guid_task_name.yml
    title: Suspicious Scheduled Task Name As GUID
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects creation of a scheduled task with a GUID like name
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/Create") and (record['COMMAND_LINE'].contains("/TN \"{") or record['COMMAND_LINE'].contains("/TN \'{") or record['COMMAND_LINE'].contains("/TN {")) and (record['COMMAND_LINE'].contains("}\"") or record['COMMAND_LINE'].contains("}\'") or record['COMMAND_LINE'].contains("}")))

sigma_suspicious_scheduled_task_name_as_guid.sigma_meta = dict(
    level="medium"
)

def sigma_devinit_lolbin_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_devinit_lolbin.yml
    title: DevInit Lolbin Download
    fields: ['CommandLine']
    level: high
    description: Detects a certain command line flag combination used by devinit.exe lolbin to download arbitrary MSI packages on a Windows system
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-t msi-install") and record['COMMAND_LINE'].contains("-i http"))

sigma_devinit_lolbin_download.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_msiexec_embedding_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msiexec_embedding.yml
    title: Suspicious MsiExec Embedding Parent
    fields: ['CommandLine', 'Image', 'ParentCommandLine']
    level: medium
    description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe")) and record['PARENT_COMMAND_LINE'].contains("MsiExec.exe") and record['PARENT_COMMAND_LINE'].contains("-Embedding")) and not ((record['PROCESS_NAME'].endswith(":\\Windows\\System32\\cmd.exe") and record['COMMAND_LINE'].contains("C:\\Program Files\\SplunkUniversalForwarder\\bin")) or (record['COMMAND_LINE'].contains("\\DismFoDInstall.cmd") or record['PARENT_COMMAND_LINE'].contains("\\MsiExec.exe -Embedding") and record['PARENT_COMMAND_LINE'].contains("Global\\MSI0000"))))

sigma_suspicious_msiexec_embedding_parent.sigma_meta = dict(
    level="medium"
)

def sigma_execute_files_with_msdeploy_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msdeploy.yml
    title: Execute Files with Msdeploy.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects file execution using the msdeploy.exe lolbin
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("verb:sync") and record['COMMAND_LINE'].contains("-source:RunCommand") and record['COMMAND_LINE'].contains("-dest:runCommand") and record['PROCESS_NAME'].endswith("\\msdeploy.exe"))

sigma_execute_files_with_msdeploy_exe.sigma_meta = dict(
    level="medium"
)

def sigma_rundll32_execution_without_dll_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_run_executable_invalid_extension.yml
    title: Rundll32 Execution Without DLL File
    fields: ['CommandLine', 'Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects the execution of rundll32 with a command line that doesn't contain a .dll file
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and not ((record.get('COMMAND_LINE', None) == None) or (record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'] == "") or (record['PARENT_NAME'].endswith(":\\Program Files\\Internet Explorer\\iexplore.exe") and record['COMMAND_LINE'].contains(".cpl")) or (record['PARENT_NAME'].endswith(":\\Windows\\SysWOW64\\msiexec.exe") and record['PARENT_COMMAND_LINE'].startswith("C:\\Windows\\syswow64\\MsiExec.exe -Embedding")) or (record['PARENT_NAME'].endswith(":\\Windows\\System32\\msiexec.exe") and record['PARENT_COMMAND_LINE'].startswith("C:\\Windows\\system32\\MsiExec.exe -Embedding")) or (record['PARENT_NAME'].endswith(":\\Windows\\System32\\cmd.exe") and record['PARENT_COMMAND_LINE'].contains("C:\\Program Files\\SplunkUniversalForwarder")) or (record['COMMAND_LINE'].contains("-localserver"))))

sigma_rundll32_execution_without_dll_file.sigma_meta = dict(
    level="high"
)

def sigma_dll_execution_via_rasautou_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_rasautou_dll_execution.yml
    title: DLL Execution via Rasautou.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p.
    logsource: product:windows - category:process_creation - definition:Since options '-d' and '-p' were removed in Windows 10 this rule is relevant only for Windows before 10. And as Windows 7 doesn't log command line in 4688 by default, to detect this attack you need Sysmon 1 configured or KB3004375 installed for command-line auditing (https://support.microsoft.com/en-au/help/3004375/microsoft-security-advisory-update-to-improve-windows-command-line-aud)
    """
    return ((record['PROCESS_NAME'].endswith("\\rasautou.exe") or record['ORIGINAL_FILE_NAME'] == "rasdlui.exe") and (record['COMMAND_LINE'].contains("-d") and record['COMMAND_LINE'].contains("-p")))

sigma_dll_execution_via_rasautou_exe.sigma_meta = dict(
    level="medium"
)

def sigma_disabled_volume_snapshots(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_volsnap_disable.yml
    title: Disabled Volume Snapshots
    fields: ['CommandLine']
    level: high
    description: Detects commands that temporarily turn off Volume Snapshots
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("\\Services\\VSS\\Diag") and record['COMMAND_LINE'].contains("/d Disabled"))

sigma_disabled_volume_snapshots.sigma_meta = dict(
    level="high"
)

def sigma_execution_from_suspicious_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_execution_path.yml
    title: Execution from Suspicious Folder
    fields: ['Image']
    level: high
    description: Detects a suspicious execution from an uncommon folder
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].contains("\\$Recycle.bin") or record['PROCESS_NAME'].contains("\\config\\systemprofile") or record['PROCESS_NAME'].contains("\\Intel\\Logs") or record['PROCESS_NAME'].contains("\\RSA\\MachineKeys") or record['PROCESS_NAME'].contains("\\Users\\All Users") or record['PROCESS_NAME'].contains("\\Users\\Default") or record['PROCESS_NAME'].contains("\\Users\\NetworkService") or record['PROCESS_NAME'].contains("\\Users\\Public") or record['PROCESS_NAME'].contains("\\Windows\\addins") or record['PROCESS_NAME'].contains("\\Windows\\debug") or record['PROCESS_NAME'].contains("\\Windows\\Fonts") or record['PROCESS_NAME'].contains("\\Windows\\Help") or record['PROCESS_NAME'].contains("\\Windows\\IME") or record['PROCESS_NAME'].contains("\\Windows\\Media") or record['PROCESS_NAME'].contains("\\Windows\\repair") or record['PROCESS_NAME'].contains("\\Windows\\security") or record['PROCESS_NAME'].contains("\\Windows\\System32\\Tasks") or record['PROCESS_NAME'].contains("\\Windows\\Tasks")) or record['PROCESS_NAME'].startswith("C:\\Perflogs")) and not (record['PROCESS_NAME'].startswith("C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs")))

sigma_execution_from_suspicious_folder.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_process_patterns_ntds_dit_exfil(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ntds.yml
    title: Suspicious Process Patterns NTDS.DIT Exfil
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects suspicious process patterns used in NTDS.DIT exfiltration
    logsource: product:windows - category:process_creation
    """
    return ((((record['PROCESS_NAME'].endswith("\\NTDSDump.exe") or record['PROCESS_NAME'].endswith("\\NTDSDumpEx.exe")) or (record['COMMAND_LINE'].contains("ntds.dit") and record['COMMAND_LINE'].contains("system.hiv")) or record['COMMAND_LINE'].contains("NTDSgrab.ps1")) or (record['COMMAND_LINE'].contains("ac i ntds") and record['COMMAND_LINE'].contains("create full")) or (record['COMMAND_LINE'].contains("/c copy") and record['COMMAND_LINE'].contains("\\windows\\ntds\\ntds.dit")) or (record['COMMAND_LINE'].contains("activate instance ntds") and record['COMMAND_LINE'].contains("create full")) or (record['COMMAND_LINE'].contains("powershell") and record['COMMAND_LINE'].contains("ntds.dit"))) or (record['COMMAND_LINE'].contains("ntds.dit") and ((record['PARENT_NAME'].contains("\\apache") or record['PARENT_NAME'].contains("\\tomcat") or record['PARENT_NAME'].contains("\\AppData") or record['PARENT_NAME'].contains("\\Temp") or record['PARENT_NAME'].contains("\\Public") or record['PARENT_NAME'].contains("\\PerfLogs")) or (record['PROCESS_NAME'].contains("\\apache") or record['PROCESS_NAME'].contains("\\tomcat") or record['PROCESS_NAME'].contains("\\AppData") or record['PROCESS_NAME'].contains("\\Temp") or record['PROCESS_NAME'].contains("\\Public") or record['PROCESS_NAME'].contains("\\PerfLogs")))))

sigma_suspicious_process_patterns_ntds_dit_exfil.sigma_meta = dict(
    level="high"
)

def sigma_powershell_web_download(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_download_cradles.yml
    title: PowerShell Web Download
    fields: ['CommandLine']
    level: medium
    description: Detects suspicious ways to download files or content using PowerShell
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains(".DownloadString(") or record['COMMAND_LINE'].contains(".DownloadFile("))

sigma_powershell_web_download.sigma_meta = dict(
    level="medium"
)

def sigma_netsh_program_allowed_with_suspcious_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_fw_add_susp_image.yml
    title: Netsh Program Allowed with Suspcious Location
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects Netsh commands that allows a suspcious application location on Windows Firewall
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("allowedprogram")) or (record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("advfirewall") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("rule") and record['COMMAND_LINE'].contains("action=allow") and record['COMMAND_LINE'].contains("program="))) and ((record['COMMAND_LINE'].contains("%TEMP%") or record['COMMAND_LINE'].contains("%TMP%") or record['COMMAND_LINE'].contains(":\\RECYCLER") or record['COMMAND_LINE'].contains("C:\\$Recycle.bin") or record['COMMAND_LINE'].contains(":\\SystemVolumeInformation") or record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("C:\\Temp") or record['COMMAND_LINE'].contains("C:\\Users\\Public") or record['COMMAND_LINE'].contains("C:\\Users\\Default") or record['COMMAND_LINE'].contains("C:\\Users\\Desktop") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Temporary Internet Files\\Content.Outlook") or record['COMMAND_LINE'].contains("\\Local Settings\\Temporary Internet Files")) or (record['COMMAND_LINE'].startswith("C:\\Windows\\Tasks") or record['COMMAND_LINE'].startswith("C:\\Windows\\debug") or record['COMMAND_LINE'].startswith("C:\\Windows\\fonts") or record['COMMAND_LINE'].startswith("C:\\Windows\\help") or record['COMMAND_LINE'].startswith("C:\\Windows\\drivers") or record['COMMAND_LINE'].startswith("C:\\Windows\\addins") or record['COMMAND_LINE'].startswith("C:\\Windows\\cursors") or record['COMMAND_LINE'].startswith("C:\\Windows\\system32\\tasks") or record['COMMAND_LINE'].startswith("%Public%"))))

sigma_netsh_program_allowed_with_suspcious_location.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_service_binary_directory(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_service_dir.yml
    title: Suspicious Service Binary Directory
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a service binary running in a suspicious directory
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\Users\\Public") or record['PROCESS_NAME'].contains("\\$Recycle.bin") or record['PROCESS_NAME'].contains("\\Users\\All Users") or record['PROCESS_NAME'].contains("\\Users\\Default") or record['PROCESS_NAME'].contains("\\Users\\Contacts") or record['PROCESS_NAME'].contains("\\Users\\Searches") or record['PROCESS_NAME'].contains("C:\\Perflogs") or record['PROCESS_NAME'].contains("\\config\\systemprofile") or record['PROCESS_NAME'].contains("\\Windows\\Fonts") or record['PROCESS_NAME'].contains("\\Windows\\IME") or record['PROCESS_NAME'].contains("\\Windows\\addins")) and (record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\svchost.exe")))

sigma_suspicious_service_binary_directory.sigma_meta = dict(
    level="high"
)

def sigma_run_powershell_script_from_ads(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_run_powershell_script_from_ads.yml
    title: Run PowerShell Script from ADS
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects PowerShell script execution from Alternate Data Stream (ADS)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe")) and (record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("Get-Content") and record['COMMAND_LINE'].contains("-Stream"))

sigma_run_powershell_script_from_ads.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_wmi_reconnaissance(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_reconnaissance.yml
    title: Suspicious WMI Reconnaissance
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: An adversary might use WMI to list Processes running on the compromised host or list installed Software hotfix and patches.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['ORIGINAL_FILE_NAME'] == "wmic.exe") and (record['COMMAND_LINE'].contains("process") or record['COMMAND_LINE'].contains("qfe"))) and not (record['COMMAND_LINE'].contains("call") and record['COMMAND_LINE'].contains("create")))

sigma_suspicious_wmi_reconnaissance.sigma_meta = dict(
    level="medium"
)

def sigma_credential_acquisition_via_registry_hive_dumping(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_credential_acquisition_registry_hive_dumping.yml
    title: Credential Acquisition via Registry Hive Dumping
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects Credential Acquisition via Registry Hive Dumping
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and (record['COMMAND_LINE'].contains("save") or record['COMMAND_LINE'].contains("export")) and (record['COMMAND_LINE'].contains("hklm\\sam") or record['COMMAND_LINE'].contains("hklm\\security") or record['COMMAND_LINE'].contains("HKEY_LOCAL_MACHINE\\SAM") or record['COMMAND_LINE'].contains("HKEY_LOCAL_MACHINE\\SECURITY")))

sigma_credential_acquisition_via_registry_hive_dumping.sigma_meta = dict(
    level="high"
)

def sigma_application_whitelisting_bypass_via_bginfo(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_bginfo.yml
    title: Application Whitelisting Bypass via Bginfo
    fields: ['CommandLine', 'Image']
    level: medium
    description: Execute VBscript code that is referenced within the *.bgi file.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\bginfo.exe") and record['COMMAND_LINE'].contains("/popup") and record['COMMAND_LINE'].contains("/nolicprompt"))

sigma_application_whitelisting_bypass_via_bginfo.sigma_meta = dict(
    level="medium"
)

def sigma_audio_capture_via_soundrecorder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_soundrec_audio_capture.yml
    title: Audio Capture via SoundRecorder
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detect attacker collecting audio via SoundRecorder application.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SoundRecorder.exe") and record['COMMAND_LINE'].contains("/FILE"))

sigma_audio_capture_via_soundrecorder.sigma_meta = dict(
    level="medium"
)

def sigma_lazarus_activity_apr21(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_lazarus_activity_apr21.yml
    title: Lazarus Activity Apr21
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects different process creation events as described in Malwarebytes's threat report on Lazarus group activity
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("mshta") and record['COMMAND_LINE'].contains(".zip")) or (record['PARENT_NAME'] == "C:\\Windows\\System32\\wbem\\wmiprvse.exe" and record['PROCESS_NAME'] == "C:\\Windows\\System32\\mshta.exe") or (record['PARENT_NAME'].contains(":\\Users\\Public") and record['PROCESS_NAME'] == "C:\\Windows\\System32\\rundll32.exe"))

sigma_lazarus_activity_apr21.sigma_meta = dict(
    level="high"
)

def sigma_curl_start_combination(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_curl_start_combo.yml
    title: Curl Start Combination
    fields: ['CommandLine']
    level: high
    description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("curl") and record['COMMAND_LINE'].contains("http") and record['COMMAND_LINE'].contains("-o") and record['COMMAND_LINE'].contains("&"))

sigma_curl_start_combination.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rundll32_activity_invoking_sys_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_sys.yml
    title: Suspicious Rundll32 Activity Invoking Sys File
    fields: ['CommandLine']
    level: high
    description: Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32.exe") and (record['COMMAND_LINE'].contains(".sys,") or record['COMMAND_LINE'].contains(".sys")))

sigma_suspicious_rundll32_activity_invoking_sys_file.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_redirection_to_local_admin_share(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_redirect_local_admin_share.yml
    title: Suspicious Redirection to Local Admin Share
    fields: ['CommandLine']
    level: high
    description: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains(">") and (record['_raw'].contains("\\\\\\\\127.0.0.1\\\\admin$") or record['_raw'].contains("\\\\\\\\localhost\\\\admin$")))

sigma_suspicious_redirection_to_local_admin_share.sigma_meta = dict(
    level="high"
)

def sigma_purplesharp_indicator(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_purplesharp_indicators.yml
    title: PurpleSharp Indicator
    fields: ['CommandLine', 'OriginalFileName']
    level: critical
    description: Detects the execution of the PurpleSharp adversary simulation tool
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("xyz123456.exe") or record['COMMAND_LINE'].contains("PurpleSharp")) or record['ORIGINAL_FILE_NAME'] == "PurpleSharp.exe")

sigma_purplesharp_indicator.sigma_meta = dict(
    level="critical"
)

def sigma_nps_tunneling_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_nps.yml
    title: NPS Tunneling Tool
    fields: ['CommandLine', 'Image', 'md5', 'Hashes', 'sha1', 'sha256']
    level: high
    description: Detects the use of NPS a port forwarding tool
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\npc.exe") or (record['COMMAND_LINE'].contains("-server=") and record['COMMAND_LINE'].contains("-vkey=") and record['COMMAND_LINE'].contains("-password=")) or record['COMMAND_LINE'].contains("-config=npc") or ((record['HASHES'].contains("MD5=AE8ACF66BFE3A44148964048B826D005") or record['HASHES'].contains("SHA1=CEA49E9B9B67F3A13AD0BE1C2655293EA3C18181") or record['HASHES'].contains("SHA256=5A456283392FFCEEEACA3D3426C306EB470304637520D72FED1CC1FEBBBD6856")) or record['MD5'] == "ae8acf66bfe3a44148964048b826d005" or record['SHA1'] == "cea49e9b9b67f3a13ad0be1c2655293ea3c18181" or record['SHA256'] == "5a456283392ffceeeaca3d3426c306eb470304637520d72fed1cc1febbbd6856"))

sigma_nps_tunneling_tool.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_windows_update_agent_empty_cmdline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wuauclt_cmdline.yml
    title: Suspicious Windows Update Agent Empty Cmdline
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\Wuauclt.exe") or record['ORIGINAL_FILE_NAME'] == "Wuauclt.exe") and record['COMMAND_LINE'].endswith("\\Wuauclt.exe"))

sigma_suspicious_windows_update_agent_empty_cmdline.sigma_meta = dict(
    level="high"
)

def sigma_enumeration_for_3rd_party_creds_from_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_enumeration_for_credentials_cli.yml
    title: Enumeration for 3rd Party Creds From CLI
    fields: ['CommandLine']
    level: medium
    description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\Software\\SimonTatham\\PuTTY\\Sessions") or record['COMMAND_LINE'].contains("\\Software\\\\SimonTatham\\PuTTY\\SshHostKeys") or record['COMMAND_LINE'].contains("\\Software\\Mobatek\\MobaXterm") or record['COMMAND_LINE'].contains("\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin") or record['COMMAND_LINE'].contains("\\Software\\Aerofox\\FoxmailPreview") or record['COMMAND_LINE'].contains("\\Software\\Aerofox\\Foxmail\\V3.1") or record['COMMAND_LINE'].contains("\\Software\\IncrediMail\\Identities") or record['COMMAND_LINE'].contains("\\Software\\Qualcomm\\Eudora\\CommandLine") or record['COMMAND_LINE'].contains("\\Software\\RimArts\\B2\\Settings") or record['COMMAND_LINE'].contains("\\Software\\OpenVPN-GUI\\configs") or record['COMMAND_LINE'].contains("\\Software\\Martin Prikryl\\WinSCP 2\\Sessions") or record['COMMAND_LINE'].contains("\\Software\\FTPWare\\COREFTP\\Sites") or record['COMMAND_LINE'].contains("\\Software\\DownloadManager\\Passwords") or record['COMMAND_LINE'].contains("\\Software\\OpenSSH\\Agent\\Keys") or record['COMMAND_LINE'].contains("\\Software\\TightVNC\\Server") or record['COMMAND_LINE'].contains("\\Software\\ORL\\WinVNC3\\Password") or record['COMMAND_LINE'].contains("\\Software\\RealVNC\\WinVNC4"))

sigma_enumeration_for_3rd_party_creds_from_cli.sigma_meta = dict(
    level="medium"
)

def sigma_execution_of_remote_utilities_rat_rurat_from_unusual_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rurat_exec_location.yml
    title: Execution of Remote Utilities RAT (RURAT) From Unusual Location
    fields: ['Image', 'Product']
    level: medium
    description: Detects execution of Remote Utilities RAT (RURAT) from an unsual location (outisde of 'C:\Program Files')
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\rutserv.exe") or record['PROCESS_NAME'].endswith("\\rfusclient.exe")) or record['PRODUCT_NAME'] == "Remote Utilities") and not ((record['PROCESS_NAME'].startswith("C:\\Program Files\\Remote Utilities") or record['PROCESS_NAME'].startswith("C:\\Program Files (x86)\\Remote Utilities"))))

sigma_execution_of_remote_utilities_rat_rurat_from_unusual_location.sigma_meta = dict(
    level="medium"
)

def sigma_wmic_hotfix_recon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmic_hotfix_enum.yml
    title: WMIC Hotfix Recon
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects wmic known recon method to look for installed hotfixes, often used by pentest and attackers enum scripts
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['PROCESS_NAME'].endswith("\\WMIC.exe")) and (record['COMMAND_LINE'].contains("qfe") and record['COMMAND_LINE'].contains("get") and record['COMMAND_LINE'].contains("Caption,Description,HotFixID,InstalledOn")))

sigma_wmic_hotfix_recon.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_xor_encoded_powershell_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_xor_commandline.yml
    title: Suspicious XOR Encoded PowerShell Command Line
    fields: ['CommandLine', 'Product', 'ParentImage', 'Description']
    level: medium
    description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
    logsource: category:process_creation - product:windows
    """
    return (((record['DESCRIPTION'] == "Windows PowerShell" or record['PRODUCT_NAME'] == "PowerShell Core 6") and (record['COMMAND_LINE'].contains("bxor") or record['COMMAND_LINE'].contains("-join") or record['COMMAND_LINE'].contains("-join\'") or record['COMMAND_LINE'].contains("-join\"") or record['COMMAND_LINE'].contains("-join`") or record['COMMAND_LINE'].contains("char"))) and not (record['PARENT_NAME'] == "C:\\Program Files\\Amazon\\SSM\\ssm-document-worker.exe"))

sigma_suspicious_xor_encoded_powershell_command_line.sigma_meta = dict(
    level="medium"
)

def sigma_office_directory_traversal_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_dir_traversal_cli.yml
    title: Office Directory Traversal CommandLine
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects Office Applications executing a Windows child process including directory traversal patterns
    logsource: product:windows - category:process_creation
    """
    return ((record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe") or record['PARENT_NAME'].endswith("\\msaccess.exe") or record['PARENT_NAME'].endswith("\\mspub.exe") or record['PARENT_NAME'].endswith("\\eqnedt32.exe") or record['PARENT_NAME'].endswith("\\visio.exe")) and (record['PROCESS_NAME'].contains("\\Windows\\System32") or record['PROCESS_NAME'].contains("\\Windows\\SysWOW64")) and (record['COMMAND_LINE'] == "../../../.." or record['COMMAND_LINE'] == "..\\..\\..\\.." or record['COMMAND_LINE'] == "..//..//..//.."))

sigma_office_directory_traversal_commandline.sigma_meta = dict(
    level="high"
)

def sigma_powershell_sam_copy(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_sam_access.yml
    title: PowerShell SAM Copy
    fields: ['CommandLine']
    level: high
    description: Detects suspicious PowerShell scripts accessing SAM hives
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\HarddiskVolumeShadowCopy") and record['COMMAND_LINE'].contains("ystem32\\config\\sam") and (record['COMMAND_LINE'].contains("Copy-Item") or record['COMMAND_LINE'].contains("cp $_.") or record['COMMAND_LINE'].contains("cpi $_.") or record['COMMAND_LINE'].contains("copy $_.") or record['COMMAND_LINE'].contains(".File]::Copy(")))

sigma_powershell_sam_copy.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_control_panel_dll_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_control_dll_load.yml
    title: Suspicious Control Panel DLL Load
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\System32\\control.exe") and record['PROCESS_NAME'].endswith("\\rundll32.exe")) and not (record['COMMAND_LINE'].contains("Shell32.dll")))

sigma_suspicious_control_panel_dll_load.sigma_meta = dict(
    level="high"
)

def sigma_potential_remote_desktop_tunneling(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_remote_desktop_tunneling.yml
    title: Potential Remote Desktop Tunneling
    fields: ['CommandLine']
    level: medium
    description: Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains(":3389") and (record['COMMAND_LINE'].contains("-L") or record['COMMAND_LINE'].contains("-P") or record['COMMAND_LINE'].contains("-R") or record['COMMAND_LINE'].contains("-pw") or record['COMMAND_LINE'].contains("-ssh")))

sigma_potential_remote_desktop_tunneling.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_diantz_download_and_compress_into_a_cab_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.yml
    title: Suspicious Diantz Download and Compress Into a CAB File
    fields: ['CommandLine']
    level: medium
    description: Download and compress a remote file and store it in a cab file on local machine.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("diantz.exe") and record['COMMAND_LINE'].contains("") and record['COMMAND_LINE'].contains(".cab"))

sigma_suspicious_diantz_download_and_compress_into_a_cab_file.sigma_meta = dict(
    level="medium"
)

def sigma_psr_exe_capture_screenshots(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psr_capture_screenshots.yml
    title: Psr.exe Capture Screenshots
    fields: ['CommandLine', 'Image']
    level: medium
    description: The psr.exe captures desktop screenshots and saves them on the local machine
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Psr.exe") and record['COMMAND_LINE'].contains("/start"))

sigma_psr_exe_capture_screenshots.sigma_meta = dict(
    level="medium"
)

def sigma_run_whoami_as_system(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_whoami_as_system.yml
    title: Run Whoami as SYSTEM
    fields: ['User', 'Image', 'OriginalFileName']
    level: high
    description: Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.
    logsource: category:process_creation - product:windows
    """
    return ((record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")) and (record['ORIGINAL_FILE_NAME'] == "whoami.exe" or record['PROCESS_NAME'].endswith("\\whoami.exe")))

sigma_run_whoami_as_system.sigma_meta = dict(
    level="high"
)

def sigma_ryuk_ransomware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_ryuk.yml
    title: Ryuk Ransomware
    fields: ['CommandLine']
    level: high
    description: Detects Ryuk ransomware activity
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Microsoft\\Windows\\CurrentVersion\\Run") and record['COMMAND_LINE'].contains("C:\\users\\Public"))

sigma_ryuk_ransomware.sigma_meta = dict(
    level="high"
)

def sigma_excel_proxy_executing_regsvr32_with_payload_alternate(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_from_proxy_executing_regsvr32_payload2.yml
    title: Excel Proxy Executing Regsvr32 With Payload Alternate
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Excel called wmic to finally proxy execute regsvr32 with the payload.
An attacker wanted to break suspicious parent-child chain (Office app spawns LOLBin).
But we have command-line in the event which allow us to "restore" this suspicious parent-child chain and detect it.
Monitor process creation with "wmic process call create" and LOLBins in command-line with parent Office application processes.

    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("regsvr32") or record['COMMAND_LINE'].contains("rundll32") or record['COMMAND_LINE'].contains("msiexec") or record['COMMAND_LINE'].contains("mshta") or record['COMMAND_LINE'].contains("verclsid")) and (record['PROCESS_NAME'].endswith("\\wbem\\WMIC.exe") or record['COMMAND_LINE'].contains("wmic")) and (record['PARENT_NAME'].endswith("\\winword.exe") or record['PARENT_NAME'].endswith("\\excel.exe") or record['PARENT_NAME'].endswith("\\powerpnt.exe")) and (record['COMMAND_LINE'].contains("process") and record['COMMAND_LINE'].contains("create") and record['COMMAND_LINE'].contains("call")))

sigma_excel_proxy_executing_regsvr32_with_payload_alternate.sigma_meta = dict(
    level="high"
)

def sigma_sticky_key_like_backdoor_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_stickykey_like_backdoor.yml
    title: Sticky Key Like Backdoor Usage
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: critical
    description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\winlogon.exe") and record['PROCESS_NAME'].endswith("\\cmd.exe") and (record['COMMAND_LINE'].contains("sethc.exe") or record['COMMAND_LINE'].contains("utilman.exe") or record['COMMAND_LINE'].contains("osk.exe") or record['COMMAND_LINE'].contains("Magnify.exe") or record['COMMAND_LINE'].contains("Narrator.exe") or record['COMMAND_LINE'].contains("DisplaySwitch.exe")))

sigma_sticky_key_like_backdoor_usage.sigma_meta = dict(
    level="critical"
)

def sigma_overwrite_deleted_data_with_cipher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_cipher.yml
    title: Overwrite Deleted Data with Cipher
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cipher.exe") and record['COMMAND_LINE'].contains("/w:"))

sigma_overwrite_deleted_data_with_cipher.sigma_meta = dict(
    level="medium"
)

def sigma_windows_firewall_disabled_via_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_firewall_disabled_via_powershell.yml
    title: Windows Firewall Disabled via PowerShell
    fields: ['CommandLine', 'OriginalFilename', 'Image']
    level: medium
    description: Detects attempts to disable the Windows Firewall using PowerShell
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\powershell_ise.exe")) or record['ORIGINAL_FILENAME'] == "PowerShell.EXE") and (record['COMMAND_LINE'].contains("Set-NetFirewallProfile") and record['COMMAND_LINE'].contains("-Enabled") and record['COMMAND_LINE'].contains("False")) and (record['COMMAND_LINE'].contains("-All") or record['COMMAND_LINE'].contains("Public") or record['COMMAND_LINE'].contains("Domain") or record['COMMAND_LINE'].contains("Private")))

sigma_windows_firewall_disabled_via_powershell.sigma_meta = dict(
    level="medium"
)

def sigma_nsudo_tool_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tool_nsudo_execution.yml
    title: NSudo Tool Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects the use of NSudo tool for command execution
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\NSudo.exe") or record['PROCESS_NAME'].endswith("\\NSudoLC.exe") or record['PROCESS_NAME'].endswith("\\NSudoLG.exe")) or (record['ORIGINAL_FILE_NAME'] == "NSudo.exe" or record['ORIGINAL_FILE_NAME'] == "NSudoLC.exe" or record['ORIGINAL_FILE_NAME'] == "NSudoLG.exe")) and (record['COMMAND_LINE'].contains("-U:S") or record['COMMAND_LINE'].contains("-U:T") or record['COMMAND_LINE'].contains("-U:E") or record['COMMAND_LINE'].contains("-P:E") or record['COMMAND_LINE'].contains("-M:S") or record['COMMAND_LINE'].contains("-M:H") or record['COMMAND_LINE'].contains("-U=S") or record['COMMAND_LINE'].contains("-U=T") or record['COMMAND_LINE'].contains("-U=E") or record['COMMAND_LINE'].contains("-P=E") or record['COMMAND_LINE'].contains("-M=S") or record['COMMAND_LINE'].contains("-M=H") or record['COMMAND_LINE'].contains("-ShowWindowMode:Hide")))

sigma_nsudo_tool_execution.sigma_meta = dict(
    level="high"
)

def sigma_syncappvpublishingserver_vbs_execute_arbitrary_powershell_code(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh.yml
    title: SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
    fields: ['CommandLine']
    level: medium
    description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\SyncAppvPublishingServer.vbs") and record['COMMAND_LINE'].contains(";"))

sigma_syncappvpublishingserver_vbs_execute_arbitrary_powershell_code.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_whoami_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_whoami.yml
    title: Renamed Whoami Execution
    fields: ['Image', 'OriginalFileName']
    level: critical
    description: Detects the execution of whoami that has been renamed to a different name to avoid detection
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "whoami.exe" and not (record['PROCESS_NAME'].endswith("\\whoami.exe")))

sigma_renamed_whoami_execution.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_powershell_invocation_based_on_parent_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_parent_combo.yml
    title: Suspicious PowerShell Invocation Based on Parent Process
    fields: ['Image', 'ParentImage', 'CurrentDirectory']
    level: medium
    description: Detects suspicious powershell invocations from interpreters or unusual programs
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\wscript.exe") or record['PARENT_NAME'].endswith("\\cscript.exe")) and (record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe"))) and not (record['PROCESS_PATH'].contains("\\Health Service State")))

sigma_suspicious_powershell_invocation_based_on_parent_process.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_using_windows_media_player_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_wmp.yml
    title: UAC Bypass Using Windows Media Player - Process
    fields: ['IntegrityLevel', 'Image', 'ParentCommandLine']
    level: high
    description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'] == "C:\\Program Files\\Windows Media Player\\osk.exe" and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System")) or (record['PROCESS_NAME'] == "C:\\Windows\\System32\\cmd.exe" and record['PARENT_COMMAND_LINE'] == "\"C:\\Windows\\system32\\mmc.exe\" \"C:\\Windows\\system32\\eventvwr.msc\" /s" and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System")))

sigma_uac_bypass_using_windows_media_player_process.sigma_meta = dict(
    level="high"
)

def sigma_imports_registry_key_from_a_file_using_reg_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_import_from_suspicious_paths.yml
    title: Imports Registry Key From a File Using Reg.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the import of the '.reg' files from suspicious paths using the 'reg.exe' utility
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("import") and (record['COMMAND_LINE'].contains("C:\\Users") or record['COMMAND_LINE'].contains("%temp%") or record['COMMAND_LINE'].contains("%tmp%") or record['COMMAND_LINE'].contains("%appdata%") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") or record['COMMAND_LINE'].contains("C:\\Windows\\Temp") or record['COMMAND_LINE'].contains("C:\\ProgramData")))

sigma_imports_registry_key_from_a_file_using_reg_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_serv_u_process_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_servu_process_pattern.yml
    title: Suspicious Serv-U Process Pattern
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\Serv-U.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe")))

sigma_suspicious_serv_u_process_pattern.sigma_meta = dict(
    level="high"
)

def sigma_fast_reverse_proxy_frp_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_frp.yml
    title: Fast Reverse Proxy (FRP)
    fields: ['CommandLine', 'Image', 'md5', 'Hashes', 'sha1', 'sha256']
    level: high
    description: Detects the use of Fast Reverse Proxy. frp is a fast reverse proxy to help you expose a local server behind a NAT or firewall to the Internet.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\frpc.exe") or record['PROCESS_NAME'].endswith("\\frps.exe")) or record['COMMAND_LINE'].contains("\\frpc.ini") or (record['HASHES'].contains("MD5=7D9C233B8C9E3F0EA290D2B84593C842") or record['HASHES'].contains("SHA1=06DDC9280E1F1810677935A2477012960905942F") or record['HASHES'].contains("SHA256=57B0936B8D336D8E981C169466A15A5FD21A7D5A2C7DAF62D5E142EE860E387C")) or record['MD5'] == "7d9c233b8c9e3f0ea290d2b84593c842" or record['SHA1'] == "06ddc9280e1f1810677935a2477012960905942f" or record['SHA256'] == "57b0936b8d336d8e981c169466a15a5fd21a7d5a2c7daf62d5e142ee860e387c")

sigma_fast_reverse_proxy_frp_.sigma_meta = dict(
    level="high"
)

def sigma_microsoft_workflow_compiler(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_workflow_compiler.yml
    title: Microsoft Workflow Compiler
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\Microsoft.Workflow.Compiler.exe") or (record['ORIGINAL_FILE_NAME'] == "Microsoft.Workflow.Compiler.exe" and record['COMMAND_LINE'].contains(".xml")))

sigma_microsoft_workflow_compiler.sigma_meta = dict(
    level="high"
)

def sigma_msdt_executed_with_suspicious_parent(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msdt_susp_parent.yml
    title: MSDT Executed with Suspicious Parent
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects msdt.exe executed by a suspicious parent as seen in CVE-2022-30190 / Follina exploitation
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\cmd.exe") or record['PARENT_NAME'].endswith("\\mshta.exe") or record['PARENT_NAME'].endswith("\\cscript.exe") or record['PARENT_NAME'].endswith("\\wscript.exe") or record['PARENT_NAME'].endswith("\\wsl.exe") or record['PARENT_NAME'].endswith("\\rundll32.exe") or record['PARENT_NAME'].endswith("\\regsvr32.exe")) and (record['PROCESS_NAME'].endswith("\\msdt.exe") or record['ORIGINAL_FILE_NAME'] == "msdt.exe"))

sigma_msdt_executed_with_suspicious_parent.sigma_meta = dict(
    level="high"
)

def sigma_powershell_downloadfile(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ps_downloadfile.yml
    title: PowerShell DownloadFile
    fields: ['CommandLine']
    level: high
    description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("powershell") and record['COMMAND_LINE'].contains(".DownloadFile") and record['COMMAND_LINE'].contains("System.Net.WebClient"))

sigma_powershell_downloadfile.sigma_meta = dict(
    level="high"
)

def sigma_net_exe_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_net_execution.yml
    title: Net.exe Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Detects execution of Net.exe, whether suspicious or benign.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) or (record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe")) and (record['COMMAND_LINE'].contains("group") or record['COMMAND_LINE'].contains("localgroup") or record['COMMAND_LINE'].contains("user") or record['COMMAND_LINE'].contains("view") or record['COMMAND_LINE'].contains("share") or record['COMMAND_LINE'].contains("accounts") or record['COMMAND_LINE'].contains("stop") or record['COMMAND_LINE'].contains("start")))

sigma_net_exe_execution.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_7zip_subprocess(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_7zip_cve_2022_29072.yml
    title: Suspicious 7zip Subprocess
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: 7-Zip through 21.07 on Windows allows privilege escalation (CVE-2022-29072) and command execution when a file with the .7z extension is dragged to the Help>Contents area. This is caused by misconfiguration of 7z.dll and a heap overflow. The command runs in a child process under the 7zFM.exe process.
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['ORIGINAL_FILE_NAME'] == "Cmd.Exe") and record['PARENT_NAME'].endswith("\\7zFM.exe")) and not (((record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/k") or record['COMMAND_LINE'].contains("/r"))) or (record.get('COMMAND_LINE', None) == None)))

sigma_suspicious_7zip_subprocess.sigma_meta = dict(
    level="high"
)

def sigma_exchange_exploitation_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_hafnium.yml
    title: Exchange Exploitation Activity
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects activity observed by different researchers to be HAFNIUM group activity (or related) on Exchange servers
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("attrib") and record['COMMAND_LINE'].contains("+h") and record['COMMAND_LINE'].contains("+s") and record['COMMAND_LINE'].contains("+r") and record['COMMAND_LINE'].contains(".aspx")) or (record['COMMAND_LINE'].contains("schtasks") and record['COMMAND_LINE'].contains("VSPerfMon")) or (record['COMMAND_LINE'].contains("vssadmin list shadows") and record['COMMAND_LINE'].contains("Temp\\__output")) or record['COMMAND_LINE'].contains("%TEMP%\\execute.bat") or record['PROCESS_NAME'].endswith("Users\\Public\\opera\\Opera_browser.exe") or (record['PROCESS_NAME'].endswith("Opera_browser.exe") and (record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\svchost.exe"))) or record['PROCESS_NAME'].contains("\\ProgramData\\VSPerfMon") or (record['COMMAND_LINE'].contains("-t7z") and record['COMMAND_LINE'].contains("C:\\Programdata\\pst") and record['COMMAND_LINE'].contains("\\it.zip")) or (record['PROCESS_NAME'].endswith("\\makecab.exe") and (record['COMMAND_LINE'].contains("Microsoft\\Exchange Server") or record['COMMAND_LINE'].contains("inetpub\\wwwroot"))) or (record['COMMAND_LINE'].contains("\\Temp\\xx.bat") or record['COMMAND_LINE'].contains("Windows\\WwanSvcdcs") or record['COMMAND_LINE'].contains("Windows\\Temp\\cw.exe")) or (record['COMMAND_LINE'].contains("\\comsvcs.dll") and record['COMMAND_LINE'].contains("Minidump") and record['COMMAND_LINE'].contains("\\inetpub\\wwwroot")) or (record['COMMAND_LINE'].contains("dsquery") and record['COMMAND_LINE'].contains("-uco") and record['COMMAND_LINE'].contains("\\inetpub\\wwwroot")))

sigma_exchange_exploitation_activity.sigma_meta = dict(
    level="high"
)

def sigma_windows_update_client_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_wuauclt.yml
    title: Windows Update Client LOLBIN
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects code execution via the Windows Update client (wuauclt)
    logsource: product:windows - category:process_creation
    """
    return (((record['COMMAND_LINE'].contains("/UpdateDeploymentProvider") and record['COMMAND_LINE'].contains("/RunHandlerComServer") and record['COMMAND_LINE'].contains(".dll")) and (record['PROCESS_NAME'].endswith("\\wuauclt.exe") or record['ORIGINAL_FILE_NAME'] == "wuauclt.exe")) and not ((record['COMMAND_LINE'].contains("/ClassId") or record['COMMAND_LINE'].contains("wuaueng.dll"))))

sigma_windows_update_client_lolbin.sigma_meta = dict(
    level="high"
)

def sigma_use_icacls_to_hide_file_to_everyone(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_icacls_deny.yml
    title: Use Icacls to Hide File to Everyone
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detect use of icacls to deny access for everyone in Users folder sometimes used to hide malicious files
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "iCACLS.EXE" or record['PROCESS_NAME'].endswith("\\icacls.exe")) and (record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("/deny") and record['COMMAND_LINE'].contains("S-1-1-0:")))

sigma_use_icacls_to_hide_file_to_everyone.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_registration_via_cscript_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_registration_via_cscript.yml
    title: Suspicious Registration via cscript.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects when the registration of a VSS/VDS Provider as a COM+ application.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cscript.exe") and record['COMMAND_LINE'].contains("-register") and (record['COMMAND_LINE'].contains("\\Windows Kits\\10\\bin\\10.0.22000.0\\x64") or record['COMMAND_LINE'].contains("\\Windows Kits\\10\\bin\\10.0.19041.0\\x64") or record['COMMAND_LINE'].contains("\\Windows Kits\\10\\bin\\10.0.17763.0\\x64")))

sigma_suspicious_registration_via_cscript_exe.sigma_meta = dict(
    level="medium"
)

def sigma_svchost_spawning_office_application(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_office_svchost_child.yml
    title: Svchost Spawning Office Application
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects svchost process spawning an instance of an office application. This happens when the initial word application create an instance of one of the office COM objects such as 'Word.Application', 'Excel.Application'...etc. This can be used by malicious actor to create a malicious office document with macros on the fly. (See vba2clr project in reference)
    logsource: product:windows - category:process_creation
    """
    return (record['PARENT_NAME'].endswith("\\svchost.exe") and (record['PROCESS_NAME'].endswith("\\winword.exe") or record['PROCESS_NAME'].endswith("\\excel.exe") or record['PROCESS_NAME'].endswith("\\powerpnt.exe") or record['PROCESS_NAME'].endswith("\\msaccess.exe") or record['PROCESS_NAME'].endswith("\\mspub.exe") or record['PROCESS_NAME'].endswith("\\eqnedt32.exe") or record['PROCESS_NAME'].endswith("\\visio.exe")))

sigma_svchost_spawning_office_application.sigma_meta = dict(
    level="medium"
)

def sigma_html_help_shell_spawn(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_html_help_spawn.yml
    title: HTML Help Shell Spawn
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'] == "C:\\Windows\\hh.exe" or record['PARENT_NAME'] == "C:\\Windows\\SysWOW64\\hh.exe") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\MSHTA.EXE") or record['PROCESS_NAME'].endswith("\\CertUtil.exe") or record['PROCESS_NAME'].endswith("\\CertReq.exe") or record['PROCESS_NAME'].endswith("\\MSbuild.exe") or record['PROCESS_NAME'].endswith("\\installutil.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe"))) or ((record['PROCESS_NAME'].endswith("\\Windows\\hh.exe") or record['PROCESS_NAME'].endswith("\\Windows\\SysWOW64\\hh.exe")) and (record['COMMAND_LINE'].contains(".application") or record['COMMAND_LINE'].contains("\\Downloads") or record['COMMAND_LINE'].contains("\\Content.Outlook") or record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp"))))

sigma_html_help_shell_spawn.sigma_meta = dict(
    level="high"
)

def sigma_delete_important_scheduled_task(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtasks_delete.yml
    title: Delete Important Scheduled Task
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects when adversaries stop services or processes by disabling their respective schdueled tasks in order to conduct data destructive activities
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/delete") and record['COMMAND_LINE'].contains("/tn") and (record['COMMAND_LINE'].contains("\\Windows\\SystemRestore\\SR") or record['COMMAND_LINE'].contains("\\Windows\\Windows Defender") or record['COMMAND_LINE'].contains("\\Windows\\BitLocker") or record['COMMAND_LINE'].contains("\\Windows\\WindowsBackup") or record['COMMAND_LINE'].contains("\\Windows\\WindowsUpdate") or record['COMMAND_LINE'].contains("\\Windows\\UpdateOrchestrator") or record['COMMAND_LINE'].contains("\\Windows\\ExploitGuard")))

sigma_delete_important_scheduled_task.sigma_meta = dict(
    level="high"
)

def sigma_atlassian_confluence_cve_2021_26084(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_atlassian_confluence_cve_2021_26084_exploit.yml
    title: Atlassian Confluence CVE-2021-26084
    fields: ['CommandLine', 'ParentImage']
    level: high
    description: Detects spawning of suspicious child processes by Atlassian Confluence server which may indicate successful exploitation of CVE-2021-26084
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\Atlassian\\Confluence\\jre\\bin\\java.exe") and (record['COMMAND_LINE'].contains("cmd /c") or record['COMMAND_LINE'].contains("cmd /k") or record['COMMAND_LINE'].contains("powershell") or record['COMMAND_LINE'].contains("certutil") or record['COMMAND_LINE'].contains("curl") or record['COMMAND_LINE'].contains("whoami") or record['COMMAND_LINE'].contains("ipconfig")))

sigma_atlassian_confluence_cve_2021_26084.sigma_meta = dict(
    level="high"
)

def sigma_download_arbitrary_files_via_presentationhost_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_presentationhost_download.yml
    title: Download Arbitrary Files Via PresentationHost.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\presentationhost.exe") or record['ORIGINAL_FILE_NAME'] == "PresentationHost.exe") and (record['COMMAND_LINE'].contains("http://") or record['COMMAND_LINE'].contains("https://") or record['COMMAND_LINE'].contains("ftp://")))

sigma_download_arbitrary_files_via_presentationhost_exe.sigma_meta = dict(
    level="medium"
)

def sigma_fsutil_behavior_set_symlinkevaluation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_fsutil_symlinkevaluation.yml
    title: Fsutil Behavior Set SymlinkEvaluation
    fields: ['CommandLine', 'Image']
    level: medium
    description: A symbolic link is a type of file that contains a reference to another file.
This is probably done to make sure that the ransomware is able to follow shortcuts on the machine in order to find the original file to encrypt

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\fsutil.exe") and record['COMMAND_LINE'].contains("behavior") and record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("SymlinkEvaluation"))

sigma_fsutil_behavior_set_symlinkevaluation.sigma_meta = dict(
    level="medium"
)

def sigma_invocation_of_active_directory_diagnostic_tool_ntdsutil_exe_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ntdsutil_usage.yml
    title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
    fields: ['Image']
    level: medium
    description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].endswith("\\ntdsutil.exe")

sigma_invocation_of_active_directory_diagnostic_tool_ntdsutil_exe_.sigma_meta = dict(
    level="medium"
)

def sigma_uac_bypass_using_dismhost(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_dismhost.yml
    title: UAC Bypass Using DismHost
    fields: ['IntegrityLevel', 'ParentImage']
    level: high
    description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].contains("C:\\Users") and record['PARENT_NAME'].contains("\\AppData\\Local\\Temp") and record['PARENT_NAME'].contains("\\DismHost.exe") and (record['INTEGRITY_LEVEL'] == "High" or record['INTEGRITY_LEVEL'] == "System"))

sigma_uac_bypass_using_dismhost.sigma_meta = dict(
    level="high"
)

def sigma_exploiting_setupcomplete_cmd_cve_2019_1378(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2019_1378.yml
    title: Exploiting SetupComplete.cmd CVE-2019-1378
    fields: ['Image', 'ParentCommandLine']
    level: high
    description: Detects exploitation attempt of privilege escalation vulnerability via SetupComplete.cmd and PartnerSetupComplete.cmd described in CVE-2019-1378
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_COMMAND_LINE'].contains("\\cmd.exe") and record['PARENT_COMMAND_LINE'].contains("/c") and record['PARENT_COMMAND_LINE'].contains("C:\\Windows\\Setup\\Scripts") and (record['PARENT_COMMAND_LINE'].endswith("SetupComplete.cmd") or record['PARENT_COMMAND_LINE'].endswith("PartnerSetupComplete.cmd"))) and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64") or record['PROCESS_NAME'].startswith("C:\\Windows\\WinSxS") or record['PROCESS_NAME'].startswith("C:\\Windows\\Setup"))))

sigma_exploiting_setupcomplete_cmd_cve_2019_1378.sigma_meta = dict(
    level="high"
)

def sigma_execution_of_renamed_netsupport_rat(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_netsupport_rat.yml
    title: Execution of Renamed NetSupport RAT
    fields: ['Image', 'Hashes', 'OriginalFileName', 'Product', 'Imphash']
    level: high
    description: Detects execution of renamed client32.exe (NetSupport RAT) via Imphash, Product and OriginalFileName strings
    logsource: category:process_creation - product:windows
    """
    return ((record['PRODUCT_NAME'].contains("NetSupport Remote Control") or record['ORIGINAL_FILE_NAME'].contains("client32.exe") or record['IMPHASH'] == "a9d50692e95b79723f3e76fcf70d023e" or record['HASHES'].contains("IMPHASH=A9D50692E95B79723F3E76FCF70D023E")) and not (record['PROCESS_NAME'].endswith("\\client32.exe")))

sigma_execution_of_renamed_netsupport_rat.sigma_meta = dict(
    level="high"
)

def sigma_modify_group_policy_settings(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_modify_group_policy_settings.yml
    title: Modify Group Policy Settings
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and record['COMMAND_LINE'].contains("\\SOFTWARE\\Policies\\Microsoft\\Windows\\System") and (record['COMMAND_LINE'].contains("GroupPolicyRefreshTimeDC") or record['COMMAND_LINE'].contains("GroupPolicyRefreshTimeOffsetDC") or record['COMMAND_LINE'].contains("GroupPolicyRefreshTime") or record['COMMAND_LINE'].contains("GroupPolicyRefreshTimeOffset") or record['COMMAND_LINE'].contains("EnableSmartScreen") or record['COMMAND_LINE'].contains("ShellSmartScreenLevel")))

sigma_modify_group_policy_settings.sigma_meta = dict(
    level="medium"
)

def sigma_writing_of_malicious_files_to_the_fonts_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hiding_malware_in_fonts_folder.yml
    title: Writing Of Malicious Files To The Fonts Folder
    fields: ['CommandLine']
    level: medium
    description: Monitors for the hiding possible malicious files in the C:\Windows\Fonts\ location. This folder doesn't require admin privillege to be written and executed from.
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("echo") or record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("type") or record['COMMAND_LINE'].contains("file createnew") or record['COMMAND_LINE'].contains("cacls")) and record['COMMAND_LINE'].contains("C:\\Windows\\Fonts") and (record['COMMAND_LINE'].contains(".sh") or record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bin") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cmd") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".msh") or record['COMMAND_LINE'].contains(".reg") or record['COMMAND_LINE'].contains(".scr") or record['COMMAND_LINE'].contains(".ps") or record['COMMAND_LINE'].contains(".vb") or record['COMMAND_LINE'].contains(".jar") or record['COMMAND_LINE'].contains(".pl") or record['COMMAND_LINE'].contains(".inf") or record['COMMAND_LINE'].contains(".cpl") or record['COMMAND_LINE'].contains(".hta") or record['COMMAND_LINE'].contains(".msi") or record['COMMAND_LINE'].contains(".vbs")))

sigma_writing_of_malicious_files_to_the_fonts_folder.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ssh_port_forwarding(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ssh_port_forward.yml
    title: Suspicious SSH Port Forwarding
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious SSH tunnel port forwarding to a local port
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\ssh.exe") and record['COMMAND_LINE'].contains("-R"))

sigma_suspicious_ssh_port_forwarding.sigma_meta = dict(
    level="high"
)

def sigma_modification_of_existing_services_for_persistence(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_modif_of_services_for_via_commandline.yml
    title: Modification Of Existing Services For Persistence
    fields: ['CommandLine']
    level: medium
    description: Detects modification of an existing service on a compromised host in order to execute an arbitrary payload when the service is started or killed as a method of persistence.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("sc") and record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("binpath=")) or (record['COMMAND_LINE'].contains("sc") and record['COMMAND_LINE'].contains("failure") and record['COMMAND_LINE'].contains("command=")) or (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("FailureCommand") and (record['COMMAND_LINE'].contains(".sh") or record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bin$") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cmd") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".msh$") or record['COMMAND_LINE'].contains(".reg$") or record['COMMAND_LINE'].contains(".scr") or record['COMMAND_LINE'].contains(".ps") or record['COMMAND_LINE'].contains(".vb") or record['COMMAND_LINE'].contains(".jar") or record['COMMAND_LINE'].contains(".pl"))) or (record['COMMAND_LINE'].contains("reg") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("ImagePath") and (record['COMMAND_LINE'].contains(".sh") or record['COMMAND_LINE'].contains(".exe") or record['COMMAND_LINE'].contains(".dll") or record['COMMAND_LINE'].contains(".bin$") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cmd") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".msh$") or record['COMMAND_LINE'].contains(".reg$") or record['COMMAND_LINE'].contains(".scr") or record['COMMAND_LINE'].contains(".ps") or record['COMMAND_LINE'].contains(".vb") or record['COMMAND_LINE'].contains(".jar") or record['COMMAND_LINE'].contains(".pl"))))

sigma_modification_of_existing_services_for_persistence.sigma_meta = dict(
    level="medium"
)

def sigma_wannacry_ransomware(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_wannacry.yml
    title: WannaCry Ransomware
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects WannaCry ransomware activity
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\tasksche.exe") or record['PROCESS_NAME'].endswith("\\mssecsvc.exe") or record['PROCESS_NAME'].endswith("\\taskdl.exe") or record['PROCESS_NAME'].endswith("\\taskhsvc.exe") or record['PROCESS_NAME'].endswith("\\taskse.exe") or record['PROCESS_NAME'].endswith("\\111.exe") or record['PROCESS_NAME'].endswith("\\lhdfrgui.exe") or record['PROCESS_NAME'].endswith("\\linuxnew.exe") or record['PROCESS_NAME'].endswith("\\wannacry.exe")) or record['PROCESS_NAME'].contains("WanaDecryptor") or (record['COMMAND_LINE'].contains("icacls") and record['COMMAND_LINE'].contains("/grant") and record['COMMAND_LINE'].contains("Everyone:F") and record['COMMAND_LINE'].contains("/T") and record['COMMAND_LINE'].contains("/C") and record['COMMAND_LINE'].contains("/Q")) or (record['COMMAND_LINE'].contains("bcdedit") and record['COMMAND_LINE'].contains("/set") and record['COMMAND_LINE'].contains("{default}") and record['COMMAND_LINE'].contains("recoveryenabled") and record['COMMAND_LINE'].contains("no")) or (record['COMMAND_LINE'].contains("wbadmin") and record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("catalog") and record['COMMAND_LINE'].contains("-quiet")) or record['COMMAND_LINE'].contains("@Please_Read_Me@.txt"))

sigma_wannacry_ransomware.sigma_meta = dict(
    level="critical"
)

def sigma_apt29(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_apt29_thinktanks.yml
    title: APT29
    fields: ['CommandLine']
    level: high
    description: This method detects a suspicious PowerShell command line combination as used by APT29 in a campaign against U.S. think tanks.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-noni") and record['COMMAND_LINE'].contains("-ep") and record['COMMAND_LINE'].contains("bypass") and record['COMMAND_LINE'].contains("$"))

sigma_apt29.sigma_meta = dict(
    level="high"
)

def sigma_abusing_windows_telemetry_for_persistence(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_abusing_windows_telemetry_for_persistence.yml
    title: Abusing Windows Telemetry For Persistence
    fields: ['CommandLine']
    level: high
    description: Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections. This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run. The problem is, it will run any arbitrary command without restriction of location or type.
    logsource: product:windows - category:process_creation
    """
    return (record['COMMAND_LINE'].contains("schtasks") and record['COMMAND_LINE'].contains("\\Application Experience\\Microsoft Compatibility Appraiser"))

sigma_abusing_windows_telemetry_for_persistence.sigma_meta = dict(
    level="high"
)

def sigma_serv_u_exploitation_cve_2021_35211_by_dev_0322(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_servu_exploitation_cve_2021_35211.yml
    title: Serv-U Exploitation CVE-2021-35211 by DEV-0322
    fields: ['CommandLine']
    level: critical
    description: Detects patterns as noticed in exploitation of Serv-U CVE-2021-35211 vulnerability by threat group DEV-0322
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("whoami") and (record['COMMAND_LINE'].contains("./Client/Common/") or record['COMMAND_LINE'].contains(".\\Client\\Common"))) or record['COMMAND_LINE'].contains("C:\\Windows\\Temp\\Serv-U.bat"))

sigma_serv_u_exploitation_cve_2021_35211_by_dev_0322.sigma_meta = dict(
    level="critical"
)

def sigma_winrar_compressing_dump_files(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_winrar_dmp.yml
    title: Winrar Compressing Dump Files
    fields: ['CommandLine', 'Image', 'Description']
    level: high
    description: Detects a suspicious winrar execution that involves a file with a .dmp extension, which could be a step in a process of dump file exfiltration
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\rar.exe") or record['PROCESS_NAME'].endswith("\\winrar.exe")) or record['DESCRIPTION'] == "Command line RAR") and record['COMMAND_LINE'].contains(".dmp"))

sigma_winrar_compressing_dump_files.sigma_meta = dict(
    level="high"
)

def sigma_empire_powershell_launch_parameters(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_empire_launch.yml
    title: Empire PowerShell Launch Parameters
    fields: ['CommandLine']
    level: high
    description: Detects suspicious powershell command line parameters used in Empire
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-NoP -sta -NonI -W Hidden -Enc") or record['COMMAND_LINE'].contains("-noP -sta -w 1 -enc") or record['COMMAND_LINE'].contains("-NoP -NonI -W Hidden -enc") or record['COMMAND_LINE'].contains("-noP -sta -w 1 -enc") or record['COMMAND_LINE'].contains("-enc  SQB") or record['COMMAND_LINE'].contains("-nop -exec bypass -EncodedCommand"))

sigma_empire_powershell_launch_parameters.sigma_meta = dict(
    level="high"
)

def sigma_python_spawning_pretty_tty_on_windows(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_python_pty_spawn.yml
    title: Python Spawning Pretty TTY on Windows
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects python spawning a pretty tty
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("python.exe") or record['PROCESS_NAME'].endswith("python3.exe") or record['PROCESS_NAME'].endswith("python2.exe")) and ((record['COMMAND_LINE'].contains("import pty") and record['COMMAND_LINE'].contains(".spawn(")) or record['COMMAND_LINE'].contains("from pty import spawn")))

sigma_python_spawning_pretty_tty_on_windows.sigma_meta = dict(
    level="high"
)

def sigma_use_of_mftrace_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_mftrace.yml
    title: Use of Mftrace.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: The "Trace log generation tool for Media Foundation Tools" (Mftrace.exe) can be used to execute arbitrary binaries
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\mftrace.exe") or record['ORIGINAL_FILE_NAME'] == "mftrace.exe") and (record['COMMAND_LINE'].contains(".exe") and record['COMMAND_LINE'].endswith(".exe"))) or record['PARENT_NAME'].endswith("\\mftrace.exe"))

sigma_use_of_mftrace_exe.sigma_meta = dict(
    level="medium"
)

def sigma_powershell_script_run_in_appdata(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ps_appdata.yml
    title: PowerShell Script Run in AppData
    fields: ['CommandLine']
    level: medium
    description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("powershell.exe") or record['COMMAND_LINE'].contains("\\powershell") or record['COMMAND_LINE'].contains("\\pwsh") or record['COMMAND_LINE'].contains("pwsh.exe")) and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("\\AppData") and (record['COMMAND_LINE'].contains("Local") or record['COMMAND_LINE'].contains("Roaming")))

sigma_powershell_script_run_in_appdata.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_dump64_exe_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_dump64.yml
    title: Suspicious Dump64.exe Execution
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects when a user bypasses Defender by renaming a tool to dump64.exe and placing it in a Visual Studio folder
    logsource: product:windows - category:process_creation
    """
    return ((record['PROCESS_NAME'].endswith("\\dump64.exe") and not (record['PROCESS_NAME'].contains("\\Installer\\Feedback\\dump64.exe"))) or (record['PROCESS_NAME'].endswith("\\dump64.exe") and (record['COMMAND_LINE'].contains("-ma") or record['COMMAND_LINE'].contains("accpeteula"))))

sigma_suspicious_dump64_exe_execution.sigma_meta = dict(
    level="high"
)

def sigma_use_of_visualuiaverifynative_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_visualuiaverifynative.yml
    title: Use of VisualUiaVerifyNative.exe
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: VisualUiaVerifyNative.exe is a Windows SDK that can be used for AWL bypass and is listed in Microsoft's recommended block rules.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\VisualUiaVerifyNative.exe") or record['ORIGINAL_FILE_NAME'] == "VisualUiaVerifyNative.exe")

sigma_use_of_visualuiaverifynative_exe.sigma_meta = dict(
    level="medium"
)

def sigma_unidentified_attacker_november_2018(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_unidentified_nov_18.yml
    title: Unidentified Attacker November 2018
    fields: ['CommandLine']
    level: high
    description: A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cyzfc.dat,") and record['COMMAND_LINE'].endswith("PointFunctionCall"))

sigma_unidentified_attacker_november_2018.sigma_meta = dict(
    level="high"
)

def sigma_password_cracking_with_hashcat(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hashcat.yml
    title: Password Cracking with Hashcat
    fields: ['CommandLine', 'Image']
    level: high
    description: Execute Hashcat.exe with provided SAM file from registry of Windows and Password list to crack against
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\hashcat.exe") or (record['COMMAND_LINE'].contains("-a") and record['COMMAND_LINE'].contains("-m 1000") and record['COMMAND_LINE'].contains("-r")))

sigma_password_cracking_with_hashcat.sigma_meta = dict(
    level="high"
)

def sigma_handlekatz_lsass_dumper_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_handlekatz.yml
    title: HandleKatz LSASS Dumper Usage
    fields: ['CommandLine', 'Image', 'Hashes', 'Imphash']
    level: high
    description: Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\loader.exe") and record['COMMAND_LINE'].contains("--pid:")) or ((record['IMPHASH'] == "38d9e015591bbfd4929e0d0f47fa0055" or record['IMPHASH'] == "0e2216679ca6e1094d63322e3412d650") or (record['HASHES'] == "IMPHASH=38D9E015591BBFD4929E0D0F47FA0055" or record['HASHES'] == "IMPHASH=0E2216679CA6E1094D63322E3412D650")) or (record['COMMAND_LINE'].contains("--pid:") and record['COMMAND_LINE'].contains("--outfile:") and (record['COMMAND_LINE'].contains(".dmp") or record['COMMAND_LINE'].contains("lsass") or record['COMMAND_LINE'].contains(".obf") or record['COMMAND_LINE'].contains("dump"))))

sigma_handlekatz_lsass_dumper_usage.sigma_meta = dict(
    level="high"
)

def sigma_direct_autorun_keys_modification(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_direct_asep_reg_keys_modification.yml
    title: Direct Autorun Keys Modification
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("add") and (record['COMMAND_LINE'].contains("\\software\\Microsoft\\Windows\\CurrentVersion\\Run") or record['COMMAND_LINE'].contains("\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit") or record['COMMAND_LINE'].contains("\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell") or record['COMMAND_LINE'].contains("\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows") or record['COMMAND_LINE'].contains("\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") or record['COMMAND_LINE'].contains("\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell")))

sigma_direct_autorun_keys_modification.sigma_meta = dict(
    level="medium"
)

def sigma_smb_relay_attack_tools(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tools_relay_attacks.yml
    title: SMB Relay Attack Tools
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects different hacktools used for relay attacks on Windows for privilege escalation
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].contains("PetitPotam") or record['PROCESS_NAME'].contains("RottenPotato") or record['PROCESS_NAME'].contains("HotPotato") or record['PROCESS_NAME'].contains("JuicyPotato") or record['PROCESS_NAME'].contains("\\just_dce_") or record['PROCESS_NAME'].contains("Juicy Potato") or record['PROCESS_NAME'].contains("\\temp\\rot.exe") or record['PROCESS_NAME'].contains("\\Potato.exe") or record['PROCESS_NAME'].contains("\\SpoolSample.exe") or record['PROCESS_NAME'].contains("\\Responder.exe") or record['PROCESS_NAME'].contains("\\smbrelayx") or record['PROCESS_NAME'].contains("\\ntlmrelayx")) or (record['COMMAND_LINE'].contains("Invoke-Tater") or record['COMMAND_LINE'].contains("smbrelay") or record['COMMAND_LINE'].contains("ntlmrelay") or record['COMMAND_LINE'].contains("cme smb") or record['COMMAND_LINE'].contains("/ntlm:NTLMhash") or record['COMMAND_LINE'].contains("Invoke-PetitPotam") or record['COMMAND_LINE'].contains(".exe -t * -p")) or (record['COMMAND_LINE'].contains(".exe -c \"{") and record['COMMAND_LINE'].endswith("}\" -z"))) and not (((record['PROCESS_NAME'].contains("HotPotatoes6") or record['PROCESS_NAME'].contains("HotPotatoes 6") or record['PROCESS_NAME'].contains("HotPotatoes7") or record['PROCESS_NAME'].contains("HotPotatoes 7") or record['PROCESS_NAME'].contains("HotPotatoes Help") or record['PROCESS_NAME'].contains("HotPotatoes Tutorial")))))

sigma_smb_relay_attack_tools.sigma_meta = dict(
    level="critical"
)

def sigma_iis_native_code_module_command_line_installation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_iss_module_install.yml
    title: IIS Native-Code Module Command Line Installation
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects suspicious IIS native-code module installations via command line
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\appcmd.exe") and record['COMMAND_LINE'].contains("install") and record['COMMAND_LINE'].contains("module") and record['COMMAND_LINE'].contains("/name:"))

sigma_iis_native_code_module_command_line_installation.sigma_meta = dict(
    level="medium"
)

def sigma_openwith_exe_executes_specified_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_openwith.yml
    title: OpenWith.exe Executes Specified Binary
    fields: ['CommandLine', 'Image']
    level: high
    description: The OpenWith.exe executes other binary
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\OpenWith.exe") and record['COMMAND_LINE'].contains("/c"))

sigma_openwith_exe_executes_specified_binary.sigma_meta = dict(
    level="high"
)

def sigma_execution_in_webserver_root_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_execution_path_webserver.yml
    title: Execution in Webserver Root Folder
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects a suspicious program execution in a web service root folder (filter out false positives)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].contains("\\wwwroot") or record['PROCESS_NAME'].contains("\\wmpub") or record['PROCESS_NAME'].contains("\\htdocs")) and not ((record['PROCESS_NAME'].contains("bin") or record['PROCESS_NAME'].contains("\\Tools") or record['PROCESS_NAME'].contains("\\SMSComponent")) and record['PARENT_NAME'].endswith("\\services.exe")))

sigma_execution_in_webserver_root_folder.sigma_meta = dict(
    level="medium"
)

def sigma_mounted_share_deleted(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_mounted_share_deletion.yml
    title: Mounted Share Deleted
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) or (record['ORIGINAL_FILE_NAME'] == "net.exe" or record['ORIGINAL_FILE_NAME'] == "net1.exe")) and (record['COMMAND_LINE'].contains("share") and record['COMMAND_LINE'].contains("/delete")))

sigma_mounted_share_deleted.sigma_meta = dict(
    level="low"
)

def sigma_netsh_rdp_port_opening(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_allow_port_rdp.yml
    title: Netsh RDP Port Opening
    fields: ['CommandLine']
    level: high
    description: Detects netsh commands that opens the port 3389 used for RDP, used in Sarwent Malware
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("firewall add portopening") and record['COMMAND_LINE'].contains("tcp 3389")) or (record['COMMAND_LINE'].contains("netsh") and record['COMMAND_LINE'].contains("advfirewall firewall add rule") and record['COMMAND_LINE'].contains("action=allow") and record['COMMAND_LINE'].contains("protocol=TCP") and record['COMMAND_LINE'].contains("localport=3389")))

sigma_netsh_rdp_port_opening.sigma_meta = dict(
    level="high"
)

def sigma_vmtoolsd_suspicious_child_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_vmtoolsd_susp_child_process.yml
    title: VMToolsd Suspicious Child Process
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects suspicious child process creations of VMware Tools process which may indicate persistence setup
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\vmtoolsd.exe") and ((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe")) or (record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll" or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" or record['ORIGINAL_FILE_NAME'] == "REGSVR32.EXE" or record['ORIGINAL_FILE_NAME'] == "wscript.exe" or record['ORIGINAL_FILE_NAME'] == "cscript.exe"))) and not ((record['COMMAND_LINE'].contains("\\VMware\\VMware Tools\\poweron-vm-default.bat") or record['COMMAND_LINE'].contains("\\VMware\\VMware Tools\\poweroff-vm-default.bat") or record['COMMAND_LINE'].contains("\\VMware\\VMware Tools\\resume-vm-default.bat") or record['COMMAND_LINE'].contains("\\VMware\\VMware Tools\\suspend-vm-default.bat"))))

sigma_vmtoolsd_suspicious_child_process.sigma_meta = dict(
    level="high"
)

def sigma_disable_windows_iis_http_logging(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_iis_http_logging.yml
    title: Disable Windows IIS HTTP Logging
    fields: ['CommandLine', 'Image']
    level: high
    description: Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union)
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\appcmd.exe") and record['COMMAND_LINE'].contains("set") and record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("/section:httplogging") and record['COMMAND_LINE'].contains("/dontLog:true"))

sigma_disable_windows_iis_http_logging.sigma_meta = dict(
    level="high"
)

def sigma_use_short_name_path_in_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ntfs_short_name_path_use_cli.yml
    title: Use Short Name Path in Command Line
    fields: ['CommandLine', 'ParentImage']
    level: medium
    description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("~1") or record['COMMAND_LINE'].contains("~2")) and not ((record['PARENT_NAME'] == "C:\\Windows\\System32\\Dism.exe" or record['PARENT_NAME'] == "C:\\Windows\\System32\\cleanmgr.exe" or record['PARENT_NAME'] == "C:\\Program Files\\GPSoftware\\Directory Opus\\dopus.exe") or (record['PARENT_NAME'].endswith("\\WebEx\\WebexHost.exe") or record['PARENT_NAME'].endswith("\\thor\\thor64.exe") or record['PARENT_NAME'].endswith("\\veam.backup.shell.exe") or record['PARENT_NAME'].endswith("\\winget.exe") or record['PARENT_NAME'].endswith("\\Everything\\Everything.exe")) or record['PARENT_NAME'].contains("\\AppData\\Local\\Temp\\WinGet") or (record['COMMAND_LINE'].contains("\\appdata\\local\\webex\\webex64\\meetings\\wbxreport.exe") or record['COMMAND_LINE'].contains("C:\\Program Files\\Git\\post-install.bat") or record['COMMAND_LINE'].contains("C:\\Program Files\\Git\\cmd\\scalar.exe"))))

sigma_use_short_name_path_in_command_line.sigma_meta = dict(
    level="medium"
)

def sigma_conti_ntds_exfiltration_command(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_conti_7zip.yml
    title: Conti NTDS Exfiltration Command
    fields: ['CommandLine']
    level: high
    description: Detects a command used by conti to exfiltrate NTDS
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("7za.exe") and record['COMMAND_LINE'].contains("\\\\C$\\\\temp\\\\log.zip"))

sigma_conti_ntds_exfiltration_command.sigma_meta = dict(
    level="high"
)

def sigma_use_of_w32tm_as_timer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_w32tm.yml
    title: Use of W32tm as Timer
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: When configured with suitable command line arguments, w32tm can act as a delay mechanism
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\w32tm.exe") or record['ORIGINAL_FILE_NAME'] == "w32time.dll") and (record['COMMAND_LINE'].contains("/stripchart") and record['COMMAND_LINE'].contains("/computer:") and record['COMMAND_LINE'].contains("/period:") and record['COMMAND_LINE'].contains("/dataonly") and record['COMMAND_LINE'].contains("/samples:")))

sigma_use_of_w32tm_as_timer.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_xor_powershell_command_line(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_cmdline_susp_comb_methods.yml
    title: Suspicious Xor PowerShell Command Line
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects specific combinations of encoding methods in the PowerShell command lines
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and record['COMMAND_LINE'].contains("ForEach") and record['COMMAND_LINE'].contains("Xor"))

sigma_suspicious_xor_powershell_command_line.sigma_meta = dict(
    level="medium"
)

def sigma_wscript_execution_from_non_c_drive(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_lolbin_non_c_drive.yml
    title: Wscript Execution from Non C Drive
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects Wscript or Cscript executing from a drive other than C. This has been observed with Qakbot executing from within a mounted ISO file.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe")) and (record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".vbs") or record['COMMAND_LINE'].contains(".vbe")) and record['COMMAND_LINE'].contains(":")) and not (((record['COMMAND_LINE'].contains("C:") or record['COMMAND_LINE'].contains("\'C:") or record['COMMAND_LINE'].contains("\"C:"))) or (record['COMMAND_LINE'].contains("%")) or (record['COMMAND_LINE'].contains(""))))

sigma_wscript_execution_from_non_c_drive.sigma_meta = dict(
    level="medium"
)

def sigma_scheduled_task_wscript_vbscript(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_actinium_persistence.yml
    title: Scheduled Task WScript VBScript
    fields: ['CommandLine']
    level: high
    description: Detects specific process parameters as used by ACTINIUM scheduled task persistence creation.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("schtasks") and record['COMMAND_LINE'].contains("create") and record['COMMAND_LINE'].contains("wscript") and record['COMMAND_LINE'].contains("e:vbscript"))

sigma_scheduled_task_wscript_vbscript.sigma_meta = dict(
    level="high"
)

def sigma_msra_exe_process_injection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_msra_process_injection.yml
    title: Msra.exe Process Injection
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects process injection using Microsoft Remote Asssistance (Msra.exe) which has been used for discovery and persistence tactics
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\msra.exe") and record['PARENT_COMMAND_LINE'].endswith("msra.exe") and (record['PROCESS_NAME'].endswith("\\arp.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\netstat.exe") or record['PROCESS_NAME'].endswith("\\nslookup.exe") or record['PROCESS_NAME'].endswith("\\route.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\whoami.exe")))

sigma_msra_exe_process_injection.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_file_download_via_certoc_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_certoc_download.yml
    title: Suspicious File Download via CertOC.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects when a user downloads file by using CertOC.exe
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\certoc.exe") or record['ORIGINAL_FILE_NAME'] == "CertOC.exe") and record['COMMAND_LINE'].contains("-GetCACAPS"))

sigma_suspicious_file_download_via_certoc_exe.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_cmdline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_cmdline_reversed_strings.yml
    title: Suspicious PowerShell Cmdline
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects the PowerShell command lines with reversed strings
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("powershell.exe") or record['PROCESS_NAME'].endswith("pwsh.exe")) and (record['COMMAND_LINE'].contains("hctac") or record['COMMAND_LINE'].contains("kaerb") or record['COMMAND_LINE'].contains("dnammoc") or record['COMMAND_LINE'].contains("ekovn") or record['COMMAND_LINE'].contains("eliFd") or record['COMMAND_LINE'].contains("rahc") or record['COMMAND_LINE'].contains("etirw") or record['COMMAND_LINE'].contains("golon") or record['COMMAND_LINE'].contains("tninon") or record['COMMAND_LINE'].contains("eddih") or record['COMMAND_LINE'].contains("tpircS") or record['COMMAND_LINE'].contains("ssecorp") or record['COMMAND_LINE'].contains("llehsrewop") or record['COMMAND_LINE'].contains("esnopser") or record['COMMAND_LINE'].contains("daolnwod") or record['COMMAND_LINE'].contains("tneilCbeW") or record['COMMAND_LINE'].contains("tneilc") or record['COMMAND_LINE'].contains("ptth") or record['COMMAND_LINE'].contains("elifotevas") or record['COMMAND_LINE'].contains("46esab") or record['COMMAND_LINE'].contains("htaPpmeTteG") or record['COMMAND_LINE'].contains("tcejbO") or record['COMMAND_LINE'].contains("maerts") or record['COMMAND_LINE'].contains("hcaerof") or record['COMMAND_LINE'].contains("ekovni") or record['COMMAND_LINE'].contains("retupmoc"))) and not ((record['COMMAND_LINE'].contains("-EncodedCommand"))))

sigma_suspicious_powershell_cmdline.sigma_meta = dict(
    level="high"
)

def sigma_gathernetworkinfo_vbs_script_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_cscript_gathernetworkinfo.yml
    title: GatherNetworkInfo.vbs Script Usage
    fields: ['CommandLine']
    level: medium
    description: Adversaries can abuse of C:\Windows\System32\gatherNetworkInfo.vbs script along with cscript.exe to gather information about the target
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cscript.exe") and record['COMMAND_LINE'].contains("gatherNetworkInfo.vbs"))

sigma_gathernetworkinfo_vbs_script_usage.sigma_meta = dict(
    level="medium"
)

def sigma_rundll32_registered_com_objects(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_rundll32_registered_com_objects.yml
    title: Rundll32 Registered COM Objects
    fields: ['CommandLine', 'Image']
    level: high
    description: load malicious registered COM objects
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\rundll32.exe") and (record['COMMAND_LINE'].contains("-sta") or record['COMMAND_LINE'].contains("-localserver")) and record['COMMAND_LINE'].contains("{") and record['COMMAND_LINE'].contains("}"))

sigma_rundll32_registered_com_objects.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_use_of_csharp_interactive_console(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_use_of_csharp_console.yml
    title: Suspicious Use of CSharp Interactive Console
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: high
    description: Detects the execution of CSharp interactive console by PowerShell
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\csi.exe") and (record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\powershell_ise.exe")) and record['ORIGINAL_FILE_NAME'] == "csi.exe")

sigma_suspicious_use_of_csharp_interactive_console.sigma_meta = dict(
    level="high"
)

def sigma_bypass_uac_via_fodhelper_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.yml
    title: Bypass UAC via Fodhelper.exe
    fields: ['ParentImage']
    level: high
    description: Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
    logsource: category:process_creation - product:windows
    """
    return record['PARENT_NAME'].endswith("\\fodhelper.exe")

sigma_bypass_uac_via_fodhelper_exe.sigma_meta = dict(
    level="high"
)

def sigma_query_registry(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_query_registry.yml
    title: Query Registry
    fields: ['CommandLine', 'Image']
    level: low
    description: Adversaries may interact with the Windows Registry to gather information about credentials, the system, configuration, and installed software.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and (record['COMMAND_LINE'].contains("query") or record['COMMAND_LINE'].contains("save") or record['COMMAND_LINE'].contains("export")) and (record['COMMAND_LINE'].contains("currentVersion\\windows") or record['COMMAND_LINE'].contains("winlogon") or record['COMMAND_LINE'].contains("currentVersion\\shellServiceObjectDelayLoad") or record['COMMAND_LINE'].contains("currentVersion\\run") or record['COMMAND_LINE'].contains("currentVersion\\policies\\explorer\\run") or record['COMMAND_LINE'].contains("currentcontrolset\\services")))

sigma_query_registry.sigma_meta = dict(
    level="low"
)

def sigma_suspicious_dir_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_dir.yml
    title: Suspicious DIR Execution
    fields: ['CommandLine']
    level: low
    description: Detects usage of the "dir" command that's part of windows batch/cmd to collect information about directories
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("dir") and record['COMMAND_LINE'].contains("/s") and record['COMMAND_LINE'].contains("/b"))

sigma_suspicious_dir_execution.sigma_meta = dict(
    level="low"
)

def sigma_use_of_pcalua_for_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_pcalua.yml
    title: Use of Pcalua For Execution
    fields: ['CommandLine', 'Image']
    level: medium
    description: Execute commands and binaries from the context of The program compatibility assistant (Pcalua.exe). This is used as a LOLBIN for example to bypass application whitelisting.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\pcalua.exe") and record['COMMAND_LINE'].contains("-a"))

sigma_use_of_pcalua_for_execution.sigma_meta = dict(
    level="medium"
)

def sigma_lolbin_execution_of_the_ftp_exe_binary(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_ftp.yml
    title: LOLBIN Execution Of The FTP.EXE Binary
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'ParentImage']
    level: medium
    description: Detects execution of ftp.exe script execution with the "-s" flag and any child processes ran by ftp.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\ftp.exe") or ((record['PROCESS_NAME'].endswith("\\ftp.exe") or record['ORIGINAL_FILE_NAME'] == "ftp.exe") and record['COMMAND_LINE'].contains("-s:")))

sigma_lolbin_execution_of_the_ftp_exe_binary.sigma_meta = dict(
    level="medium"
)

def sigma_rclone_execution_via_command_line_or_powershell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rclone_execution.yml
    title: Rclone Execution via Command Line or PowerShell
    fields: ['CommandLine', 'Image', 'ParentImage', 'Description']
    level: high
    description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
    logsource: product:windows - category:process_creation
    """
    return ((record['COMMAND_LINE'].contains("--config") and record['COMMAND_LINE'].contains("--no-check-certificate") and record['COMMAND_LINE'].contains("copy")) or ((record['COMMAND_LINE'].contains("pass") or record['COMMAND_LINE'].contains("user") or record['COMMAND_LINE'].contains("copy") or record['COMMAND_LINE'].contains("sync") or record['COMMAND_LINE'].contains("config") or record['COMMAND_LINE'].contains("lsd") or record['COMMAND_LINE'].contains("remote") or record['COMMAND_LINE'].contains("ls") or record['COMMAND_LINE'].contains("mega") or record['COMMAND_LINE'].contains("pcloud") or record['COMMAND_LINE'].contains("ftp") or record['COMMAND_LINE'].contains("ignore-existing") or record['COMMAND_LINE'].contains("auto-confirm") or record['COMMAND_LINE'].contains("transfers") or record['COMMAND_LINE'].contains("multi-thread-streams") or record['COMMAND_LINE'].contains("no-check-certificate")) and (record['DESCRIPTION'] == "Rsync for cloud storage" or (record['PROCESS_NAME'].endswith("\\rclone.exe") and (record['PARENT_NAME'].endswith("\\PowerShell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\cmd.exe"))))))

sigma_rclone_execution_via_command_line_or_powershell.sigma_meta = dict(
    level="high"
)

def sigma_privilege_escalation_via_named_pipe_impersonation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_priv_escalation_via_named_pipe.yml
    title: Privilege Escalation via Named Pipe Impersonation
    fields: ['CommandLine', 'OriginalFilename', 'Image']
    level: high
    description: Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe")) or (record['ORIGINAL_FILENAME'] == "Cmd.Exe" or record['ORIGINAL_FILENAME'] == "PowerShell.EXE")) and (record['COMMAND_LINE'].contains("echo") and record['COMMAND_LINE'].contains(">") and record['COMMAND_LINE'].contains("\\\\\\\\.\\\\pipe")))

sigma_privilege_escalation_via_named_pipe_impersonation.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_extexport_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_extexport.yml
    title: Suspicious Extexport Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Extexport.exe loads dll and is execute from other folder the original path
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Extexport.exe") or record['PROCESS_NAME'].endswith("\\Extexport.exe") or record['ORIGINAL_FILE_NAME'] == "extexport.exe")

sigma_suspicious_extexport_execution.sigma_meta = dict(
    level="medium"
)

def sigma_operator_bloopers_cobalt_strike_modules(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_cobaltstrike_bloopers_modules.yml
    title: Operator Bloopers Cobalt Strike Modules
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects use of Cobalt Strike module commands accidentally entered in the CMD shell
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "Cmd.Exe" or record['PROCESS_NAME'].endswith("\\cmd.exe")) and ((record['COMMAND_LINE'].startswith("cmd.exe") or record['COMMAND_LINE'].startswith("c:\\windows\\system32\\cmd.exe")) and (record['COMMAND_LINE'].contains("Invoke-UserHunter") or record['COMMAND_LINE'].contains("Invoke-ShareFinder") or record['COMMAND_LINE'].contains("Invoke-Kerberoast") or record['COMMAND_LINE'].contains("Invoke-SMBAutoBrute") or record['COMMAND_LINE'].contains("Invoke-Nightmare") or record['COMMAND_LINE'].contains("zerologon") or record['COMMAND_LINE'].contains("av_query"))))

sigma_operator_bloopers_cobalt_strike_modules.sigma_meta = dict(
    level="high"
)

def sigma_grabbing_sensitive_hives_via_reg_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_grabbing_sensitive_hives_via_reg.yml
    title: Grabbing Sensitive Hives via Reg Utility
    fields: ['CommandLine', 'Image']
    level: medium
    description: Dump sam, system or security hives using REG.exe utility
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and (record['COMMAND_LINE'].contains("save") or record['COMMAND_LINE'].contains("export") or record['COMMAND_LINE'].contains("ˢave") or record['COMMAND_LINE'].contains("eˣport")) and (record['COMMAND_LINE'].contains("hklm") or record['COMMAND_LINE'].contains("hk˪m") or record['COMMAND_LINE'].contains("hkey_local_machine") or record['COMMAND_LINE'].contains("hkey_˪ocal_machine") or record['COMMAND_LINE'].contains("hkey_loca˪_machine") or record['COMMAND_LINE'].contains("hkey_˪oca˪_machine")) and (record['COMMAND_LINE'].endswith("\\system") or record['COMMAND_LINE'].endswith("\\sam") or record['COMMAND_LINE'].endswith("\\security") or record['COMMAND_LINE'].endswith("\\ˢystem") or record['COMMAND_LINE'].endswith("\\syˢtem") or record['COMMAND_LINE'].endswith("\\ˢyˢtem") or record['COMMAND_LINE'].endswith("\\ˢam") or record['COMMAND_LINE'].endswith("\\ˢecurity")))

sigma_grabbing_sensitive_hives_via_reg_utility.sigma_meta = dict(
    level="medium"
)

def sigma_psexec_tool_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_tool_psexec.yml
    title: PsExec Tool Execution
    fields: ['User', 'Image']
    level: low
    description: Detects PsExec service execution via default service image name
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\PSEXESVC.exe") and (record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI")))

sigma_psexec_tool_execution.sigma_meta = dict(
    level="low"
)

def sigma_notpetya_ransomware_activity(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_malware_notpetya.yml
    title: NotPetya Ransomware Activity
    fields: ['CommandLine', 'Image']
    level: critical
    description: Detects NotPetya ransomware activity in which the extracted passwords are passed back to the main module via named pipe, the file system journal of drive C is deleted and windows eventlogs are cleared using wevtutil
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("\\AppData\\Local\\Temp") and record['COMMAND_LINE'].contains("\\\\\\\\.\\\\pipe")) or (record['PROCESS_NAME'].endswith("\\rundll32.exe") and (record['COMMAND_LINE'].endswith(".dat,#1") or record['COMMAND_LINE'].endswith(".dat #1"))) or record['_raw'].contains("\\perfc.dat"))

sigma_notpetya_ransomware_activity.sigma_meta = dict(
    level="critical"
)

def sigma_ke3chang_registry_key_modifications(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_ke3chang_regadd.yml
    title: Ke3chang Registry Key Modifications
    fields: ['CommandLine']
    level: critical
    description: Detects Registry modifications performed by Ke3chang malware in campaigns running in 2019 and 2020
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("-Property DWORD -name DisableFirstRunCustomize -value 2 -Force") or record['COMMAND_LINE'].contains("-Property String -name Check_Associations -value") or record['COMMAND_LINE'].contains("-Property DWORD -name IEHarden -value 0 -Force"))

sigma_ke3chang_registry_key_modifications.sigma_meta = dict(
    level="critical"
)

def sigma_use_of_scriptrunner_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_scriptrunner.yml
    title: Use of Scriptrunner.exe
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ScriptRunner.exe") or record['ORIGINAL_FILE_NAME'] == "ScriptRunner.exe") and record['COMMAND_LINE'].contains("-appvscript"))

sigma_use_of_scriptrunner_exe.sigma_meta = dict(
    level="medium"
)

def sigma_disable_windows_defender_av_security_monitoring(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_disable_defender_av_security_monitoring.yml
    title: Disable Windows Defender AV Security Monitoring
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects attackers attempting to disable Windows Defender using Powershell
    logsource: category:process_creation - product:windows
    """
    return ((((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) or (record['ORIGINAL_FILE_NAME'] == "PowerShell.EXE" or record['ORIGINAL_FILE_NAME'] == "pwsh.dll")) and (record['COMMAND_LINE'].contains("-DisableBehaviorMonitoring $true") or record['COMMAND_LINE'].contains("-DisableRuntimeMonitoring $true"))) or ((record['PROCESS_NAME'].endswith("\\sc.exe") or record['ORIGINAL_FILE_NAME'] == "sc.exe") and ((record['COMMAND_LINE'].contains("stop") and record['COMMAND_LINE'].contains("WinDefend")) or (record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("WinDefend")) or (record['COMMAND_LINE'].contains("config") and record['COMMAND_LINE'].contains("WinDefend") and record['COMMAND_LINE'].contains("start=disabled")))))

sigma_disable_windows_defender_av_security_monitoring.sigma_meta = dict(
    level="high"
)

def sigma_zoho_dctask64_process_injection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_dctask64_proc_inject.yml
    title: ZOHO Dctask64 Process Injection
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious process injection using ZOHO's dctask64.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\dctask64.exe") and not (record['COMMAND_LINE'].contains("DesktopCentral_Agent\\agent")))

sigma_zoho_dctask64_process_injection.sigma_meta = dict(
    level="high"
)

def sigma_pubprn_vbs_proxy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml
    title: Pubprn.vbs Proxy Execution
    fields: ['CommandLine']
    level: medium
    description: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\pubprn.vbs") and record['COMMAND_LINE'].contains("script:"))

sigma_pubprn_vbs_proxy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_regedit_as_trusted_installer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regedit_trustedinstaller.yml
    title: Regedit as Trusted Installer
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\regedit.exe") and (record['PARENT_NAME'].endswith("\\TrustedInstaller.exe") or record['PARENT_NAME'].endswith("\\ProcessHacker.exe")))

sigma_regedit_as_trusted_installer.sigma_meta = dict(
    level="high"
)

def sigma_scheduled_task_creation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_schtask_creation.yml
    title: Scheduled Task Creation
    fields: ['CommandLine', 'User', 'Image']
    level: low
    description: Detects the creation of scheduled tasks in user session
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\schtasks.exe") and record['COMMAND_LINE'].contains("/create")) and not ((record['USERNAME'].contains("AUTHORI") or record['USERNAME'].contains("AUTORI"))))

sigma_scheduled_task_creation.sigma_meta = dict(
    level="low"
)

def sigma_password_provided_in_command_line_of_net_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_net_use_password_plaintext.yml
    title: Password Provided In Command Line Of Net.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects a when net.exe is called with a password in the command line
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'] == "C:\\Windows\\System32\\net.exe" and record['COMMAND_LINE'].contains("net") and record['COMMAND_LINE'].contains("use") and record['COMMAND_LINE'].contains(":*") and record['COMMAND_LINE'].contains("/USER:*")) and not ((record['COMMAND_LINE'].endswith("*"))))

sigma_password_provided_in_command_line_of_net_exe.sigma_meta = dict(
    level="medium"
)

def sigma_netsh_port_or_application_allowed(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_netsh_fw_add.yml
    title: Netsh Port or Application Allowed
    fields: ['CommandLine', 'Image']
    level: medium
    description: Allow Incoming Connections by Port or Application on Windows Firewall
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\netsh.exe") and record['COMMAND_LINE'].contains("firewall") and record['COMMAND_LINE'].contains("add")) and not (((record['COMMAND_LINE'].contains("\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=C:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any") or record['COMMAND_LINE'].contains("\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=C:\\Program Files\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any")))))

sigma_netsh_port_or_application_allowed.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_ntdll_pipe_redirection(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_ntdll_type_redirect.yml
    title: Suspicious Ntdll Pipe Redirection
    fields: ['CommandLine']
    level: high
    description: Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("type %windir%\\system32\\ntdll.dll") or record['COMMAND_LINE'].contains("type %systemroot%\\system32\\ntdll.dll") or record['COMMAND_LINE'].contains("type c:\\windows\\system32\\ntdll.dll") or record['COMMAND_LINE'].contains("\\\\ntdll.dll > \\\\\\\\.\\\\pipe"))

sigma_suspicious_ntdll_pipe_redirection.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_auditpol_usage(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sus_auditpol_usage.yml
    title: Suspicious Auditpol Usage
    fields: ['CommandLine', 'Image']
    level: high
    description: Threat actors can use auditpol binary to change audit policy configuration to impair detection capability.
This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\auditpol.exe") and (record['COMMAND_LINE'].contains("disable") or record['COMMAND_LINE'].contains("clear") or record['COMMAND_LINE'].contains("remove") or record['COMMAND_LINE'].contains("restore")))

sigma_suspicious_auditpol_usage.sigma_meta = dict(
    level="high"
)

def sigma_phishing_pattern_iso_in_archive(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_archiver_iso_phishing.yml
    title: Phishing Pattern ISO in Archive
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects cases in which an ISO files is opend within an archiver like 7Zip or Winrar, which is a sign of phishing as threat actors put small ISO files in archives as email attachments to bypass certain filters and protective measures (mark of web)
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\Winrar.exe") or record['PARENT_NAME'].endswith("\\7zFM.exe") or record['PARENT_NAME'].endswith("\\peazip.exe")) and (record['PROCESS_NAME'].endswith("\\isoburn.exe") or record['PROCESS_NAME'].endswith("\\PowerISO.exe") or record['PROCESS_NAME'].endswith("\\ImgBurn.exe")))

sigma_phishing_pattern_iso_in_archive.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_execution_of_sc_to_delete_av_services(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sc_delete_av_services.yml
    title: Suspicious Execution of Sc to Delete AV Services
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects when attackers use "sc.exe" to delete AV services from the system in order to avoid detection
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\sc.exe") or record['ORIGINAL_FILE_NAME'] == "sc.exe") and record['COMMAND_LINE'].contains("delete") and (record['COMMAND_LINE'].contains("AvgAdminServer") or record['COMMAND_LINE'].contains("AVG Antivirus") or record['COMMAND_LINE'].contains("MBEndpointAgent") or record['COMMAND_LINE'].contains("MBAMService") or record['COMMAND_LINE'].contains("MBCloudEA") or record['COMMAND_LINE'].contains("avgAdminClient") or record['COMMAND_LINE'].contains("SAVService") or record['COMMAND_LINE'].contains("SAVAdminService") or record['COMMAND_LINE'].contains("Sophos AutoUpdate Service") or record['COMMAND_LINE'].contains("Sophos Clean Service") or record['COMMAND_LINE'].contains("Sophos Device Control Service") or record['COMMAND_LINE'].contains("Sophos File Scanner Service") or record['COMMAND_LINE'].contains("Sophos Health Service") or record['COMMAND_LINE'].contains("Sophos MCS Agent") or record['COMMAND_LINE'].contains("Sophos MCS Client") or record['COMMAND_LINE'].contains("SntpService") or record['COMMAND_LINE'].contains("swc_service") or record['COMMAND_LINE'].contains("swi_service") or record['COMMAND_LINE'].contains("Sophos UI") or record['COMMAND_LINE'].contains("swi_update") or record['COMMAND_LINE'].contains("Sophos Web Control Service") or record['COMMAND_LINE'].contains("Sophos System Protection Service") or record['COMMAND_LINE'].contains("Sophos Safestore Service") or record['COMMAND_LINE'].contains("hmpalertsvc") or record['COMMAND_LINE'].contains("RpcEptMapper") or record['COMMAND_LINE'].contains("Sophos Endpoint Defense Service") or record['COMMAND_LINE'].contains("SophosFIM") or record['COMMAND_LINE'].contains("swi_filter") or record['COMMAND_LINE'].contains("FirebirdGuardianDefaultInstance") or record['COMMAND_LINE'].contains("FirebirdServerDefaultInstance") or record['COMMAND_LINE'].contains("WRSVC") or record['COMMAND_LINE'].contains("ekrn") or record['COMMAND_LINE'].contains("ekrnEpsw") or record['COMMAND_LINE'].contains("klim6") or record['COMMAND_LINE'].contains("AVP18.0.0") or record['COMMAND_LINE'].contains("KLIF") or record['COMMAND_LINE'].contains("klpd") or record['COMMAND_LINE'].contains("klflt") or record['COMMAND_LINE'].contains("klbackupdisk") or record['COMMAND_LINE'].contains("klbackupflt") or record['COMMAND_LINE'].contains("klkbdflt") or record['COMMAND_LINE'].contains("klmouflt") or record['COMMAND_LINE'].contains("klhk") or record['COMMAND_LINE'].contains("KSDE1.0.0") or record['COMMAND_LINE'].contains("kltap") or record['COMMAND_LINE'].contains("ScSecSvc") or record['COMMAND_LINE'].contains("Core Mail Protection") or record['COMMAND_LINE'].contains("Core Scanning Server") or record['COMMAND_LINE'].contains("Core Scanning ServerEx") or record['COMMAND_LINE'].contains("Online Protection System") or record['COMMAND_LINE'].contains("RepairService") or record['COMMAND_LINE'].contains("Core Browsing Protection") or record['COMMAND_LINE'].contains("Quick Update Service") or record['COMMAND_LINE'].contains("McAfeeFramework") or record['COMMAND_LINE'].contains("macmnsvc") or record['COMMAND_LINE'].contains("masvc") or record['COMMAND_LINE'].contains("mfemms") or record['COMMAND_LINE'].contains("mfevtp") or record['COMMAND_LINE'].contains("TmFilter") or record['COMMAND_LINE'].contains("TMLWCSService") or record['COMMAND_LINE'].contains("tmusa") or record['COMMAND_LINE'].contains("TmPreFilter") or record['COMMAND_LINE'].contains("TMSmartRelayService") or record['COMMAND_LINE'].contains("TMiCRCScanService") or record['COMMAND_LINE'].contains("VSApiNt") or record['COMMAND_LINE'].contains("TmCCSF") or record['COMMAND_LINE'].contains("tmlisten") or record['COMMAND_LINE'].contains("TmProxy") or record['COMMAND_LINE'].contains("ntrtscan") or record['COMMAND_LINE'].contains("ofcservice") or record['COMMAND_LINE'].contains("TmPfw") or record['COMMAND_LINE'].contains("PccNTUpd") or record['COMMAND_LINE'].contains("PandaAetherAgent") or record['COMMAND_LINE'].contains("PSUAService") or record['COMMAND_LINE'].contains("NanoServiceMain") or record['COMMAND_LINE'].contains("EPIntegrationService") or record['COMMAND_LINE'].contains("EPProtectedService") or record['COMMAND_LINE'].contains("EPRedline") or record['COMMAND_LINE'].contains("EPSecurityService") or record['COMMAND_LINE'].contains("EPUpdateService")))

sigma_suspicious_execution_of_sc_to_delete_av_services.sigma_meta = dict(
    level="high"
)

def sigma_script_event_consumer_spawning_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_script_event_consumer_spawn.yml
    title: Script Event Consumer Spawning Process
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\scrcons.exe") and (record['PROCESS_NAME'].endswith("\\svchost.exe") or record['PROCESS_NAME'].endswith("\\dllhost.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\msbuild.exe")))

sigma_script_event_consumer_spawning_process.sigma_meta = dict(
    level="high"
)

def sigma_raccine_uninstall(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_disable_raccine.yml
    title: Raccine Uninstall
    fields: ['CommandLine']
    level: high
    description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("taskkill") and record['COMMAND_LINE'].contains("RaccineSettings.exe")) or (record['COMMAND_LINE'].contains("reg.exe") and record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("Raccine Tray")) or (record['COMMAND_LINE'].contains("schtasks") and record['COMMAND_LINE'].contains("/DELETE") and record['COMMAND_LINE'].contains("Raccine Rules Updater")))

sigma_raccine_uninstall.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_rundll32_invoking_inline_vbscript(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_inline_vbs.yml
    title: Suspicious Rundll32 Invoking Inline VBScript
    fields: ['CommandLine']
    level: high
    description: Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("rundll32.exe") and record['COMMAND_LINE'].contains("Execute") and record['COMMAND_LINE'].contains("RegRead") and record['COMMAND_LINE'].contains("window.close"))

sigma_suspicious_rundll32_invoking_inline_vbscript.sigma_meta = dict(
    level="high"
)

def sigma_wmi_persistence_script_event_consumer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wmi_persistence_script_event_consumer.yml
    title: WMI Persistence - Script Event Consumer
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects WMI script event consumers
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'] == "C:\\WINDOWS\\system32\\wbem\\scrcons.exe" and record['PARENT_NAME'] == "C:\\Windows\\System32\\svchost.exe")

sigma_wmi_persistence_script_event_consumer.sigma_meta = dict(
    level="medium"
)

def sigma_powershell_base64_encoded_shellcode(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_b64_shellcode.yml
    title: PowerShell Base64 Encoded Shellcode
    fields: ['CommandLine']
    level: critical
    description: Detects Base64 encoded Shellcode
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("AAAAYInlM") and (record['COMMAND_LINE'].contains("OiCAAAAYInlM") or record['COMMAND_LINE'].contains("OiJAAAAYInlM")))

sigma_powershell_base64_encoded_shellcode.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_customshellhost_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_customshellhost.yml
    title: Suspicious CustomShellHost Execution
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects the execution of CustomShellHost binary where the child isn't located in 'C:\Windows\explorer.exe'
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\CustomShellHost.exe") and not (record['PROCESS_NAME'] == "C:\\Windows\\explorer.exe"))

sigma_suspicious_customshellhost_execution.sigma_meta = dict(
    level="medium"
)

def sigma_delete_safeboot_keys_via_reg_utility(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_delete_safeboot.yml
    title: Delete SafeBoot Keys Via Reg Utility
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and (record['COMMAND_LINE'].contains("delete") and record['COMMAND_LINE'].contains("\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot")))

sigma_delete_safeboot_keys_via_reg_utility.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_svchost_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_svchost.yml
    title: Suspicious Svchost Process
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a suspicious svchost process start
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\svchost.exe") and not (((record['PARENT_NAME'].endswith("\\services.exe") or record['PARENT_NAME'].endswith("\\MsMpEng.exe") or record['PARENT_NAME'].endswith("\\Mrt.exe") or record['PARENT_NAME'].endswith("\\rpcnet.exe") or record['PARENT_NAME'].endswith("\\ngen.exe") or record['PARENT_NAME'].endswith("\\TiWorker.exe"))) or (record.get('PARENT_NAME', None) == None) or (record['PARENT_NAME'] == "") or (record['PARENT_NAME'] == "-")))

sigma_suspicious_svchost_process.sigma_meta = dict(
    level="high"
)

def sigma_weak_or_abused_passwords_in_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_weak_or_abused_passwords.yml
    title: Weak or Abused Passwords In CLI
    fields: ['CommandLine']
    level: medium
    description: Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI. An example would be a threat actor creating a new user via the net command and providing the password inline
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("Asd123.aaaa") or record['COMMAND_LINE'].contains("password123") or record['COMMAND_LINE'].contains("123456789") or record['COMMAND_LINE'].contains("P@ssw0rd!"))

sigma_weak_or_abused_passwords_in_cli.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_microsoft_onenote_child_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_microsoft_onenote_child_process.yml
    title: Suspicious Microsoft OneNote Child Process
    fields: ['CommandLine', 'OriginalFilename', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious child processes of the Microsoft OneNote application. This may indicate an attempt to execute malicious embedded objects from a .one file.
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\onenote.exe") and (((record['ORIGINAL_FILENAME'] == "RUNDLL32.exe" or record['ORIGINAL_FILENAME'] == "REGSVR32.exe" or record['ORIGINAL_FILENAME'] == "bitsadmin.exe" or record['ORIGINAL_FILENAME'] == "CertUtil.exe" or record['ORIGINAL_FILENAME'] == "InstallUtil.exe" or record['ORIGINAL_FILENAME'] == "schtasks.exe" or record['ORIGINAL_FILENAME'] == "wmic.exe" or record['ORIGINAL_FILENAME'] == "cscript.exe" or record['ORIGINAL_FILENAME'] == "wscript.exe" or record['ORIGINAL_FILENAME'] == "CMSTP.EXE" or record['ORIGINAL_FILENAME'] == "Microsoft.Workflow.Compiler.exe" or record['ORIGINAL_FILENAME'] == "RegAsm.exe" or record['ORIGINAL_FILENAME'] == "RegSvcs.exe" or record['ORIGINAL_FILENAME'] == "MSHTA.EXE" or record['ORIGINAL_FILENAME'] == "Msxsl.exe" or record['ORIGINAL_FILENAME'] == "IEExec.exe" or record['ORIGINAL_FILENAME'] == "Cmd.Exe" or record['ORIGINAL_FILENAME'] == "PowerShell.EXE" or record['ORIGINAL_FILENAME'] == "HH.exe" or record['ORIGINAL_FILENAME'] == "javaw.exe" or record['ORIGINAL_FILENAME'] == "pcalua.exe" or record['ORIGINAL_FILENAME'] == "curl.exe" or record['ORIGINAL_FILENAME'] == "ScriptRunner.exe" or record['ORIGINAL_FILENAME'] == "CertOC.exe" or record['ORIGINAL_FILENAME'] == "WorkFolders.exe" or record['ORIGINAL_FILENAME'] == "odbcconf.exe" or record['ORIGINAL_FILENAME'] == "msiexec.exe" or record['ORIGINAL_FILENAME'] == "msdt.exe") or (record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\bitsadmin.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\installutil.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cmstp.exe") or record['PROCESS_NAME'].endswith("\\Microsoft.Workflow.Compiler.exe") or record['PROCESS_NAME'].endswith("\\regasm.exe") or record['PROCESS_NAME'].endswith("\\regsvcs.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\msxsl.exe") or record['PROCESS_NAME'].endswith("\\ieexec.exe") or record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\javaw.exe") or record['PROCESS_NAME'].endswith("\\pcalua.exe") or record['PROCESS_NAME'].endswith("\\curl.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\certoc.exe") or record['PROCESS_NAME'].endswith("\\workfolders.exe") or record['PROCESS_NAME'].endswith("\\odbcconf.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\msdt.exe"))) or (record['PROCESS_NAME'].endswith("\\explorer.exe") and (record['COMMAND_LINE'].contains(".hta") or record['COMMAND_LINE'].contains(".vb") or record['COMMAND_LINE'].contains(".wsh") or record['COMMAND_LINE'].contains(".js") or record['COMMAND_LINE'].contains(".ps") or record['COMMAND_LINE'].contains(".scr") or record['COMMAND_LINE'].contains(".pif") or record['COMMAND_LINE'].contains(".bat") or record['COMMAND_LINE'].contains(".cmd"))) or (record['PROCESS_NAME'].contains("\\AppData") or record['PROCESS_NAME'].contains("\\Users\\Public") or record['PROCESS_NAME'].contains("\\ProgramData") or record['PROCESS_NAME'].contains("\\Windows\\Tasks") or record['PROCESS_NAME'].contains("\\Windows\\Temp") or record['PROCESS_NAME'].contains("\\Windows\\System32\\Tasks"))))

sigma_suspicious_microsoft_onenote_child_process.sigma_meta = dict(
    level="medium"
)

def sigma_utilityfunctions_ps1_proxy_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_utilityfunctions.yml
    title: UtilityFunctions.ps1 Proxy Dll
    fields: ['CommandLine']
    level: medium
    description: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("UtilityFunctions.ps1") or record['COMMAND_LINE'].contains("RegSnapin"))

sigma_utilityfunctions_ps1_proxy_dll.sigma_meta = dict(
    level="medium"
)

def sigma_bluemashroom_dll_load(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_bluemashroom.yml
    title: BlueMashroom DLL Load
    fields: ['CommandLine']
    level: critical
    description: Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report
    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("\\regsvr32") and record['COMMAND_LINE'].contains("\\AppData\\Local")) or (record['COMMAND_LINE'].contains("\\AppData\\Local") and record['COMMAND_LINE'].contains(",DllEntry"))) and not ((record['COMMAND_LINE'].contains("AppData\\Local\\Microsoft\\TeamsMeetingAddin") or (record['COMMAND_LINE'].endswith("\\x86\\Microsoft.Teams.AddinLoader.dll") or record['COMMAND_LINE'].endswith("\\x86\\Microsoft.Teams.AddinLoader.dll\"") or record['COMMAND_LINE'].endswith("\\x64\\Microsoft.Teams.AddinLoader.dll") or record['COMMAND_LINE'].endswith("\\x64\\Microsoft.Teams.AddinLoader.dll\""))) or (record['COMMAND_LINE'].endswith("\\AppData\\Local\\WebEx\\WebEx64\\Meetings\\atucfobj.dll"))))

sigma_bluemashroom_dll_load.sigma_meta = dict(
    level="critical"
)

def sigma_execution_in_outlook_temp_folder(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_outlook_temp.yml
    title: Execution in Outlook Temp Folder
    fields: ['Image']
    level: high
    description: Detects a suspicious program execution in Outlook temp folder
    logsource: category:process_creation - product:windows
    """
    return record['PROCESS_NAME'].contains("\\Temporary Internet Files\\Content.Outlook")

sigma_execution_in_outlook_temp_folder.sigma_meta = dict(
    level="high"
)

def sigma_msexchange_transport_agent_installation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_win_exchange_transportagent.yml
    title: MSExchange Transport Agent Installation
    fields: ['CommandLine']
    level: medium
    description: Detects the Installation of a Exchange Transport Agent
    logsource: product:windows - category:process_creation
    """
    return record['COMMAND_LINE'].contains("Install-TransportAgent")

sigma_msexchange_transport_agent_installation.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_openconsole(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_openconsole.yml
    title: Use of OpenConsole
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting
    logsource: category:process_creation - product:windows
    """
    return ((record['ORIGINAL_FILE_NAME'] == "OpenConsole.exe" or record['PROCESS_NAME'].endswith("\\OpenConsole.exe")) and not (record['PROCESS_NAME'].startswith("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal")))

sigma_use_of_openconsole.sigma_meta = dict(
    level="medium"
)

def sigma_use_of_ultraviewer_remote_access_software(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_ultraviewer.yml
    title: Use of UltraViewer Remote Access Software
    fields: ['OriginalFileName', 'Product', 'Company']
    level: medium
    description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

    logsource: category:process_creation - product:windows
    """
    return (record['PRODUCT_NAME'] == "UltraViewer" or record['COMPANY'] == "DucFabulous Co,ltd" or record['ORIGINAL_FILE_NAME'] == "UltraViewer_Desktop.exe")

sigma_use_of_ultraviewer_remote_access_software.sigma_meta = dict(
    level="medium"
)

def sigma_execution_of_netsupport_rat_from_unusual_location(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_netsupport_rat_exec_location.yml
    title: Execution of NetSupport RAT From Unusual Location
    fields: ['Image', 'Hashes', 'OriginalFileName', 'Product', 'Imphash']
    level: medium
    description: Detects execution of client32.exe (NetSupport RAT) from an unsual location (outisde of 'C:\Program Files')
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\client32.exe") or record['PRODUCT_NAME'].contains("NetSupport Remote Control") or record['ORIGINAL_FILE_NAME'].contains("client32.exe") or record['IMPHASH'] == "a9d50692e95b79723f3e76fcf70d023e" or record['HASHES'].contains("IMPHASH=a9d50692e95b79723f3e76fcf70d023e")) and not ((record['PROCESS_NAME'].startswith("C:\\Program Files") or record['PROCESS_NAME'].startswith("C:\\Program Files (x86)"))))

sigma_execution_of_netsupport_rat_from_unusual_location.sigma_meta = dict(
    level="medium"
)

def sigma_sysinternals_sdelete_delete_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sdelete.yml
    title: Sysinternals SDelete Delete File
    fields: ['CommandLine', 'OriginalFileName']
    level: high
    description: Detects the use of SDelete to erase a file not the free space
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "sdelete.exe" and not ((record['COMMAND_LINE'].contains("-h") or record['COMMAND_LINE'].contains("-c") or record['COMMAND_LINE'].contains("-z") or record['COMMAND_LINE'].contains("/\\?"))))

sigma_sysinternals_sdelete_delete_file.sigma_meta = dict(
    level="high"
)

def sigma_accessing_winapi_via_commandline(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_inline_win_api_access.yml
    title: Accessing WinAPI Via CommandLine
    fields: ['CommandLine']
    level: high
    description: Detects the use of WinAPI Functions via the commandline as seen used by threat actors via the tool winapiexec
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("WaitForSingleObject") or record['COMMAND_LINE'].contains("QueueUserApc") or record['COMMAND_LINE'].contains("RtlCreateUserThread") or record['COMMAND_LINE'].contains("OpenProcess") or record['COMMAND_LINE'].contains("VirtualAlloc") or record['COMMAND_LINE'].contains("VirtualFree") or record['COMMAND_LINE'].contains("WriteProcessMemory") or record['COMMAND_LINE'].contains("CreateUserThread") or record['COMMAND_LINE'].contains("CloseHandle") or record['COMMAND_LINE'].contains("GetDelegateForFunctionPointer") or record['COMMAND_LINE'].contains("CreateThread") or record['COMMAND_LINE'].contains("memcpy") or record['COMMAND_LINE'].contains("LoadLibrary") or record['COMMAND_LINE'].contains("GetModuleHandle") or record['COMMAND_LINE'].contains("GetProcAddress") or record['COMMAND_LINE'].contains("VirtualProtect") or record['COMMAND_LINE'].contains("FreeLibrary") or record['COMMAND_LINE'].contains("ReadProcessMemory") or record['COMMAND_LINE'].contains("CreateRemoteThread") or record['COMMAND_LINE'].contains("AdjustTokenPrivileges") or record['COMMAND_LINE'].contains("WriteInt32") or record['COMMAND_LINE'].contains("OpenThreadToken") or record['COMMAND_LINE'].contains("PtrToString") or record['COMMAND_LINE'].contains("FreeHGlobal") or record['COMMAND_LINE'].contains("ZeroFreeGlobalAllocUnicode") or record['COMMAND_LINE'].contains("OpenProcessToken") or record['COMMAND_LINE'].contains("GetTokenInformation") or record['COMMAND_LINE'].contains("SetThreadToken") or record['COMMAND_LINE'].contains("ImpersonateLoggedOnUser") or record['COMMAND_LINE'].contains("RevertToSelf") or record['COMMAND_LINE'].contains("GetLogonSessionData") or record['COMMAND_LINE'].contains("CreateProcessWithToken") or record['COMMAND_LINE'].contains("DuplicateTokenEx") or record['COMMAND_LINE'].contains("OpenWindowStation") or record['COMMAND_LINE'].contains("OpenDesktop") or record['COMMAND_LINE'].contains("MiniDumpWriteDump") or record['COMMAND_LINE'].contains("AddSecurityPackage") or record['COMMAND_LINE'].contains("EnumerateSecurityPackages") or record['COMMAND_LINE'].contains("GetProcessHandle") or record['COMMAND_LINE'].contains("DangerousGetHandle") or record['COMMAND_LINE'].contains("kernel32") or record['COMMAND_LINE'].contains("Advapi32") or record['COMMAND_LINE'].contains("msvcrt") or record['COMMAND_LINE'].contains("ntdll") or record['COMMAND_LINE'].contains("user32") or record['COMMAND_LINE'].contains("secur32"))

sigma_accessing_winapi_via_commandline.sigma_meta = dict(
    level="high"
)

def sigma_rundll32_spawning_explorer(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_spawn_explorer.yml
    title: RunDLL32 Spawning Explorer
    fields: ['Image', 'ParentCommandLine', 'ParentImage']
    level: high
    description: Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\rundll32.exe") and record['PROCESS_NAME'].endswith("\\explorer.exe")) and not (record['PARENT_COMMAND_LINE'].contains("\\shell32.dll,Control_RunDLL")))

sigma_rundll32_spawning_explorer.sigma_meta = dict(
    level="high"
)

def sigma_whoami_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_whoami.yml
    title: Whoami Execution
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects the execution of whoami, which is often used by attackers after exploitation / privilege escalation but rarely used by administrators
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\whoami.exe") or record['ORIGINAL_FILE_NAME'] == "whoami.exe")

sigma_whoami_execution.sigma_meta = dict(
    level="medium"
)

def sigma_abusing_findstr_for_defense_evasion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_findstr.yml
    title: Abusing Findstr for Defense Evasion
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("findstr") or record['PROCESS_NAME'].endswith("findstr.exe") or record['ORIGINAL_FILE_NAME'] == "FINDSTR.EXE") and (((record['COMMAND_LINE'].contains("/v") or record['COMMAND_LINE'].contains("-v")) and (record['COMMAND_LINE'].contains("/l") or record['COMMAND_LINE'].contains("-l"))) or ((record['COMMAND_LINE'].contains("/s") or record['COMMAND_LINE'].contains("-s")) and (record['COMMAND_LINE'].contains("/i") or record['COMMAND_LINE'].contains("-i")))))

sigma_abusing_findstr_for_defense_evasion.sigma_meta = dict(
    level="medium"
)

def sigma_exploit_for_cve_2015_1641(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_exploit_cve_2015_1641.yml
    title: Exploit for CVE-2015-1641
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects Winword starting uncommon sub process MicroScMgmt.exe as used in exploits for CVE-2015-1641
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\WINWORD.EXE") and record['PROCESS_NAME'].endswith("\\MicroScMgmt.exe"))

sigma_exploit_for_cve_2015_1641.sigma_meta = dict(
    level="critical"
)

def sigma_securityxploded_tool(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_secutyxploded.yml
    title: SecurityXploded Tool
    fields: ['Image', 'OriginalFileName', 'Company']
    level: critical
    description: Detects the execution of SecurityXploded Tools
    logsource: category:process_creation - product:windows
    """
    return (record['COMPANY'] == "SecurityXploded" or record['PROCESS_NAME'].endswith("PasswordDump.exe") or record['ORIGINAL_FILE_NAME'].endswith("PasswordDump.exe"))

sigma_securityxploded_tool.sigma_meta = dict(
    level="critical"
)

def sigma_suspicious_eventlog_clear_or_configuration_using_wevtutil(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml
    title: Suspicious Eventlog Clear or Configuration Using Wevtutil
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects clearing or configuration of eventlogs using wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others).
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\wevtutil.exe") and (record['COMMAND_LINE'].contains("clear-log") or record['COMMAND_LINE'].contains("cl") or record['COMMAND_LINE'].contains("set-log") or record['COMMAND_LINE'].contains("sl"))) or ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("Clear-EventLog") or record['COMMAND_LINE'].contains("Remove-EventLog") or record['COMMAND_LINE'].contains("Limit-EventLog") or record['COMMAND_LINE'].contains("Clear-WinEvent"))) or (record['PROCESS_NAME'].endswith("\\wmic.exe") and record['COMMAND_LINE'].contains("ClearEventLog")))

sigma_suspicious_eventlog_clear_or_configuration_using_wevtutil.sigma_meta = dict(
    level="high"
)

def sigma_gpresult_display_group_policy_information(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_gpresult.yml
    title: Gpresult Display Group Policy Information
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information
    logsource: product:windows - category:process_creation
    """
    return (record['PROCESS_NAME'].endswith("\\gpresult.exe") and (record['COMMAND_LINE'].contains("/z") or record['COMMAND_LINE'].contains("/v")))

sigma_gpresult_display_group_policy_information.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_msdt_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_msdt.yml
    title: Renamed Msdt.exe
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects process creation with a renamed Msdt.exe
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "msdt.exe" and not ((record['PROCESS_NAME'].endswith("\\msdt.exe"))))

sigma_renamed_msdt_exe.sigma_meta = dict(
    level="high"
)

def sigma_set_windows_system_file_with_attrib(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_attrib_system.yml
    title: Set Windows System File with Attrib
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Marks a file as a system file using the attrib.exe utility
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\attrib.exe") or record['ORIGINAL_FILE_NAME'] == "ATTRIB.EXE") and record['COMMAND_LINE'].contains("+s"))

sigma_set_windows_system_file_with_attrib.sigma_meta = dict(
    level="low"
)

def sigma_service_imagepath_change_with_reg_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_reg_service_imagepath_change.yml
    title: Service ImagePath Change with Reg.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services

    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\reg.exe") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("SYSTEM\\CurrentControlSet\\Services") and record['COMMAND_LINE'].contains("ImagePath") and (record['COMMAND_LINE'].contains("/d") or record['COMMAND_LINE'].contains("-d")))

sigma_service_imagepath_change_with_reg_exe.sigma_meta = dict(
    level="medium"
)

def sigma_mavinject_inject_dll_into_running_process(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_creation_mavinject_process_injection.yml
    title: Mavinject Inject DLL Into Running Process
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects process injection using the signed Windows tool "Mavinject" via the "INJECTRUNNING" flag or a renamed execution of the tool
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("/INJECTRUNNING") or ((record['ORIGINAL_FILE_NAME'] == "mavinject32.exe" or record['ORIGINAL_FILE_NAME'] == "mavinject64.exe") and not ((record['PROCESS_NAME'].endswith("\\mavinject32.exe") or record['PROCESS_NAME'].endswith("\\mavinject64.exe")))))

sigma_mavinject_inject_dll_into_running_process.sigma_meta = dict(
    level="high"
)

def sigma_regsvr32_anomaly(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_regsvr32_anomalies.yml
    title: Regsvr32 Anomaly
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects various anomalies in relation to regsvr32.exe
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['COMMAND_LINE'].contains("\\Temp")) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and (record['PARENT_NAME'].endswith("\\powershell.exe") or record['PARENT_NAME'].endswith("\\pwsh.exe") or record['PARENT_NAME'].endswith("\\powershell_ise.exe"))) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['PARENT_NAME'].endswith("\\cmd.exe")) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['COMMAND_LINE'].contains("/i:") and record['COMMAND_LINE'].contains("http") and record['COMMAND_LINE'].endswith("scrobj.dll")) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and record['COMMAND_LINE'].contains("/i:") and record['COMMAND_LINE'].contains("ftp") and record['COMMAND_LINE'].endswith("scrobj.dll")) or (record['PROCESS_NAME'].endswith("\\wscript.exe") and record['PARENT_NAME'].endswith("\\regsvr32.exe")) or (record['PROCESS_NAME'].endswith("\\EXCEL.EXE") and record['COMMAND_LINE'].contains("..\\..\\..\\Windows\\System32\\regsvr32.exe")) or (record['PARENT_NAME'].endswith("\\mshta.exe") and record['PROCESS_NAME'].endswith("\\regsvr32.exe")) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and (record['COMMAND_LINE'].contains("\\AppData\\Local") or record['COMMAND_LINE'].contains("C:\\Users\\Public"))) or (record['PROCESS_NAME'].endswith("\\regsvr32.exe") and (record['COMMAND_LINE'].endswith(".jpg") or record['COMMAND_LINE'].endswith(".jpeg") or record['COMMAND_LINE'].endswith(".png") or record['COMMAND_LINE'].endswith(".gif") or record['COMMAND_LINE'].endswith(".bin") or record['COMMAND_LINE'].endswith(".tmp") or record['COMMAND_LINE'].endswith(".temp") or record['COMMAND_LINE'].endswith(".txt")))) and not (((record['COMMAND_LINE'].contains("\\AppData\\Local\\Microsoft\\Teams") or record['COMMAND_LINE'].contains("\\AppData\\Local\\WebEx\\WebEx64\\Meetings\\atucfobj.dll"))) or (record['PARENT_NAME'] == "C:\\Program Files\\Box\\Box\\FS\\streem.exe" and record['COMMAND_LINE'].contains("\\Program Files\\Box\\Box\\Temp")) or (record['COMMAND_LINE'].endswith("/s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll"))))

sigma_regsvr32_anomaly.sigma_meta = dict(
    level="high"
)

def sigma_ta505_dropper_load_pattern(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_ta505_dropper.yml
    title: TA505 Dropper Load Pattern
    fields: ['Image', 'OriginalFileName', 'ParentImage']
    level: critical
    description: Detects mshta loaded by wmiprvse as parent as used by TA505 malicious documents
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\wmiprvse.exe") and (record['PROCESS_NAME'].endswith("\\mshta.exe") or record['ORIGINAL_FILE_NAME'] == "mshta.exe"))

sigma_ta505_dropper_load_pattern.sigma_meta = dict(
    level="critical"
)

def sigma_veeambackup_database_credentials_dump(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.yml
    title: VeeamBackup Database Credentials Dump
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects dump of credentials in VeeamBackup dbo
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sqlcmd.exe") and record['COMMAND_LINE'].contains("SELECT") and record['COMMAND_LINE'].contains("TOP") and record['COMMAND_LINE'].contains("[VeeamBackup].[dbo].[Credentials]"))

sigma_veeambackup_database_credentials_dump.sigma_meta = dict(
    level="high"
)

def sigma_xsl_script_processing(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_xsl_script_processing.yml
    title: XSL Script Processing
    fields: ['CommandLine', 'Image']
    level: medium
    description: Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. Rule detects when adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\wmic.exe") and record['COMMAND_LINE'].contains("/format")) and not ((record['COMMAND_LINE'].contains("/Format:List") or record['COMMAND_LINE'].contains("/Format:htable") or record['COMMAND_LINE'].contains("/Format:hform") or record['COMMAND_LINE'].contains("/Format:table") or record['COMMAND_LINE'].contains("/Format:mof") or record['COMMAND_LINE'].contains("/Format:value") or record['COMMAND_LINE'].contains("/Format:rawxml") or record['COMMAND_LINE'].contains("/Format:xml") or record['COMMAND_LINE'].contains("/Format:csv")))) or record['PROCESS_NAME'].endswith("\\msxsl.exe"))

sigma_xsl_script_processing.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_listing_of_network_connections(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_network_listing_connections.yml
    title: Suspicious Listing of Network Connections
    fields: ['CommandLine']
    level: low
    description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("netstat") or (record['COMMAND_LINE'].contains("net") and ((record['COMMAND_LINE'].endswith("use") or record['COMMAND_LINE'].endswith("sessions")) or (record['COMMAND_LINE'].contains("use") or record['COMMAND_LINE'].contains("sessions")))))

sigma_suspicious_listing_of_network_connections.sigma_meta = dict(
    level="low"
)

def sigma_process_dump_via_rundll32_and_comsvcs_dll(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_process_dump_rundll32_comsvcs.yml
    title: Process Dump via Rundll32 and Comsvcs.dll
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects process memory dump via comsvcs.dll and rundll32 using different techniques (ordinal, minidump function...etc)
    logsource: category:process_creation - product:windows
    """
    return (((record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['ORIGINAL_FILE_NAME'] == "RUNDLL32.EXE" or record['COMMAND_LINE'].contains("rundll32")) and (record['COMMAND_LINE'].contains("comsvcs") and record['COMMAND_LINE'].contains("full") and (record['COMMAND_LINE'].contains("24") or record['COMMAND_LINE'].contains("#24") or record['COMMAND_LINE'].contains("#+24") or record['COMMAND_LINE'].contains("MiniDump")))) or record['COMMAND_LINE'].contains("#-4294967272"))

sigma_process_dump_via_rundll32_and_comsvcs_dll.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_grpconv_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_grpconv.yml
    title: Suspicious GrpConv Execution
    fields: ['CommandLine']
    level: high
    description: Detects the suspicious execution of a utility to convert Windows 3.x .grp files or for persistence purposes by malicious software or actors
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("grpconv.exe -o") or record['COMMAND_LINE'].contains("grpconv -o"))

sigma_suspicious_grpconv_execution.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_where_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_where_execution.yml
    title: Suspicious Where Execution
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.

    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\where.exe") or record['ORIGINAL_FILE_NAME'] == "where.exe") and (record['COMMAND_LINE'].contains("places.sqlite") or record['COMMAND_LINE'].contains("cookies.sqlite") or record['COMMAND_LINE'].contains("formhistory.sqlite") or record['COMMAND_LINE'].contains("logins.json") or record['COMMAND_LINE'].contains("key4.db") or record['COMMAND_LINE'].contains("key3.db") or record['COMMAND_LINE'].contains("sessionstore.jsonlz4") or record['COMMAND_LINE'].contains("History") or record['COMMAND_LINE'].contains("Bookmarks") or record['COMMAND_LINE'].contains("Cookies") or record['COMMAND_LINE'].contains("Login Data")))

sigma_suspicious_where_execution.sigma_meta = dict(
    level="low"
)

def sigma_winnti_pipemon_characteristics(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_winnti_pipemon.yml
    title: Winnti Pipemon Characteristics
    fields: ['CommandLine']
    level: critical
    description: Detects specific process characteristics of Winnti Pipemon malware reported by ESET
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("setup0.exe -p") or (record['COMMAND_LINE'].contains("setup.exe") and (record['COMMAND_LINE'].endswith("-x:0") or record['COMMAND_LINE'].endswith("-x:1") or record['COMMAND_LINE'].endswith("-x:2"))))

sigma_winnti_pipemon_characteristics.sigma_meta = dict(
    level="critical"
)

def sigma_use_of_the_sftp_exe_binary_as_a_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_sftp.yml
    title: Use Of The SFTP.EXE Binary As A LOLBIN
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects the usage of the "sftp.exe" binary as a LOLBIN by abusing the "-D" flag
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sftp.exe") and (record['COMMAND_LINE'].contains("-D ..") or record['COMMAND_LINE'].contains("-D C:")))

sigma_use_of_the_sftp_exe_binary_as_a_lolbin.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_pdqdeployrunner(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_pdqdeploy_runner_susp_children.yml
    title: Suspicious Execution Of PDQDeployRunner
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: medium
    description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].contains("PDQDeployRunner-") and ((record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\rundll32.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\csc.exe") or record['PROCESS_NAME'].endswith("\\dllhost.exe") or record['PROCESS_NAME'].endswith("\\certutil.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\wsl.exe")) or (record['PROCESS_NAME'].contains("C:\\Users\\Public") or record['PROCESS_NAME'].contains("C:\\ProgramData") or record['PROCESS_NAME'].contains("C:\\Windows\\TEMP") or record['PROCESS_NAME'].contains("\\AppData\\Local\\Temp")) or (record['COMMAND_LINE'].contains("iex") or record['COMMAND_LINE'].contains("Invoke-") or record['COMMAND_LINE'].contains("DownloadString") or record['COMMAND_LINE'].contains("http") or record['COMMAND_LINE'].contains("-enc") or record['COMMAND_LINE'].contains("-encodedcommand") or record['COMMAND_LINE'].contains("FromBase64String") or record['COMMAND_LINE'].contains("-decode") or record['COMMAND_LINE'].contains("-w hidden"))))

sigma_suspicious_execution_of_pdqdeployrunner.sigma_meta = dict(
    level="medium"
)

def sigma_silenttrinity_stager_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_silenttrinity_stage_use.yml
    title: SILENTTRINITY Stager Execution
    fields: ['Description']
    level: high
    description: Detects SILENTTRINITY stager use
    logsource: category:process_creation - product:windows
    """
    return record['DESCRIPTION'].contains("st2stager")

sigma_silenttrinity_stager_execution.sigma_meta = dict(
    level="high"
)

def sigma_invoke_obfuscation_var_launcher_obfuscation(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_var.yml
    title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated Powershell via VAR++ LAUNCHER
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("&&set") and record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("/c") and record['COMMAND_LINE'].contains("-f") and (record['COMMAND_LINE'].contains("{0}") or record['COMMAND_LINE'].contains("{1}") or record['COMMAND_LINE'].contains("{2}") or record['COMMAND_LINE'].contains("{3}") or record['COMMAND_LINE'].contains("{4}") or record['COMMAND_LINE'].contains("{5}")))

sigma_invoke_obfuscation_var_launcher_obfuscation.sigma_meta = dict(
    level="high"
)

def sigma_lsass_memory_dumping(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lsass_dump.yml
    title: LSASS Memory Dumping
    fields: ['CommandLine', 'Image']
    level: high
    description: Detect creation of dump files containing the memory space of lsass.exe, which contains sensitive credentials.
Identifies usage of Sysinternals procdump.exe to export the memory space of lsass.exe which contains sensitive credentials.

    logsource: category:process_creation - product:windows
    """
    return (((record['COMMAND_LINE'].contains("lsass") and record['COMMAND_LINE'].contains(".dmp")) and not (record['PROCESS_NAME'].endswith("\\werfault.exe"))) or (record['PROCESS_NAME'].contains("\\procdump") and record['PROCESS_NAME'].endswith(".exe") and record['COMMAND_LINE'].contains("lsass")))

sigma_lsass_memory_dumping.sigma_meta = dict(
    level="high"
)

def sigma_execution_via_workfolders_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_workfolders.yml
    title: Execution via WorkFolders.exe
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects using WorkFolders.exe to execute an arbitrary control.exe
    logsource: category:process_creation - product:windows - definition:Requirements: Sysmon ProcessCreation logging must be activated
    """
    return ((record['PROCESS_NAME'].endswith("\\control.exe") and record['PARENT_NAME'].endswith("\\WorkFolders.exe")) and not (record['PROCESS_NAME'] == "C:\\Windows\\System32\\control.exe"))

sigma_execution_via_workfolders_exe.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_subsystem_for_linux_bash_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_bash.yml
    title: Suspicious Subsystem for Linux Bash Execution
    fields: ['CommandLine', 'ParentCommandLine']
    level: medium
    description: Performs execution of specified file, can be used for defensive evasion.
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("bash.exe") and record['COMMAND_LINE'].contains("-c")) and not (((record['PARENT_COMMAND_LINE'].contains("C:\\Program Files\\Git\\post-install.bat") or record['PARENT_COMMAND_LINE'].contains("C:\\Program Files (x86)\\Git\\post-install.bat") or record['PARENT_COMMAND_LINE'].contains("echo /etc/post-install/*.post")) or record['COMMAND_LINE'].contains("echo /etc/post-install/*.post"))))

sigma_suspicious_subsystem_for_linux_bash_execution.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_recon_activity_using_findstr_keywords(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_findstr_recon_everyone.yml
    title: Suspicious Recon Activity Using Findstr Keywords
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: medium
    description: Detects usage of findstr with the "EVERYONE" keyword. This is often used in combination with icacls to look for misconfigured files or folders permissions
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\findstr.exe") and record['ORIGINAL_FILE_NAME'] == "FINDSTR.EXE" and (record['COMMAND_LINE'].contains("\"Everyone\"") or record['COMMAND_LINE'].contains("\'Everyone\'"))) or (record['COMMAND_LINE'].contains("icacls") and record['COMMAND_LINE'].contains("findstr") and record['COMMAND_LINE'].contains("Everyone")))

sigma_suspicious_recon_activity_using_findstr_keywords.sigma_meta = dict(
    level="medium"
)

def sigma_modifies_the_registry_from_a_file(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_regini.yml
    title: Modifies the Registry From a File
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: low
    description: Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\regini.exe") or record['ORIGINAL_FILE_NAME'] == "REGINI.EXE") and not (re.match(':[^ \\\\]', record['COMMAND_LINE'])))

sigma_modifies_the_registry_from_a_file.sigma_meta = dict(
    level="low"
)

def sigma_lazarus_session_highjacker(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_lazarus_session_highjack.yml
    title: Lazarus Session Highjacker
    fields: ['Image']
    level: high
    description: Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\msdtc.exe") or record['PROCESS_NAME'].endswith("\\gpvc.exe")) and not ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64"))))

sigma_lazarus_session_highjacker.sigma_meta = dict(
    level="high"
)

def sigma_execution_via_mssql_xp_cmdshell_stored_procedure(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
    title: Execution via MSSQL Xp_cmdshell Stored Procedure
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects execution via MSSQL xp_cmdshell stored procedure. Malicious users may attempt to elevate their privileges by using xp_cmdshell, which is disabled by default.
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\cmd.exe") and record['PARENT_NAME'].endswith("\\sqlservr.exe"))

sigma_execution_via_mssql_xp_cmdshell_stored_procedure.sigma_meta = dict(
    level="high"
)

def sigma_execution_of_suspicious_file_type_extension(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_non_exe_image.yml
    title: Execution of Suspicious File Type Extension
    fields: ['Image', 'ParentImage']
    level: high
    description: Checks whether the image specified in a process creation event doesn't refer to an .exe file (caused by process ghosting or other unorthodox methods to start a process)
    logsource: category:process_creation - product:windows
    """
    return (not ((record['PROCESS_NAME'].endswith(".exe") or record['PROCESS_NAME'].endswith(".tmp"))) and not ((record.get('PROCESS_NAME', None) == None) or ((record['PROCESS_NAME'] == "Registry" or record['PROCESS_NAME'] == "MemCompression" or record['PROCESS_NAME'] == "vmmem")) or ((record['PROCESS_NAME'] == "-" or record['PROCESS_NAME'] == "")) or (record['PROCESS_NAME'].startswith("C:\\Windows\\Installer\\MSI")) or ((record['PARENT_NAME'].startswith("C:\\ProgramData\\Avira") or record['PARENT_NAME'].startswith("C:\\Windows\\System32\\DriverStore\\FileRepository"))) or (record['PROCESS_NAME'].endswith(".scr")) or (record['PROCESS_NAME'].contains("NVIDIA\\NvBackend") and record['PROCESS_NAME'].endswith(".dat")) or ((record['PROCESS_NAME'].startswith("C:\\Windows\\System32") or record['PROCESS_NAME'].startswith("C:\\Windows\\SysWOW64")) and record['PROCESS_NAME'].endswith(".com")) or (record['PROCESS_NAME'].endswith("\\WinSCP.com")) or (record['PROCESS_NAME'].contains("C:\\Users") and record['PROCESS_NAME'].contains("\\AppData") and record['PROCESS_NAME'].contains(".tmp") and record['PROCESS_NAME'].contains("CodeSetup")) or (record['PROCESS_NAME'].endswith("\\program\\soffice.bin")) or ((record['PROCESS_NAME'] == "C:\\Program Files\\EMC NetWorker\\Management\\GST\\apache\\cgi-bin\\update_jnlp.cgi" or record['PROCESS_NAME'] == "C:\\Program Files (x86)\\EMC NetWorker\\Management\\GST\\apache\\cgi-bin\\update_jnlp.cgi")) or ((record['PROCESS_NAME'].startswith("C:\\Program Files (x86)\\WINPAKPRO") or record['PROCESS_NAME'].startswith("C:\\Program Files\\WINPAKPRO")) and record['PROCESS_NAME'].endswith(".ngn")) or ((record['PROCESS_NAME'] == "C:\\Program Files (x86)\\MyQ\\Server\\pcltool.dll" or record['PROCESS_NAME'] == "C:\\Program Files\\MyQ\\Server\\pcltool.dll")) or ((record['PROCESS_NAME'].startswith("C:\\Program Files\\Microsoft Visual Studio") or record['PROCESS_NAME'].startswith("C:\\Program Files (x86)\\Microsoft Visual Studio")) and record['PROCESS_NAME'].endswith(".com")) or (record['PROCESS_NAME'].startswith("C:\\Config.Msi") and (record['PROCESS_NAME'].endswith(".rbf") or record['PROCESS_NAME'].endswith(".rbs"))) or (record['PROCESS_NAME'].contains("\\AppData\\Local\\Packages") and record['PROCESS_NAME'].contains("\\LocalState\\rootfs")) or (record['PROCESS_NAME'].endswith("\\LZMA_EXE")) or (record['PARENT_NAME'].startswith("C:\\Windows\\Temp") and record['PROCESS_NAME'].startswith("C:\\Windows\\Temp\\Helper")) or (record['PARENT_NAME'].startswith("C:\\Windows\\Temp") and record['PARENT_NAME'].endswith("\\TBT_Dock_Firmware\\GetDockVer32W.exe"))))

sigma_execution_of_suspicious_file_type_extension.sigma_meta = dict(
    level="high"
)

def sigma_powershell_defender_exclusion(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_defender_exclusion.yml
    title: Powershell Defender Exclusion
    fields: ['CommandLine']
    level: medium
    description: Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets
    logsource: category:process_creation - product:windows
    """
    return ((record['COMMAND_LINE'].contains("Add-MpPreference") or record['COMMAND_LINE'].contains("Set-MpPreference")) and (record['COMMAND_LINE'].contains("-ExclusionPath") or record['COMMAND_LINE'].contains("-ExclusionExtension") or record['COMMAND_LINE'].contains("-ExclusionProcess") or record['COMMAND_LINE'].contains("-ExclusionIpAddress")))

sigma_powershell_defender_exclusion.sigma_meta = dict(
    level="medium"
)

def sigma_copy_dmp_files_from_share(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_copy_dmp_from_share.yml
    title: Copy DMP Files From Share
    fields: ['CommandLine']
    level: high
    description: Detects usage of the copy command to copy files with the .dmp extensions from a remote share
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains(".dmp") and record['COMMAND_LINE'].contains("copy") and record['COMMAND_LINE'].contains("") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/r") or record['COMMAND_LINE'].contains("/k")))

sigma_copy_dmp_files_from_share.sigma_meta = dict(
    level="high"
)

def sigma_certutil_encode(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_certutil_encode.yml
    title: Certutil Encode
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\certutil.exe") and record['COMMAND_LINE'].contains("-f") and record['COMMAND_LINE'].contains("-encode"))

sigma_certutil_encode.sigma_meta = dict(
    level="medium"
)

def sigma_renamed_or_portable_vmnat_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_renamed_vmnat.yml
    title: Renamed or Portable Vmnat.exe
    fields: ['Image', 'OriginalFileName']
    level: high
    description: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "vmnat.exe" and not ((record['PROCESS_NAME'].endswith("vmnat.exe")) or ((record['PROCESS_NAME'] == "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmnat.exe" or record['PROCESS_NAME'] == "C:\\Windows\\SysWOW64\\vmnat.exe"))))

sigma_renamed_or_portable_vmnat_exe.sigma_meta = dict(
    level="high"
)

def sigma_modification_of_boot_configuration(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_bootconf_mod.yml
    title: Modification of Boot Configuration
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\bcdedit.exe") or record['ORIGINAL_FILE_NAME'] == "bcdedit.exe") and record['COMMAND_LINE'].contains("set") and ((record['COMMAND_LINE'].contains("bootstatuspolicy") and record['COMMAND_LINE'].contains("ignoreallfailures")) or (record['COMMAND_LINE'].contains("recoveryenabled") and record['COMMAND_LINE'].contains("no"))))

sigma_modification_of_boot_configuration.sigma_meta = dict(
    level="high"
)

def sigma_cl_mutexverifiers_ps1_proxy_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_cl_mutexverifiers.yml
    title: CL_Mutexverifiers.ps1 Proxy Execution
    fields: ['CommandLine']
    level: medium
    description: Detects the use of a Microsoft signed script to execute commands
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("\\CL_Mutexverifiers.ps1") and record['COMMAND_LINE'].contains("runAfterCancelProcess"))

sigma_cl_mutexverifiers_ps1_proxy_execution.sigma_meta = dict(
    level="medium"
)

def sigma_invoke_obfuscation_clip_launcher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_invoke_obfuscation_clip.yml
    title: Invoke-Obfuscation CLIP+ Launcher
    fields: ['CommandLine']
    level: high
    description: Detects Obfuscated use of Clip.exe to execute PowerShell
    logsource: category:process_creation - product:windows
    """
    return (record['COMMAND_LINE'].contains("cmd") and record['COMMAND_LINE'].contains("&&") and record['COMMAND_LINE'].contains("clipboard]::") and record['COMMAND_LINE'].contains("-f") and (record['COMMAND_LINE'].contains("/c") or record['COMMAND_LINE'].contains("/r")))

sigma_invoke_obfuscation_clip_launcher.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_call_by_ordinal(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_rundll32_by_ordinal.yml
    title: Suspicious Call by Ordinal
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\rundll32.exe") and (record['COMMAND_LINE'].contains(",#") or record['COMMAND_LINE'].contains(", #") or record['COMMAND_LINE'].contains(".dll #") or record['COMMAND_LINE'].contains(".ocx #"))) and not ((record['COMMAND_LINE'].contains("EDGEHTML.dll") and record['COMMAND_LINE'].contains("#141")) or ((record['PARENT_NAME'].contains("\\Msbuild\\Current\\Bin") or record['PARENT_NAME'].contains("\\Tracker.exe")) and (record['COMMAND_LINE'].contains("\\FileTracker32.dll,#1") or record['COMMAND_LINE'].contains("\\FileTracker32.dll\",#1") or record['COMMAND_LINE'].contains("\\FileTracker64.dll,#1") or record['COMMAND_LINE'].contains("\\FileTracker64.dll\",#1")))))

sigma_suspicious_call_by_ordinal.sigma_meta = dict(
    level="high"
)

def sigma_powershell_get_process_lsass(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_powershell_getprocess_lsass.yml
    title: PowerShell Get-Process LSASS
    fields: ['CommandLine']
    level: high
    description: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
    logsource: category:process_creation - product:windows
    """
    return record['COMMAND_LINE'].contains("Get-Process lsass")

sigma_powershell_get_process_lsass.sigma_meta = dict(
    level="high"
)

def sigma_microsoft_outlook_product_spawning_windows_shell(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_outlook_shell.yml
    title: Microsoft Outlook Product Spawning Windows Shell
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects a Windows command and scripting interpreter executable started from Microsoft Outlook
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\OUTLOOK.EXE") and (record['PROCESS_NAME'].endswith("\\cmd.exe") or record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe") or record['PROCESS_NAME'].endswith("\\wscript.exe") or record['PROCESS_NAME'].endswith("\\cscript.exe") or record['PROCESS_NAME'].endswith("\\sh.exe") or record['PROCESS_NAME'].endswith("\\bash.exe") or record['PROCESS_NAME'].endswith("\\scrcons.exe") or record['PROCESS_NAME'].endswith("\\schtasks.exe") or record['PROCESS_NAME'].endswith("\\regsvr32.exe") or record['PROCESS_NAME'].endswith("\\hh.exe") or record['PROCESS_NAME'].endswith("\\wmic.exe") or record['PROCESS_NAME'].endswith("\\mshta.exe") or record['PROCESS_NAME'].endswith("\\msiexec.exe") or record['PROCESS_NAME'].endswith("\\forfiles.exe") or record['PROCESS_NAME'].endswith("\\scriptrunner.exe") or record['PROCESS_NAME'].endswith("\\mftrace.exe") or record['PROCESS_NAME'].endswith("\\AppVLP.exe") or record['PROCESS_NAME'].endswith("\\svchost.exe") or record['PROCESS_NAME'].endswith("\\msbuild.exe") or record['PROCESS_NAME'].endswith("\\msdt.exe")))

sigma_microsoft_outlook_product_spawning_windows_shell.sigma_meta = dict(
    level="high"
)

def sigma_renamed_zoho_dctask64(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_renamed_dctask64.yml
    title: Renamed ZOHO Dctask64
    fields: ['Image', 'Hashes']
    level: high
    description: Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation
    logsource: category:process_creation - product:windows
    """
    return (record['HASHES'].contains("6834B1B94E49701D77CCB3C0895E1AFD") and not (record['PROCESS_NAME'].endswith("\\dctask64.exe")))

sigma_renamed_zoho_dctask64.sigma_meta = dict(
    level="high"
)

def sigma_webshell_hacking_activity_patterns(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_webshell_hacking.yml
    title: Webshell Hacking Activity Patterns
    fields: ['CommandLine', 'Image', 'ParentImage']
    level: high
    description: Detects certain parent child patterns found in cases in which a webshell is used to perform certain credential dumping or exfiltration activities on a compromised system
    logsource: category:process_creation - product:windows
    """
    return (((record['PARENT_NAME'].endswith("\\w3wp.exe") or record['PARENT_NAME'].endswith("\\php-cgi.exe") or record['PARENT_NAME'].endswith("\\nginx.exe") or record['PARENT_NAME'].endswith("\\httpd.exe") or record['PARENT_NAME'].endswith("\\caddy.exe") or record['PARENT_NAME'].endswith("\\ws_tomcatservice.exe")) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['PARENT_NAME'].contains("-tomcat-") or record['PARENT_NAME'].contains("\\tomcat"))) or ((record['PARENT_NAME'].endswith("\\java.exe") or record['PARENT_NAME'].endswith("\\javaw.exe")) and (record['COMMAND_LINE'].contains("catalina.jar") or record['COMMAND_LINE'].contains("CATALINA_HOME")))) and ((record['COMMAND_LINE'].contains("rundll32") and record['COMMAND_LINE'].contains("comsvcs")) or (record['COMMAND_LINE'].contains("-hp") and record['COMMAND_LINE'].contains("a") and record['COMMAND_LINE'].contains("-m")) or (record['COMMAND_LINE'].contains("net") and record['COMMAND_LINE'].contains("user") and record['COMMAND_LINE'].contains("/add")) or (record['COMMAND_LINE'].contains("net") and record['COMMAND_LINE'].contains("localgroup") and record['COMMAND_LINE'].contains("administrators") and record['COMMAND_LINE'].contains("/add")) or (record['PROCESS_NAME'].endswith("\\ntdsutil.exe") or record['PROCESS_NAME'].endswith("\\ldifde.exe") or record['PROCESS_NAME'].endswith("\\adfind.exe") or record['PROCESS_NAME'].endswith("\\procdump.exe") or record['PROCESS_NAME'].endswith("\\Nanodump.exe") or record['PROCESS_NAME'].endswith("\\vssadmin.exe") or record['PROCESS_NAME'].endswith("\\fsutil.exe")) or (record['COMMAND_LINE'].contains("-NoP") or record['COMMAND_LINE'].contains("-W Hidden") or record['COMMAND_LINE'].contains("-decode") or record['COMMAND_LINE'].contains("/decode") or record['COMMAND_LINE'].contains("reg save") or record['COMMAND_LINE'].contains(".downloadstring(") or record['COMMAND_LINE'].contains(".downloadfile(") or record['COMMAND_LINE'].contains("FromBase64String") or record['COMMAND_LINE'].contains("/ticket:") or record['COMMAND_LINE'].contains("sekurlsa") or record['COMMAND_LINE'].contains(".dmp full") or record['COMMAND_LINE'].contains("process call create") or record['COMMAND_LINE'].contains("whoami /priv"))))

sigma_webshell_hacking_activity_patterns.sigma_meta = dict(
    level="high"
)

def sigma_suspicious_powershell_parameter_substring(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_powershell_susp_parameter_variation.yml
    title: Suspicious PowerShell Parameter Substring
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects suspicious PowerShell invocation with a parameter substring
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\powershell.exe") or record['PROCESS_NAME'].endswith("\\pwsh.exe")) and (record['COMMAND_LINE'].contains("-windowstyle h") or record['COMMAND_LINE'].contains("-windowstyl h") or record['COMMAND_LINE'].contains("-windowsty h") or record['COMMAND_LINE'].contains("-windowst h") or record['COMMAND_LINE'].contains("-windows h") or record['COMMAND_LINE'].contains("-windo h") or record['COMMAND_LINE'].contains("-wind h") or record['COMMAND_LINE'].contains("-win h") or record['COMMAND_LINE'].contains("-wi h") or record['COMMAND_LINE'].contains("-win h") or record['COMMAND_LINE'].contains("-win hi") or record['COMMAND_LINE'].contains("-win hid") or record['COMMAND_LINE'].contains("-win hidd") or record['COMMAND_LINE'].contains("-win hidde") or record['COMMAND_LINE'].contains("-NoPr") or record['COMMAND_LINE'].contains("-NoPro") or record['COMMAND_LINE'].contains("-NoProf") or record['COMMAND_LINE'].contains("-NoProfi") or record['COMMAND_LINE'].contains("-NoProfil") or record['COMMAND_LINE'].contains("-nonin") or record['COMMAND_LINE'].contains("-nonint") or record['COMMAND_LINE'].contains("-noninte") or record['COMMAND_LINE'].contains("-noninter") or record['COMMAND_LINE'].contains("-nonintera") or record['COMMAND_LINE'].contains("-noninterac") or record['COMMAND_LINE'].contains("-noninteract") or record['COMMAND_LINE'].contains("-noninteracti") or record['COMMAND_LINE'].contains("-noninteractiv") or record['COMMAND_LINE'].contains("-ec") or record['COMMAND_LINE'].contains("-encodedComman") or record['COMMAND_LINE'].contains("-encodedComma") or record['COMMAND_LINE'].contains("-encodedComm") or record['COMMAND_LINE'].contains("-encodedCom") or record['COMMAND_LINE'].contains("-encodedCo") or record['COMMAND_LINE'].contains("-encodedC") or record['COMMAND_LINE'].contains("-encoded") or record['COMMAND_LINE'].contains("-encode") or record['COMMAND_LINE'].contains("-encod") or record['COMMAND_LINE'].contains("-enco") or record['COMMAND_LINE'].contains("-en") or record['COMMAND_LINE'].contains("-executionpolic") or record['COMMAND_LINE'].contains("-executionpoli") or record['COMMAND_LINE'].contains("-executionpol") or record['COMMAND_LINE'].contains("-executionpo") or record['COMMAND_LINE'].contains("-executionp") or record['COMMAND_LINE'].contains("-execution bypass") or record['COMMAND_LINE'].contains("-executio bypass") or record['COMMAND_LINE'].contains("-executi bypass") or record['COMMAND_LINE'].contains("-execut bypass") or record['COMMAND_LINE'].contains("-execu bypass") or record['COMMAND_LINE'].contains("-exec bypass") or record['COMMAND_LINE'].contains("-exe bypass") or record['COMMAND_LINE'].contains("-ex bypass") or record['COMMAND_LINE'].contains("-ep bypass") or record['COMMAND_LINE'].contains("/windowstyle h") or record['COMMAND_LINE'].contains("/windowstyl h") or record['COMMAND_LINE'].contains("/windowsty h") or record['COMMAND_LINE'].contains("/windowst h") or record['COMMAND_LINE'].contains("/windows h") or record['COMMAND_LINE'].contains("/windo h") or record['COMMAND_LINE'].contains("/wind h") or record['COMMAND_LINE'].contains("/win h") or record['COMMAND_LINE'].contains("/wi h") or record['COMMAND_LINE'].contains("/win h") or record['COMMAND_LINE'].contains("/win hi") or record['COMMAND_LINE'].contains("/win hid") or record['COMMAND_LINE'].contains("/win hidd") or record['COMMAND_LINE'].contains("/win hidde") or record['COMMAND_LINE'].contains("/NoPr") or record['COMMAND_LINE'].contains("/NoPro") or record['COMMAND_LINE'].contains("/NoProf") or record['COMMAND_LINE'].contains("/NoProfi") or record['COMMAND_LINE'].contains("/NoProfil") or record['COMMAND_LINE'].contains("/nonin") or record['COMMAND_LINE'].contains("/nonint") or record['COMMAND_LINE'].contains("/noninte") or record['COMMAND_LINE'].contains("/noninter") or record['COMMAND_LINE'].contains("/nonintera") or record['COMMAND_LINE'].contains("/noninterac") or record['COMMAND_LINE'].contains("/noninteract") or record['COMMAND_LINE'].contains("/noninteracti") or record['COMMAND_LINE'].contains("/noninteractiv") or record['COMMAND_LINE'].contains("/ec") or record['COMMAND_LINE'].contains("/encodedComman") or record['COMMAND_LINE'].contains("/encodedComma") or record['COMMAND_LINE'].contains("/encodedComm") or record['COMMAND_LINE'].contains("/encodedCom") or record['COMMAND_LINE'].contains("/encodedCo") or record['COMMAND_LINE'].contains("/encodedC") or record['COMMAND_LINE'].contains("/encoded") or record['COMMAND_LINE'].contains("/encode") or record['COMMAND_LINE'].contains("/encod") or record['COMMAND_LINE'].contains("/enco") or record['COMMAND_LINE'].contains("/en") or record['COMMAND_LINE'].contains("/executionpolic") or record['COMMAND_LINE'].contains("/executionpoli") or record['COMMAND_LINE'].contains("/executionpol") or record['COMMAND_LINE'].contains("/executionpo") or record['COMMAND_LINE'].contains("/executionp") or record['COMMAND_LINE'].contains("/execution bypass") or record['COMMAND_LINE'].contains("/executio bypass") or record['COMMAND_LINE'].contains("/executi bypass") or record['COMMAND_LINE'].contains("/execut bypass") or record['COMMAND_LINE'].contains("/execu bypass") or record['COMMAND_LINE'].contains("/exec bypass") or record['COMMAND_LINE'].contains("/exe bypass") or record['COMMAND_LINE'].contains("/ex bypass") or record['COMMAND_LINE'].contains("/ep bypass")))

sigma_suspicious_powershell_parameter_substring.sigma_meta = dict(
    level="high"
)

def sigma_net_exe_user_account_creation_never_expire(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_net_user_add_never_expire.yml
    title: Net.exe User Account Creation - Never Expire
    fields: ['CommandLine', 'Image']
    level: high
    description: Detects creation of local users via the net.exe command with the option "never expire"
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\net.exe") or record['PROCESS_NAME'].endswith("\\net1.exe")) and record['COMMAND_LINE'].contains("user") and record['COMMAND_LINE'].contains("add") and record['COMMAND_LINE'].contains("expires:never"))

sigma_net_exe_user_account_creation_never_expire.sigma_meta = dict(
    level="high"
)

def sigma_dumping_process_via_sqldumper_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_lolbin_susp_sqldumper_activity.yml
    title: Dumping Process via Sqldumper.exe
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects process dump via legitimate sqldumper.exe binary
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\sqldumper.exe") and (record['COMMAND_LINE'].contains("0x0110") or record['COMMAND_LINE'].contains("0x01100:40")))

sigma_dumping_process_via_sqldumper_exe.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_process_parents(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_parents.yml
    title: Suspicious Process Parents
    fields: ['Image', 'ParentImage']
    level: high
    description: Detects suspicious parent processes that should not have any children or should only have a single possible child program
    logsource: category:process_creation - product:windows
    """
    return ((record['PARENT_NAME'].endswith("\\minesweeper.exe") or record['PARENT_NAME'].endswith("\\winver.exe") or record['PARENT_NAME'].endswith("\\bitsadmin.exe")) or ((record['PARENT_NAME'].endswith("\\csrss.exe") or record['PARENT_NAME'].endswith("\\certutil.exe") or record['PARENT_NAME'].endswith("\\eventvwr.exe") or record['PARENT_NAME'].endswith("\\calc.exe") or record['PARENT_NAME'].endswith("\\notepad.exe")) and not (((record['PROCESS_NAME'].endswith("\\WerFault.exe") or record['PROCESS_NAME'].endswith("\\wermgr.exe") or record['PROCESS_NAME'].endswith("\\conhost.exe") or record['PROCESS_NAME'].endswith("\\mmc.exe") or record['PROCESS_NAME'].endswith("\\win32calc.exe") or record['PROCESS_NAME'].endswith("\\notepad.exe"))) or (record.get('PROCESS_NAME', None) == None))))

sigma_suspicious_process_parents.sigma_meta = dict(
    level="high"
)

def sigma_recon_information_for_export_with_command_prompt(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_recon.yml
    title: Recon Information for Export with Command Prompt
    fields: ['Image', 'ParentCommandLine', 'OriginalFileName']
    level: medium
    description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
    logsource: product:windows - category:process_creation
    """
    return (((record['PROCESS_NAME'].endswith("\\tree.com") or record['PROCESS_NAME'].endswith("\\WMIC.exe") or record['PROCESS_NAME'].endswith("\\doskey.exe") or record['PROCESS_NAME'].endswith("\\sc.exe")) or (record['ORIGINAL_FILE_NAME'] == "wmic.exe" or record['ORIGINAL_FILE_NAME'] == "DOSKEY.EXE" or record['ORIGINAL_FILE_NAME'] == "sc.exe")) and (record['PARENT_COMMAND_LINE'].contains("> %TEMP%") or record['PARENT_COMMAND_LINE'].contains("> %TMP%")))

sigma_recon_information_for_export_with_command_prompt.sigma_meta = dict(
    level="medium"
)

def sigma_sharpldapwhoami(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_hack_sharpldapwhoami.yml
    title: SharpLdapWhoami
    fields: ['CommandLine', 'Image', 'OriginalFileName', 'Product']
    level: high
    description: Detects SharpLdapWhoami, a whoami alternative by asking the LDAP service on a domain controller
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\SharpLdapWhoami.exe") or record['ORIGINAL_FILE_NAME'].contains("SharpLdapWhoami") or record['PRODUCT_NAME'] == "SharpLdapWhoami" or (record['COMMAND_LINE'].endswith("/method:ntlm") or record['COMMAND_LINE'].endswith("/method:kerb") or record['COMMAND_LINE'].endswith("/method:nego") or record['COMMAND_LINE'].endswith("/m:nego") or record['COMMAND_LINE'].endswith("/m:ntlm") or record['COMMAND_LINE'].endswith("/m:kerb")))

sigma_sharpldapwhoami.sigma_meta = dict(
    level="high"
)

def sigma_squirrel_lolbin(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_squirrel_lolbin.yml
    title: Squirrel Lolbin
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects Possible Squirrel Packages Manager as Lolbin
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\update.exe") and record['COMMAND_LINE'].contains(".exe") and (record['COMMAND_LINE'].contains("--processStart") or record['COMMAND_LINE'].contains("--processStartAndWait") or record['COMMAND_LINE'].contains("--createShortcut"))) and not ((record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local\\Discord\\Update.exe") and record['COMMAND_LINE'].contains("--processStart") and record['COMMAND_LINE'].contains("Discord.exe")) or (record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local\\GitHubDesktop\\Update.exe") and record['COMMAND_LINE'].contains("GitHubDesktop.exe") and (record['COMMAND_LINE'].contains("--createShortcut") or record['COMMAND_LINE'].contains("--processStartAndWait"))) or (record['COMMAND_LINE'].contains("C:\\Users") and record['COMMAND_LINE'].contains("\\AppData\\Local\\Microsoft\\Teams\\Update.exe") and record['COMMAND_LINE'].contains("Teams.exe") and (record['COMMAND_LINE'].contains("--processStart") or record['COMMAND_LINE'].contains("--createShortcut")))))

sigma_squirrel_lolbin.sigma_meta = dict(
    level="medium"
)

def sigma_remote_powershell_session_host_process_winrm_(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_remote_powershell_session_process.yml
    title: Remote PowerShell Session Host Process (WinRM)
    fields: ['Image', 'ParentImage']
    level: medium
    description: Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wsmprovhost.exe") or record['PARENT_NAME'].endswith("\\wsmprovhost.exe"))

sigma_remote_powershell_session_host_process_winrm_.sigma_meta = dict(
    level="medium"
)

def sigma_psexec_service_execution(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_psexesvc.yml
    title: PsExec Service Execution
    fields: ['Image', 'OriginalFileName']
    level: medium
    description: Detects launch of the PSEXESVC service, which means that this system was the target of a psexec remote execution
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'] == "C:\\Windows\\PSEXESVC.exe" or record['ORIGINAL_FILE_NAME'] == "psexesvc.exe")

sigma_psexec_service_execution.sigma_meta = dict(
    level="medium"
)

def sigma_reg_add_suspicious_paths(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_reg_add.yml
    title: Reg Add Suspicious Paths
    fields: ['CommandLine', 'Image', 'OriginalFileName']
    level: high
    description: Detects when an adversary uses the reg.exe utility to add or modify new keys or subkeys
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\reg.exe") or record['ORIGINAL_FILE_NAME'] == "reg.exe") and (record['COMMAND_LINE'].contains("\\AppDataLow\\Software\\Microsoft") or record['COMMAND_LINE'].contains("\\Policies\\Microsoft\\Windows\\OOBE") or record['COMMAND_LINE'].contains("\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") or record['COMMAND_LINE'].contains("\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon") or record['COMMAND_LINE'].contains("\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") or record['COMMAND_LINE'].contains("\\Microsoft\\Windows Defender")))

sigma_reg_add_suspicious_paths.sigma_meta = dict(
    level="high"
)

def sigma_process_dump_via_rdrleakdiag_exe(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_process_dump_rdrleakdiag.yml
    title: Process Dump via RdrLeakDiag.exe
    fields: ['CommandLine', 'OriginalFileName']
    level: high
    description: Detects a process memory dump performed by RdrLeakDiag.exe
    logsource: category:process_creation - product:windows
    """
    return (record['ORIGINAL_FILE_NAME'] == "RdrLeakDiag.exe" and record['COMMAND_LINE'].contains("fullmemdmp"))

sigma_process_dump_via_rdrleakdiag_exe.sigma_meta = dict(
    level="high"
)

def sigma_wevtutil_recon(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_wevtutil_recon.yml
    title: Wevtutil Recon
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of the wevtutil utility to perform reconnaissance
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\wevtutil.exe") and (record['COMMAND_LINE'].contains("qe") or record['COMMAND_LINE'].contains("query-events")) and (record['COMMAND_LINE'].contains("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational") or record['COMMAND_LINE'].contains("Microsoft-Windows-Terminal-Services-RemoteConnectionManager/Operational")))

sigma_wevtutil_recon.sigma_meta = dict(
    level="medium"
)

def sigma_suspicious_execution_of_shutdown(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_susp_shutdown.yml
    title: Suspicious Execution of Shutdown
    fields: ['CommandLine', 'Image']
    level: medium
    description: Use of the commandline to shutdown or reboot windows
    logsource: category:process_creation - product:windows
    """
    return (record['PROCESS_NAME'].endswith("\\shutdown.exe") and (record['COMMAND_LINE'].contains("/r") or record['COMMAND_LINE'].contains("/s")))

sigma_suspicious_execution_of_shutdown.sigma_meta = dict(
    level="medium"
)

def sigma_obfuscated_ip_via_cli(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_obfuscated_ip_via_cli.yml
    title: Obfuscated IP Via CLI
    fields: ['CommandLine', 'Image']
    level: medium
    description: Detects usage of an encoded/obfuscated version of an IP address (hex, octal...) via commandline
    logsource: category:process_creation - product:windows
    """
    return ((record['PROCESS_NAME'].endswith("\\ping.exe") or record['PROCESS_NAME'].endswith("\\arp.exe")) and (record['COMMAND_LINE'].contains("0x") or re.match(' [0-9]{7,13}', record['COMMAND_LINE'])))

sigma_obfuscated_ip_via_cli.sigma_meta = dict(
    level="medium"
)

def sigma_emissary_panda_malware_sllauncher(record):
    """
    file_id: rules/windows/process_creation/proc_creation_win_apt_emissarypanda_sep19.yml
    title: Emissary Panda Malware SLLauncher
    fields: ['Image', 'ParentImage']
    level: critical
    description: Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27
    logsource: category:process_creation - product:windows
    """
    return (record['PARENT_NAME'].endswith("\\sllauncher.exe") and record['PROCESS_NAME'].endswith("\\svchost.exe"))

sigma_emissary_panda_malware_sllauncher.sigma_meta = dict(
    level="critical"
)

CLI_ONLY_COMPAT_METHODS=[
  "sigma_suspicious_reg_add_bitlocker",
  "sigma_hurricane_panda_activity",
  "sigma_uac_bypass_using_event_viewer_recentviews",
  "sigma_invoke_obfuscation_obfuscated_iex_invocation",
  "sigma_suspicious_powershell_download_and_execute_pattern",
  "sigma_crackmapexec_command_line_flags",
  "sigma_mstsc_shadowing",
  "sigma_suspicious_printerports_creation_cve_2020_1048_",
  "sigma_anydesk_inline_piped_password",
  "sigma_firewall_disabled_via_netsh",
  "sigma_execution_via_cl_invocation_ps1",
  "sigma_persistence_via_typedpaths_commandline",
  "sigma_obfuscated_ip_download",
  "sigma_suspicious_commandline_escape",
  "sigma_fireball_archer_install",
  "sigma_whoami_as_parameter",
  "sigma_hydra_password_guessing_hack_tool",
  "sigma_suspicious_powershell_mailbox_export_to_share",
  "sigma_suspicious_dosfuscation_character_in_commandline",
  "sigma_taskkill_symantec_endpoint_protection",
  "sigma_suspicious_powershell_no_file_or_command",
  "sigma_anydesk_silent_installation",
  "sigma_suspicious_scan_loop_network",
  "sigma_copy_from_volume_shadow_copy",
  "sigma_crackmapexec_powershell_obfuscation",
  "sigma_psexec_service_start",
  "sigma_lockergoga_ransomware",
  "sigma_rundll32_js_runhtmlapplication_pattern",
  "sigma_sticky_key_backdoor_copy_cmd_exe",
  "sigma_complus_etwenabled_command_line_arguments",
  "sigma_sofacy_trojan_loader_activity",
  "sigma_systemnightmare_exploitation_script_execution",
  "sigma_abusable_invoke_athremotefxvgpudisablementcommand",
  "sigma_powershell_encoded_character_syntax",
  "sigma_invoke_obfuscation_stdin_launcher",
  "sigma_msiexec_web_install",
  "sigma_adcspwn_hack_tool",
  "sigma_disabled_ie_security_features",
  "sigma_invoke_obfuscation_via_use_rundll32",
  "sigma_arbitrary_shell_command_execution_via_settingcontent_ms",
  "sigma_dropping_of_password_filter_dll",
  "sigma_suspicious_encoded_obfuscated_load_string",
  "sigma_suspicious_use_of_procdump_on_lsass",
  "sigma_powershell_get_clipboard_cmdlet_via_cli",
  "sigma_compress_data_and_lock_with_password_for_exfiltration_with_winzip",
  "sigma_suspicious_del_in_commandline",
  "sigma_suspicious_extrac32_alternate_data_stream_execution",
  "sigma_suspicious_ping_and_del_combination",
  "sigma_dtrack_process_creation",
  "sigma_rundll32_without_parameters",
  "sigma_conti_volume_shadow_listing",
  "sigma_esentutl_gather_credentials",
  "sigma_procdump_evasion",
  "sigma_suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet",
  "sigma_operation_wocao_activity",
  "sigma_stop_or_remove_antivirus_service",
  "sigma_suspicious_advancedrun_runas_priv_user",
  "sigma_suspicious_powershell_obfuscated_powershell_code",
  "sigma_mercury_command_line_patterns",
  "sigma_infdefaultinstall_exe_inf_execution",
  "sigma_covenant_launcher_indicators",
  "sigma_psexec_paexec_escalation_to_local_system",
  "sigma_runxcmd_tool_execution_as_system",
  "sigma_suspicious_diantz_alternate_data_stream_execution",
  "sigma_suspicious_vbscript_un2452_pattern",
  "sigma_f_secure_c3_load_by_rundll32",
  "sigma_invoke_obfuscation_compress_obfuscation",
  "sigma_emotet_process_creation",
  "sigma_suspicious_encoded_powershell_command_line",
  "sigma_suspicious_zipexec_execution",
  "sigma_rar_usage_with_password_and_compression_level",
  "sigma_suspicious_rundll32_script_in_commandline",
  "sigma_java_running_with_remote_debugging",
  "sigma_wmic_uninstall_security_product",
  "sigma_evilnum_golden_chickens_deployment_via_ocx_files",
  "sigma_mshtml_dll_runhtmlapplication_abuse",
  "sigma_windows_crypto_mining_indicators",
  "sigma_suspicious_add_user_to_remote_desktop_users_group",
  "sigma_powershell_web_download_and_execution",
  "sigma_audio_capture_via_powershell",
  "sigma_windows_cmd_delete_file",
  "sigma_invoke_obfuscation_via_use_mshta",
  "sigma_sliver_c2_implant_activity_pattern",
  "sigma_malicious_base64_encoded_powershell_invoke_cmdlets",
  "sigma_snatch_ransomware",
  "sigma_adfind_usage_detection",
  "sigma_suspicious_desktopimgdownldr_command",
  "sigma_disable_of_etw_trace",
  "sigma_obfuscated_command_line_using_special_unicode_characters",
  "sigma_suspicious_minimized_msedge_start",
  "sigma_nircmd_tool_execution_as_local_system",
  "sigma_turla_group_commands_may_2020",
  "sigma_frombase64string_command_line",
  "sigma_tasks_folder_evasion",
  "sigma_suspicious_wmic_execution_processcallcreate",
  "sigma_lazarus_activity_dec20",
  "sigma_base64_mz_header_in_commandline",
  "sigma_base64_encoded_reflective_assembly_load",
  "sigma_change_powershell_policies_to_an_insecure_level",
  "sigma_cl_loadassembly_ps1_proxy_execution",
  "sigma_psexec_paexec_flags",
  "sigma_suspicious_usage_of_the_manage_bde_wsf_script",
  "sigma_suspicious_reg_add_open_command",
  "sigma_base64_encoded_listing_of_shadowcopy",
  "sigma_missing_space_characters_in_command_lines",
  "sigma_compress_data_and_lock_with_password_for_exfiltration_with_7_zip",
  "sigma_reg_add_run_key",
  "sigma_suspicious_ultravnc_execution",
  "sigma_suspicious_characters_in_commandline",
  "sigma_uninstall_crowdstrike_falcon",
  "sigma_taidoor_rat_dll_load",
  "sigma_invoke_obfuscation_rundll_launcher",
  "sigma_add_user_to_local_administrators",
  "sigma_lazarus_loaders",
  "sigma_conti_ransomware_execution",
  "sigma_using_appvlp_to_circumvent_asr_file_path_rule",
  "sigma_suspicious_adfind_enumeration",
  "sigma_empire_powershell_uac_bypass",
  "sigma_network_reconnaissance_activity",
  "sigma_suspicious_netsh_discovery_command",
  "sigma_tropictrooper_campaign_november_2018",
  "sigma_execute_from_alternate_data_streams",
  "sigma_change_default_file_association",
  "sigma_root_certificate_installed_from_susp_locations",
  "sigma_explorer_process_tree_break",
  "sigma_suspicious_nt_resource_kit_auditpol_usage",
  "sigma_baby_shark_activity",
  "sigma_zip_a_folder_with_powershell_for_staging_in_temp",
  "sigma_ps_exe_renamed_sysinternals_tool",
  "sigma_discover_private_keys",
  "sigma_crackmapexec_command_execution",
  "sigma_sensitive_registry_access_via_volume_shadow_copy",
  "sigma_shadow_copies_access_via_symlink",
  "sigma_suspicious_usage_of_shellexec_rundll",
  "sigma_invoke_obfuscation_var_launcher",
  "sigma_suspicious_rdp_redirect_using_tscon",
  "sigma_suspicious_debugger_registration_cmdline",
  "sigma_tamper_windows_defender_remove_mppreference",
  "sigma_disable_or_delete_windows_eventlog",
  "sigma_turla_group_lateral_movement",
  "sigma_unc2452_powershell_pattern",
  "sigma_suspicious_office_token_search_via_cli",
  "sigma_usage_of_sysinternals_tools",
  "sigma_reg_disable_security_service",
  "sigma_write_protect_for_storage_disabled",
  "sigma_usage_of_web_request_commands_and_cmdlets",
  "sigma_change_default_file_association_to_executable",
  "sigma_invoke_obfuscation_via_use_clip",
  "sigma_launch_vsdevshell_ps1_proxy_execution",
  "sigma_monitoring_for_persistence_via_bits",
  "sigma_suspicious_wmic_activescripteventconsumer_creation",
  "sigma_register_app_vbs_proxy_execution",
  "sigma_monitoring_winget_for_lolbin_execution",
  "sigma_suspicious_base64_encoded_powershell_invoke",
  "sigma_process_creation_using_sysnative_folder",
  "sigma_adwind_rat_jrat",
  "sigma_new_network_provider_commandline",
  "sigma_screenconnect_remote_access",
  "sigma_powershell_amsi_bypass_via_net_reflection",
  "sigma_capture_a_network_trace_with_netsh_exe",
  "sigma_suspicious_regsvr32_http_ip_pattern",
  "sigma_registry_dump_of_sam_creds_and_secrets",
  "sigma_wscript_shell_run_in_commandline",
  "sigma_suspicious_network_command",
  "sigma_suspicious_sysvol_domain_group_policy_access",
  "sigma_shimcache_flush",
  "sigma_suspicious_conhost_legacy_option",
  "sigma_detect_virtualbox_driver_installation_or_starting_of_vms",
  "sigma_invoke_obfuscation_via_stdin",
  "sigma_suspicious_runas_like_flag_combination",
  "sigma_conti_backup_database",
  "sigma_devinit_lolbin_download",
  "sigma_disabled_volume_snapshots",
  "sigma_powershell_web_download",
  "sigma_curl_start_combination",
  "sigma_suspicious_rundll32_activity_invoking_sys_file",
  "sigma_suspicious_redirection_to_local_admin_share",
  "sigma_enumeration_for_3rd_party_creds_from_cli",
  "sigma_powershell_sam_copy",
  "sigma_potential_remote_desktop_tunneling",
  "sigma_suspicious_diantz_download_and_compress_into_a_cab_file",
  "sigma_ryuk_ransomware",
  "sigma_syncappvpublishingserver_vbs_execute_arbitrary_powershell_code",
  "sigma_powershell_downloadfile",
  "sigma_writing_of_malicious_files_to_the_fonts_folder",
  "sigma_modification_of_existing_services_for_persistence",
  "sigma_apt29",
  "sigma_abusing_windows_telemetry_for_persistence",
  "sigma_serv_u_exploitation_cve_2021_35211_by_dev_0322",
  "sigma_empire_powershell_launch_parameters",
  "sigma_powershell_script_run_in_appdata",
  "sigma_unidentified_attacker_november_2018",
  "sigma_netsh_rdp_port_opening",
  "sigma_conti_ntds_exfiltration_command",
  "sigma_scheduled_task_wscript_vbscript",
  "sigma_gathernetworkinfo_vbs_script_usage",
  "sigma_suspicious_dir_execution",
  "sigma_ke3chang_registry_key_modifications",
  "sigma_pubprn_vbs_proxy_execution",
  "sigma_suspicious_ntdll_pipe_redirection",
  "sigma_raccine_uninstall",
  "sigma_suspicious_rundll32_invoking_inline_vbscript",
  "sigma_powershell_base64_encoded_shellcode",
  "sigma_weak_or_abused_passwords_in_cli",
  "sigma_utilityfunctions_ps1_proxy_dll",
  "sigma_bluemashroom_dll_load",
  "sigma_msexchange_transport_agent_installation",
  "sigma_accessing_winapi_via_commandline",
  "sigma_suspicious_listing_of_network_connections",
  "sigma_suspicious_grpconv_execution",
  "sigma_winnti_pipemon_characteristics",
  "sigma_invoke_obfuscation_var_launcher_obfuscation",
  "sigma_powershell_defender_exclusion",
  "sigma_copy_dmp_files_from_share",
  "sigma_cl_mutexverifiers_ps1_proxy_execution",
  "sigma_invoke_obfuscation_clip_launcher",
  "sigma_powershell_get_process_lsass"
]