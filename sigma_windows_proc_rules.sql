-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_reg_bitlocker.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%REG%" ESCAPE '\' AND COMMAND_LINE LIKE "%ADD%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\SOFTWARE\\Policies\\Microsoft\\FVE%" ESCAPE '\' AND COMMAND_LINE LIKE "%/v%" ESCAPE '\' AND COMMAND_LINE LIKE "%/f%" ESCAPE '\' AND (COMMAND_LINE LIKE "%EnableBDEWithNoTPM%" ESCAPE '\' OR COMMAND_LINE LIKE "%UseAdvancedStartup%" ESCAPE '\' OR COMMAND_LINE LIKE "%UseTPM%" ESCAPE '\' OR COMMAND_LINE LIKE "%UseTPMKey%" ESCAPE '\' OR COMMAND_LINE LIKE "%UseTPMKeyPIN%" ESCAPE '\' OR COMMAND_LINE LIKE "%RecoveryKeyMessageSource%" ESCAPE '\' OR COMMAND_LINE LIKE "%UseTPMPIN%" ESCAPE '\' OR COMMAND_LINE LIKE "%RecoveryKeyMessage%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_hurricane_panda.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%localgroup%" ESCAPE '\' AND COMMAND_LINE LIKE "%admin%" ESCAPE '\' AND COMMAND_LINE LIKE "%/add%" ESCAPE '\') OR (COMMAND_LINE LIKE "%\\Win64.exe%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%\\Event Viewer\\RecentViews%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\EventV~1\\RecentViews%" ESCAPE '\') AND COMMAND_LINE LIKE "%>%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%IEX ((New-Object Net.WebClient).DownloadString%" ESCAPE '\' OR COMMAND_LINE LIKE "%IEX (New-Object Net.WebClient).DownloadString%" ESCAPE '\' OR COMMAND_LINE LIKE "%IEX((New-Object Net.WebClient).DownloadString%" ESCAPE '\' OR COMMAND_LINE LIKE "%IEX(New-Object Net.WebClient).DownloadString%" ESCAPE '\' OR COMMAND_LINE LIKE "% -command (New-Object System.Net.WebClient).DownloadFile(%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c (New-Object System.Net.WebClient).DownloadFile(%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_crackmapexec_flags.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -M pe\_inject %" ESCAPE '\' OR (COMMAND_LINE LIKE "% --local-auth%" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -x %" ESCAPE '\') OR (COMMAND_LINE LIKE "% --local-auth%" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p %" ESCAPE '\' AND COMMAND_LINE LIKE "% -H 'NTHASH'%" ESCAPE '\') OR (COMMAND_LINE LIKE "% mssql %" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p %" ESCAPE '\' AND COMMAND_LINE LIKE "% -M %" ESCAPE '\' AND COMMAND_LINE LIKE "% -d %" ESCAPE '\') OR (COMMAND_LINE LIKE "% smb %" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -H %" ESCAPE '\' AND COMMAND_LINE LIKE "% -M %" ESCAPE '\' AND COMMAND_LINE LIKE "% -o %" ESCAPE '\') OR (COMMAND_LINE LIKE "% smb %" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p %" ESCAPE '\' AND COMMAND_LINE LIKE "% --local-auth%" ESCAPE '\')) OR (COMMAND_LINE LIKE "% --local-auth%" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p %" ESCAPE '\' AND COMMAND_LINE LIKE "% 10.%" ESCAPE '\' AND COMMAND_LINE LIKE "% 192.168.%" ESCAPE '\' AND COMMAND_LINE LIKE "%/24 %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_rdp_hijack_shadowing.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%noconsentprompt%" ESCAPE '\' AND COMMAND_LINE LIKE "%shadow:%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_exploit_cve_2020_1048.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Add-PrinterPort -Name%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bat%" ESCAPE '\')) OR COMMAND_LINE LIKE "%Generic / Text Only%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_anydesk_piped_password_via_cli.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%/c%" ESCAPE '\' AND COMMAND_LINE LIKE "%echo %" ESCAPE '\' AND COMMAND_LINE LIKE "% --set-password%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_netsh_firewall_disable.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%netsh%" ESCAPE '\' AND COMMAND_LINE LIKE "%firewall%" ESCAPE '\' AND COMMAND_LINE LIKE "%set%" ESCAPE '\' AND COMMAND_LINE LIKE "%opmode%" ESCAPE '\' AND COMMAND_LINE LIKE "%mode=disable%" ESCAPE '\') OR (COMMAND_LINE LIKE "%netsh%" ESCAPE '\' AND COMMAND_LINE LIKE "%advfirewall%" ESCAPE '\' AND COMMAND_LINE LIKE "%set%" ESCAPE '\' AND COMMAND_LINE LIKE "%state%" ESCAPE '\' AND COMMAND_LINE LIKE "%off%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_cl_invocation.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%CL\_Invocation.ps1%" ESCAPE '\' AND COMMAND_LINE LIKE "%SyncInvoke%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_persistence_typed_paths.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_obfuscated_ip_download.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Invoke-WebRequest%" ESCAPE '\' OR COMMAND_LINE LIKE "%iwr %" ESCAPE '\' OR COMMAND_LINE LIKE "%wget %" ESCAPE '\' OR COMMAND_LINE LIKE "%curl %" ESCAPE '\' OR COMMAND_LINE LIKE "%DownloadFile%" ESCAPE '\' OR COMMAND_LINE LIKE "%DownloadString%" ESCAPE '\') AND ((COMMAND_LINE LIKE "%//0x%" ESCAPE '\' OR COMMAND_LINE LIKE "%.0x%" ESCAPE '\' OR COMMAND_LINE LIKE "%.00x%" ESCAPE '\') OR (COMMAND_LINE LIKE "%http://\%%" ESCAPE '\' AND COMMAND_LINE LIKE "%\%2e%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_cli_escape.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%h^t^t^p%" ESCAPE '\' OR COMMAND_LINE LIKE "%h"t"t"p%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_crime_fireball.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%InstallArcherSvc%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%.exe whoami%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_hack_hydra.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-u %" ESCAPE '\' AND COMMAND_LINE LIKE "%-p %" ESCAPE '\' AND (COMMAND_LINE LIKE "%^USER^%" ESCAPE '\' OR COMMAND_LINE LIKE "%^PASS^%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_mailboxexport_share.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%New-MailboxExportRequest%" ESCAPE '\' AND COMMAND_LINE LIKE "% -Mailbox %" ESCAPE '\' AND COMMAND_LINE LIKE "% -FilePath \\\\\*" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%^^%" ESCAPE '\' OR COMMAND_LINE LIKE "%,;,%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%COMSPEC:~%" ESCAPE '\' OR COMMAND_LINE LIKE "% s^et %" ESCAPE '\' OR COMMAND_LINE LIKE "% s^e^t %" ESCAPE '\' OR COMMAND_LINE LIKE "% se^t %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_taskkill_sep.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%taskkill%" ESCAPE '\' AND COMMAND_LINE LIKE "% /F %" ESCAPE '\' AND COMMAND_LINE LIKE "% /IM %" ESCAPE '\' AND COMMAND_LINE LIKE "%ccSvcHst.exe%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_schtasks_powershell_windowsapps_execution.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -windowstyle hidden"" ESCAPE '\' OR COMMAND_LINE LIKE "% -windowstyle hidden" ESCAPE '\' OR COMMAND_LINE LIKE "% -windowstyle hidden'" ESCAPE '\' OR COMMAND_LINE LIKE "% -w hidden"" ESCAPE '\' OR COMMAND_LINE LIKE "% -w hidden" ESCAPE '\' OR COMMAND_LINE LIKE "% -w hidden'" ESCAPE '\' OR COMMAND_LINE LIKE "% -ep bypass"" ESCAPE '\' OR COMMAND_LINE LIKE "% -ep bypass" ESCAPE '\' OR COMMAND_LINE LIKE "% -ep bypass'" ESCAPE '\' OR COMMAND_LINE LIKE "% -noni"" ESCAPE '\' OR COMMAND_LINE LIKE "% -noni" ESCAPE '\' OR COMMAND_LINE LIKE "% -noni'" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_anydesk_silent_install.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%--install%" ESCAPE '\' AND COMMAND_LINE LIKE "%--start-with-win%" ESCAPE '\' AND COMMAND_LINE LIKE "%--silent%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_network_scan_loop.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%for %" ESCAPE '\' OR COMMAND_LINE LIKE "%foreach %" ESCAPE '\') AND (COMMAND_LINE LIKE "%nslookup%" ESCAPE '\' OR COMMAND_LINE LIKE "%ping%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_cmd_shadowcopy_access.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%copy \\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_crackmapexec_powershell_obfuscation.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%powershell.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwsh.exe%" ESCAPE '\') AND (COMMAND_LINE LIKE "%join%split%" ESCAPE '\' OR COMMAND_LINE LIKE "%( $ShellId[1]+$ShellId[13]+'x')%" ESCAPE '\' OR COMMAND_LINE LIKE "%( $PSHome[%]+$PSHOME[%]+%" ESCAPE '\' OR COMMAND_LINE LIKE "%( $env:Public[13]+$env:Public[5]+'x')%" ESCAPE '\' OR COMMAND_LINE LIKE "%( $env:ComSpec[4,%,25]-Join'')%" ESCAPE '\' OR COMMAND_LINE LIKE "%[1,3]+'x'-Join'')%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_psexesvc_start.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "C:\\Windows\\PSEXESVC.exe" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_mal_lockergoga_ransomware.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%-i SM-tgytutrc -s%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_rundll32_js_runhtmlapplication.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' AND COMMAND_LINE LIKE "%javascript%" ESCAPE '\' AND COMMAND_LINE LIKE "%..\\..\\mshtml,RunHTMLApplication%" ESCAPE '\') OR COMMAND_LINE LIKE "%;document.write();GetObject("script%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_sticky_keys_unauthenticated_privileged_cmd_access.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "copy /y C:\\windows\\system32\\cmd.exe C:\\windows\\system32\\sethc.exe" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_etw_modification_cmdline.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%COMPlus\_ETWEnabled=0%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_sofacy.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%\%APPDATA\%\\%" ESCAPE '\') AND (COMMAND_LINE LIKE "%.dat",%" ESCAPE '\' OR (COMMAND_LINE LIKE "%.dll",#1" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll #1" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll" #1" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_exploit_systemnightmare.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%printnightmare.gentilkiwi.com%" ESCAPE '\' OR COMMAND_LINE LIKE "% /user:gentilguest %" ESCAPE '\' OR COMMAND_LINE LIKE "%Kiwi Legit Printer%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_athremotefxvgpudisablementcommand.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Invoke-ATHRemoteFXvGPUDisablementCommand %" ESCAPE '\' AND (COMMAND_LINE LIKE "%-ModuleName %" ESCAPE '\' OR COMMAND_LINE LIKE "%-ModulePath %" ESCAPE '\' OR COMMAND_LINE LIKE "%-ScriptBlock %" ESCAPE '\' OR COMMAND_LINE LIKE "%-RemoteFXvGPUDisablementFilePath%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_encoded_param.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%(WCHAR)0x%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_stdin.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%powershell%" ESCAPE '\' AND (COMMAND_LINE LIKE "%/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%/r%" ESCAPE '\')) AND (COMMAND_LINE LIKE "%noexit%" ESCAPE '\' OR (COMMAND_LINE LIKE "%input%" ESCAPE '\' AND COMMAND_LINE LIKE "%$%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_msiexec_web_install.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% msiexec%" ESCAPE '\' AND COMMAND_LINE LIKE "%://%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_hack_adcspwn.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% --adcs %" ESCAPE '\' AND COMMAND_LINE LIKE "% --port %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_disable_ie_features.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -name IEHarden %" ESCAPE '\' AND COMMAND_LINE LIKE "% -value 0 %" ESCAPE '\') OR (COMMAND_LINE LIKE "% -name DEPOff %" ESCAPE '\' AND COMMAND_LINE LIKE "% -value 1 %" ESCAPE '\') OR (COMMAND_LINE LIKE "% -name DisableFirstRunCustomize %" ESCAPE '\' AND COMMAND_LINE LIKE "% -value 2 %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_rundll32.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%&&%" ESCAPE '\' AND COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' AND COMMAND_LINE LIKE "%shell32.dll%" ESCAPE '\' AND COMMAND_LINE LIKE "%shellexec\_rundll%" ESCAPE '\' AND (COMMAND_LINE LIKE "%value%" ESCAPE '\' OR COMMAND_LINE LIKE "%invoke%" ESCAPE '\' OR COMMAND_LINE LIKE "%comspec%" ESCAPE '\' OR COMMAND_LINE LIKE "%iex%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_arbitrary_shell_execution_via_settingcontent.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%.SettingContent-ms%" ESCAPE '\' AND NOT (COMMAND_LINE LIKE "%immersivecontrolpanel%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_credential_access_via_password_filter.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa%" ESCAPE '\' AND COMMAND_LINE LIKE "%scecli\\0%" ESCAPE '\' AND COMMAND_LINE LIKE "%reg add%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_base64_load.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACIATABvACIAKwAiAGEAZAAiACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACIATABvAGEAIgArACIAZAAiACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACcATABvACcAKwAnAGEAZAAnACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%oAOgAoACcATABvAGEAJwArACcAZAAnACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_procdump_lsass.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -ma %" ESCAPE '\' OR COMMAND_LINE LIKE "% /ma %" ESCAPE '\') AND COMMAND_LINE LIKE "% ls%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_get_clipboard.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%Get-Clipboard%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_winzip.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%winzip.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%winzip64.exe%" ESCAPE '\') AND COMMAND_LINE LIKE "%-s"%" ESCAPE '\' AND (COMMAND_LINE LIKE "% -min %" ESCAPE '\' OR COMMAND_LINE LIKE "% -a %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_del.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%del %" ESCAPE '\' AND COMMAND_LINE LIKE "%\*.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%/f %" ESCAPE '\' AND COMMAND_LINE LIKE "%/q %" ESCAPE '\') OR (COMMAND_LINE LIKE "%del %" ESCAPE '\' AND COMMAND_LINE LIKE "%\*.dll%" ESCAPE '\' AND COMMAND_LINE LIKE "%C:\\ProgramData\\%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_dtrack.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "% echo EEEE > %" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE = "rundll32.exe"

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_conti.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%vssadmin list shadows%" ESCAPE '\' AND COMMAND_LINE LIKE "%log.txt%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_esentutl_params.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%esentutl%" ESCAPE '\' AND COMMAND_LINE LIKE "% /p%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_procdump_evasion.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%copy procdump%" ESCAPE '\' OR COMMAND_LINE LIKE "%move procdump%" ESCAPE '\') OR (COMMAND_LINE LIKE "%copy %" ESCAPE '\' AND COMMAND_LINE LIKE "%.dmp %" ESCAPE '\' AND (COMMAND_LINE LIKE "%2.dmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%lsass%" ESCAPE '\' OR COMMAND_LINE LIKE "%out.dmp%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%copy lsass.exe\_%" ESCAPE '\' OR COMMAND_LINE LIKE "%move lsass.exe\_%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_get_localgroup_member_recon.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Get-LocalGroupMember %" ESCAPE '\' AND (COMMAND_LINE LIKE "%domain admins%" ESCAPE '\' OR COMMAND_LINE LIKE "% administrator%" ESCAPE '\' OR COMMAND_LINE LIKE "% administrateur%" ESCAPE '\' OR COMMAND_LINE LIKE "%enterprise admins%" ESCAPE '\' OR COMMAND_LINE LIKE "%Exchange Trusted Subsystem%" ESCAPE '\' OR COMMAND_LINE LIKE "%Remote Desktop Users%" ESCAPE '\' OR COMMAND_LINE LIKE "%Utilisateurs du Bureau à distance%" ESCAPE '\' OR COMMAND_LINE LIKE "%Usuarios de escritorio remoto%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_wocao.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%checkadmin.exe 127.0.0.1 -all%" ESCAPE '\' OR COMMAND_LINE LIKE "%netsh advfirewall firewall add rule name=powershell dir=in%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /c powershell.exe -ep bypass -file c:\\s.ps1%" ESCAPE '\' OR COMMAND_LINE LIKE "%/tn win32times /f%" ESCAPE '\' OR COMMAND_LINE LIKE "%create win32times binPath=%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\c$\\windows\\system32\\devmgr.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "% -exec bypass -enc JgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%type %keepass\\KeePass.config.xml%" ESCAPE '\' OR COMMAND_LINE LIKE "%iie.exe iie.txt%" ESCAPE '\' OR COMMAND_LINE LIKE "%reg query HKEY\_CURRENT\_USER\\Software\\%\\PuTTY\\Sessions\\%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_service_modification.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Stop-Service %" ESCAPE '\' OR COMMAND_LINE LIKE "%Remove-Service %" ESCAPE '\') AND (COMMAND_LINE LIKE "% McAfeeDLPAgentService%" ESCAPE '\' OR COMMAND_LINE LIKE "% Trend Micro Deep Security Manager%" ESCAPE '\' OR COMMAND_LINE LIKE "% TMBMServer%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos%" ESCAPE '\' OR COMMAND_LINE LIKE "%Symantec%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_advancedrun_priv_user.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%/EXEFilename%" ESCAPE '\' OR COMMAND_LINE LIKE "%/CommandLine%" ESCAPE '\') AND ((COMMAND_LINE LIKE "% /RunAs 8 %" ESCAPE '\' OR COMMAND_LINE LIKE "% /RunAs 4 %" ESCAPE '\' OR COMMAND_LINE LIKE "% /RunAs 10 %" ESCAPE '\' OR COMMAND_LINE LIKE "% /RunAs 11 %" ESCAPE '\') OR (COMMAND_LINE LIKE "%/RunAs 8" ESCAPE '\' OR COMMAND_LINE LIKE "%/RunAs 4" ESCAPE '\' OR COMMAND_LINE LIKE "%/RunAs 10" ESCAPE '\' OR COMMAND_LINE LIKE "%/RunAs 11" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_ps_encoded_obfusc.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%IAAtAGIAeABvAHIAIAAwAHgA%" ESCAPE '\' OR COMMAND_LINE LIKE "%AALQBiAHgAbwByACAAMAB4A%" ESCAPE '\' OR COMMAND_LINE LIKE "%gAC0AYgB4AG8AcgAgADAAeA%" ESCAPE '\' OR COMMAND_LINE LIKE "%AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AuAEkAbgB2AG8AawBlACgAKQAgAHwAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMQB9AHsAMAB9ACIAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADEAfQB7ADAAfQAiACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAxAH0AewAwAH0AIgAgAC0AZgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMAB9AHsAMwB9ACIAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADAAfQB7ADMAfQAiACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAwAH0AewAzAH0AIgAgAC0AZgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMgB9AHsAMAB9ACIAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADIAfQB7ADAAfQAiACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAyAH0AewAwAH0AIgAgAC0AZgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMQB9AHsAMAB9ACcAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADEAfQB7ADAAfQAnACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAxAH0AewAwAH0AJwAgAC0AZgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMAB9AHsAMwB9ACcAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADAAfQB7ADMAfQAnACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAwAH0AewAzAH0AJwAgAC0AZgAg%" ESCAPE '\' OR COMMAND_LINE LIKE "%AHsAMgB9AHsAMAB9ACcAIAAtAGYAI%" ESCAPE '\' OR COMMAND_LINE LIKE "%B7ADIAfQB7ADAAfQAnACAALQBmAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%AewAyAH0AewAwAH0AJwAgAC0AZgAg%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_mercury.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-exec bypass -w 1 -enc%" ESCAPE '\' AND COMMAND_LINE LIKE "%UwB0AGEAcgB0AC0ASgBvAGIAIAAtAFMAYwByAGkAcAB0AEIAbABvAGMAaw%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_infdefaultinstall.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%InfDefaultInstall.exe %" ESCAPE '\' AND COMMAND_LINE LIKE "%.inf%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_covenant.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%-Sta%" ESCAPE '\' AND COMMAND_LINE LIKE "%-Nop%" ESCAPE '\' AND COMMAND_LINE LIKE "%-Window%" ESCAPE '\' AND COMMAND_LINE LIKE "%Hidden%" ESCAPE '\' AND (COMMAND_LINE LIKE "%-Command%" ESCAPE '\' OR COMMAND_LINE LIKE "%-EncodedCommand%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%sv o (New-Object IO.MemorySteam);sv d %" ESCAPE '\' OR COMMAND_LINE LIKE "%mshta file.hta%" ESCAPE '\' OR COMMAND_LINE LIKE "%GruntHTTP%" ESCAPE '\' OR COMMAND_LINE LIKE "%-EncodedCommand cwB2ACAAbwAgA%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_psexex_paexec_escalate_system.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s powershell%" ESCAPE '\') AND (COMMAND_LINE LIKE "%psexec%" ESCAPE '\' OR COMMAND_LINE LIKE "%paexec%" ESCAPE '\' OR COMMAND_LINE LIKE "%accepteula%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /c %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /k %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /r %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_tool_runx_as_system.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% /account=system %" ESCAPE '\' AND COMMAND_LINE LIKE "%/exec=%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_vbscript_unc2452.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Execute%" ESCAPE '\' AND COMMAND_LINE LIKE "%CreateObject%" ESCAPE '\' AND COMMAND_LINE LIKE "%RegRead%" ESCAPE '\' AND COMMAND_LINE LIKE "%window.close%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\Microsoft\\Windows\\CurrentVersion%" ESCAPE '\') AND NOT (COMMAND_LINE LIKE "%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_c3_load_by_rundll32.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%.dll%" ESCAPE '\' AND COMMAND_LINE LIKE "%StartNodeRelay%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_compress.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%new-object%" ESCAPE '\' AND COMMAND_LINE LIKE "%text.encoding]::ascii%" ESCAPE '\' AND (COMMAND_LINE LIKE "%system.io.compression.deflatestream%" ESCAPE '\' OR COMMAND_LINE LIKE "%system.io.streamreader%" ESCAPE '\') AND COMMAND_LINE LIKE "%readtoend" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_emotet.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -e% PAA%" ESCAPE '\' OR COMMAND_LINE LIKE "%JABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%QAZQBuAHYAOgB1AHMAZQByAHAAcgBvAGYAaQBsAGUA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlA%" ESCAPE '\' OR COMMAND_LINE LIKE "%IgAoACcAKgAnACkAOwAkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%IAKAAnACoAJwApADsAJA%" ESCAPE '\' OR COMMAND_LINE LIKE "%iACgAJwAqACcAKQA7ACQA%" ESCAPE '\' OR COMMAND_LINE LIKE "%JABGAGwAeAByAGgAYwBmAGQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%PQAkAGUAbgB2ADoAdABlAG0AcAArACgA%" ESCAPE '\' OR COMMAND_LINE LIKE "%0AJABlAG4AdgA6AHQAZQBtAHAAKwAoA%" ESCAPE '\' OR COMMAND_LINE LIKE "%9ACQAZQBuAHYAOgB0AGUAbQBwACsAKA%" ESCAPE '\') AND NOT ((COMMAND_LINE LIKE "%fAAgAEMAbwBuAHYAZQByAHQAVABvAC0ASgBzAG8AbgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%wAIABDAG8AbgB2AGUAcgB0AFQAbwAtAEoAcwBvAG4AIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUA%" ESCAPE '\' OR COMMAND_LINE LIKE "%8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlA%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_enc_cmd.yml;
SELECT * FROM eventlog WHERE ((((COMMAND_LINE LIKE "% -e%" ESCAPE '\' AND COMMAND_LINE LIKE "% JAB%" ESCAPE '\') OR (COMMAND_LINE LIKE "% -e%" ESCAPE '\' AND COMMAND_LINE LIKE "% JAB%" ESCAPE '\' AND COMMAND_LINE LIKE "% -w%" ESCAPE '\' AND COMMAND_LINE LIKE "% hidden %" ESCAPE '\')) OR (COMMAND_LINE LIKE "% -e%" ESCAPE '\' AND (COMMAND_LINE LIKE "% BA^J%" ESCAPE '\' OR COMMAND_LINE LIKE "% SUVYI%" ESCAPE '\' OR COMMAND_LINE LIKE "% SQBFAFgA%" ESCAPE '\' OR COMMAND_LINE LIKE "% aQBlAHgA%" ESCAPE '\' OR COMMAND_LINE LIKE "% aWV4I%" ESCAPE '\' OR COMMAND_LINE LIKE "% IAA%" ESCAPE '\' OR COMMAND_LINE LIKE "% IAB%" ESCAPE '\' OR COMMAND_LINE LIKE "% UwB%" ESCAPE '\' OR COMMAND_LINE LIKE "% cwB%" ESCAPE '\')) OR COMMAND_LINE LIKE "%.exe -ENCOD %" ESCAPE '\') AND NOT (COMMAND_LINE LIKE "% -ExecutionPolicy%" ESCAPE '\' AND COMMAND_LINE LIKE "%remotesigned %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_zipexec.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%/generic:Microsoft\_Windows\_Shell\_ZipFolder:filename=%" ESCAPE '\' AND COMMAND_LINE LIKE "%.zip%" ESCAPE '\' AND COMMAND_LINE LIKE "%/pass:%" ESCAPE '\' AND COMMAND_LINE LIKE "%/user:%" ESCAPE '\') OR (COMMAND_LINE LIKE "%/delete%" ESCAPE '\' AND COMMAND_LINE LIKE "%Microsoft\_Windows\_Shell\_ZipFolder:filename=%" ESCAPE '\' AND COMMAND_LINE LIKE "%.zip%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_rar_flags.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -hp%" ESCAPE '\' AND (COMMAND_LINE LIKE "% -m%" ESCAPE '\' OR COMMAND_LINE LIKE "% a %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_rundll32_script_run.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' AND COMMAND_LINE LIKE "%mshtml,RunHTMLApplication%" ESCAPE '\' AND (COMMAND_LINE LIKE "%javascript:%" ESCAPE '\' OR COMMAND_LINE LIKE "%vbscript:%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_vul_java_remote_debugging.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%transport=dt\_socket,address=%" ESCAPE '\' AND (COMMAND_LINE LIKE "%jre1.%" ESCAPE '\' OR COMMAND_LINE LIKE "%jdk1.%" ESCAPE '\')) AND NOT (COMMAND_LINE LIKE "%address=127.0.0.1%" ESCAPE '\' OR COMMAND_LINE LIKE "%address=localhost%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_wmic_security_product_uninstall.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "%wmic%" ESCAPE '\' AND COMMAND_LINE LIKE "%product where %" ESCAPE '\' AND COMMAND_LINE LIKE "%call uninstall%" ESCAPE '\' AND COMMAND_LINE LIKE "%/nointeractive%" ESCAPE '\') OR (COMMAND_LINE LIKE "%wmic%" ESCAPE '\' AND COMMAND_LINE LIKE "%caption like %" ESCAPE '\' AND (COMMAND_LINE LIKE "%call delete%" ESCAPE '\' OR COMMAND_LINE LIKE "%call terminate%" ESCAPE '\'))) AND (COMMAND_LINE LIKE "%Antivirus%" ESCAPE '\' OR COMMAND_LINE LIKE "%AVG %" ESCAPE '\' OR COMMAND_LINE LIKE "%Crowdstrike Sensor%" ESCAPE '\' OR COMMAND_LINE LIKE "%DLP Endpoint%" ESCAPE '\' OR COMMAND_LINE LIKE "%Endpoint Detection%" ESCAPE '\' OR COMMAND_LINE LIKE "%Endpoint Protection%" ESCAPE '\' OR COMMAND_LINE LIKE "%Endpoint Security%" ESCAPE '\' OR COMMAND_LINE LIKE "%Endpoint Sensor%" ESCAPE '\' OR COMMAND_LINE LIKE "%ESET File Security%" ESCAPE '\' OR COMMAND_LINE LIKE "%Malwarebytes%" ESCAPE '\' OR COMMAND_LINE LIKE "%McAfee Agent%" ESCAPE '\' OR COMMAND_LINE LIKE "%Microsoft Security Client%" ESCAPE '\' OR COMMAND_LINE LIKE "%Threat Protection%" ESCAPE '\' OR COMMAND_LINE LIKE "%VirusScan%" ESCAPE '\' OR COMMAND_LINE LIKE "%Webroot SecureAnywhere%" ESCAPE '\' OR COMMAND_LINE LIKE "%Windows Defender%" ESCAPE '\' OR COMMAND_LINE LIKE "%CarbonBlack%" ESCAPE '\' OR COMMAND_LINE LIKE "%Carbon Black%" ESCAPE '\' OR COMMAND_LINE LIKE "%Cb Defense Sensor 64-bit%" ESCAPE '\' OR COMMAND_LINE LIKE "%Dell Threat Defense%" ESCAPE '\' OR COMMAND_LINE LIKE "%Cylance %" ESCAPE '\' OR COMMAND_LINE LIKE "%LogRhythm System Monitor Service%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Anti-Virus%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos AutoUpdate%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Management Console%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Management Database%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Credential Store%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Update Manager%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Management Server%" ESCAPE '\' OR COMMAND_LINE LIKE "%Sophos Remote Management System%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%Sophos\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%carbon\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%cylance\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%eset\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%symantec\%%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_evilnum_jul20.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%regsvr32%" ESCAPE '\' AND COMMAND_LINE LIKE "%/s%" ESCAPE '\' AND COMMAND_LINE LIKE "%/i%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\AppData\\Roaming\\%" ESCAPE '\' AND COMMAND_LINE LIKE "%.ocx%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_mshtml_runhtmlapplication.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\..\\%" ESCAPE '\' AND COMMAND_LINE LIKE "%mshtml%" ESCAPE '\' AND COMMAND_LINE LIKE "%RunHTMLApplication%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_crypto_mining_monero.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% --cpu-priority=%" ESCAPE '\' OR COMMAND_LINE LIKE "%--donate-level=0%" ESCAPE '\' OR COMMAND_LINE LIKE "% -o pool.%" ESCAPE '\' OR COMMAND_LINE LIKE "% --nicehash%" ESCAPE '\' OR COMMAND_LINE LIKE "% --algo=rx/0 %" ESCAPE '\' OR COMMAND_LINE LIKE "%stratum+tcp://%" ESCAPE '\' OR COMMAND_LINE LIKE "%stratum+udp://%" ESCAPE '\' OR COMMAND_LINE LIKE "%LS1kb25hdGUtbGV2ZWw9%" ESCAPE '\' OR COMMAND_LINE LIKE "%0tZG9uYXRlLWxldmVsP%" ESCAPE '\' OR COMMAND_LINE LIKE "%tLWRvbmF0ZS1sZXZlbD%" ESCAPE '\' OR COMMAND_LINE LIKE "%c3RyYXR1bSt0Y3A6Ly%" ESCAPE '\' OR COMMAND_LINE LIKE "%N0cmF0dW0rdGNwOi8v%" ESCAPE '\' OR COMMAND_LINE LIKE "%zdHJhdHVtK3RjcDovL%" ESCAPE '\' OR COMMAND_LINE LIKE "%c3RyYXR1bSt1ZHA6Ly%" ESCAPE '\' OR COMMAND_LINE LIKE "%N0cmF0dW0rdWRwOi8v%" ESCAPE '\' OR COMMAND_LINE LIKE "%zdHJhdHVtK3VkcDovL%" ESCAPE '\') AND NOT ((COMMAND_LINE LIKE "% pool.c %" ESCAPE '\' OR COMMAND_LINE LIKE "% pool.o %" ESCAPE '\' OR COMMAND_LINE LIKE "%gcc -%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "%localgroup %" ESCAPE '\' AND COMMAND_LINE LIKE "% /add%" ESCAPE '\') OR (COMMAND_LINE LIKE "%Add-LocalGroupMember %" ESCAPE '\' AND COMMAND_LINE LIKE "% -Group %" ESCAPE '\')) AND (COMMAND_LINE LIKE "%Remote Desktop Users%" ESCAPE '\' OR COMMAND_LINE LIKE "%Utilisateurs du Bureau à distance%" ESCAPE '\' OR COMMAND_LINE LIKE "%Usuarios de escritorio remoto%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_download_iex.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%.DownloadString(%" ESCAPE '\' OR COMMAND_LINE LIKE "%.DownloadFile(%" ESCAPE '\' OR COMMAND_LINE LIKE "%Invoke-WebRequest %" ESCAPE '\') AND (COMMAND_LINE LIKE "%IEX(%" ESCAPE '\' OR COMMAND_LINE LIKE "%IEX (%" ESCAPE '\' OR COMMAND_LINE LIKE "%I`EX%" ESCAPE '\' OR COMMAND_LINE LIKE "%IE`X%" ESCAPE '\' OR COMMAND_LINE LIKE "%I`E`X%" ESCAPE '\' OR COMMAND_LINE LIKE "%| IEX%" ESCAPE '\' OR COMMAND_LINE LIKE "%|IEX %" ESCAPE '\' OR COMMAND_LINE LIKE "%Invoke-Execution%" ESCAPE '\' OR COMMAND_LINE LIKE "%;iex $%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_audio_capture.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%WindowsAudioDevice-Powershell-Cmdlet%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_cmd_delete.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% del %" ESCAPE '\' AND COMMAND_LINE LIKE "%/f%" ESCAPE '\') OR (COMMAND_LINE LIKE "%rmdir%" ESCAPE '\' AND COMMAND_LINE LIKE "%/s%" ESCAPE '\' AND COMMAND_LINE LIKE "%/q%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_mhsta.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%set%" ESCAPE '\' AND COMMAND_LINE LIKE "%&&%" ESCAPE '\' AND COMMAND_LINE LIKE "%mshta%" ESCAPE '\' AND COMMAND_LINE LIKE "%vbscript:createobject%" ESCAPE '\' AND COMMAND_LINE LIKE "%.run%" ESCAPE '\' AND COMMAND_LINE LIKE "%(window.close)%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_c2_sliver.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_base64_invoke_susp_cmdlets.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBCAGwAbwBvAGQASABvAHUAbgBkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0AQgBsAG8AbwBkAEgAbwB1AG4AZA%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAEIAbABvAG8AZABIAG8AdQBuAGQA%" ESCAPE '\' OR COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6A%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAeg%" ESCAPE '\' OR COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBXAE0ASQBFAHgAZQBjA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0AVwBNAEkARQB4AGUAYw%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAFcATQBJAEUAeABlAGMA%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_crime_snatch_ransomware.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%shutdown /r /f /t 00%" ESCAPE '\' OR COMMAND_LINE LIKE "%net stop SuperBackupMan%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_adfind_usage.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%domainlist%" ESCAPE '\' OR COMMAND_LINE LIKE "%trustdmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%dcmodes%" ESCAPE '\' OR COMMAND_LINE LIKE "%adinfo%" ESCAPE '\' OR COMMAND_LINE LIKE "% dclist %" ESCAPE '\' OR COMMAND_LINE LIKE "%computer\_pwdnotreqd%" ESCAPE '\' OR COMMAND_LINE LIKE "%objectcategory=%" ESCAPE '\' OR COMMAND_LINE LIKE "%-subnets -f%" ESCAPE '\' OR COMMAND_LINE LIKE "%name="Domain Admins"%" ESCAPE '\' OR COMMAND_LINE LIKE "%-sc u:%" ESCAPE '\' OR COMMAND_LINE LIKE "%domainncs%" ESCAPE '\' OR COMMAND_LINE LIKE "%dompol%" ESCAPE '\' OR COMMAND_LINE LIKE "% oudmp %" ESCAPE '\' OR COMMAND_LINE LIKE "%subnetdmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%gpodmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%fspdmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%users\_noexpire%" ESCAPE '\' OR COMMAND_LINE LIKE "%computers\_active%" ESCAPE '\' OR COMMAND_LINE LIKE "%computers\_pwdnotreqd%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_desktopimgdownldr.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% /lockscreenurl:%" ESCAPE '\' AND NOT ((COMMAND_LINE LIKE "%.jpg%" ESCAPE '\' OR COMMAND_LINE LIKE "%.jpeg%" ESCAPE '\' OR COMMAND_LINE LIKE "%.png%" ESCAPE '\'))) OR (COMMAND_LINE LIKE "%reg delete%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\PersonalizationCSP%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_etw_trace_evasion.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%cl%" ESCAPE '\' AND COMMAND_LINE LIKE "%/Trace%" ESCAPE '\') OR (COMMAND_LINE LIKE "%clear-log%" ESCAPE '\' AND COMMAND_LINE LIKE "%/Trace%" ESCAPE '\') OR (COMMAND_LINE LIKE "%sl%" ESCAPE '\' AND COMMAND_LINE LIKE "%/e:false%" ESCAPE '\') OR (COMMAND_LINE LIKE "%set-log%" ESCAPE '\' AND COMMAND_LINE LIKE "%/e:false%" ESCAPE '\') OR (COMMAND_LINE LIKE "%logman%" ESCAPE '\' AND COMMAND_LINE LIKE "%update%" ESCAPE '\' AND COMMAND_LINE LIKE "%trace%" ESCAPE '\' AND COMMAND_LINE LIKE "%--p%" ESCAPE '\' AND COMMAND_LINE LIKE "%-ets%" ESCAPE '\') OR COMMAND_LINE LIKE "%Remove-EtwTraceProvider%" ESCAPE '\' OR (COMMAND_LINE LIKE "%Set-EtwTraceProvider%" ESCAPE '\' AND COMMAND_LINE LIKE "%0x11%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_char_in_cmd.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%â%" ESCAPE '\' OR COMMAND_LINE LIKE "%€%" ESCAPE '\' OR COMMAND_LINE LIKE "%£%" ESCAPE '\' OR COMMAND_LINE LIKE "%¯%" ESCAPE '\' OR COMMAND_LINE LIKE "%®%" ESCAPE '\' OR COMMAND_LINE LIKE "%µ%" ESCAPE '\' OR COMMAND_LINE LIKE "%¶%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_msedge_minimized_download.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%start /min msedge%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_tool_nircmd_as_system.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "% runassystem %" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_turla_comrat_may20.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%tracert -h 10 yahoo.com%" ESCAPE '\' OR COMMAND_LINE LIKE "%.WSqmCons))|iex;%" ESCAPE '\' OR COMMAND_LINE LIKE "%Fr`omBa`se6`4Str`ing%" ESCAPE '\') OR (COMMAND_LINE LIKE "%net use https://docs.live.net%" ESCAPE '\' AND COMMAND_LINE LIKE "%@aol.co.uk%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%::FromBase64String(%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_task_folder_evasion.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%echo %" ESCAPE '\' OR COMMAND_LINE LIKE "%copy %" ESCAPE '\' OR COMMAND_LINE LIKE "%type %" ESCAPE '\' OR COMMAND_LINE LIKE "%file createnew%" ESCAPE '\') AND (COMMAND_LINE LIKE "% C:\\Windows\\System32\\Tasks\\%" ESCAPE '\' OR COMMAND_LINE LIKE "% C:\\Windows\\SysWow64\\Tasks\\%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_wmic_proc_create.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%process %" ESCAPE '\' AND COMMAND_LINE LIKE "%call %" ESCAPE '\' AND COMMAND_LINE LIKE "%create %" ESCAPE '\' AND (COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' OR COMMAND_LINE LIKE "%bitsadmin%" ESCAPE '\' OR COMMAND_LINE LIKE "%regsvr32%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /c %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /k %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /r %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /c %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /k %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /r %" ESCAPE '\' OR COMMAND_LINE LIKE "%powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "%certutil%" ESCAPE '\' OR COMMAND_LINE LIKE "%cscript%" ESCAPE '\' OR COMMAND_LINE LIKE "%wscript%" ESCAPE '\' OR COMMAND_LINE LIKE "%mshta%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Users\\Public\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Windows\\Temp\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\AppData\\Local\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%temp\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%tmp\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%ProgramData\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%appdata\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%comspec\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%\%localappdata\%%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_lazarus_activity_dec20.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%reg.exe save hklm\\sam \%temp\%\\~reg\_sam.save%" ESCAPE '\' OR COMMAND_LINE LIKE "%1q2w3e4r@#$@#$@#$%" ESCAPE '\' OR COMMAND_LINE LIKE "% -hp1q2w3e4 %" ESCAPE '\' OR COMMAND_LINE LIKE "%.dat data03 10000 -p %" ESCAPE '\') OR (COMMAND_LINE LIKE "%process call create%" ESCAPE '\' AND COMMAND_LINE LIKE "% > \%temp\%\\~%" ESCAPE '\') OR (COMMAND_LINE LIKE "%netstat -aon | find %" ESCAPE '\' AND COMMAND_LINE LIKE "% > \%temp\%\\~%" ESCAPE '\') OR COMMAND_LINE LIKE "%.255 10 C:\\ProgramData\\%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_inline_base64_mz_header.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%TVqQAAMAAAAEAAAA%" ESCAPE '\' OR COMMAND_LINE LIKE "%TVpQAAIAAAAEAA8A%" ESCAPE '\' OR COMMAND_LINE LIKE "%TVqAAAEAAAAEABAA%" ESCAPE '\' OR COMMAND_LINE LIKE "%TVoAAAAAAAAAAAAA%" ESCAPE '\' OR COMMAND_LINE LIKE "%TVpTAQEAAAAEAAAA%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_base64_reflective_assembly_load.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA%" ESCAPE '\' OR COMMAND_LINE LIKE "%sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA%" ESCAPE '\' OR COMMAND_LINE LIKE "%bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA%" ESCAPE '\' OR COMMAND_LINE LIKE "%AFsAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiAC%" ESCAPE '\' OR COMMAND_LINE LIKE "%BbAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgAp%" ESCAPE '\' OR COMMAND_LINE LIKE "%AWwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAK%" ESCAPE '\' OR COMMAND_LINE LIKE "%WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAKQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiACkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgApA%" ESCAPE '\' OR COMMAND_LINE LIKE "%WwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA%" ESCAPE '\' OR COMMAND_LINE LIKE "%sAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA%" ESCAPE '\' OR COMMAND_LINE LIKE "%bAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_set_policies_to_unsecure_level.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "% -executionpolicy %" ESCAPE '\' OR COMMAND_LINE LIKE "% -ep %" ESCAPE '\' OR COMMAND_LINE LIKE "% -exec %" ESCAPE '\') AND (COMMAND_LINE LIKE "%Unrestricted%" ESCAPE '\' OR COMMAND_LINE LIKE "%bypass%" ESCAPE '\' OR COMMAND_LINE LIKE "%RemoteSigned%" ESCAPE '\')) AND NOT ((COMMAND_LINE LIKE "%C:\\Program Files%" ESCAPE '\' OR COMMAND_LINE LIKE "%C:\\ProgramData%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\AppData\\Roaming\\Code\\%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_cl_loadassembly.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\CL\_LoadAssembly.ps1%" ESCAPE '\' OR COMMAND_LINE LIKE "%LoadAssemblyFromPath %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_psexex_paexec_flags.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "% -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s -i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s /i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /s -i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -s /i powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i -s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -i /s powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i -s powershell%" ESCAPE '\') OR (COMMAND_LINE LIKE "%accepteula%" ESCAPE '\' AND COMMAND_LINE LIKE "% -u %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p %" ESCAPE '\' AND COMMAND_LINE LIKE "% \\\*" ESCAPE '\')) AND NOT ((COMMAND_LINE LIKE "%paexec%" ESCAPE '\' OR COMMAND_LINE LIKE "%PsExec%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_manage_bde_lolbas.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cscript%" ESCAPE '\' AND COMMAND_LINE LIKE "%manage-bde.wsf%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_reg_open_command.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "%add%" ESCAPE '\' AND COMMAND_LINE LIKE "%hkcu\\software\\classes\\ms-settings\\shell\\open\\command%" ESCAPE '\' AND COMMAND_LINE LIKE "%/ve %" ESCAPE '\' AND COMMAND_LINE LIKE "%/d%" ESCAPE '\') OR (COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "%add%" ESCAPE '\' AND COMMAND_LINE LIKE "%hkcu\\software\\classes\\ms-settings\\shell\\open\\command%" ESCAPE '\' AND COMMAND_LINE LIKE "%/v%" ESCAPE '\' AND COMMAND_LINE LIKE "%DelegateExecute%" ESCAPE '\') OR (COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "%delete%" ESCAPE '\' AND COMMAND_LINE LIKE "%hkcu\\software\\classes\\ms-settings%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_base64_listing_shadowcopy.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%VwBpAG4AMwAyAF8AUwBoAGEAZABvAHcAYwBvAHAAeQAgAHwAIABGAG8AcgBFAGEAYwBoAC0ATwBiAGoAZQBjAHQA%" ESCAPE '\' OR COMMAND_LINE LIKE "%cAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0A%" ESCAPE '\' OR COMMAND_LINE LIKE "%XAGkAbgAzADIAXwBTAGgAYQBkAG8AdwBjAG8AcAB5ACAAfAAgAEYAbwByAEUAYQBjAGgALQBPAGIAagBlAGMAdA%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_missing_spaces.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "%cmd.exe/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\cmd/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%"cmd/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe/k%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\cmd/k%" ESCAPE '\' OR COMMAND_LINE LIKE "%"cmd/k%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe/r%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\cmd/r%" ESCAPE '\' OR COMMAND_LINE LIKE "%"cmd/r%" ESCAPE '\') OR (COMMAND_LINE LIKE "%/cwhoami%" ESCAPE '\' OR COMMAND_LINE LIKE "%/cpowershell%" ESCAPE '\' OR COMMAND_LINE LIKE "%/cschtasks%" ESCAPE '\' OR COMMAND_LINE LIKE "%/cbitsadmin%" ESCAPE '\' OR COMMAND_LINE LIKE "%/ccertutil%" ESCAPE '\' OR COMMAND_LINE LIKE "%/kwhoami%" ESCAPE '\' OR COMMAND_LINE LIKE "%/kpowershell%" ESCAPE '\' OR COMMAND_LINE LIKE "%/kschtasks%" ESCAPE '\' OR COMMAND_LINE LIKE "%/kbitsadmin%" ESCAPE '\' OR COMMAND_LINE LIKE "%/kcertutil%" ESCAPE '\') OR (COMMAND_LINE LIKE "%cmd.exe /c%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /c%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /k%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /k%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /r%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /r%" ESCAPE '\')) AND NOT (((COMMAND_LINE LIKE "%cmd.exe /c %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /c %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /k %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /k %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /r %" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd /r %" ESCAPE '\')) OR (COMMAND_LINE LIKE "%AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node\_modules%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe/c ." ESCAPE '\' OR COMMAND_LINE = "cmd.exe /c")))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_7z.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%7z.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%7za.exe%" ESCAPE '\') AND COMMAND_LINE LIKE "% -p%" ESCAPE '\' AND (COMMAND_LINE LIKE "% a %" ESCAPE '\' OR COMMAND_LINE LIKE "% u %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_reg_add_run_key.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "% ADD %" ESCAPE '\' AND COMMAND_LINE LIKE "%Software\\Microsoft\\Windows\\CurrentVersion\\Run%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_gamaredon_ultravnc.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-autoreconnect %" ESCAPE '\' AND COMMAND_LINE LIKE "%-connect %" ESCAPE '\' AND COMMAND_LINE LIKE "%-id:%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_commandline_chars.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%ˣ%" ESCAPE '\' OR COMMAND_LINE LIKE "%˪%" ESCAPE '\' OR COMMAND_LINE LIKE "%ˢ%" ESCAPE '\') OR (COMMAND_LINE LIKE "%∕%" ESCAPE '\' OR COMMAND_LINE LIKE "%⁄%" ESCAPE '\') OR (COMMAND_LINE LIKE "%―%" ESCAPE '\' OR COMMAND_LINE LIKE "%—%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_uninstall_crowdstrike_falcon.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\WindowsSensor.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "% /uninstall%" ESCAPE '\' AND COMMAND_LINE LIKE "% /quiet%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_taidoor.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%dll,MyStart%" ESCAPE '\' OR COMMAND_LINE LIKE "%dll MyStart%" ESCAPE '\') OR (COMMAND_LINE LIKE "% MyStart" ESCAPE '\' AND COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_rundll.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%shell32.dll%" ESCAPE '\' AND COMMAND_LINE LIKE "%shellexec\_rundll%" ESCAPE '\' AND COMMAND_LINE LIKE "%powershell%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_add_local_admin.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "%localgroup %" ESCAPE '\' AND COMMAND_LINE LIKE "% /add%" ESCAPE '\') OR (COMMAND_LINE LIKE "%Add-LocalGroupMember %" ESCAPE '\' AND COMMAND_LINE LIKE "% -Group %" ESCAPE '\')) AND (COMMAND_LINE LIKE "% administrators %" ESCAPE '\' OR COMMAND_LINE LIKE "% administrateur%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_lazarus_loader.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%cmd.exe /c %" ESCAPE '\' AND COMMAND_LINE LIKE "% -p 0x%" ESCAPE '\' AND (COMMAND_LINE LIKE "%C:\\ProgramData\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%C:\\RECYCLER\\%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%rundll32.exe %" ESCAPE '\' AND COMMAND_LINE LIKE "%C:\\ProgramData\\%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.bin,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.tmp,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dat,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.io,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ini,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.db,%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_conti_cmd_ransomware.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-m %" ESCAPE '\' AND COMMAND_LINE LIKE "%-net %" ESCAPE '\' AND COMMAND_LINE LIKE "%-size %" ESCAPE '\' AND COMMAND_LINE LIKE "%-nomutex %" ESCAPE '\' AND COMMAND_LINE LIKE "%-p \\\\\*" ESCAPE '\' AND COMMAND_LINE LIKE "%$%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_asr_bypass_via_appvlp_re.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%appvlp.exe%" ESCAPE '\' AND (COMMAND_LINE LIKE "%cmd.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%powershell.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwsh.exe%" ESCAPE '\') AND (COMMAND_LINE LIKE "%.sh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bin%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bat%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "%.js%" ESCAPE '\' OR COMMAND_LINE LIKE "%.msh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.reg%" ESCAPE '\' OR COMMAND_LINE LIKE "%.scr%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ps%" ESCAPE '\' OR COMMAND_LINE LIKE "%.vb%" ESCAPE '\' OR COMMAND_LINE LIKE "%.jar%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pl%" ESCAPE '\' OR COMMAND_LINE LIKE "%.inf%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_adfind_enumeration.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%lockoutduration%" ESCAPE '\' OR COMMAND_LINE LIKE "%lockoutthreshold%" ESCAPE '\' OR COMMAND_LINE LIKE "%lockoutobservationwindow%" ESCAPE '\' OR COMMAND_LINE LIKE "%maxpwdage%" ESCAPE '\' OR COMMAND_LINE LIKE "%minpwdage%" ESCAPE '\' OR COMMAND_LINE LIKE "%minpwdlength%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwdhistorylength%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwdproperties%" ESCAPE '\') OR COMMAND_LINE LIKE "%-sc admincountdmp%" ESCAPE '\' OR COMMAND_LINE LIKE "%-sc exchaddresses%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_empire_uac_bypass.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)%" ESCAPE '\' OR COMMAND_LINE LIKE "% -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_recon_network_activity.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%nslookup%" ESCAPE '\' AND COMMAND_LINE LIKE "%\_ldap.\_tcp.dc.\_msdcs.%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_netsh_discovery_command.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%netsh %" ESCAPE '\' AND COMMAND_LINE LIKE "%show %" ESCAPE '\' AND COMMAND_LINE LIKE "%firewall %" ESCAPE '\' AND (COMMAND_LINE LIKE "%config %" ESCAPE '\' OR COMMAND_LINE LIKE "%state %" ESCAPE '\' OR COMMAND_LINE LIKE "%rule %" ESCAPE '\' OR COMMAND_LINE LIKE "%name=all%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_tropictrooper.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_alternate_data_streams.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%txt:%" ESCAPE '\' AND ((COMMAND_LINE LIKE "%type %" ESCAPE '\' AND COMMAND_LINE LIKE "% > %" ESCAPE '\') OR (COMMAND_LINE LIKE "%makecab %" ESCAPE '\' AND COMMAND_LINE LIKE "%.cab%" ESCAPE '\') OR (COMMAND_LINE LIKE "%reg %" ESCAPE '\' AND COMMAND_LINE LIKE "% export %" ESCAPE '\') OR (COMMAND_LINE LIKE "%regedit %" ESCAPE '\' AND COMMAND_LINE LIKE "% /E %" ESCAPE '\') OR (COMMAND_LINE LIKE "%esentutl %" ESCAPE '\' AND COMMAND_LINE LIKE "% /y %" ESCAPE '\' AND COMMAND_LINE LIKE "% /d %" ESCAPE '\' AND COMMAND_LINE LIKE "% /o %" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_change_default_file_association.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%assoc%" ESCAPE '\' AND (COMMAND_LINE LIKE "% /c %" ESCAPE '\' OR COMMAND_LINE LIKE "% /k %" ESCAPE '\' OR COMMAND_LINE LIKE "% /r %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_import_cert_susp_locations.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Import-Certificate%" ESCAPE '\' AND COMMAND_LINE LIKE "% -File-Path %" ESCAPE '\' AND COMMAND_LINE LIKE "%Cert:\\LocalMachine\\Root%" ESCAPE '\' AND (COMMAND_LINE LIKE "%\\AppData\\Local\\Temp\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%C:\\Windows\\TEMP\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Desktop\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Downloads\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Perflogs\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%C:\\Users\\Public\\%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_explorer_break_proctree.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}%" ESCAPE '\' OR (COMMAND_LINE LIKE "%explorer.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "% /root,%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_nt_resource_kit_auditpol_usage.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%/logon:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/system:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/sam:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/privilege:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/object:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/process:none%" ESCAPE '\' OR COMMAND_LINE LIKE "%/policy:none%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_babyshark.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%reg query "HKEY\_CURRENT\_USER\\Software\\Microsoft\\Terminal Server Client\\Default"%" ESCAPE '\' OR COMMAND_LINE LIKE "%powershell.exe mshta.exe http%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /c taskkill /im cmd.exe%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_zip_compress.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Compress-Archive %" ESCAPE '\' AND COMMAND_LINE LIKE "% -Path %" ESCAPE '\' AND COMMAND_LINE LIKE "% -DestinationPath %" ESCAPE '\' AND COMMAND_LINE LIKE "%$env:TEMP\\%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_ta17_293a_ps.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE = "ps.exe -accepteula"

-- sigma rule file rules/windows/process_creation/proc_creation_win_discover_private_keys.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%dir %" ESCAPE '\' OR COMMAND_LINE LIKE "%findstr %" ESCAPE '\') AND (COMMAND_LINE LIKE "%.key%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pgp%" ESCAPE '\' OR COMMAND_LINE LIKE "%.gpg%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ppk%" ESCAPE '\' OR COMMAND_LINE LIKE "%.p12%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pem%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pfx%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cer%" ESCAPE '\' OR COMMAND_LINE LIKE "%.p7b%" ESCAPE '\' OR COMMAND_LINE LIKE "%.asc%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_crackmapexec_execution.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%cmd.exe /Q /c % 1> \\%\\%\\% 2>&1" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /C % > \\%\\%\\% 2>&1" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe /C % > %\\Temp\\% 2>&1" ESCAPE '\') AND (COMMAND_LINE LIKE "%powershell.exe -exec bypass -noni -nop -w 1 -C "%" ESCAPE '\' OR COMMAND_LINE LIKE "%powershell.exe -noni -nop -w 1 -enc %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_conti_shadowcopy.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%" ESCAPE '\' AND (COMMAND_LINE LIKE "%\\NTDS.dit%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\SYSTEM%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\SECURITY%" ESCAPE '\' OR COMMAND_LINE LIKE "%C:\\tmp\\log%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_shadow_copies_access_symlink.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%mklink%" ESCAPE '\' AND COMMAND_LINE LIKE "%HarddiskVolumeShadowCopy%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_shellexec_rundll_usage.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%ShellExec\_RunDLL%" ESCAPE '\' AND (COMMAND_LINE LIKE "%regsvr32%" ESCAPE '\' OR COMMAND_LINE LIKE "%msiexec%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Users\\Public\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%odbcconf%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Desktop\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Temp\\%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_var.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%"set%" ESCAPE '\' AND COMMAND_LINE LIKE "%-f%" ESCAPE '\' AND (COMMAND_LINE LIKE "%/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%/r%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_tscon_rdp_redirect.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "% /dest:rdp-tcp:%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_install_reg_debugger_backdoor.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\CurrentVersion\\Image File Execution Options\\%" ESCAPE '\' AND (COMMAND_LINE LIKE "%sethc.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%utilman.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%osk.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%magnify.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%narrator.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%displayswitch.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%atbroker.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%HelpPane.exe%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_tamper_defender_remove_mppreference.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Remove-MpPreference%" ESCAPE '\' AND (COMMAND_LINE LIKE "%-ControlledFolderAccessProtectedFolders %" ESCAPE '\' OR COMMAND_LINE LIKE "%-AttackSurfaceReductionRules\_Ids %" ESCAPE '\' OR COMMAND_LINE LIKE "%-AttackSurfaceReductionRules\_Actions %" ESCAPE '\' OR COMMAND_LINE LIKE "%-CheckForSignaturesBeforeRunningScan %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_disable_eventlog.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%logman %" ESCAPE '\' AND (COMMAND_LINE LIKE "%stop %" ESCAPE '\' OR COMMAND_LINE LIKE "%delete %" ESCAPE '\') AND COMMAND_LINE LIKE "%EventLog-System%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_turla_commands_critical.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "net use \\\\\%DomainController\%\\C$ "P@ssw0rd" %" ESCAPE '\' OR COMMAND_LINE LIKE "dir c:\\%.doc% /s" ESCAPE '\' OR COMMAND_LINE LIKE "dir \%TEMP\%\\%.exe" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_unc2452_ps.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Invoke-WMIMethod win32\_process -name create -argumentlist%" ESCAPE '\' AND COMMAND_LINE LIKE "%rundll32 c:\\windows%" ESCAPE '\') OR (COMMAND_LINE LIKE "%wmic /node:%" ESCAPE '\' AND COMMAND_LINE LIKE "%process call create "rundll32 c:\\windows%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_office_token_search.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%eyJ0eXAiOi%" ESCAPE '\' OR COMMAND_LINE LIKE "% eyJ0eX%" ESCAPE '\' OR COMMAND_LINE LIKE "% "eyJ0eX"%" ESCAPE '\' OR COMMAND_LINE LIKE "% 'eyJ0eX'%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_sysinternals_eula_accepted.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -accepteula%" ESCAPE '\' OR COMMAND_LINE LIKE "% /accepteula%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_reg_disable_sec_services.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "%add%" ESCAPE '\') AND ((COMMAND_LINE LIKE "% /d 4%" ESCAPE '\' AND COMMAND_LINE LIKE "% /v Start%" ESCAPE '\' AND (COMMAND_LINE LIKE "%\\Sense%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\WinDefend%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\MsMpSvc%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\NisSrv%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\WdBoot%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\WdNisDrv%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\WdNisSvc%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\wscsvc%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\SecurityHealthService%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\wuauserv%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\UsoSvc%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\WdFilter%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\AppIDSvc%" ESCAPE '\')) OR (COMMAND_LINE LIKE "% /d 1%" ESCAPE '\' AND COMMAND_LINE LIKE "%Windows Defender%" ESCAPE '\' AND (COMMAND_LINE LIKE "%DisableIOAVProtection%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableOnAccessProtection%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableRoutinelyTakingAction%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableScanOnRealtimeEnable%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableBlockAtFirstSeen%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableBehaviorMonitoring%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableEnhancedNotifications%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableAntiSpyware%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableAntiSpywareRealtimeProtection%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableConfig%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisablePrivacyMode%" ESCAPE '\' OR COMMAND_LINE LIKE "%SignatureDisableUpdateOnStartupWithoutEngine%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableArchiveScanning%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableIntrusionPreventionSystem%" ESCAPE '\' OR COMMAND_LINE LIKE "%DisableScriptScanning%" ESCAPE '\'))))

-- sigma rule file rules/windows/process_creation/proc_creation_win_write_protect_for_storage_disabled.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%reg add%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\system\\currentcontrolset\\control%" ESCAPE '\' AND COMMAND_LINE LIKE "%write protection%" ESCAPE '\' AND COMMAND_LINE LIKE "%0%" ESCAPE '\' AND (COMMAND_LINE LIKE "%storage%" ESCAPE '\' OR COMMAND_LINE LIKE "%storagedevicepolicies%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_web_request_cmd_and_cmdlets.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Invoke-WebRequest%" ESCAPE '\' OR COMMAND_LINE LIKE "%iwr %" ESCAPE '\' OR COMMAND_LINE LIKE "%wget %" ESCAPE '\' OR COMMAND_LINE LIKE "%curl %" ESCAPE '\' OR COMMAND_LINE LIKE "%Net.WebClient%" ESCAPE '\' OR COMMAND_LINE LIKE "%Start-BitsTransfer%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_change_default_file_assoc_susp.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%assoc %" ESCAPE '\' AND COMMAND_LINE LIKE "%exefile%" ESCAPE '\' AND (COMMAND_LINE LIKE "% /c %" ESCAPE '\' OR COMMAND_LINE LIKE "% /r %" ESCAPE '\' OR COMMAND_LINE LIKE "% /k %" ESCAPE '\')) AND NOT (COMMAND_LINE LIKE "%.exe=exefile%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_clip.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%echo%" ESCAPE '\' AND COMMAND_LINE LIKE "%clip%" ESCAPE '\' AND COMMAND_LINE LIKE "%&&%" ESCAPE '\' AND (COMMAND_LINE LIKE "%clipboard%" ESCAPE '\' OR COMMAND_LINE LIKE "%invoke%" ESCAPE '\' OR COMMAND_LINE LIKE "%i`%" ESCAPE '\' OR COMMAND_LINE LIKE "%n`%" ESCAPE '\' OR COMMAND_LINE LIKE "%v`%" ESCAPE '\' OR COMMAND_LINE LIKE "%o`%" ESCAPE '\' OR COMMAND_LINE LIKE "%k`%" ESCAPE '\' OR COMMAND_LINE LIKE "%e`%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Launch-VsDevShell.ps1%" ESCAPE '\' AND (COMMAND_LINE LIKE "%VsWherePath %" ESCAPE '\' OR COMMAND_LINE LIKE "%VsInstallationPath %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_monitoring_for_persistence_via_bits.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%bitsadmin%" ESCAPE '\' AND COMMAND_LINE LIKE "%/SetNotifyCmdLine%" ESCAPE '\' AND (COMMAND_LINE LIKE "%\%COMSPEC\%%" ESCAPE '\' OR COMMAND_LINE LIKE "%cmd.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%regsvr32.exe%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%bitsadmin%" ESCAPE '\' AND COMMAND_LINE LIKE "%/Addfile%" ESCAPE '\' AND (COMMAND_LINE LIKE "%http:%" ESCAPE '\' OR COMMAND_LINE LIKE "%https:%" ESCAPE '\' OR COMMAND_LINE LIKE "%ftp:%" ESCAPE '\' OR COMMAND_LINE LIKE "%ftps:%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_wmic_eventconsumer_create.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%ActiveScriptEventConsumer%" ESCAPE '\' AND COMMAND_LINE LIKE "% CREATE %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_register_app.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\register\_app.vbs%" ESCAPE '\' AND COMMAND_LINE LIKE "%-register%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_execution_via_winget.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%winget%" ESCAPE '\' AND COMMAND_LINE LIKE "%install%" ESCAPE '\' AND (COMMAND_LINE LIKE "%-m %" ESCAPE '\' OR COMMAND_LINE LIKE "%--manifest%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_base64_invoke.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQ%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0A%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtA%" ESCAPE '\') AND NOT (((COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBCAGwAbwBvAGQASABvAHUAbgBkA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0AQgBsAG8AbwBkAEgAbwB1AG4AZA%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAEIAbABvAG8AZABIAG8AdQBuAGQA%" ESCAPE '\' OR COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6A%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAeg%" ESCAPE '\' OR COMMAND_LINE LIKE "%SQBuAHYAbwBrAGUALQBXAE0ASQBFAHgAZQBjA%" ESCAPE '\' OR COMMAND_LINE LIKE "%kAbgB2AG8AawBlAC0AVwBNAEkARQB4AGUAYw%" ESCAPE '\' OR COMMAND_LINE LIKE "%JAG4AdgBvAGsAZQAtAFcATQBJAEUAeABlAGMA%" ESCAPE '\'))))

-- sigma rule file rules/windows/process_creation/proc_creation_win_sysnative.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "C:\\Windows\\Sysnative\\%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_mal_adwind.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%\\AppData\\Roaming\\Oracle%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\java%" ESCAPE '\' AND COMMAND_LINE LIKE "%.exe %" ESCAPE '\') OR (COMMAND_LINE LIKE "%cscript.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%Retrive%" ESCAPE '\' AND COMMAND_LINE LIKE "%.vbs %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_new_network_provider.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%\\System\\CurrentControlSet\\Services\\%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\NetworkProvider%" ESCAPE '\') AND NOT ((COMMAND_LINE LIKE "%\\System\\CurrentControlSet\\Services\\WebClient\\NetworkProvider%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\NetworkProvider%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\System\\CurrentControlSet\\Services\\RDPNP\\NetworkProvider%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_screenconnect_access.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%e=Access&%" ESCAPE '\' AND COMMAND_LINE LIKE "%y=Guest&%" ESCAPE '\' AND COMMAND_LINE LIKE "%&p=%" ESCAPE '\' AND COMMAND_LINE LIKE "%&c=%" ESCAPE '\' AND COMMAND_LINE LIKE "%&k=%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_amsi_bypass.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%System.Management.Automation.AmsiUtils%" ESCAPE '\' OR COMMAND_LINE LIKE "%amsiInitFailed%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_netsh_packet_capture.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%netsh%" ESCAPE '\' AND COMMAND_LINE LIKE "%trace%" ESCAPE '\' AND COMMAND_LINE LIKE "%start%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_regsvr32_http_pattern.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% /s%" ESCAPE '\' AND COMMAND_LINE LIKE "% /u%" ESCAPE '\' AND (COMMAND_LINE LIKE "% /i:http://1%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://2%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://3%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://4%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://5%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://6%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://7%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://8%" ESCAPE '\' OR COMMAND_LINE LIKE "% /i:http://9%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_reg_dump_sam.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% save %" ESCAPE '\' AND (COMMAND_LINE LIKE "%HKLM\\sam%" ESCAPE '\' OR COMMAND_LINE LIKE "%HKLM\\system%" ESCAPE '\' OR COMMAND_LINE LIKE "%HKLM\\security%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_wscript_shell_cli.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Wscript.%" ESCAPE '\' AND COMMAND_LINE LIKE "%.Shell%" ESCAPE '\' AND COMMAND_LINE LIKE "%.Run%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_network_command.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%ipconfig /all%" ESCAPE '\' OR COMMAND_LINE LIKE "%netsh interface show interface%" ESCAPE '\' OR COMMAND_LINE LIKE "%arp -a%" ESCAPE '\' OR COMMAND_LINE LIKE "%nbtstat -n%" ESCAPE '\' OR COMMAND_LINE LIKE "%net config%" ESCAPE '\' OR COMMAND_LINE LIKE "%route print%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_sysvol_access.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\SYSVOL\\%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\policies\\%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_shimcache_flush.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' AND COMMAND_LINE LIKE "%apphelp.dll%" ESCAPE '\' AND (COMMAND_LINE LIKE "%ShimFlushCache%" ESCAPE '\' OR COMMAND_LINE LIKE "%#250%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%rundll32%" ESCAPE '\' AND COMMAND_LINE LIKE "%kernel32.dll%" ESCAPE '\' AND (COMMAND_LINE LIKE "%BaseFlushAppcompatCache%" ESCAPE '\' OR COMMAND_LINE LIKE "%#46%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_conhost_option.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%conhost.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%0xffffffff%" ESCAPE '\' AND COMMAND_LINE LIKE "%-ForceV1%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_run_virtualbox.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%VBoxRT.dll,RTR3Init%" ESCAPE '\' OR COMMAND_LINE LIKE "%VBoxC.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%VBoxDrv.sys%" ESCAPE '\') OR (COMMAND_LINE LIKE "%startvm%" ESCAPE '\' OR COMMAND_LINE LIKE "%controlvm%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_stdin.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%set%" ESCAPE '\' AND COMMAND_LINE LIKE "%&&%" ESCAPE '\' AND (COMMAND_LINE LIKE "%environment%" ESCAPE '\' OR COMMAND_LINE LIKE "%invoke%" ESCAPE '\' OR COMMAND_LINE LIKE "%input%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_command_flag_pattern.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "% -u system %" ESCAPE '\' OR COMMAND_LINE LIKE "% --user system %" ESCAPE '\' OR COMMAND_LINE LIKE "% -u NT%" ESCAPE '\' OR COMMAND_LINE LIKE "% -u "NT%" ESCAPE '\' OR COMMAND_LINE LIKE "% -u 'NT%" ESCAPE '\' OR COMMAND_LINE LIKE "% --system %" ESCAPE '\' OR COMMAND_LINE LIKE "% -u administrator %" ESCAPE '\') AND (COMMAND_LINE LIKE "% -c cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c "cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c "powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% --command cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "% --command powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c whoami%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c wscript%" ESCAPE '\' OR COMMAND_LINE LIKE "% -c cscript%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_conti_sqlcmd.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%sqlcmd %" ESCAPE '\' OR COMMAND_LINE LIKE "%sqlcmd.exe%" ESCAPE '\') AND COMMAND_LINE LIKE "% -S localhost %" ESCAPE '\' AND (COMMAND_LINE LIKE "%sys.sysprocesses%" ESCAPE '\' OR COMMAND_LINE LIKE "%master.dbo.sysdatabases%" ESCAPE '\' OR COMMAND_LINE LIKE "%BACKUP DATABASE%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_devinit_lolbin.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -t msi-install %" ESCAPE '\' AND COMMAND_LINE LIKE "% -i http%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_volsnap_disable.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%reg%" ESCAPE '\' AND COMMAND_LINE LIKE "% add %" ESCAPE '\' AND COMMAND_LINE LIKE "%\\Services\\VSS\\Diag%" ESCAPE '\' AND COMMAND_LINE LIKE "%/d Disabled%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_download_cradles.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%.DownloadString(%" ESCAPE '\' OR COMMAND_LINE LIKE "%.DownloadFile(%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_curl_start_combo.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% /c %" ESCAPE '\' AND COMMAND_LINE LIKE "%curl %" ESCAPE '\' AND COMMAND_LINE LIKE "%http%" ESCAPE '\' AND COMMAND_LINE LIKE "%-o%" ESCAPE '\' AND COMMAND_LINE LIKE "%&%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_rundll32_sys.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.sys,%" ESCAPE '\' OR COMMAND_LINE LIKE "%.sys %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_enumeration_for_credentials_cli.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\Software\\SimonTatham\\PuTTY\\Sessions%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\Mobatek\\MobaXterm\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\Aerofox\\FoxmailPreview%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\Aerofox\\Foxmail\\V3.1%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\IncrediMail\\Identities%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\Qualcomm\\Eudora\\CommandLine%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\RimArts\\B2\\Settings%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\OpenVPN-GUI\\configs%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\Martin Prikryl\\WinSCP 2\\Sessions%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\FTPWare\\COREFTP\\Sites%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\DownloadManager\\Passwords%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\OpenSSH\\Agent\\Keys%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\TightVNC\\Server%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\ORL\\WinVNC3\\Password%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\Software\\RealVNC\\WinVNC4%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_sam_access.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\HarddiskVolumeShadowCopy%" ESCAPE '\' AND COMMAND_LINE LIKE "%ystem32\\config\\sam%" ESCAPE '\' AND (COMMAND_LINE LIKE "%Copy-Item%" ESCAPE '\' OR COMMAND_LINE LIKE "%cp $\_.%" ESCAPE '\' OR COMMAND_LINE LIKE "%cpi $\_.%" ESCAPE '\' OR COMMAND_LINE LIKE "%copy $\_.%" ESCAPE '\' OR COMMAND_LINE LIKE "%.File]::Copy(%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_remote_desktop_tunneling.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%:3389%" ESCAPE '\' AND (COMMAND_LINE LIKE "% -L %" ESCAPE '\' OR COMMAND_LINE LIKE "% -P %" ESCAPE '\' OR COMMAND_LINE LIKE "% -R %" ESCAPE '\' OR COMMAND_LINE LIKE "% -pw %" ESCAPE '\' OR COMMAND_LINE LIKE "% -ssh %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%diantz.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "% \\\\\*" ESCAPE '\' AND COMMAND_LINE LIKE "%.cab%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_ryuk.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Microsoft\\Windows\\CurrentVersion\\Run%" ESCAPE '\' AND COMMAND_LINE LIKE "%C:\\users\\Public\\%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\SyncAppvPublishingServer.vbs%" ESCAPE '\' AND COMMAND_LINE LIKE "%;%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_ps_downloadfile.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%powershell%" ESCAPE '\' AND COMMAND_LINE LIKE "%.DownloadFile%" ESCAPE '\' AND COMMAND_LINE LIKE "%System.Net.WebClient%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_hiding_malware_in_fonts_folder.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%echo%" ESCAPE '\' OR COMMAND_LINE LIKE "%copy%" ESCAPE '\' OR COMMAND_LINE LIKE "%type%" ESCAPE '\' OR COMMAND_LINE LIKE "%file createnew%" ESCAPE '\' OR COMMAND_LINE LIKE "%cacls%" ESCAPE '\') AND COMMAND_LINE LIKE "%C:\\Windows\\Fonts\\%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.sh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bin%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bat%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "%.js%" ESCAPE '\' OR COMMAND_LINE LIKE "%.msh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.reg%" ESCAPE '\' OR COMMAND_LINE LIKE "%.scr%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ps%" ESCAPE '\' OR COMMAND_LINE LIKE "%.vb%" ESCAPE '\' OR COMMAND_LINE LIKE "%.jar%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pl%" ESCAPE '\' OR COMMAND_LINE LIKE "%.inf%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cpl%" ESCAPE '\' OR COMMAND_LINE LIKE "%.hta%" ESCAPE '\' OR COMMAND_LINE LIKE "%.msi%" ESCAPE '\' OR COMMAND_LINE LIKE "%.vbs%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_modif_of_services_for_via_commandline.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%sc %" ESCAPE '\' AND COMMAND_LINE LIKE "%config %" ESCAPE '\' AND COMMAND_LINE LIKE "%binpath=%" ESCAPE '\') OR (COMMAND_LINE LIKE "%sc %" ESCAPE '\' AND COMMAND_LINE LIKE "%failure%" ESCAPE '\' AND COMMAND_LINE LIKE "%command=%" ESCAPE '\') OR (COMMAND_LINE LIKE "%reg %" ESCAPE '\' AND COMMAND_LINE LIKE "%add %" ESCAPE '\' AND COMMAND_LINE LIKE "%FailureCommand%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.sh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bin$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bat%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "%.js%" ESCAPE '\' OR COMMAND_LINE LIKE "%.msh$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.reg$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.scr%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ps%" ESCAPE '\' OR COMMAND_LINE LIKE "%.vb%" ESCAPE '\' OR COMMAND_LINE LIKE "%.jar%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pl%" ESCAPE '\')) OR (COMMAND_LINE LIKE "%reg %" ESCAPE '\' AND COMMAND_LINE LIKE "%add %" ESCAPE '\' AND COMMAND_LINE LIKE "%ImagePath%" ESCAPE '\' AND (COMMAND_LINE LIKE "%.sh%" ESCAPE '\' OR COMMAND_LINE LIKE "%.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bin$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.bat%" ESCAPE '\' OR COMMAND_LINE LIKE "%.cmd%" ESCAPE '\' OR COMMAND_LINE LIKE "%.js%" ESCAPE '\' OR COMMAND_LINE LIKE "%.msh$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.reg$%" ESCAPE '\' OR COMMAND_LINE LIKE "%.scr%" ESCAPE '\' OR COMMAND_LINE LIKE "%.ps%" ESCAPE '\' OR COMMAND_LINE LIKE "%.vb%" ESCAPE '\' OR COMMAND_LINE LIKE "%.jar%" ESCAPE '\' OR COMMAND_LINE LIKE "%.pl%" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_apt29_thinktanks.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-noni%" ESCAPE '\' AND COMMAND_LINE LIKE "%-ep%" ESCAPE '\' AND COMMAND_LINE LIKE "%bypass%" ESCAPE '\' AND COMMAND_LINE LIKE "%$%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_abusing_windows_telemetry_for_persistence.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%schtasks%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\Application Experience\\Microsoft Compatibility Appraiser%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_servu_exploitation_cve_2021_35211.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%whoami%" ESCAPE '\' AND (COMMAND_LINE LIKE "%./Client/Common/%" ESCAPE '\' OR COMMAND_LINE LIKE "%.\\Client\\Common\\%" ESCAPE '\')) OR COMMAND_LINE LIKE "%C:\\Windows\\Temp\\Serv-U.bat%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_empire_launch.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% -NoP -sta -NonI -W Hidden -Enc %" ESCAPE '\' OR COMMAND_LINE LIKE "% -noP -sta -w 1 -enc %" ESCAPE '\' OR COMMAND_LINE LIKE "% -NoP -NonI -W Hidden -enc %" ESCAPE '\' OR COMMAND_LINE LIKE "% -noP -sta -w 1 -enc%" ESCAPE '\' OR COMMAND_LINE LIKE "% -enc  SQB%" ESCAPE '\' OR COMMAND_LINE LIKE "% -nop -exec bypass -EncodedCommand %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_ps_appdata.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%powershell.exe%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\powershell%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\pwsh%" ESCAPE '\' OR COMMAND_LINE LIKE "%pwsh.exe%" ESCAPE '\') AND COMMAND_LINE LIKE "%/c %" ESCAPE '\' AND COMMAND_LINE LIKE "%\\AppData\\%" ESCAPE '\' AND (COMMAND_LINE LIKE "%Local\\%" ESCAPE '\' OR COMMAND_LINE LIKE "%Roaming\\%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_unidentified_nov_18.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cyzfc.dat,%" ESCAPE '\' AND COMMAND_LINE LIKE "%PointFunctionCall" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_netsh_allow_port_rdp.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%netsh%" ESCAPE '\' AND COMMAND_LINE LIKE "%firewall add portopening%" ESCAPE '\' AND COMMAND_LINE LIKE "%tcp 3389%" ESCAPE '\') OR (COMMAND_LINE LIKE "%netsh%" ESCAPE '\' AND COMMAND_LINE LIKE "%advfirewall firewall add rule%" ESCAPE '\' AND COMMAND_LINE LIKE "%action=allow%" ESCAPE '\' AND COMMAND_LINE LIKE "%protocol=TCP%" ESCAPE '\' AND COMMAND_LINE LIKE "%localport=3389%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_malware_conti_7zip.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%7za.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\C$\\temp\\log.zip%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_actinium_persistence.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%schtasks%" ESCAPE '\' AND COMMAND_LINE LIKE "%create%" ESCAPE '\' AND COMMAND_LINE LIKE "%wscript%" ESCAPE '\' AND COMMAND_LINE LIKE "%e:vbscript%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_cscript_gathernetworkinfo.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cscript.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%gatherNetworkInfo.vbs%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_dir.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%dir %" ESCAPE '\' AND COMMAND_LINE LIKE "% /s%" ESCAPE '\' AND COMMAND_LINE LIKE "% /b%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_ke3chang_regadd.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%-Property DWORD -name DisableFirstRunCustomize -value 2 -Force%" ESCAPE '\' OR COMMAND_LINE LIKE "%-Property String -name Check\_Associations -value%" ESCAPE '\' OR COMMAND_LINE LIKE "%-Property DWORD -name IEHarden -value 0 -Force%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\pubprn.vbs%" ESCAPE '\' AND COMMAND_LINE LIKE "%script:%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_ntdll_type_redirect.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%type \%windir\%\\system32\\ntdll.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%type \%systemroot\%\\system32\\ntdll.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%type c:\\windows\\system32\\ntdll.dll%" ESCAPE '\' OR COMMAND_LINE LIKE "%\\ntdll.dll > \\\\.\\pipe\\\*" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_disable_raccine.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%taskkill %" ESCAPE '\' AND COMMAND_LINE LIKE "%RaccineSettings.exe%" ESCAPE '\') OR (COMMAND_LINE LIKE "%reg.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%delete%" ESCAPE '\' AND COMMAND_LINE LIKE "%Raccine Tray%" ESCAPE '\') OR (COMMAND_LINE LIKE "%schtasks%" ESCAPE '\' AND COMMAND_LINE LIKE "%/DELETE%" ESCAPE '\' AND COMMAND_LINE LIKE "%Raccine Rules Updater%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_rundll32_inline_vbs.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%rundll32.exe%" ESCAPE '\' AND COMMAND_LINE LIKE "%Execute%" ESCAPE '\' AND COMMAND_LINE LIKE "%RegRead%" ESCAPE '\' AND COMMAND_LINE LIKE "%window.close%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_b64_shellcode.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%AAAAYInlM%" ESCAPE '\' AND (COMMAND_LINE LIKE "%OiCAAAAYInlM%" ESCAPE '\' OR COMMAND_LINE LIKE "%OiJAAAAYInlM%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_weak_or_abused_passwords.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%Asd123.aaaa%" ESCAPE '\' OR COMMAND_LINE LIKE "%password123%" ESCAPE '\' OR COMMAND_LINE LIKE "%123456789%" ESCAPE '\' OR COMMAND_LINE LIKE "%P@ssw0rd!%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_utilityfunctions.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%UtilityFunctions.ps1%" ESCAPE '\' OR COMMAND_LINE LIKE "%RegSnapin %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_bluemashroom.yml;
SELECT * FROM eventlog WHERE (((COMMAND_LINE LIKE "%\\regsvr32%" ESCAPE '\' AND COMMAND_LINE LIKE "%\\AppData\\Local\\%" ESCAPE '\') OR (COMMAND_LINE LIKE "%\\AppData\\Local\\%" ESCAPE '\' AND COMMAND_LINE LIKE "%,DllEntry%" ESCAPE '\')) AND NOT ((COMMAND_LINE LIKE "%AppData\\Local\\Microsoft\\TeamsMeetingAddin\\%" ESCAPE '\' OR (COMMAND_LINE LIKE "%\\x86\\Microsoft.Teams.AddinLoader.dll" ESCAPE '\' OR COMMAND_LINE LIKE "%\\x86\\Microsoft.Teams.AddinLoader.dll"" ESCAPE '\' OR COMMAND_LINE LIKE "%\\x64\\Microsoft.Teams.AddinLoader.dll" ESCAPE '\' OR COMMAND_LINE LIKE "%\\x64\\Microsoft.Teams.AddinLoader.dll"" ESCAPE '\')) OR (COMMAND_LINE LIKE "%\\AppData\\Local\\WebEx\\WebEx64\\Meetings\\atucfobj.dll" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_win_exchange_transportagent.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%Install-TransportAgent%" ESCAPE '\'

-- sigma rule file rules/windows/process_creation/proc_creation_win_inline_win_api_access.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "% WaitForSingleObject %" ESCAPE '\' OR COMMAND_LINE LIKE "% QueueUserApc %" ESCAPE '\' OR COMMAND_LINE LIKE "% RtlCreateUserThread %" ESCAPE '\' OR COMMAND_LINE LIKE "% OpenProcess %" ESCAPE '\' OR COMMAND_LINE LIKE "% VirtualAlloc %" ESCAPE '\' OR COMMAND_LINE LIKE "% VirtualFree %" ESCAPE '\' OR COMMAND_LINE LIKE "% WriteProcessMemory %" ESCAPE '\' OR COMMAND_LINE LIKE "% CreateUserThread %" ESCAPE '\' OR COMMAND_LINE LIKE "% CloseHandle %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetDelegateForFunctionPointer %" ESCAPE '\' OR COMMAND_LINE LIKE "% CreateThread %" ESCAPE '\' OR COMMAND_LINE LIKE "% memcpy %" ESCAPE '\' OR COMMAND_LINE LIKE "% LoadLibrary %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetModuleHandle %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetProcAddress %" ESCAPE '\' OR COMMAND_LINE LIKE "% VirtualProtect %" ESCAPE '\' OR COMMAND_LINE LIKE "% FreeLibrary %" ESCAPE '\' OR COMMAND_LINE LIKE "% ReadProcessMemory %" ESCAPE '\' OR COMMAND_LINE LIKE "% CreateRemoteThread %" ESCAPE '\' OR COMMAND_LINE LIKE "% AdjustTokenPrivileges %" ESCAPE '\' OR COMMAND_LINE LIKE "% WriteInt32 %" ESCAPE '\' OR COMMAND_LINE LIKE "% OpenThreadToken %" ESCAPE '\' OR COMMAND_LINE LIKE "% PtrToString %" ESCAPE '\' OR COMMAND_LINE LIKE "% FreeHGlobal %" ESCAPE '\' OR COMMAND_LINE LIKE "% ZeroFreeGlobalAllocUnicode %" ESCAPE '\' OR COMMAND_LINE LIKE "% OpenProcessToken %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetTokenInformation %" ESCAPE '\' OR COMMAND_LINE LIKE "% SetThreadToken %" ESCAPE '\' OR COMMAND_LINE LIKE "% ImpersonateLoggedOnUser %" ESCAPE '\' OR COMMAND_LINE LIKE "% RevertToSelf %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetLogonSessionData %" ESCAPE '\' OR COMMAND_LINE LIKE "% CreateProcessWithToken %" ESCAPE '\' OR COMMAND_LINE LIKE "% DuplicateTokenEx %" ESCAPE '\' OR COMMAND_LINE LIKE "% OpenWindowStation %" ESCAPE '\' OR COMMAND_LINE LIKE "% OpenDesktop %" ESCAPE '\' OR COMMAND_LINE LIKE "% MiniDumpWriteDump %" ESCAPE '\' OR COMMAND_LINE LIKE "% AddSecurityPackage %" ESCAPE '\' OR COMMAND_LINE LIKE "% EnumerateSecurityPackages %" ESCAPE '\' OR COMMAND_LINE LIKE "% GetProcessHandle %" ESCAPE '\' OR COMMAND_LINE LIKE "% DangerousGetHandle %" ESCAPE '\' OR COMMAND_LINE LIKE "% kernel32 %" ESCAPE '\' OR COMMAND_LINE LIKE "% Advapi32 %" ESCAPE '\' OR COMMAND_LINE LIKE "% msvcrt %" ESCAPE '\' OR COMMAND_LINE LIKE "% ntdll %" ESCAPE '\' OR COMMAND_LINE LIKE "% user32 %" ESCAPE '\' OR COMMAND_LINE LIKE "% secur32 %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_network_listing_connections.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%netstat%" ESCAPE '\' OR (COMMAND_LINE LIKE "%net %" ESCAPE '\' AND ((COMMAND_LINE LIKE "% use" ESCAPE '\' OR COMMAND_LINE LIKE "% sessions" ESCAPE '\') OR (COMMAND_LINE LIKE "% use %" ESCAPE '\' OR COMMAND_LINE LIKE "% sessions %" ESCAPE '\'))))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_susp_grpconv.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%grpconv.exe -o%" ESCAPE '\' OR COMMAND_LINE LIKE "%grpconv -o%" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_apt_winnti_pipemon.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%setup0.exe -p%" ESCAPE '\' OR (COMMAND_LINE LIKE "%setup.exe%" ESCAPE '\' AND (COMMAND_LINE LIKE "%-x:0" ESCAPE '\' OR COMMAND_LINE LIKE "%-x:1" ESCAPE '\' OR COMMAND_LINE LIKE "%-x:2" ESCAPE '\')))

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_var.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%&&set%" ESCAPE '\' AND COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%/c%" ESCAPE '\' AND COMMAND_LINE LIKE "%-f%" ESCAPE '\' AND (COMMAND_LINE LIKE "%{0}%" ESCAPE '\' OR COMMAND_LINE LIKE "%{1}%" ESCAPE '\' OR COMMAND_LINE LIKE "%{2}%" ESCAPE '\' OR COMMAND_LINE LIKE "%{3}%" ESCAPE '\' OR COMMAND_LINE LIKE "%{4}%" ESCAPE '\' OR COMMAND_LINE LIKE "%{5}%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_powershell_defender_exclusion.yml;
SELECT * FROM eventlog WHERE ((COMMAND_LINE LIKE "%Add-MpPreference %" ESCAPE '\' OR COMMAND_LINE LIKE "%Set-MpPreference %" ESCAPE '\') AND (COMMAND_LINE LIKE "% -ExclusionPath %" ESCAPE '\' OR COMMAND_LINE LIKE "% -ExclusionExtension %" ESCAPE '\' OR COMMAND_LINE LIKE "% -ExclusionProcess %" ESCAPE '\' OR COMMAND_LINE LIKE "% -ExclusionIpAddress %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_copy_dmp_from_share.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%.dmp%" ESCAPE '\' AND COMMAND_LINE LIKE "%copy %" ESCAPE '\' AND COMMAND_LINE LIKE "% \\\\\*" ESCAPE '\' AND (COMMAND_LINE LIKE "% /c %" ESCAPE '\' OR COMMAND_LINE LIKE "% /r %" ESCAPE '\' OR COMMAND_LINE LIKE "% /k %" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_lolbin_cl_mutexverifiers.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%\\CL\_Mutexverifiers.ps1%" ESCAPE '\' AND COMMAND_LINE LIKE "%runAfterCancelProcess %" ESCAPE '\')

-- sigma rule file rules/windows/process_creation/proc_creation_win_invoke_obfuscation_clip.yml;
SELECT * FROM eventlog WHERE (COMMAND_LINE LIKE "%cmd%" ESCAPE '\' AND COMMAND_LINE LIKE "%&&%" ESCAPE '\' AND COMMAND_LINE LIKE "%clipboard]::%" ESCAPE '\' AND COMMAND_LINE LIKE "%-f%" ESCAPE '\' AND (COMMAND_LINE LIKE "%/c%" ESCAPE '\' OR COMMAND_LINE LIKE "%/r%" ESCAPE '\'))

-- sigma rule file rules/windows/process_creation/proc_creation_win_susp_powershell_getprocess_lsass.yml;
SELECT * FROM eventlog WHERE COMMAND_LINE LIKE "%Get-Process lsass%" ESCAPE '\'

