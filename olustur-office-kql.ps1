$ruleId = [guid]::NewGuid().ToString()
$lines = @(
  "id: $ruleId"
  'title: Office Application Spawning a Shell (Behavioral)'
  'description: Detects a Microsoft Office application (Word, Excel, Outlook, etc.) spawning a shell or script interpreter (powershell, cmd, wscript, mshta), a hallmark of macro-based phishing and initial access.'
  'severity: High'
  'tactics:'
  '  - InitialAccess'
  '  - Execution'
  'techniques:'
  '  - T1566'
  '  - T1059'
  'query: |'
  '  Event'
  '  | where Source == "Microsoft-Windows-Sysmon"'
  '  | where EventID == 1'
  '  | extend'
  '      Image       = extract(@''Name="Image">([^<]+)<'', 1, EventData),'
  '      ParentImage = extract(@''Name="ParentImage">([^<]+)<'', 1, EventData),'
  '      CmdLine     = extract(@''Name="CommandLine">([^<]+)<'', 1, EventData),'
  '      ParentCmd   = extract(@''Name="ParentCommandLine">([^<]+)<'', 1, EventData),'
  '      Account     = extract(@''Name="User">([^<]+)<'', 1, EventData)'
  '  | where ParentImage has_any ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe","visio.exe")'
  '  | where Image has_any ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")'
  '  | extend Computer = tostring(Computer)'
  '  | project TimeGenerated, Computer, Account, ParentImage, Image, CmdLine, ParentCmd'
)
$lines | Out-File -FilePath "rules\kql\office_spawning_shell.yaml" -Encoding utf8
Get-Content "rules\kql\office_spawning_shell.yaml"