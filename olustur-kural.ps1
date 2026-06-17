$ruleId = [guid]::NewGuid().ToString()
$lines = @(
  'title: Suspicious Encoded PowerShell Command Line'
  "id: $ruleId"
  'status: experimental'
  'description: Detects powershell.exe launched with an encoded command argument (-enc/-EncodedCommand), commonly used to obfuscate payloads.'
  'references:'
  '  - https://attack.mitre.org/techniques/T1059/001/'
  'author: Yusuf Efil'
  'date: 2026-06-13'
  'logsource:'
  '  category: process_creation'
  '  product: windows'
  'detection:'
  '  selection:'
  "    Image|endswith: '\powershell.exe'"
  '    CommandLine|contains:'
  "      - ' -enc '"
  "      - ' -EncodedCommand '"
  "      - ' -ec '"
  '  condition: selection'
  'falsepositives:'
  '  - Legitimate admin automation using encoded commands'
  'level: high'
  'tags:'
  '  - attack.execution'
  '  - attack.t1059.001'
  '  - attack.defense_evasion'
  '  - attack.t1027'
)
$lines | Out-File -FilePath "rules\sigma\win_susp_encoded_powershell.yml" -Encoding utf8
Get-Content "rules\sigma\win_susp_encoded_powershell.yml"