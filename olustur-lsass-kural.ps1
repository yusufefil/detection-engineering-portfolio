$ruleId = [guid]::NewGuid().ToString()
$lines = @(
  'title: LSASS Memory Dump via Comsvcs or ProcDump'
  "id: $ruleId"
  'status: experimental'
  'description: Detects credential dumping attempts targeting lsass.exe via comsvcs.dll MiniDump or procdump, a common credential access technique.'
  'references:'
  '  - https://attack.mitre.org/techniques/T1003/001/'
  'author: Yusuf Efil'
  'date: 2026-06-17'
  'logsource:'
  '  category: process_creation'
  '  product: windows'
  'detection:'
  '  selection_comsvcs:'
  '    CommandLine|contains|all:'
  '      - ''comsvcs.dll'''
  '      - ''MiniDump'''
  '  selection_procdump:'
  '    CommandLine|contains|all:'
  '      - ''procdump'''
  '      - ''lsass'''
  '  condition: selection_comsvcs or selection_procdump'
  'falsepositives:'
  '  - Legitimate debugging or crash dump collection by administrators'
  'level: high'
  'tags:'
  '  - attack.credential_access'
  '  - attack.t1003.001'
)
$lines | Out-File -FilePath "rules\sigma\win_lsass_dump.yml" -Encoding utf8
Get-Content "rules\sigma\win_lsass_dump.yml"