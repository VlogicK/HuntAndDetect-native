param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = '082c4eef-9ad3-5cb6-8968-2a330384a581'

resource analyticRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    displayName: 'Shimcache Flush Activity'
    description: 'Detects attempts to flush Shimcache, which may indicate anti-forensic activity. Adversaries may use this technique to erase evidence of executed files and hinder post-compromise analysis.'
    enabled: true
    query: '''
//Rule Autor: VlogicK
DeviceProcessEvents
| where FileName has "Rundll32.exe"
| where ((ProcessCommandLine has_any("ShimFlushCache","BaseFlushAppcompatCache"))
    or (ProcessCommandLine has_any (@"#250",@"#46") and ProcessCommandLine has_any ("apphelp.dll","kernel32.dll")))
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    severity: 'Medium'
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'DefenseEvasion'
    ]
  }
}
