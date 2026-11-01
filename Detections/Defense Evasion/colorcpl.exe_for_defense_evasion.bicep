param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = '84535502-de95-5003-94c2-fb5d29aa25f1'

resource analyticRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    displayName: 'Colorcpl Abuse for Defense Evasion'
    description: 'Detects use of the legitimate Windows colorcpl.exe utility with bitsadmin.exe. Guildma (Astaroth) malware has been observed abusing colorcpl.exe to copy bitsadmin.exe into a less-scrutinized directory before using it to retrieve additional payloads.'
    enabled: true
    query: '''
//Rule Autor: VlogicK
DeviceProcessEvents
| where FileName =~ "colorcpl.exe"
| where ProcessCommandLine has "bitsadmin.exe"
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
