param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = 'ca433e75-e313-59f7-899b-64e12a93f8eb'

resource analyticRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    displayName: 'Hijacking Text File Associations'
    description: 'Detects registry modification events that change the default handler for .txt files, potentially establishing persistence.'
    enabled: true
    query: '''
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\\txtfile\\shell\\open\\command", @"\\FileExts\\.txt\\UserChoice") or RegistryKey endswith @"\\.txt"
| where RegistryValueData !has "notepad.exe"
'''
    queryFrequency: 'PT5H'
    queryPeriod: 'PT5H'
    severity: 'Medium'
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'Persistence'
    ]
  }
}
