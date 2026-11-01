param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = '70c70e2c-aba2-525c-9a9e-ee2820a475cf'

resource analyticRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    displayName: 'RMM Tools Hunting'
    description: 'Detects usage of known Remote Monitoring and Management (RMM) tool executables or network connections to known RMM domains. These tools are commonly used in legitimate IT operations but are also frequently abused by threat actors for remote access and persistence.'
    enabled: true
    query: '''
//Rule Autor: VlogicK
let RMMIOCs=externaldata (ToolName:string,
  ExecutableName:string,
  ProcessName:string,
  Domain:string)["https://raw.githubusercontent.com/VlogicK/HuntAndDetect/main/Detections/Command%20and%20Control/Enhanced_RMM_Tools_List_With_Domains.csv"]
  with (format="csv", ignoreFirstRecord=true);
let RMMProcNames=RMMIOCs
| distinct ProcessName;
let RMMDomains=RMMIOCs
| distinct Domain;
let procesEventsQuery=DeviceProcessEvents
| where FileName has_any (RMMProcNames)
| extend eventtype="ProcessEvent";
let networkEventsQuery=DeviceNetworkEvents
| where RemoteUrl has_any (RMMDomains)
| extend eventtype="NetworkEvent";
union procesEventsQuery, networkEventsQuery
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    severity: 'Medium'
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'CommandAndControl'
      'DefenseEvasion'
    ]
  }
}
