param workspaceName string
param ruleId string
param displayName string
param description string = ''
param severity string = 'Medium'
param query string
param tactics array = []
param techniques array = []

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: ws
  name: ruleId
  kind: 'Scheduled'
  properties: {
    displayName: displayName
    description: description
    severity: severity
    enabled: true
    query: query
    queryFrequency: 'PT5M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    tactics: tactics
    techniques: techniques
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [ { identifier: 'HostName', columnName: 'Computer' } ]
      }
      {
        entityType: 'Account'
        fieldMappings: [ { identifier: 'Name', columnName: 'Account' } ]
      }
    ]
  }
}
