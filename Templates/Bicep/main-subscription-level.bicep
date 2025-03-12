targetScope = 'subscription'

@description('The location where the policy assignment will be created.')
param location string = 'northeurope'

@description('Create remediation task for non-compliant resources?')
param createRemediationTask bool = true

param policyName string = 'Enforce-ServiceBus-TLS-1.2'
param policyDisplayName string = 'Enforce TLS 1.2 for Service Bus Namespaces'
param policyDescription string = 'This policy ensures that Service Bus namespaces have a minimum TLS version of 1.2.'
param policyCategory string = 'Security'

// Create the Policy Definition
resource policyDefinition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName
  properties: {
    displayName: policyDisplayName
    description: policyDescription
    policyType: 'Custom'
    mode: 'All'
    metadata: {
      category: policyCategory
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.EventHub/namespaces'
          }
          {
            anyOf: [
              {
                field: 'Microsoft.EventHub/namespaces/minimumTlsVersion'
                equals: '1.0'
              }
              {
                field: 'Microsoft.EventHub/namespaces/minimumTlsVersion'
                equals: '1.1'
              }
            ]
          }
        ]
      }
      then: {
        effect: 'modify'
        details: {
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419' // Azure Service Bus Data Owner
          ]
          operations: [
            {
              operation: 'addOrReplace'
              field: 'Microsoft.EventHub/namespaces/minimumTlsVersion'
              value: '1.2'
            }
          ]
        }
      }
    }
    parameters: {}
  }
}

// Assign the Policy with System Assigned Identity
resource policyAssignment 'Microsoft.Authorization/policyAssignments@2025-01-01' = {
  name: '${policyName}-assignment'
  location: location
  scope: subscription()
  properties: {
    displayName: policyDisplayName
    description: 'Ensures that Event Hub namespaces enforce TLS 1.2.'
    policyDefinitionId: policyDefinition.id
    enforcementMode: 'Default'
  }
  identity: {
    type: 'SystemAssigned'
  }
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, policyAssignment.name) // Unique role assignment name
  scope: subscription() // Assign at subscription level
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'f090c5cfd-751d-490a-894a-3ce6f1109419'
    ) // Azure Service Bus Data Owner
    principalId: policyAssignment.identity.principalId // Managed identity of the policy assignment resource
    principalType: 'ServicePrincipal'
  }
}

// Create remediation task if specified
resource remediationTask 'Microsoft.PolicyInsights/remediations@2021-10-01' = if (createRemediationTask) {
  name: 'remediate-eventhub-tls'
  scope: subscription()
  properties: {
    policyAssignmentId: policyAssignment.id
    resourceDiscoveryMode: 'ReEvaluateCompliance'
    failureThreshold: { percentage: 0 }
  }
}
