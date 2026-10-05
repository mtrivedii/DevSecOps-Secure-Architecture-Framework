// Yellow Teamer: Azure infrastructure as Bicep.
//
// Reconstructed from the architecture documented in the Body of Knowledge
// (see /Documentation), after the original Azure resources were decommissioned.
// The live environment was built in the portal, so this file describes the same
// design but was not the template that produced it. It compiles with
// `az bicep build --file infra/main.bicep`.
//
// Resource names follow the Body of Knowledge: maanit-logs, maanit-web-app,
// maanit-website, maanit-server/maanit-db, maanit-frontdoor and the WAF policy "firewall".

targetScope = 'resourceGroup'

@description('Azure region for the resources.')
param location string = resourceGroup().location

@description('Public hostname of the site, used for CORS and the Front Door custom domain.')
param customDomain string = 'maanitwebapp.com'

@description('Name of the App Service web app. Must be globally unique.')
param webAppName string = 'maanit-website'

@description('Globally unique storage account name for file uploads (3 to 24 lowercase letters and digits).')
param storageAccountName string = 'secureapp${uniqueString(resourceGroup().id)}'

@description('Name of the Azure SQL logical server. Must be globally unique.')
param sqlServerName string = 'maanit-server'

@description('Entra ID object ID of the person or group that administers the SQL server.')
param sqlAdminObjectId string

@description('Entra ID login name of the SQL administrator.')
param sqlAdminLogin string

@description('Public IP addresses allowed to reach the SQL server (developers and services).')
param sqlAllowedIps array = []

@description('WAF mode. Detection only logs. Prevention blocks. The Hacking Week red team found the original deployment in Detection mode.')
@allowed([
  'Detection'
  'Prevention'
])
param wafMode string = 'Prevention'

// ---------------------------------------------------------------- Monitoring

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'maanit-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'maanit-web-app'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
  }
}

// ------------------------------------------------------------------- Storage

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

// Private container (name matches getSasToken.js). The backend hands out short-lived, write-only SAS URLs.
resource uploads 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'secure-uploads'
  properties: {
    publicAccess: 'None'
  }
}

// ----------------------------------------------------------------------- SQL

resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'User'
      login: sqlAdminLogin
      sid: sqlAdminObjectId
      tenantId: tenant().tenantId
      azureADOnlyAuthentication: true
    }
  }
}

resource sqlDb 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: 'maanit-db'
  location: location
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

// Transparent Data Encryption with a service-managed key.
resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-08-01-preview' = {
  parent: sqlDb
  name: 'current'
  properties: {
    state: 'Enabled'
  }
}

// Lets App Service reach the server (the documented "Azure services" exception).
resource allowAzureServices 'Microsoft.Sql/servers/firewallRules@2023-08-01-preview' = {
  parent: sqlServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource allowedIps 'Microsoft.Sql/servers/firewallRules@2023-08-01-preview' = [for (ip, i) in sqlAllowedIps: {
  parent: sqlServer
  name: 'allow-${i}'
  properties: {
    startIpAddress: ip
    endIpAddress: ip
  }
}]

// Defender for SQL: vulnerability scanning and threat detection.
resource sqlAdvancedThreatProtection 'Microsoft.Sql/servers/advancedThreatProtectionSettings@2023-08-01-preview' = {
  parent: sqlServer
  name: 'Default'
  properties: {
    state: 'Enabled'
  }
}

// ---------------------------------------------------------------- App Service

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${webAppName}-plan'
  location: location
  kind: 'linux'
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  properties: {
    reserved: true
  }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned' // Managed Identity used to reach Azure SQL
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'NODE|20-lts'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      alwaysOn: true
      cors: {
        allowedOrigins: [
          'https://${customDomain}'
          'https://${webAppName}.azurewebsites.net'
        ]
        supportCredentials: true
      }
      appSettings: [
        {
          name: 'DB_SERVER'
          value: sqlServer.properties.fullyQualifiedDomainName
        }
        {
          name: 'DB_NAME'
          value: sqlDb.name
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        // JWT_SECRET and the storage access key are not stored in this file.
        // Set them as App Service application settings after deployment.
      ]
    }
  }
}

// ---------------------------------------------------- Front Door and WAF policy

resource wafPolicy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: 'firewall'
  location: 'global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: wafMode
      requestBodyCheck: 'Enabled'
      customBlockResponseStatusCode: 403
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.1'
        }
      ]
    }
    customRules: {
      rules: [
        {
          // Per-IP rate limit on the login endpoint.
          name: 'RateLimitLogin'
          priority: 10
          enabledState: 'Enabled'
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 20
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [
                '/api/login'
              ]
              transforms: [
                'Lowercase'
              ]
            }
          ]
        }
        {
          // Per-IP rate limit on the 2FA endpoints.
          name: 'RateLimit2FA'
          priority: 20
          enabledState: 'Enabled'
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 10
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [
                '/api/2fa'
              ]
              transforms: [
                'Lowercase'
              ]
            }
          ]
        }
        {
          // Basic command injection patterns in the query string and body.
          name: 'BlockCommandInjection'
          priority: 30
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'QueryString'
              operator: 'Contains'
              matchValue: [
                ';'
                '|'
                '&&'
                '`'
                '$('
              ]
              transforms: [
                'UrlDecode'
              ]
            }
          ]
        }
        {
          // Path traversal attempts.
          name: 'BlockPathTraversal'
          priority: 40
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [
                '../'
                '..%2f'
              ]
              transforms: [
                'UrlDecode'
                'Lowercase'
              ]
            }
          ]
        }
      ]
    }
  }
}

resource frontDoor 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: 'maanit-frontdoor'
  location: 'global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
}

resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: frontDoor
  name: 'maanit-endpoint'
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  parent: frontDoor
  name: 'app-service'
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
    }
    healthProbeSettings: {
      probePath: '/'
      probeRequestType: 'HEAD'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 100
    }
  }
}

resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  parent: originGroup
  name: 'maanit-website'
  properties: {
    hostName: webApp.properties.defaultHostName
    originHostHeader: webApp.properties.defaultHostName
    httpsPort: 443
    enabledState: 'Enabled'
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  parent: endpoint
  name: 'default-route'
  dependsOn: [
    origin
  ]
  properties: {
    originGroup: {
      id: originGroup.id
    }
    supportedProtocols: [
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    httpsRedirect: 'Enabled'
    linkToDefaultDomain: 'Enabled'
  }
}

// Attach the WAF policy to the endpoint.
resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {
  parent: frontDoor
  name: 'waf'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: {
        id: wafPolicy.id
      }
      associations: [
        {
          domains: [
            {
              id: endpoint.id
            }
          ]
          patternsToMatch: [
            '/*'
          ]
        }
      ]
    }
  }
}

// Front Door access and WAF logs go to the Log Analytics workspace for the dashboard.
resource frontDoorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-maanit-logs'
  scope: frontDoor
  properties: {
    workspaceId: logs.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
}

// ------------------------------------------------------------------- Outputs

output webAppName string = webApp.name
output webAppPrincipalId string = webApp.identity.principalId
output frontDoorHostName string = endpoint.properties.hostName
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
