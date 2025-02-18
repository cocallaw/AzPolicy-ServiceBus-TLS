# Azure Policy for Azure Service Bus minimumTlsVersion

## Summary

This example Azure Policy checks the minimumTlsVersion of an Azure Service Bus resource and if the minimumTlsVersion is set to 1.0 or 1.1, it updates the minimumTlsVersion to 1.2 using a modify operation.

## Remediation Permissions

For remediation the following role needs to be assigned to the user or system assigned managed identity that will be executing the remediation task:

| Role Definition             | ID                                   |
|-----------------------------|--------------------------------------|
| Azure Service Bus Data Owner | 090c5cfd-751d-490a-894a-3ce6f1109419 |
