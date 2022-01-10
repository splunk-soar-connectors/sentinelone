[comment]: # "Auto-generated SOAR connector documentation"
# SentinelOne

Publisher: SentinelOne  
Connector Version: 2\.1\.2  
Product Vendor: SentinelOne  
Product Name: SentinelOne  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with the SentinelOne Singularity platform to perform prevention, detection, remediation, and forensic endpoint management tasks

[comment]: # " File: readme.md"
[comment]: # "    Copyright (c) SentinelOne, 2018-2021"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This version of the SentinelOne app is compatible with Phantom **4.9.39220+**

## Playbook Backward Compatibility

The below-mentioned actions have been modified. Hence, it is requested to the end-user to update
their existing playbooks by re-inserting \| modifying \| deleting \| creating the corresponding
action blocks or by providing appropriate values to these action parameters to ensure the correct
functioning of the playbooks created on the earlier versions of the app.

-   The existing action parameter 'site_tokens' has been removed from the 'Block Hash', 'Unlock
    Hash', 'Quarantine Device', 'Unquarantine Device', 'Mitigate Threat', and 'Scan Endpoint'
    actions.
-   New actions 'Get Threat Info' and 'On Poll' have been added.
-   Existing actions 'List Endpoints' and 'List Threats' have been removed.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SentinelOne asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**sentinelone\_console\_url** |  required  | string | SentinelOne Console URL
**sentinelone\_api\_token** |  required  | password | SentinelOne API Token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[block hash](#action-block-hash) - Add a file hash to the global blocklist  
[unblock hash](#action-unblock-hash) - Remove a hash from the global blocklist  
[quarantine device](#action-quarantine-device) - Quarantine an endpoint  
[unquarantine device](#action-unquarantine-device) - Unquarantine an endpoint  
[mitigate threat](#action-mitigate-threat) - Mitigate an identified threat  
[scan endpoint](#action-scan-endpoint) - Scan an endpoint for dormant threats  
[get endpoint info](#action-get-endpoint-info) - Get detailed information about an endpoint/agent  
[get threat info](#action-get-threat-info) - Get detailed information about a threat  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'block hash'
Add a file hash to the global blocklist

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of a file to block | string |  `sha1` 
**description** |  required  | Description | string | 
**os\_family** |  required  | OS Family | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `sha1` 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.os\_family | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock hash'
Remove a hash from the global blocklist

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of a file to remove from the blocklist | string |  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `sha1` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Quarantine an endpoint

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The hostname of an endpoint to quarantine | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unquarantine an endpoint

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The hostname of an endpoint to unquarantine | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'mitigate threat'
Mitigate an identified threat

Type: **correct**  
Read only: **False**

Mitigate threats such as <b>kill</b>, <b>quarantine</b>, <b>remediate</b>, or <b>rollback</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The threat ID | string |  `sentinelone s1 threat id` 
**action** |  required  | Allowed values include\: kill, quarantine, remediate, rollback, and disconnectFromNetwork | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_id | string |  `sentinelone s1 threat id` 
action\_result\.parameter\.action | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scan endpoint'
Scan an endpoint for dormant threats

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The hostname of an endpoint to scan | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get endpoint info'
Get detailed information about an endpoint/agent

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The hostname of an endpoint to get information | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data\.\*\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.data\.\*\.scanStatus | string | 
action\_result\.data\.\*\.data\.\*\.scanStartedAt | string | 
action\_result\.data\.\*\.data\.\*\.scanFinishedAt | string | 
action\_result\.data\.\*\.data\.\*\.infected | boolean | 
action\_result\.data\.\*\.data\.\*\.isActive | boolean | 
action\_result\.data\.\*\.data\.\*\.isUpToDate | boolean | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.data\.\*\.data\.\*\.threatRebootRequired | boolean | 
action\_result\.data\.\*\.data\.\*\.networkStatus | string | 
action\_result\.data\.\*\.data\.\*\.activeThreats | numeric | 
action\_result\.data\.\*\.data\.\*\.domain | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get threat info'
Get detailed information about a threat

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The S1 Threat ID for a specific threat | string |  `sentinelone s1 threat id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_id | string |  `sentinelone s1 threat id` 
action\_result\.data\.\*\.data\.\*\.threatInfo\.mitigationStatusDescription | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.threatName | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.confidenceLevel | string | 
action\_result\.data\.\*\.data\.\*\.agentRealtimeInfo\.agentComputerName | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.threatInfo\.incidentStatusDescription | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.analystVerdictDescription | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.engines | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.initiatedByDescription | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.classification | string | 
action\_result\.data\.\*\.data\.\*\.agentDetectionInfo\.agentVersion | string | 
action\_result\.data\.\*\.data\.\*\.agentRealtimeInfo\.agentVersion | string | 
action\_result\.data\.\*\.data\.\*\.mitigationStatus\.\*\.action | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.pendingActions | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.rebootRequired | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.failedActions | boolean | 
action\_result\.data\.\*\.data\.\*\.agentDetectionInfo\.agentMitigationMode | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.mitigatedPreemptively | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.externalTicketExists | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.sha1 | string | 
action\_result\.data\.\*\.data\.\*\.agentRealtimeInfo\.agentOsRevision | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.automaticallyResolved | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.detectionType | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.filePath | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.maliciousProcessArguments | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.storyline | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Container IDs to limit the ingestion to | string | 
**start\_time** |  optional  | Start of the time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of the time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 

#### Action Output
No Output