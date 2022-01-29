[comment]: # "Auto-generated SOAR connector documentation"
# SentinelOne

Publisher: SentinelOne  
Connector Version: 2\.2\.3  
Product Vendor: SentinelOne  
Product Name: SentinelOne  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with the SentinelOne Singularity platform to perform prevention, detection, remediation, and forensic endpoint management tasks

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) SentinelOne, 2018-2022"
[comment]: # ""
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
This version of the SentinelOne app is compatible with Splunk SOAR version **5.1.0** and above.

## Playbook Backward Compatibility

The below-mentioned actions are newly added.

-   download from cloud
-   update threat incident
-   get threat timeline
-   update threat analystverdict
-   fetch threat file
-   export threats
-   export mitigation report
-   export threat timeline
-   add threat note
-   get threat notes
-   hash reputation
-   create firewall rule
-   list firewall rules
-   get devicecontrol events
-   get cves
-   list applications
-   fetch firewall logs
-   fetch firewall rules
-   get file
-   broadcast message
-   shutdown endpoint
-   abort scan

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the SentinelOne server. Below are the
default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


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
[abort scan](#action-abort-scan) - Stop a Full Disk Scan on endpoint/agent  
[shutdown endpoint](#action-shutdown-endpoint) - Shutdown an endpoint  
[broadcast message](#action-broadcast-message) - Send a Message through the Agents that users can see  
[get file](#action-get-file) - Fetch files from endpoints to analyze the root of threats  
[fetch firewall rules](#action-fetch-firewall-rules) - Fetch the firewall rules  
[fetch firewall logs](#action-fetch-firewall-logs) - Fetch the firewall logs  
[scan endpoint](#action-scan-endpoint) - Start a Full Disk Scan on endpoint/agent  
[get endpoint info](#action-get-endpoint-info) - Get detailed information about an endpoint/agent  
[get threat info](#action-get-threat-info) - Get detailed information about a threat  
[list applications](#action-list-applications) - Get the applications, and their data, installed on endpoints  
[get cves](#action-get-cves) - Get known CVEs for applications that are installed on endpoints with Application Risk\-enabled Agents  
[get devicecontrol events](#action-get-devicecontrol-events) - Get the data of Device Control events on Windows and macOS endpoints  
[list firewall rules](#action-list-firewall-rules) - Get the Firewall Control rules for a scope specified  
[create firewall rule](#action-create-firewall-rule) - Create a Firewall Control rule  
[hash reputation](#action-hash-reputation) - Get the reputation of a hash, given the required SHA1  
[get threat notes](#action-get-threat-notes) - Get the threat notes  
[add threat note](#action-add-threat-note) - Add a threat note to multiple threats  
[export threat timeline](#action-export-threat-timeline) - Export a threat's timeline  
[export mitigation report](#action-export-mitigation-report) - Export the mitigation report of threat  
[export threats](#action-export-threats) - Export data of threats  
[fetch threat file](#action-fetch-threat-file) - Fetch a file associated with the threat  
[update threat analystverdict](#action-update-threat-analystverdict) - Change the verdict of a threat, as determined by a Console user  
[get threat timeline](#action-get-threat-timeline) - Get a threat's timeline  
[update threat incident](#action-update-threat-incident) - Update the incident details of a threat  
[download from cloud](#action-download-from-cloud) - Download threat file from cloud  
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
**ip\_hostname** |  required  | The IP or hostname of an endpoint to quarantine | string |  `host name`  `ip` 

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

## action: 'unquarantine device'
Unquarantine an endpoint

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to unquarantine | string |  `host name`  `ip` 

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

## action: 'mitigate threat'
Mitigate an identified threat

Type: **generic**  
Read only: **False**

Mitigate threats such as <b>kill</b>, <b>quarantine</b>, <b>remediate</b>, or <b>rollback\-remediation</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The threat ID | string |  `sentinelone s1 threat id` 
**action** |  required  | Allowed values include\: kill, quarantine, un\-quarantine, remediate and rollback\-remediation | string | 

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

## action: 'abort scan'
Stop a Full Disk Scan on endpoint/agent

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to abort scan | string |  `host name`  `ip` 

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

## action: 'shutdown endpoint'
Shutdown an endpoint

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to shutdown | string |  `host name`  `ip` 

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

## action: 'broadcast message'
Send a Message through the Agents that users can see

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to broadcast Message | string |  `host name`  `ip` 
**message** |  required  | Message | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.parameter\.message | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Fetch files from endpoints to analyze the root of threats

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_path** |  required  | The file path of an endpoint | string |  `file path` 
**password** |  required  | Password | string | 
**ip\_hostname** |  required  | The IP or hostname of an endpoint to fetch file | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.password | string | 
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'fetch firewall rules'
Fetch the firewall rules

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to fetch firewall rules | string |  `host name`  `ip` 

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

## action: 'fetch firewall logs'
Fetch the firewall logs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to fetch firewall logs | string |  `host name`  `ip` 

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

## action: 'scan endpoint'
Start a Full Disk Scan on endpoint/agent

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to scan | string |  `host name`  `ip` 

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
**ip\_hostname** |  required  | The IP or hostname of an endpoint to get information | string |  `host name`  `ip` 

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
action\_result\.data\.\*\.data\.\*\.domain | string |  `domain` 
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
action\_result\.data\.\*\.data\.\*\.threatInfo\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.data\.\*\.agentRealtimeInfo\.agentOsRevision | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.automaticallyResolved | boolean | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.detectionType | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.filePath | string |  `file path` 
action\_result\.data\.\*\.data\.\*\.threatInfo\.maliciousProcessArguments | string | 
action\_result\.data\.\*\.data\.\*\.threatInfo\.storyline | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list applications'
Get the applications, and their data, installed on endpoints

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | The IP or hostname of an endpoint to get applications | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data\.\*\.data\.\*\.agentComputerName | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.agentDomain | string |  `domain` 
action\_result\.data\.\*\.data\.\*\.agentId | string | 
action\_result\.data\.\*\.data\.\*\.agentInfected | boolean | 
action\_result\.data\.\*\.data\.\*\.agentIsActive | boolean | 
action\_result\.data\.\*\.data\.\*\.agentIsDecommissioned | boolean | 
action\_result\.data\.\*\.data\.\*\.agentMachineType | string | 
action\_result\.data\.\*\.data\.\*\.agentNetworkStatus | string | 
action\_result\.data\.\*\.data\.\*\.agentOperationalState | string | 
action\_result\.data\.\*\.data\.\*\.agentOsType | string | 
action\_result\.data\.\*\.data\.\*\.agentUuid | string | 
action\_result\.data\.\*\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.data\.\*\.data\.\*\.installedAt | string | 
action\_result\.data\.\*\.data\.\*\.name | string | 
action\_result\.data\.\*\.data\.\*\.osType | string | 
action\_result\.data\.\*\.data\.\*\.publisher | string | 
action\_result\.data\.\*\.data\.\*\.riskLevel | string | 
action\_result\.data\.\*\.data\.\*\.signed | boolean | 
action\_result\.data\.\*\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.data\.\*\.type | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.data\.\*\.data\.\*\.agentVersion | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get cves'
Get known CVEs for applications that are installed on endpoints with Application Risk\-enabled Agents

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.data\.\*\.description | string | 
action\_result\.data\.\*\.data\.\*\.publishedAt | string | 
action\_result\.data\.\*\.data\.\*\.link | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.data\.\*\.data\.\*\.score | numeric | 
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.riskLevel | string | 
action\_result\.data\.\*\.data\.\*\.cveId | string | 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get devicecontrol events'
Get the data of Device Control events on Windows and macOS endpoints

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | The IP or hostname of an endpoint to get information | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data\.\*\.data\.\*\.agentId | string | 
action\_result\.data\.\*\.data\.\*\.computerName | string | 
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.deviceClass | string | 
action\_result\.data\.\*\.data\.\*\.deviceName | string | 
action\_result\.data\.\*\.data\.\*\.eventId | string | 
action\_result\.data\.\*\.data\.\*\.eventTime | string | 
action\_result\.data\.\*\.data\.\*\.eventType | string | 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.data\.\*\.data\.\*\.interface | string | 
action\_result\.data\.\*\.data\.\*\.lastLoggedInUserName | string |  `user name` 
action\_result\.data\.\*\.data\.\*\.lmpVersion | string | 
action\_result\.data\.\*\.data\.\*\.minorClass | string | 
action\_result\.data\.\*\.data\.\*\.productId | string | 
action\_result\.data\.\*\.data\.\*\.profileUuids | string | 
action\_result\.data\.\*\.data\.\*\.ruleId | string | 
action\_result\.data\.\*\.data\.\*\.serviceClass | string | 
action\_result\.data\.\*\.data\.\*\.uId | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.data\.\*\.data\.\*\.vendorId | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list firewall rules'
Get the Firewall Control rules for a scope specified

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.data\.\*\.action | string | 
action\_result\.data\.\*\.data\.\*\.application\.type | string | 
action\_result\.data\.\*\.data\.\*application\.values | string | 
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.creator | string | 
action\_result\.data\.\*\.data\.\*\.creatorId | string | 
action\_result\.data\.\*\.data\.\*\.description | string | 
action\_result\.data\.\*\.data\.\*\.direction | string | 
action\_result\.data\.\*\.data\.\*\.editable | boolean | 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.data\.\*\.data\.\*\.localHost\.type | string | 
action\_result\.data\.\*\.data\.\*\.localHost\.values | string | 
action\_result\.data\.\*\.data\.\*\.localPort\.type | string | 
action\_result\.data\.\*\.data\.\*\.localPort\.values | string | 
action\_result\.data\.\*\.data\.\*\.location\.type | string | 
action\_result\.data\.\*\.data\.\*\.location\.values | string | 
action\_result\.data\.\*\.data\.\*\.name | string |  `firewall rule name` 
action\_result\.data\.\*\.data\.\*\.order | numeric | 
action\_result\.data\.\*\.data\.\*\.osType | string | 
action\_result\.data\.\*\.data\.\*\.osTypes | string | 
action\_result\.data\.\*\.data\.\*\.protocol | string | 
action\_result\.data\.\*\.data\.\*\.remoteHost\.type | string | 
action\_result\.data\.\*\.data\.\*\.remoteHost\.values | string | 
action\_result\.data\.\*\.data\.\*\.remoteHosts\.\*\.type | string | 
action\_result\.data\.\*\.data\.\*\.remoteHosts\.\*\.values | string | 
action\_result\.data\.\*\.data\.\*\.remotePort\.type | string | 
action\_result\.data\.\*\.data\.\*\.remotePort\.values | string | 
action\_result\.data\.\*\.data\.\*\.ruleCategory | string | 
action\_result\.data\.\*\.data\.\*\.scope | string | 
action\_result\.data\.\*\.data\.\*\.scopeId | string | 
action\_result\.data\.\*\.data\.\*\.status | string | 
action\_result\.data\.\*\.data\.\*\.tag | string | 
action\_result\.data\.\*\.data\.\*\.tagIds | string | 
action\_result\.data\.\*\.data\.\*\.tagNames | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create firewall rule'
Create a Firewall Control rule

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule\_name** |  required  | The name of the firewall rule | string |  `firewall rule name` 
**tag\_ids** |  optional  | Tag ID \(comma separated values\) | string | 
**description** |  required  | Description | string | 
**type** |  required  | Type of the remote host | string | 
**value** |  required  | Value of the remote host | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.rule\_name | string |  `firewall rule name` 
action\_result\.parameter\.tag\_ids | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.type | string | 
action\_result\.parameter\.value | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hash reputation'
Get the reputation of a hash, given the required SHA1

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of a file to get the reputation | string |  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `sha1` 
action\_result\.data\.\*\.data\.\*\.data\.\*\.rank | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get threat notes'
Get the threat notes

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
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.creator | string | 
action\_result\.data\.\*\.data\.\*\.creatorId | string | 
action\_result\.data\.\*\.data\.\*\.edited | boolean | 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.data\.\*\.data\.\*\.text | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add threat note'
Add a threat note to multiple threats

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_ids** |  required  | The S1 Threat IDs for specific threats \(comma separated values\) | string |  `sentinelone s1 threat ids` 
**note** |  required  | Threat Note text | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_ids | string |  `sentinelone s1 threat ids` 
action\_result\.parameter\.note | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'export threat timeline'
Export a threat's timeline

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
action\_result\.data\.\*\.data\.\*\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'export mitigation report'
Export the mitigation report of threat

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
action\_result\.data\.\*\.data\.\*\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'export threats'
Export data of threats

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | The IP or hostname of an endpoint | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data\.\*\.data\.\*\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'fetch threat file'
Fetch a file associated with the threat

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The S1 Threat ID for a specific threat | string |  `sentinelone s1 threat id` 
**password** |  required  | Password | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_id | string |  `sentinelone s1 threat id` 
action\_result\.parameter\.password | string | 
action\_result\.summary\.threat\_file\_download\_url | string |  `url` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update threat analystverdict'
Change the verdict of a threat, as determined by a Console user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The S1 Threat ID for a specific threat | string |  `sentinelone s1 threat id` 
**analyst\_verdict** |  required  | Analyst verdict | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_id | string |  `sentinelone s1 threat id` 
action\_result\.parameter\.analyst\_verdict | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get threat timeline'
Get a threat's timeline

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
action\_result\.data\.\*\.data\.\*\.accountId | string | 
action\_result\.data\.\*\.data\.\*\.activityType | string | 
action\_result\.data\.\*\.data\.\*\.agentId | string | 
action\_result\.data\.\*\.data\.\*\.agentUpdatedVersion | string | 
action\_result\.data\.\*\.data\.\*\.createdAt | string | 
action\_result\.data\.\*\.data\.\*\.data\.accountName | string | 
action\_result\.data\.\*\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.data\.\*\.data\.fileContentHash | string |  `hash` 
action\_result\.data\.\*\.data\.\*\.data\.fullScopeDetails | string | 
action\_result\.data\.\*\.data\.\*\.data\.groupName | string | 
action\_result\.data\.\*\.data\.\*\.data\.osFamily | string | 
action\_result\.data\.\*\.data\.\*\.data\.scopeLevel | string | 
action\_result\.data\.\*\.data\.\*\.data\.scopeName | string | 
action\_result\.data\.\*\.data\.\*\.data\.siteName | string | 
action\_result\.data\.\*\.data\.\*\.data\.username | string |  `user name` 
action\_result\.data\.\*\.data\.\*\.groupId | string | 
action\_result\.data\.\*\.data\.\*\.hash | string |  `hash` 
action\_result\.data\.\*\.data\.\*\.id | string | 
action\_result\.data\.\*\.data\.\*\.osFamily | string | 
action\_result\.data\.\*\.data\.\*\.primaryDescription | string | 
action\_result\.data\.\*\.data\.\*\.secondaryDescription | string | 
action\_result\.data\.\*\.data\.\*\.siteId | boolean | 
action\_result\.data\.\*\.data\.\*\.threatId | string | 
action\_result\.data\.\*\.data\.\*\.updatedAt | string | 
action\_result\.data\.\*\.data\.\*\.userId | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update threat incident'
Update the incident details of a threat

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**s1\_threat\_id** |  required  | The S1 Threat ID for a specific threat | string |  `sentinelone s1 threat id` 
**analyst\_verdict** |  required  | Analyst verdict | string | 
**incident\_status** |  required  | A specific incident status | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.s1\_threat\_id | string |  `sentinelone s1 threat id` 
action\_result\.parameter\.analyst\_verdict | string | 
action\_result\.parameter\.incident\_status | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'download from cloud'
Download threat file from cloud

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
action\_result\.data\.\*\.data\.\*\.fileName | string |  `file name` 
action\_result\.data\.\*\.data\.\*\.downloadUrl | string |  `url` 
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