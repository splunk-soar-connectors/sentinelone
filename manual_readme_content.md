[comment]: # " File: README.md"
[comment]: # "  Copyright (c) SentinelOne, 2018-2023"
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
