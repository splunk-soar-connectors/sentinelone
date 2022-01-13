**Unreleased**
* The following actions are modified so that they work with IP addresses too:  
    * Quarantine device: This command isolate (quarantine) endpoints from the network.
    * Unquarantine device: This command reconnects to the network at all endpoints.
    * Scan endpoint: This command runs a Full Disk Scan on Agents that match the filter.
    * Get endpoint info: Get detailed information about an endpoint/agent.
* Modified command to support new SentinelOne API:
    * Block hash: Add a file hash to the global blocklist.
* The following new actions are implemented:
    * AGENT ACTIONS
        * Abort Scan: Stop a Full Disk Scan on endpoint/agent.
        * Broadcast Message: Send a message through the Agents that users can see.
        * Fetch Files (P1): Fetch files from endpoints to analyze the root of threats.
        * Fetch Firewall Logs: Get Firewall Control events in the local log file.
        * Fetch Firewall Rules: Fetch firewall rules.
        * Shutdown: Shutdown endpoint.
    * APPLICATION RISK
        * Get Applications: Get the applications, and their data, installed on endpoints.
        * Get CVEs: Get known CVEs for applications that are installed on endpoints with Application Risk-enabled Agents.
    * DEVICE CONTROL
        * Get Device Control Events (given a hostname or IP): Get the data of Device Control events on Windows and macOS endpoints.
    * FIREWALL CONTROL
        * Get Firewall Rules: Get the Firewall Control rules for a scope specified.
        * Create Firewall Rule: Create a Firewall Control rule.
    * HASHES
        * Hash Reputation: Get the reputation of a hash, given the required SHA1.
    * THREAT NOTES:
        * Add Note to Multiple: Add a threat note to multiple threats.
        * Get Threat Notes: Get the threat notes.
    * THREATS:
        * Download from cloud: Download threat file from cloud.
        * Export Mitigation Report: Export the mitigation report of threat.
        * Export Threat Timeline: Export a threat's timeline.
        * Export Threats: Export data of threats.
        * Fetch Threat File: Fetch a file associated with the threat.
        * Update Threat Analyst Verdict: Change the verdict of a threat, as determined by a Console user.
        * Get Threat Timeline: Get a threat's timeline.
        * Update Threat Incident: Update the incident details of a threat.
