# Azure Front Door WAF Blocklist Update
 
## Overview
 
This Azure Function App is designed to automatically update a Web Application Firewall (WAF) policy in Azure Front Door with IP addresses and CIDR blocks fetched from specified URLs. The primary goal is to maintain an up-to-date blocklist of IPs that pose security threats, ensuring the WAF policy reflects the latest threat intelligence.
 
## Architecture
 
The app is triggered by a timer, running at scheduled intervals to fetch new IPs and update the WAF policy accordingly. It performs several key operations:
 
- **Fetching IPs:** Retrieves lists of IP addresses and CIDR blocks from predefined URLs.

- **Filtering and Validation:** Ensures only valid IPs and non-overlapping CIDR blocks are processed.

- **Updating the WAF Policy:** Adds new IPs to the blocklist and removes outdated ones from the Azure Front Door WAF policy.
 
### Prerequisites
 
1. **Assign Permission:**

   Create a function app with a system-managed identity. This system-managed identity needs to be assigned the network contributor role to the WAF policy it needs to modify.
 
2. **Add Environment Variables:**

   Three environment variables need to be created. Navigate to the function app in Azure, go to the configuration blade, and add the following environment variables:

   - `SUBSCRIPTION_ID`: Azure Subscription ID where the Front Door resource is located.

   - `RESOURCE_GROUP_NAME`: Name of the resource group containing the Front Door resource.

   - `POLICY_NAME`: Name of the WAF policy to be updated.
 
It can be deployed from your local Visual Studio Code or using the deployment center in Azure. If using your local machine, you will need the following:
 
- Visual Studio Code

- Azure Function Extension for Visual Studio Code

- Azure Account Extension

- Azure CLI

- Azure Function Core Tools
 
## Key Components
 
- **Azure Functions:** Utilizes timer-triggered functions for periodic execution.

- **Azure Identity:** For secure Azure service authentication.

- **Azure Front Door Management Client:** Manages WAF policies in Azure Front Door.

- **Azure Storage Blob:** Logs changes to IP lists for audit and tracking purposes.
 
## Environment Variables
 
- `SUBSCRIPTION_ID`: Azure Subscription ID where the Front Door resource is located.

- `RESOURCE_GROUP_NAME`: Name of the resource group containing the Front Door resource.

- `POLICY_NAME`: Name of the WAF policy to be updated.
 
## Dependencies
 
- azure-functions

- azure-identity

- azure-mgmt-frontdoor

- requests

- ipaddress
 
## Logic Flow
 
The Azure Function App is structured around several key functions, each responsible for a distinct aspect of managing IP blocklists for Azure Front Door's WAF policy.
 
### 1. Main Function (`main`)
 
- **Purpose:** Orchestrates the process of fetching, filtering, and updating IP addresses and CIDR blocks in the WAF policy.

- **Logic Flow:**

  - Triggered by a timer, adhering to a schedule defined in the function app's settings.

  - Retrieves environment variables specifying the Azure subscription ID, resource group, and WAF policy name.

  - Initializes the Azure Front Door Management Client using Azure Identity for secure API communication.

  - Calls `fetch_ips_from_urls` to retrieve and validate IPs from predefined URLs.

  - Filters overlapping IPs by invoking `filter_overlapping_ips`.

  - Updates the WAF policy by passing the filtered IPs to `update_waf_policy`.
 
### 2. Fetch IPs from URLs (`fetch_ips_from_urls`)
 
- **Purpose:** Fetches lists of IP addresses and CIDR blocks from specified URLs, ensuring only valid and unique entries are returned.

- **Logic Flow:**

  - Iterates over a list of URLs, making HTTP GET requests to fetch data.

  - Parses the response content using regular expressions to find IP addresses and CIDR blocks.

  - Validates each found IP or CIDR block.

  - Aggregates valid IPs into a set to ensure uniqueness and returns the set.
 
### 3. Filter Overlapping IPs (`filter_overlapping_ips`)
 
- **Purpose:** Removes individual IP addresses already covered by CIDR blocks to avoid redundancy in the WAF policy.

- **Logic Flow:**

  - Segregates IPs into CIDR blocks and individual IP addresses.

  - Sorts CIDR blocks by their prefix length and network address for efficient processing.

  - Filters out individual IPs that fall within any of the CIDR blocks.

  - Returns a consolidated set of non-overlapping IPs and CIDR blocks.
 
### 4. Update WAF Policy (`update_waf_policy`)
 
- **Purpose:** Adds new IPs to and removes outdated IPs from the Azure Front Door WAF policy.

- **Logic Flow:**

  - Retrieves the current WAF policy configuration.

  - Extracts existing IPs from the policy by calling `get_all_existing_ips`.

  - Determines which IPs need to be added or removed based on a comparison with `new_ips`.

  - Calls `update_rules_with_ips` to apply these changes to the policy.

  - If changes are made, logs these updates for auditing purposes.
 
### 5. Get or Create Rule (`get_or_create_rule`)
 
- **Purpose:** Ensures there is a dedicated custom rule for managing the IP blocklist within the WAF policy.

- **Logic Flow:**

  - Identifies existing rules with the prefix `companymanagedblocklist` and calculates the next rule index.

  - If no suitable existing rule is found, constructs a new rule with a unique name and adds it to the WAF policy.

  - Returns the rule object for further manipulation.
 
## Logging and Monitoring
 
The app uses Azure's native logging capabilities to record its operations and outcomes, including successful operations and errors. These logs are vital for monitoring the app's performance and troubleshooting issues.
 
## Security and Authentication
 
Authentication to Azure services is managed via the Azure Identity library, utilizing managed identities where possible for enhanced security. Sensitive data are stored in environment variables to minimize hard-coded information.
 
## Maintenance and Extension
 
The app is designed for easy maintenance and can be extended by adding new URLs to the `urls` list or modifying the Azure Function's timer schedule to change the execution frequency. Regular updates to dependencies are recommended to address security vulnerabilities and maintain compatibility with Azure services.
 
## Conclusion
 
This Azure Function App automates the critical task of maintaining a dynamic IP blocklist in Azure Front Door's WAF policy, leveraging up-to-date threat intelligence to enhance web application security. Through efficient automation, validation, and logging, it ensures that WAF policies are always aligned with the latest security data.
