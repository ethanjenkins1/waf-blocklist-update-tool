import datetime
import logging
import os
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.frontdoor import FrontDoorManagementClient
from azure.mgmt.frontdoor.models import CustomRule, MatchCondition, MatchVariable, Operator
import re
from ipaddress import ip_network, ip_address
from azure.storage.blob import BlobServiceClient

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    logging.info(f'Python timer trigger function ran at {utc_timestamp}')

    subscription_id = os.getenv('SUBSCRIPTION_ID')
    resource_group_name = os.getenv('RESOURCE_GROUP_NAME')
    policy_name = os.getenv('POLICY_NAME')

    credential = DefaultAzureCredential()
    client = FrontDoorManagementClient(credential, subscription_id)

    urls = [
        'https://www.spamhaus.org/drop/edrop.txt',
        'https://check.torproject.org/exit-addresses',
        'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
    ]

    new_ips = fetch_ips_from_urls(urls)
    filtered_ips = filter_overlapping_ips(new_ips)
    update_waf_policy(client, resource_group_name, policy_name, filtered_ips)

def fetch_ips_from_urls(urls):
    new_ips = set()
    for url in urls:
        response = requests.get(url)
        if response.status_code == 200:
            found_ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', response.text))
            valid_ips = {ip for ip in found_ips if is_valid_ip_or_cidr(ip)}
            logging.info(f"Successfully pulled {len(valid_ips)} IPs/CIDRs from {url}")
            new_ips.update(valid_ips)
        else:
            logging.error(f"Error fetching IPs from {url}: HTTP {response.status_code}")
    return new_ips

def filter_overlapping_ips(ips):
    ip_networks = [ip_network(ip) for ip in ips]
    sorted_networks = sorted(ip_networks, key=lambda x: x.prefixlen)
    filtered_networks = []
    for network in sorted_networks:
        if not any(network.overlaps(existing_network) for existing_network in filtered_networks):
            filtered_networks.append(network)
    return {str(network) for network in filtered_networks}

def update_waf_policy(client, resource_group_name, policy_name, new_ips):
    waf_policy = client.policies.get(resource_group_name, policy_name)
    existing_ips = get_all_existing_ips(waf_policy)
    ips_to_add = new_ips.difference(existing_ips)
    ips_to_remove = existing_ips.difference(new_ips)

    update_rules_with_ips(client, waf_policy, ips_to_add, ips_to_remove, resource_group_name, policy_name)

    log_ip_changes(ips_to_add, ips_to_remove)

def get_all_existing_ips(waf_policy):
    return {ip for rule in waf_policy.custom_rules.rules if rule.name.startswith('companymanagedblocklist') for condition in rule.match_conditions for ip in condition.match_value}

def update_rules_with_ips(client, waf_policy, ips_to_add, ips_to_remove, resource_group_name, policy_name):
    for rule in waf_policy.custom_rules.rules:
        if rule.name.startswith('companymanagedblocklist'):
            for condition in rule.match_conditions:
                if condition.match_variable == MatchVariable.REMOTE_ADDR:
                    condition.match_value = [ip for ip in condition.match_value if ip not in ips_to_remove]

    for ip in ips_to_add:
        added = False
        for rule in waf_policy.custom_rules.rules:
            if rule.name.startswith('companymanagedblocklist') and len(rule.match_conditions[0].match_value) < 600:
                if ip not in rule.match_conditions[0].match_value:
                    rule.match_conditions[0].match_value.append(ip)
                    added = True
                    break
        if not added:
            new_rule = get_or_create_rule(client, waf_policy)  # Corrected usage here
            new_rule.match_conditions[0].match_value.append(ip)

    client.policies.begin_create_or_update(resource_group_name, policy_name, waf_policy).result()

def get_or_create_rule(client, waf_policy):  # Corrected function signature
    existing_rules_count = sum(1 for rule in waf_policy.custom_rules.rules if rule.name.startswith('companymanagedblocklist'))
    rule_index = existing_rules_count + 1
    rule_name = f'companymanagedblocklist{rule_index}'
    priority = 900 + rule_index

    existing_rule = next((rule for rule in waf_policy.custom_rules.rules if rule.name == rule_name), None)
    if existing_rule:
        return existing_rule

    new_rule = CustomRule(
        name=rule_name,
        priority=priority,
        rule_type="MatchRule",
        action="Block",
        match_conditions=[MatchCondition(match_variable=MatchVariable.REMOTE_ADDR, operator=Operator.IP_MATCH, match_value=[])]
    )
    waf_policy.custom_rules.rules.append(new_rule)
    return new_rule

def is_valid_ip_or_cidr(ip):
    try:
        if '/' in ip:
            ip_network(ip, strict=False)
        else:
            ip_address(ip)
        return True
    except ValueError:
        return False

def log_ip_changes(ips_to_add, ips_to_remove):
    conn_str = os.getenv('AzureWebJobsStorage')
    container_name = 'fd-ip-change-logs'
    blob_service_client = BlobServiceClient.from_connection_string(conn_str)

    try:
        container_client = blob_service_client.get_container_client(container_name)

        if not container_client.exists():
            container_client.create_container()

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        blob_name = f'ip-changes-{timestamp}.log'
        blob_client = container_client.get_blob_client(blob_name)

        log_message = f"Changes at {timestamp}:\n"

        if ips_to_add:
            log_message += f"Added IPs/CIDRs:\n" + '\n'.join(ips_to_add) + '\n'

        if ips_to_remove:
            log_message += f"Removed IPs/CIDRs:\n" + '\n'.join(ips_to_remove) + '\n'

        blob_client.upload_blob(log_message, overwrite=True)
        logging.info("IP changes logged to Azure Storage")
    except Exception as e:
        logging.error(f"Failed to log IP changes: {e}")
