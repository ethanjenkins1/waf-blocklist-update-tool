import datetime
import logging
import os
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import WebApplicationFirewallCustomRule, MatchCondition, MatchVariable
import re
from ipaddress import ip_network, ip_address
from azure.storage.blob import BlobServiceClient

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    logging.info(f'Python timer trigger function ran at {utc_timestamp}')

    subscription_id = os.getenv('SUBSCRIPTION_ID')
    resource_group_name = os.getenv('RESOURCE_GROUP_NAME')
    agw_name = os.getenv('AGW_WAF_NAME')

    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    urls = [
        'https://www.spamhaus.org/drop/edrop.txt',
        'https://check.torproject.org/exit-addresses',
        'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
    ]

    new_ips = fetch_ips_from_urls(urls)
    filtered_ips = filter_overlapping_ips(new_ips)
    added_ips, removed_ips = update_agw_waf_policy(network_client, resource_group_name, agw_name, filtered_ips)
    log_ip_changes(added_ips, removed_ips)

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
    cidr_blocks = sorted((ip_network(ip) for ip in ips if '/' in ip), key=lambda x: (x.prefixlen, x.network_address))
    individual_ips = {ip for ip in ips if '/' not in ip}

    for block in cidr_blocks:
        individual_ips = {ip for ip in individual_ips if not ip_address(ip) in block}

    return {str(ip) for ip in cidr_blocks}.union(individual_ips)

def update_agw_waf_policy(network_client, resource_group_name, agw_name, new_ips):
    waf_policy = network_client.web_application_firewall_policies.get(resource_group_name, agw_name)
    
    if not waf_policy.custom_rules:
        waf_policy.custom_rules = []

    existing_ips = set()
    for rule in waf_policy.custom_rules:
        if rule.name.startswith("companymanagedblocklist"):
            for condition in rule.match_conditions:
                if condition.match_variables[0].variable_name == "RemoteAddr":
                    existing_ips.update(condition.match_values)

    unique_new_ips = new_ips - existing_ips
    removed_ips = existing_ips - new_ips
    added_ips = set()

    for ip in unique_new_ips:
        rule_added_to = find_or_create_rule_for_ip(waf_policy, ip)
        if rule_added_to:
            added_ips.add(ip)

    for rule in waf_policy.custom_rules:
        if rule.name.startswith("companymanagedblocklist"):
            for ip in list(rule.match_conditions[0].match_values):
                if ip in removed_ips:
                    rule.match_conditions[0].match_values.remove(ip)
                    logging.info(f"Removed IP: {ip}")

    if added_ips or removed_ips:
        network_client.web_application_firewall_policies.create_or_update(
            resource_group_name, agw_name, waf_policy
        )
        logging.info(f"WAF Policy updated. Added IPs: {len(added_ips)}. Removed IPs: {len(removed_ips)}.")

    return added_ips, removed_ips

def find_or_create_rule_for_ip(waf_policy, ip):
    for rule in waf_policy.custom_rules:
        if rule.name.startswith("companymanagedblocklist") and len(rule.match_conditions[0].match_values) < 600:
            rule.match_conditions[0].match_values.append(ip)
            return rule
    
    return create_new_rule_for_ip(waf_policy, ip)


def create_new_rule_for_ip(waf_policy, ip):
    new_rule_index = len([rule for rule in waf_policy.custom_rules if rule.name.startswith("companymanagedblocklist")]) + 1
    rule_name = f"companymanagedblocklist{new_rule_index}"
    new_rule_priority = 90 + new_rule_index
    
    new_rule = WebApplicationFirewallCustomRule(
        name=rule_name,
        priority=new_rule_priority,
        rule_type="MatchRule",
        action="Block",
        match_conditions=[
            MatchCondition(
                match_variables=[MatchVariable(variable_name="RemoteAddr")],
                operator="IPMatch",
                negation_cond=False,
                match_values=[ip]
            )
        ]
    )
    
    waf_policy.custom_rules.append(new_rule)
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
    container_name = 'agw-ip-change-logs'
    blob_service_client = BlobServiceClient.from_connection_string(conn_str)

    try:
        container_client = blob_service_client.get_container_client(container_name)
        if not container_client.exists():
            container_client.create_container()

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        blob_name = f'agw-ip-changes-{timestamp}.log'
        blob_client = container_client.get_blob_client(blob_name)

        log_message = f"Changes at {timestamp}:\n"

        if ips_to_add:
            log_message += "Added IPs/CIDRs:\n" + '\n'.join(filter(is_valid_ip_or_cidr, ips_to_add)) + '\n'

        if ips_to_remove:
            log_message += "Removed IPs/CIDRs:\n" + '\n'.join(filter(is_valid_ip_or_cidr, ips_to_remove)) + '\n'

        blob_client.upload_blob(log_message, overwrite=True)
        logging.info("IP changes logged to Azure Storage")
    except Exception as e:
        logging.error(f"Failed to log IP changes: {e}")
