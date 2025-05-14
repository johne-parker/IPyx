import requests
import os
import random
import json
from collections import defaultdict
import time
import re
import socket

# --- Configuration ---dyme---
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TARGET_COUNTRIES = ["PL", "AE", "JP", "KR", "SG", "RU", "DE", "TW", "US"]

NUM_IPS_TO_TEST = 20
NUM_FASTEST_IPS_FOR_DNS = 3
TARGET_PORT = "443"
TCP_TIMEOUT = 1
IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
PROXY_STATUS = False
RECORD_TTL = 60

# Helper to get a generic domain placeholder
def get_domain_placeholder(country_code):
    return f"[DNS for {country_code}]"

# --- TCP Ping Function ---
def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    ip_pattern = re.compile(IPV4_REGEX)
    if not ip_pattern.match(host):
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_time = time.time()
        s.connect((host, int(port)))
        end_time = time.time()
        latency = (end_time - start_time) * 1000
        s.close()
        return latency
    except (socket.timeout, socket.error):
        return None

# --- Cloudflare API Functions ---
def cf_api_request(method, endpoint, zone_id, api_token, params=None, data=None):
    # (This function's logging is already fairly generic or error-focused,
    #  it doesn't directly log specific user domain names unless they are part of an error URL from CF)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    base_url = CF_API_BASE_URL.rstrip('/')
    zone_segment = f"/zones/{zone_id}" if zone_id else ""
    endpoint_segment = f"/{endpoint.lstrip('/')}" if endpoint else ""
    url = f"{base_url}{zone_segment}{endpoint_segment}"
    try:
        response = requests.request(method, url, headers=headers, params=params, json=data, timeout=20)
        response.raise_for_status()
        try:
            response_data = response.json()
            if not response_data.get("success"):
                # The URL here might contain zone_id, which is not the domain name itself
                print(f"ERROR: Cloudflare API operation not successful ({method} {url}). Response: {response_data.get('errors', 'No error details')}")
                return None
            return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT'] or \
               (method.upper() == 'GET' and response.text.strip() == '' and response_data.get("result") is None):
                return {"success": True, "result": []}
            elif response.status_code == 200 and method.upper() == 'GET' and endpoint == "":
                 print(f"ERROR: Non-JSON response when fetching Zone info for Zone ID (not shown).") # Zone ID not domain
                 return None
            print(f"WARNING: Could not parse Cloudflare API response as JSON ({method}, URL involved Zone ID). Status: {response.status_code}. Body (first 100 chars): {response.text[:100]}")
            return None
    except requests.exceptions.Timeout:
        print(f"ERROR: Cloudflare API request timed out ({method}, URL involved Zone ID)")
        return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Cloudflare API request failed ({method}, URL involved Zone ID): {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}. Body (first 100 chars): {e.response.text[:100] if e.response.text else '[No Body]'}")
        return None

def verify_cf_credentials(zone_id, api_token):
    print("Verifying Cloudflare credentials...")
    response_data = cf_api_request("GET", "", zone_id, api_token) # Gets zone details
    if response_data and response_data.get("success"):
        zone_info = response_data.get("result")
        if zone_info and zone_info.get("id") == zone_id:
            print(f"Credentials verified for Zone ID (not shown). Cloudflare account access confirmed.")
            return True
        else:
            print(f"ERROR: Cloudflare API response successful, but no valid Zone information found for Zone ID (not shown).")
            return False
    else:
        print("ERROR: Cloudflare credential verification failed. Please check CF_ZONE_ID and CF_API_TOKEN.")
        return False

def get_cf_dns_records(zone_id, api_token, domain_name_placeholder): # Takes placeholder
    actual_domain_name = domain_name_placeholder # In this context, placeholder is actual name, but we won't log it
    endpoint = "dns_records"
    params = {"type": "A", "name": actual_domain_name, "per_page": 100}
    response_data = cf_api_request("GET", endpoint, zone_id, api_token, params=params)
    if response_data and response_data.get("success"):
        # print(f"  - Queried records for {domain_name_placeholder}") # No need to log success here
        return response_data.get("result", [])
    # print(f"  - Failed to get DNS records for {domain_name_placeholder} or no records found.") # No need to log failure here, parent will
    return []

def delete_cf_dns_record(zone_id, api_token, record_id, country_code_placeholder):
    endpoint = f"dns_records/{record_id}"
    response_data = cf_api_request("DELETE", endpoint, zone_id, api_token)
    if response_data and response_data.get("success"):
        return True
    else:
        print(f"    - WARNING: Failed to delete a DNS record for {get_domain_placeholder(country_code_placeholder)} (Record ID: {record_id}).")
        return False

def clear_cf_domain_a_records(zone_id, api_token, domain_name, country_code): # Takes actual domain for CF, CC for logging
    domain_placeholder = get_domain_placeholder(country_code)
    # print(f"  - Starting cleanup of existing 'A' records for {domain_placeholder}...")
    existing_records = get_cf_dns_records(zone_id, api_token, domain_name) # Pass actual domain to CF
    if not existing_records:
        # print(f"  - No existing 'A' records found for {domain_placeholder}. No cleanup needed.")
        return True

    deletion_results = []
    # print(f"  - Preparing to delete {len(existing_records)} records for {domain_placeholder}...")
    for record in existing_records:
        record_id = record.get("id")
        if record_id:
            # Pass country_code for logging placeholder if delete fails
            result = delete_cf_dns_record(zone_id, api_token, record_id, country_code)
            deletion_results.append(result)
            time.sleep(0.3)
        else:
            print(f"WARNING: Found a record for {domain_placeholder} without an ID.")
            deletion_results.append(False)

    if all(deletion_results):
        # print(f"  - Successfully cleared {len(deletion_results)} 'A' records for {domain_placeholder}.")
        return True
    else:
        failures = deletion_results.count(False)
        print(f"WARNING: Encountered {failures} failures while clearing records for {domain_placeholder}.")
        return False

def create_cf_dns_record(zone_id, api_token, domain_name, ip_address, country_code): # Takes actual domain for CF, CC for logging
    domain_placeholder = get_domain_placeholder(country_code)
    endpoint = "dns_records"
    data = {
        "type": "A",
        "name": domain_name, # Actual domain name for Cloudflare
        "content": ip_address,
        "ttl": RECORD_TTL,
        "proxied": PROXY_STATUS
    }
    response_data = cf_api_request("POST", endpoint, zone_id, api_token, data=data)
    if response_data and response_data.get("success"):
        return True
    else:
        print(f"    - WARNING: Failed to create DNS record for {domain_placeholder} with IP (not shown).")
        return False

# --- Main Logic ---
def process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, target_countries, domain_map):
    if not verify_cf_credentials(cf_zone_id, cf_api_token):
        return

    print(f"Fetching IP data from configured RAW_URL...")
    all_ips_by_country = defaultdict(list)
    ip_pattern = re.compile(IPV4_REGEX)

    try:
        response = requests.get(raw_url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                ip, port_str, country_code_from_file = parts[0], parts[1], parts[2]
                if country_code_from_file in target_countries and port_str == TARGET_PORT:
                    if ip_pattern.match(ip):
                        all_ips_by_country[country_code_from_file].append(ip)
        print(f"Finished processing source IP list. Found data for {len(all_ips_by_country)} target countries with matching port.")

    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout when fetching raw URL.")
        return
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to fetch raw URL: {e}")
        return
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during IP fetching: {e}")
        import traceback
        traceback.print_exc()
        return

    if not all_ips_by_country:
        print("No IPs found for any target countries after initial filtering. Exiting.")
        return

    overall_success_count = 0
    overall_failure_count = 0

    for country_code_iter in target_countries: # Iterate using the keys from target_countries list
        actual_domain_name = domain_map.get(country_code_iter)
        domain_placeholder_for_log = get_domain_placeholder(country_code_iter)

        if not actual_domain_name:
            print(f"WARNING: No domain mapping for country '{country_code_iter}'. Skipping.")
            continue

        country_specific_ips = all_ips_by_country.get(country_code_iter, [])
        if not country_specific_ips:
            continue

        num_to_actually_test = min(NUM_IPS_TO_TEST, len(country_specific_ips))
        if num_to_actually_test == 0:
            continue
            
        ips_to_test = random.sample(country_specific_ips, num_to_actually_test)
        responsive_ips_with_latency = []
        
        for ip_addr in ips_to_test:
            latency = tcp_ping(ip_addr, TARGET_PORT)
            if latency is not None:
                responsive_ips_with_latency.append({"ip": ip_addr, "latency": latency})
            time.sleep(0.05)

        if not responsive_ips_with_latency:
            print(f"INFO: No responsive IPs for {domain_placeholder_for_log} after testing.")
            continue

        responsive_ips_with_latency.sort(key=lambda x: x["latency"])
        fastest_ips = [item["ip"] for item in responsive_ips_with_latency[:NUM_FASTEST_IPS_FOR_DNS]]
        
        if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, actual_domain_name, country_code_iter):
            print(f"WARNING: Issues clearing old DNS records for {domain_placeholder_for_log}. Proceeding.")

        creation_success_for_country = 0
        if fastest_ips:
            for ip_to_add in fastest_ips:
                # Pass actual_domain_name to CF, country_code_iter for logging placeholder if create fails
                if create_cf_dns_record(cf_zone_id, cf_api_token, actual_domain_name, ip_to_add, country_code_iter):
                    creation_success_for_country +=1
                time.sleep(0.3)
            
            if creation_success_for_country == len(fastest_ips) and len(fastest_ips) > 0 :
                print(f"SUCCESS: {domain_placeholder_for_log} updated with {creation_success_for_country} IPs.")
                overall_success_count += 1
            elif len(fastest_ips) > 0 : # Partial success or complete failure but attempts were made
                print(f"PARTIAL/FAIL: {domain_placeholder_for_log}: {creation_success_for_country}/{len(fastest_ips)} IPs updated.")
                overall_failure_count +=1
            else: # No fastest_ips to begin with (should be caught by earlier checks, but as a safeguard)
                print(f"INFO: No IPs to update for {domain_placeholder_for_log}.")

        else: # No fastest_ips after sorting (e.g., if NUM_FASTEST_IPS_FOR_DNS is 0 or list became empty)
             print(f"INFO: No IPs selected after filtering for {domain_placeholder_for_log}, so no DNS records created.")


    print(f"\nOverall DNS Update Summary: {overall_success_count} countries/domains successfully updated, {overall_failure_count} had issues or no IPs to update.")


# --- Main Execution ---
if __name__ == "__main__":
    print("--- Enhanced DNS Update Script Starting ---")
    print(f"Script start time (UTC): {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())}")

    raw_url = os.environ.get("RAW_URL")
    cf_zone_id = os.environ.get("CF_ZONE_ID")
    cf_api_token = os.environ.get("CF_API_TOKEN")
    domain_map_json_str = os.environ.get("DOMAIN_MAP_JSON")
    target_countries_json_str = os.environ.get("TARGET_COUNTRIES_JSON")

    missing_vars = []
    if not raw_url: missing_vars.append("RAW_URL")
    if not cf_zone_id: missing_vars.append("CF_ZONE_ID")
    if not cf_api_token: missing_vars.append("CF_API_TOKEN")
    if not domain_map_json_str: missing_vars.append("DOMAIN_MAP_JSON")

    if missing_vars:
        print(f"ERROR: Critical environment variables not set: {', '.join(missing_vars)}")
    else:
        try:
            domain_map = json.loads(domain_map_json_str) # Actual domain names loaded here
            if not isinstance(domain_map, dict):
                raise ValueError("DOMAIN_MAP_JSON must be a JSON object (dictionary).")

            target_countries = DEFAULT_TARGET_COUNTRIES
            if target_countries_json_str:
                target_countries = json.loads(target_countries_json_str)
                if not isinstance(target_countries, list):
                    raise ValueError("TARGET_COUNTRIES_JSON must be a JSON array (list) of strings.")
            print(f"Configured to process {len(target_countries)} target countries/regions.")

            effective_target_countries_for_processing = []
            for country_key in target_countries:
                if country_key in domain_map:
                    effective_target_countries_for_processing.append(country_key)
                else:
                    print(f"WARNING: Country code '{country_key}' is in target list but not found in DOMAIN_MAP. It will be skipped.")
            
            if not effective_target_countries_for_processing:
                print("ERROR: No valid target countries to process after checking against DOMAIN_MAP. Exiting.")
            else:
                # Pass the full domain_map and the filtered list of country codes to process
                process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, effective_target_countries_for_processing, domain_map)

        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse JSON from environment variable: {e}")
            if 'domain_map_json_str' in locals() and e.doc == domain_map_json_str:
                print("Error likely occurred while parsing DOMAIN_MAP_JSON.")
            if 'target_countries_json_str' in locals() and e.doc == target_countries_json_str:
                print("Error likely occurred while parsing TARGET_COUNTRIES_JSON.")
        except ValueError as e:
            print(f"ERROR: Invalid configuration: {e}")

    print(f"--- DNS Update Script Finished (UTC): {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())} ---")
