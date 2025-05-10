import requests
import os
import random
import json
from collections import defaultdict
import time
import re
import socket

# --- Configuration ---
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TARGET_COUNTRIES = ["PL", "AE", "JP", "KR", "SG", "RU", "DE", "TW", "US"]

NUM_IPS_TO_TEST = 20
NUM_FASTEST_IPS_FOR_DNS = 3 # As per your dnsupdate.py, this was 3. Adjust if needed.
TARGET_PORT = "443"
TCP_TIMEOUT = 1
IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
PROXY_STATUS = False
RECORD_TTL = 60

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
                print(f"ERROR: Cloudflare API operation not successful ({method} {url}). Response: {response_data}")
                return None
            return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT'] or \
               (method.upper() == 'GET' and response.text.strip() == '' and response_data.get("result") is None):
                # Consider this a success for certain operations if needed, but log minimally for privacy
                # print(f"INFO: CF API {method} for {url} successful with status {response.status_code}, non-standard/empty JSON.")
                return {"success": True, "result": []}
            elif response.status_code == 200 and method.upper() == 'GET' and endpoint == "":
                 print(f"ERROR: Non-JSON response when fetching Zone info for {zone_id}.")
                 return None
            print(f"WARNING: Could not parse Cloudflare API response as JSON ({method} {url}). Status: {response.status_code}. Body (first 100 chars): {response.text[:100]}")
            return None
    except requests.exceptions.Timeout:
        print(f"ERROR: Cloudflare API request timed out ({method} {url})")
        return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Cloudflare API request failed ({method} {url}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}. Body (first 100 chars): {e.response.text[:100] if e.response.text else '[No Body]'}")
        return None

def verify_cf_credentials(zone_id, api_token):
    print("Verifying Cloudflare credentials...") # Keep: important check
    response_data = cf_api_request("GET", "", zone_id, api_token)
    if response_data and response_data.get("success"):
        zone_info = response_data.get("result")
        if zone_info and zone_info.get("id") == zone_id:
            zone_name = zone_info.get("name", "N/A")
            print(f"Credentials verified for Zone ID: {zone_id} (Name: {zone_name})") # Keep: confirms access
            return True
        else:
            print(f"ERROR: Cloudflare API response successful, but no valid Zone information found for Zone ID: {zone_id}.")
            return False
    else:
        print("ERROR: Cloudflare credential verification failed. Please check CF_ZONE_ID and CF_API_TOKEN.")
        return False

def get_cf_dns_records(zone_id, api_token, domain_name):
    endpoint = "dns_records"
    params = {"type": "A", "name": domain_name, "per_page": 100}
    response_data = cf_api_request("GET", endpoint, zone_id, api_token, params=params)
    if response_data and response_data.get("success"):
        return response_data.get("result", [])
    return []

def delete_cf_dns_record(zone_id, api_token, record_id, domain_name):
    endpoint = f"dns_records/{record_id}"
    response_data = cf_api_request("DELETE", endpoint, zone_id, api_token)
    if response_data and response_data.get("success"):
        # print(f"    - Successfully deleted record ID: {record_id} for {domain_name}") # Removed detailed log
        return True
    else:
        print(f"    - WARNING: Failed to delete record ID: {record_id} for {domain_name}.") # Keep warning
        return False

def clear_cf_domain_a_records(zone_id, api_token, domain_name):
    existing_records = get_cf_dns_records(zone_id, api_token, domain_name)
    if not existing_records:
        # print(f"  - No existing 'A' records found for domain '{domain_name}'. No cleanup needed.") # Reduced
        return True

    deletion_results = []
    # print(f"  - Preparing to delete {len(existing_records)} records for {domain_name}...") # Reduced
    for record in existing_records:
        record_id = record.get("id")
        if record_id:
            result = delete_cf_dns_record(zone_id, api_token, record_id, domain_name)
            deletion_results.append(result)
            time.sleep(0.3)
        else:
            print(f"WARNING: Found a record for {domain_name} without an ID: {record.get('name')}") # Keep warning
            deletion_results.append(False)

    if all(deletion_results):
        # print(f"  - Successfully cleared {len(deletion_results)} 'A' records for domain '{domain_name}'.") # Reduced
        return True
    else:
        failures = deletion_results.count(False)
        print(f"WARNING: Encountered {failures} failures while clearing records for domain '{domain_name}'.") # Keep warning
        return False

def create_cf_dns_record(zone_id, api_token, domain_name, ip_address):
    # print(f"    - Attempting to create 'A' record for '{domain_name}' -> {ip_address}...") # Removed IP
    endpoint = "dns_records"
    data = {
        "type": "A",
        "name": domain_name,
        "content": ip_address,
        "ttl": RECORD_TTL,
        "proxied": PROXY_STATUS
    }
    response_data = cf_api_request("POST", endpoint, zone_id, api_token, data=data)
    if response_data and response_data.get("success"):
        # print(f"    - Successfully created record: {domain_name} -> {ip_address}") # Removed IP
        return True
    else:
        print(f"    - WARNING: Failed to create record for {domain_name} with IP (not shown).") # Keep warning, hide IP
        return False

# --- Main Logic ---
def process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, target_countries, domain_map):
    if not verify_cf_credentials(cf_zone_id, cf_api_token):
        return

    print(f"Fetching IP data from configured RAW_URL...") # Keep: general step
    all_ips_by_country = defaultdict(list)
    ip_pattern = re.compile(IPV4_REGEX)

    try:
        response = requests.get(raw_url, timeout=30)
        response.raise_for_status()
        # print("Successfully fetched data, processing...") # Reduced
        lines = response.text.splitlines()
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                ip, port_str, country_code = parts[0], parts[1], parts[2]
                if country_code in target_countries and port_str == TARGET_PORT:
                    if ip_pattern.match(ip):
                        all_ips_by_country[country_code].append(ip)
        # print(f"Finished processing source IP list. Found IPs for countries: {list(all_ips_by_country.keys())}") # Reduced
        print(f"Finished processing source IP list. Found data for {len(all_ips_by_country)} target countries.")


    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout when fetching raw URL.") # Keep error
        return
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to fetch raw URL: {e}") # Keep error
        return
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during IP fetching: {e}") # Keep error
        import traceback
        traceback.print_exc()
        return

    if not all_ips_by_country:
        print("No IPs found for any target countries after initial filtering. Exiting.") # Keep: important status
        return

    overall_success_count = 0
    overall_failure_count = 0

    for country_code in target_countries:
        # print(f"\n--- Processing Country: {country_code} ---") # Removed detailed country header
        domain_name = domain_map.get(country_code)
        if not domain_name:
            print(f"WARNING: No domain mapping for country '{country_code}'. Skipping.") # Keep warning
            continue

        country_specific_ips = all_ips_by_country.get(country_code, [])
        if not country_specific_ips:
            # print(f"  No IPs on port {TARGET_PORT} found for {country_code} from source. Skipping DNS for {domain_name}.") # Reduced
            continue

        # print(f"  Found {len(country_specific_ips)} IPs for {country_code} on port {TARGET_PORT}.") # Removed count

        num_to_actually_test = min(NUM_IPS_TO_TEST, len(country_specific_ips))
        if num_to_actually_test == 0:
            continue
            
        ips_to_test = random.sample(country_specific_ips, num_to_actually_test)
        # print(f"  Randomly selected {len(ips_to_test)} IPs for TCPing for {country_code}...") # Reduced

        responsive_ips_with_latency = []
        # print(f"  Performing TCPing on {len(ips_to_test)} IPs for {country_code} (port {TARGET_PORT}, timeout {TCP_TIMEOUT}s)...") # Reduced
        
        for ip_addr in ips_to_test:
            latency = tcp_ping(ip_addr, TARGET_PORT)
            if latency is not None:
                responsive_ips_with_latency.append({"ip": ip_addr, "latency": latency})
            time.sleep(0.05)

        # print(f"  TCPing complete for {country_code}. {len(responsive_ips_with_latency)} responded.") # Reduced

        if not responsive_ips_with_latency:
            # print(f"  No responsive IPs for {country_code} after TCPing. Skipping DNS for {domain_name}.") # Reduced
            continue

        responsive_ips_with_latency.sort(key=lambda x: x["latency"])
        fastest_ips = [item["ip"] for item in responsive_ips_with_latency[:NUM_FASTEST_IPS_FOR_DNS]]
        
        # This whole block was privacy sensitive, removing IP and latency details
        # print(f"  Selected {len(fastest_ips)} fastest IPs for DNS ({domain_name}):")
        # for item in responsive_ips_with_latency[:NUM_FASTEST_IPS_FOR_DNS]:
        #     print(f"    - {item['ip']} (Latency: {item['latency']:.2f} ms)")

        # print(f"  Updating Cloudflare DNS for {domain_name} with {len(fastest_ips)} IPs...") # Reduced
        if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, domain_name):
            print(f"WARNING: Issues clearing old DNS records for {domain_name}. Proceeding.") # Keep warning

        creation_success_for_country = 0
        if fastest_ips:
            for ip_to_add in fastest_ips:
                if create_cf_dns_record(cf_zone_id, cf_api_token, domain_name, ip_to_add):
                    creation_success_for_country +=1
                time.sleep(0.3)
            
            if creation_success_for_country == len(fastest_ips):
                print(f"SUCCESS: DNS for {domain_name} (Country: {country_code}) updated with {creation_success_for_country} IPs.")
                overall_success_count += 1
            else:
                print(f"PARTIAL/FAIL: DNS for {domain_name} (Country: {country_code}): {creation_success_for_country}/{len(fastest_ips)} IPs updated.")
                overall_failure_count +=1
        else:
             # print(f"  No IPs selected after filtering for {domain_name}, no DNS records created.") # Reduced
             print(f"INFO: No responsive/fast IPs found to update DNS for {domain_name} (Country: {country_code}).")


    print(f"\nOverall DNS Update Summary: {overall_success_count} countries/domains successfully updated, {overall_failure_count} had issues.")


# --- Main Execution ---
if __name__ == "__main__":
    print("--- Enhanced DNS Update Script Starting ---") # Keep: Script start
    print(f"Script start time (UTC): {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())}") # Keep: Timestamp

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
        print(f"ERROR: Critical environment variables not set: {', '.join(missing_vars)}") # Keep: Critical error
    else:
        try:
            domain_map = json.loads(domain_map_json_str)
            if not isinstance(domain_map, dict):
                raise ValueError("DOMAIN_MAP_JSON must be a JSON object (dictionary).")
            # print(f"Successfully loaded DOMAIN_MAP: {domain_map}") # Removed: Potentially sensitive

            target_countries = DEFAULT_TARGET_COUNTRIES
            if target_countries_json_str:
                target_countries = json.loads(target_countries_json_str)
                if not isinstance(target_countries, list):
                    raise ValueError("TARGET_COUNTRIES_JSON must be a JSON array (list) of strings.")
            # print(f"Target countries to process: {target_countries}") # Removed: Potentially sensitive
            print(f"Configured to process {len(target_countries)} target countries.")


            effective_domain_map = {}
            valid_target_countries = []
            for country in target_countries:
                if country in domain_map:
                    effective_domain_map[country] = domain_map[country]
                    valid_target_countries.append(country)
                else:
                    print(f"WARNING: Country '{country}' is in TARGET_COUNTRIES but not in DOMAIN_MAP. It will be skipped.") # Keep warning
            
            if not valid_target_countries:
                print("ERROR: No valid target countries to process after checking against DOMAIN_MAP. Exiting.") # Keep: Critical error
            else:
                process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, valid_target_countries, effective_domain_map)

        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse JSON from environment variable: {e}") # Keep: Critical error
            if 'domain_map_json_str' in locals() and e.doc == domain_map_json_str:
                print("Error likely occurred while parsing DOMAIN_MAP_JSON.")
            if 'target_countries_json_str' in locals() and e.doc == target_countries_json_str:
                print("Error likely occurred while parsing TARGET_COUNTRIES_JSON.")
        except ValueError as e:
            print(f"ERROR: Invalid configuration: {e}") # Keep: Critical error

    print(f"--- DNS Update Script Finished (UTC): {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())} ---") # Keep: Script end
