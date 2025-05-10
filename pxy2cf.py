import requests
import os
import random
import json
from collections import defaultdict
import time
import re
import socket

CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TARGET_COUNTRIES = ["PL", "AE", "JP", "KR", "SG", "RU", "DE", "TW", "US"] 

NUM_IPS_TO_TEST = 20
NUM_FASTEST_IPS_FOR_DNS = 3
TARGET_PORT = "443"
TCP_TIMEOUT = 1 
IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
PROXY_STATUS = False
RECORD_TTL = 60 

def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    """
    Performs a TCP connection test to the given host and port.
    Returns latency in milliseconds if successful, None otherwise.
    """
    ip_pattern = re.compile(IPV4_REGEX)
    if not ip_pattern.match(host):
        # print(f"    - Invalid IP format for TCP ping: {host}") # Optional: for debugging
        return None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_time = time.time()
        s.connect((host, int(port))) # Port needs to be int for socket
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # in milliseconds
        s.close()
        # print(f"    - TCP Ping to {host}:{port} successful, latency: {latency:.2f} ms") # Optional: for debugging
        return latency
    except (socket.timeout, socket.error) as e:
        # print(f"    - TCP Ping to {host}:{port} failed: {e}") # Optional: for debugging
        return None

def cf_api_request(method, endpoint, zone_id, api_token, params=None, data=None):
    """Unified Cloudflare API request handler."""
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
                print(f"ERROR: Cloudflare API operation not successful ({method} {url}).")
                print(f"Response: {response_data}")
                return None
            return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT'] or \
               (method.upper() == 'GET' and response.text.strip() == '' and response_data.get("result") is None): # some GETs might return empty success
                print(f"INFO: {method} request successful with status {response.status_code}, but no standard JSON success body or empty result.")
                return {"success": True, "result": []} # Assume success with empty result for safety
            elif response.status_code == 200 and method.upper() == 'GET' and endpoint == "": # Specifically for zone info
                 print(f"ERROR: Non-JSON response when fetching Zone info for {zone_id}.")
                 return None
            print(f"WARNING: Could not parse Cloudflare API response as JSON ({method} {url}). Status: {response.status_code}")
            print(f"Response body (first 500 chars): {response.text[:500]}")
            return None
    except requests.exceptions.Timeout:
        print(f"ERROR: Cloudflare API request timed out ({method} {url})")
        return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Cloudflare API request failed ({method} {url}): {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            try:
                print(f"Response body: {e.response.text[:500]}")
            except Exception:
                print("Could not read response body.")
        return None

def verify_cf_credentials(zone_id, api_token):
    """Verifies Cloudflare API Token and Zone ID."""
    print("Verifying Cloudflare credentials...")
    response_data = cf_api_request("GET", "", zone_id, api_token) # Empty endpoint means /zones/{zone_id}
    if response_data and response_data.get("success"):
        zone_info = response_data.get("result")
        if zone_info and zone_info.get("id") == zone_id:
            zone_name = zone_info.get("name", "N/A")
            print(f"Credentials verified! Can access Zone ID: {zone_id} (Name: {zone_name})")
            return True
        else:
            print(f"ERROR: Cloudflare API response successful, but no valid Zone information found.")
            print(f"Response: {response_data}")
            return False
    else:
        print("ERROR: Cloudflare credential verification failed. Please check CF_ZONE_ID and CF_API_TOKEN.")
        return False

def get_cf_dns_records(zone_id, api_token, domain_name):
    """Gets all Cloudflare DNS 'A' records for the specified domain."""
    print(f"  - Querying existing 'A' records for domain '{domain_name}' (for cleanup)...")
    endpoint = "dns_records"
    params = {"type": "A", "name": domain_name, "per_page": 100} # Get up to 100 records
    response_data = cf_api_request("GET", endpoint, zone_id, api_token, params=params)
    if response_data and response_data.get("success"):
        records = response_data.get("result", [])
        print(f"  - Found {len(records)} matching 'A' records.")
        return records
    else:
        print(f"  - Failed to get DNS records for {domain_name} or no records found.")
        return []

def delete_cf_dns_record(zone_id, api_token, record_id):
    """Deletes the specified Cloudflare DNS record."""
    endpoint = f"dns_records/{record_id}"
    print(f"    - Attempting to delete record ID: {record_id}...")
    response_data = cf_api_request("DELETE", endpoint, zone_id, api_token)
    if response_data and response_data.get("success"): # Check for success, even if no JSON body
        print(f"    - Successfully deleted record ID: {record_id}")
        return True
    else:
        print(f"    - Failed to delete record ID: {record_id}.")
        return False

def clear_cf_domain_a_records(zone_id, api_token, domain_name):
    """Clears all 'A' records for the specified domain."""
    print(f"  - Starting cleanup of existing 'A' records for domain '{domain_name}'...")
    existing_records = get_cf_dns_records(zone_id, api_token, domain_name)
    if not existing_records:
        print(f"  - No existing 'A' records found for domain '{domain_name}'. No cleanup needed.")
        return True

    deletion_results = []
    print(f"  - Preparing to delete {len(existing_records)} records...")
    for record in existing_records:
        record_id = record.get("id")
        if record_id:
            result = delete_cf_dns_record(zone_id, api_token, record_id)
            deletion_results.append(result)
            time.sleep(0.3) # Brief pause to avoid hitting API rate limits too hard
        else:
            print(f"WARNING: Found a record without an ID: {record}")
            deletion_results.append(False)

    if all(deletion_results):
        print(f"  - Successfully cleared {len(deletion_results)} 'A' records for domain '{domain_name}'.")
        return True
    else:
        failures = deletion_results.count(False)
        print(f"WARNING: Encountered {failures} failures while clearing records for domain '{domain_name}'.")
        return False

def create_cf_dns_record(zone_id, api_token, domain_name, ip_address):
    """Creates a Cloudflare DNS 'A' record."""
    print(f"    - Attempting to create 'A' record for '{domain_name}' -> {ip_address}...")
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
        print(f"    - Successfully created record: {domain_name} -> {ip_address}")
        return True
    else:
        print(f"    - Failed to create record: {domain_name} -> {ip_address}")
        return False

def process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, target_countries, domain_map):
    """
    Fetches, TCPings, filters IPs, and updates Cloudflare DNS records.
    """
    if not verify_cf_credentials(cf_zone_id, cf_api_token):
        return

    print(f"\nFetching IP data from {raw_url}...")
    all_ips_by_country = defaultdict(list)
    ip_pattern = re.compile(IPV4_REGEX)

    try:
        response = requests.get(raw_url, timeout=30)
        response.raise_for_status()
        print("Successfully fetched data, processing...")
        lines = response.text.splitlines()
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                ip, port_str, country_code = parts[0], parts[1], parts[2]
                if country_code in target_countries and port_str == TARGET_PORT:
                    if ip_pattern.match(ip):
                        all_ips_by_country[country_code].append(ip)
                    # else: # Optional: log invalid IPs
                        # print(f"  Skipping invalid IP format: {ip} for country {country_code}")
        print(f"Finished processing source IP list. Found IPs for countries: {list(all_ips_by_country.keys())}")

    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout when fetching raw URL ({raw_url}).")
        return
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to fetch raw URL: {e}")
        return
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during IP fetching or initial processing: {e}")
        import traceback
        traceback.print_exc()
        return

    if not all_ips_by_country:
        print("No IPs found for any target countries after initial filtering. Exiting.")
        return

    for country_code in target_countries:
        print(f"\n--- Processing Country: {country_code} ---")
        domain_name = domain_map.get(country_code)
        if not domain_name:
            print(f"  WARNING: No domain mapping found for country code '{country_code}' in DOMAIN_MAP. Skipping.")
            continue

        country_specific_ips = all_ips_by_country.get(country_code, [])
        if not country_specific_ips:
            print(f"  No IPs on port {TARGET_PORT} found for country {country_code} from the source. Skipping DNS update for {domain_name}.")
            continue

        print(f"  Found {len(country_specific_ips)} IPs for {country_code} on port {TARGET_PORT}.")

        num_to_actually_test = min(NUM_IPS_TO_TEST, len(country_specific_ips))
        if num_to_actually_test == 0:
            print(f"  No IPs to test for {country_code}. Skipping.")
            continue
            
        ips_to_test = random.sample(country_specific_ips, num_to_actually_test)
        print(f"  Randomly selected {len(ips_to_test)} IPs for TCPing: {ips_to_test[:5]}... (showing max 5)") # Show a few

        responsive_ips_with_latency = []
        print(f"  Performing TCPing on {len(ips_to_test)} IPs for {country_code} (port {TARGET_PORT}, timeout {TCP_TIMEOUT}s)...")
        test_count = 0
        for ip_addr in ips_to_test:
            test_count += 1
            if test_count % 10 == 0 or test_count == len(ips_to_test): # Progress update
                 print(f"    Testing IP {test_count}/{len(ips_to_test)}: {ip_addr}")
            latency = tcp_ping(ip_addr, TARGET_PORT) # TARGET_PORT is string, tcp_ping converts
            if latency is not None:
                responsive_ips_with_latency.append({"ip": ip_addr, "latency": latency})
            time.sleep(0.05) # Small delay between pings if needed, though timeout handles most waits

        print(f"  TCPing complete. {len(responsive_ips_with_latency)} out of {len(ips_to_test)} IPs responded.")

        if not responsive_ips_with_latency:
            print(f"  No responsive IPs found for {country_code} after TCPing. Skipping DNS update for {domain_name}.")
            continue

        responsive_ips_with_latency.sort(key=lambda x: x["latency"])
        fastest_ips = [item["ip"] for item in responsive_ips_with_latency[:NUM_FASTEST_IPS_FOR_DNS]]
        print(f"  Selected {len(fastest_ips)} fastest IPs for DNS ({domain_name}):")
        for item in responsive_ips_with_latency[:NUM_FASTEST_IPS_FOR_DNS]:
            print(f"    - {item['ip']} (Latency: {item['latency']:.2f} ms)")

        print(f"  Updating Cloudflare DNS for {domain_name} with {len(fastest_ips)} IPs...")
        if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, domain_name):
            print(f"  WARNING: Issues clearing old DNS records for {domain_name}. Proceeding with creating new ones.")

        creation_results = []
        if fastest_ips:
            for ip_to_add in fastest_ips:
                result = create_cf_dns_record(cf_zone_id, cf_api_token, domain_name, ip_to_add)
                creation_results.append(result)
                time.sleep(0.3) # API rate limit consideration
            success_count = creation_results.count(True)
            failure_count = len(creation_results) - success_count
            print(f"  DNS update for {domain_name} complete: {success_count} created, {failure_count} failed.")
        else:
             print(f"  No IPs selected after filtering for {domain_name}, so no DNS records created.")


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
            domain_map = json.loads(domain_map_json_str)
            if not isinstance(domain_map, dict):
                raise ValueError("DOMAIN_MAP_JSON must be a JSON object (dictionary).")
            print(f"Successfully loaded DOMAIN_MAP: {domain_map}")

            target_countries = DEFAULT_TARGET_COUNTRIES
            if target_countries_json_str:
                target_countries = json.loads(target_countries_json_str)
                if not isinstance(target_countries, list):
                    raise ValueError("TARGET_COUNTRIES_JSON must be a JSON array (list) of strings.")
            print(f"Target countries to process: {target_countries}")
            
            effective_domain_map = {}
            valid_target_countries = []
            for country in target_countries:
                if country in domain_map:
                    effective_domain_map[country] = domain_map[country]
                    valid_target_countries.append(country)
                else:
                    print(f"WARNING: Country '{country}' is in TARGET_COUNTRIES but not in DOMAIN_MAP. It will be skipped.")
            
            if not valid_target_countries:
                print("ERROR: No valid target countries to process after checking against DOMAIN_MAP. Exiting.")
            else:
                process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, valid_target_countries, effective_domain_map)

        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse JSON from environment variable: {e}")
            if 'domain_map_json_str' in locals() and e.doc == domain_map_json_str:
                print("Error occurred while parsing DOMAIN_MAP_JSON.")
            if 'target_countries_json_str' in locals() and e.doc == target_countries_json_str:
                print("Error occurred while parsing TARGET_COUNTRIES_JSON.")
        except ValueError as e:
            print(f"ERROR: Invalid configuration: {e}")

    print(f"--- DNS Update Script Finished (UTC): {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())} ---")
