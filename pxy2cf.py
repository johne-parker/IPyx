import requests
import os
import random # 确保已导入 random 模块
import json
from collections import defaultdict
import time
import re
import socket
from bs4 import BeautifulSoup

# --- Configuration ---
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TARGET_COUNTRIES = ["PL", "AE", "JP", "KR", "SG", "RU", "DE", "TW", "US"]

NUM_IPS_TO_TEST = 20
NUM_FASTEST_IPS_FOR_DNS = 3 # 我们需要欺诈值最低且都小于40的3个IP
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

# --- Scamalytics Fraud Score Function ---
def get_scamalytics_fraud_score(ip_address):
    """
    访问 Scamalytics 网站获取给定 IP 地址的欺诈分数。
    """
    url = f"https://scamalytics.com/ip/{ip_address}"
    # 使用更具体的 User-Agent 和其他请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Connection': 'keep-alive',
        'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Host': 'scamalytics.com'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30) 
        response.raise_for_status() # 检查HTTP请求是否成功 (2xx 状态码)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        score_div = soup.find('div', class_='score')
        
        if score_div:
            score_text = score_div.get_text(strip=True)
            try:
                score = int(score_text.replace("Fraud Score:", "").strip())
                return score
            except ValueError:
                print(f"WARNING: 无法解析 IP {ip_address} 的欺诈分数文本: '{score_text}'")
                return None
        else:
            print(f"WARNING: 未能在 IP {ip_address} 的页面中找到欺诈分数元素。")
            return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: 请求 IP {ip_address} 时发生网络错误: {e}")
        return None
    except Exception as e:
        print(f"ERROR: 处理 IP {ip_address} 欺诈分数时发生未知错误: {e}")
        return None

# --- Cloudflare API Functions (unchanged) ---
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
                print(f"ERROR: Cloudflare API operation not successful ({method} {url}). Response: {response_data.get('errors', 'No error details')}")
                return None
            return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT'] or \
               (method.upper() == 'GET' and response.text.strip() == '' and response_data.get("result") is None):
                return {"success": True, "result": []}
            elif response.status_code == 200 and method.upper() == 'GET' and endpoint == "":
                 print(f"ERROR: Non-JSON response when fetching Zone info for Zone ID (not shown).")
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
    response_data = cf_api_request("GET", "", zone_id, api_token)
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

def get_cf_dns_records(zone_id, api_token, domain_name_placeholder):
    actual_domain_name = domain_name_placeholder
    endpoint = "dns_records"
    params = {"type": "A", "name": actual_domain_name, "per_page": 100}
    response_data = cf_api_request("GET", endpoint, zone_id, api_token, params=params)
    if response_data and response_data.get("success"):
        return response_data.get("result", [])
    return []

def delete_cf_dns_record(zone_id, api_token, record_id, country_code_placeholder):
    endpoint = f"dns_records/{record_id}"
    response_data = cf_api_request("DELETE", endpoint, zone_id, api_token)
    if response_data and response_data.get("success"):
        return True
    else:
        print(f"    - WARNING: Failed to delete a DNS record for {get_domain_placeholder(country_code_placeholder)} (Record ID: {record_id}).")
        return False

def clear_cf_domain_a_records(zone_id, api_token, domain_name, country_code):
    domain_placeholder = get_domain_placeholder(country_code)
    existing_records = get_cf_dns_records(zone_id, api_token, domain_name)
    if not existing_records:
        return True

    deletion_results = []
    for record in existing_records:
        record_id = record.get("id")
        if record_id:
            result = delete_cf_dns_record(zone_id, api_token, record_id, country_code)
            deletion_results.append(result)
            time.sleep(0.3)
        else:
            print(f"WARNING: Found a record for {domain_placeholder} without an ID.")
            deletion_results.append(False)

    if all(deletion_results):
        return True
    else:
        failures = deletion_results.count(False)
        print(f"WARNING: Encountered {failures} failures while clearing records for {domain_placeholder}.")
        return False

def create_cf_dns_record(zone_id, api_token, domain_name, ip_address, country_code):
    domain_placeholder = get_domain_placeholder(country_code)
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

    for country_code_iter in target_countries:
        actual_domain_name = domain_map.get(country_code_iter)
        domain_placeholder_for_log = get_domain_placeholder(country_code_iter)

        if not actual_domain_name:
            print(f"WARNING: No domain mapping for country '{country_code_iter}'. Skipping.")
            continue

        country_specific_ips = all_ips_by_country.get(country_code_iter, [])
        if not country_specific_ips:
            print(f"INFO: No IPs available from source for {domain_placeholder_for_log}.")
            continue

        num_to_actually_test = min(NUM_IPS_TO_TEST, len(country_specific_ips))
        if num_to_actually_test == 0:
            print(f"INFO: Not enough IPs to test for {domain_placeholder_for_log}.")
            continue
            
        ips_to_test = random.sample(country_specific_ips, num_to_actually_test)
        
        # 步骤1: TCP Ping 筛选
        responsive_ips_with_latency = []
        print(f"  - [{domain_placeholder_for_log}] Performing TCP ping test on {len(ips_to_test)} IPs...")
        for ip_addr in ips_to_test:
            latency = tcp_ping(ip_addr, TARGET_PORT)
            if latency is not None:
                responsive_ips_with_latency.append({"ip": ip_addr, "latency": latency})
            # TCP Ping 之间的延迟，使用较小的随机浮点数
            time.sleep(random.uniform(0.1, 0.5)) 
        
        if not responsive_ips_with_latency:
            print(f"  - [{domain_placeholder_for_log}] 警告: TCP Ping 后没有找到响应的IP。")
            overall_failure_count += 1
            continue

        # 步骤2: 欺诈分数检查
        ips_with_fraud_score = []
        print(f"  - [{domain_placeholder_for_log}] Checking fraud scores for {len(responsive_ips_with_latency)} responsive IPs...")
        for ip_info in responsive_ips_with_latency:
            ip_addr = ip_info["ip"]
            fraud_score = get_scamalytics_fraud_score(ip_addr)
            
            if fraud_score is not None:
                print(f"    - IP: {ip_addr}, 欺诈分数: {fraud_score}")
                if fraud_score < 40: # 只保留欺诈分数小于 40 的IP
                    ips_with_fraud_score.append({
                        "ip": ip_addr,
                        "latency": ip_info["latency"],
                        "fraud_score": fraud_score
                    })
            else:
                print(f"    - IP: {ip_addr}, 欺诈分数: 无法获取 (跳过)")
            
            # Scamalytics 网站查询之间的延迟，使用 5 到 12 秒的随机整数
            time.sleep(random.randint(8, 15)) 

        if not ips_with_fraud_score:
            print(f"  - [{domain_placeholder_for_log}] 警告: 没有找到欺诈分数低于 40 的IP。")
            overall_failure_count += 1
            continue

        # 步骤3: 排序并选择最佳IP
        # 优先按欺诈分数升序，然后按延迟升序排序
        ips_with_fraud_score.sort(key=lambda x: (x["fraud_score"], x["latency"]))
        
        # 选择前 NUM_FASTEST_IPS_FOR_DNS (3) 个IP
        final_ips_for_dns = [item["ip"] for item in ips_with_fraud_score[:NUM_FASTEST_IPS_FOR_DNS]]
        
        # 步骤4: 检查数量是否满足要求
        if len(final_ips_for_dns) < NUM_FASTEST_IPS_FOR_DNS:
            print(f"  - [{domain_placeholder_for_log}] 警告: 找到的欺诈分数低于40的IP数量不足 {NUM_FASTEST_IPS_FOR_DNS} 个 ({len(final_ips_for_dns)}个)。将不更新DNS记录。")
            overall_failure_count += 1
            continue # 跳过当前国家的DNS更新

        print(f"  - [{domain_placeholder_for_log}] 选定用于DNS更新的IP ({len(final_ips_for_dns)} 个): {final_ips_for_dns}")

        # 步骤5: 清理并创建DNS记录
        if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, actual_domain_name, country_code_iter):
            print(f"WARNING: Issues clearing old DNS records for {domain_placeholder_for_log}. Proceeding anyway to attempt creation.")

        creation_success_for_country = 0
        for ip_to_add in final_ips_for_dns:
            if create_cf_dns_record(cf_zone_id, cf_api_token, actual_domain_name, ip_to_add, country_code_iter):
                creation_success_for_country +=1
            time.sleep(0.3) # Cloudflare API 请求之间的延迟保持不变
            
        if creation_success_for_country == len(final_ips_for_dns) and len(final_ips_for_dns) > 0 :
            print(f"SUCCESS: {domain_placeholder_for_log} updated with {creation_success_for_country} IPs.")
            overall_success_count += 1
        elif len(final_ips_for_dns) > 0 : # 部分成功或完全失败但尝试过
            print(f"PARTIAL/FAIL: {domain_placeholder_for_log}: {creation_success_for_country}/{len(final_ips_for_dns)} IPs updated.")
            overall_failure_count +=1
        else: # 没有最终IP可供更新 (此情况通常会被前面的 `if len(final_ips_for_dns) < NUM_FASTEST_IPS_FOR_DNS` 捕获)
            print(f"INFO: No IPs to update for {domain_placeholder_for_log} (this state should be rare due to prior checks).")


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
            domain_map = json.loads(domain_map_json_str)
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
