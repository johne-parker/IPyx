import requests
import os
import random
import json
from collections import defaultdict
import time
import re # Import re for IP validation

# --- 配置 ---
# Cloudflare API 的基础 URL
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
# 国家代码到域名的映射
DOMAIN_MAP = {
    "PL": "pl.nan.eu.org",
    "AE": "ae.nan.eu.org",
    "CA": "ca.nan.eu.org",
}
# 要处理的国家代码列表
TARGET_COUNTRIES = ["PL", "AE", "CA"]
# 每个国家随机选择的端口为443的IP数量上限
NUM_IPS_PER_COUNTRY = 5 # <<< Goal: Up to 5 records per domain
# IPv4 Regex for validation
IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
# Cloudflare Proxied status (Orange/Grey cloud)
PROXY_STATUS = False # Default to False (Grey cloud)
# DNS Record TTL (Time To Live) in seconds. 1 = Automatic
RECORD_TTL = 60 # e.g., 60 seconds

# --- Cloudflare API 函数 ---

def cf_api_request(method, endpoint, zone_id, api_token, params=None, data=None):
    """统一处理 Cloudflare API 请求"""
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    base_url = CF_API_BASE_URL.rstrip('/')
    # Zone ID might be None for verification endpoints if we used /user/tokens/verify
    zone_segment = f"/zones/{zone_id}" if zone_id else "" 
    endpoint_segment = f"/{endpoint.lstrip('/')}" if endpoint else "" # Handle empty endpoint for zone root
    
    url = f"{base_url}{zone_segment}{endpoint_segment}"

    try:
        response = requests.request(method, url, headers=headers, params=params, json=data, timeout=20)
        response.raise_for_status() 

        try:
             response_data = response.json()
             if not response_data.get("success"):
                 print(f"错误：Cloudflare API 操作未成功 ({method} {url}).")
                 print(f"响应: {response_data}")
                 return None
             return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT', 'GET']: # GET /zones/{id} success has JSON
                print(f"信息: {method} 请求成功，状态码 {response.status_code}，无JSON响应体或非标准成功响应。")
                # For GET /zones/{id}, success requires JSON, so treat non-JSON as error here
                if method.upper() == 'GET' and endpoint == "": # Specific check for zone verification endpoint
                     print(f"错误: 获取 Zone 信息时响应非 JSON。")
                     return None
                return {"success": True} 
            else:
                print(f"警告：无法解析 Cloudflare API 响应为 JSON ({method} {url}). 状态码: {response.status_code}")
                print(f"响应体 (前500字符): {response.text[:500]}")
                return None

    except requests.exceptions.Timeout:
        print(f"错误：Cloudflare API 请求超时 ({method} {url})")
        return None
    except requests.exceptions.RequestException as e:
        print(f"错误：Cloudflare API 请求失败 ({method} {url}): {e}")
        if hasattr(e, 'response') and e.response is not None:
             print(f"响应状态码: {e.response.status_code}")
             try:
                 print(f"响应体: {e.response.text[:500]}")
             except Exception:
                 print("无法读取响应体。")
        return None

# <<< Function: Verify Credentials (Integrated) >>>
def verify_cf_credentials(zone_id, api_token):
    """验证 Cloudflare API Token 和 Zone ID 是否有效"""
    print("开始验证 Cloudflare 凭据...")
    # Use GET /zones/{zone_id} endpoint for verification
    endpoint = "" # API helper builds the full /zones/{zone_id} URL
    response_data = cf_api_request("GET", endpoint, zone_id, api_token)

    if response_data and response_data.get("success"):
        # Check if result is actually present, as success:true might be returned even on errors sometimes
        zone_info = response_data.get("result") 
        if zone_info and zone_info.get("id") == zone_id:
             zone_name = zone_info.get("name", "N/A")
             print(f"凭据验证成功！可以访问 Zone ID: {zone_id} (名称: {zone_name})")
             return True
        else:
             print(f"错误：Cloudflare API 响应成功，但未找到有效的 Zone 信息。")
             print(f"响应: {response_data}")
             return False
    else:
        print("错误：Cloudflare 凭据验证失败。请检查 CF_ZONE_ID 和 CF_API_TOKEN。")
        # The cf_api_request function already prints detailed errors
        return False

def get_cf_dns_records(zone_id, api_token, domain_name):
    """获取指定域名的所有 Cloudflare DNS 'A' 记录"""
    print(f"  - 正在查询域名 '{domain_name}' 的现有 'A' 记录 (用于清理)...")
    endpoint = "dns_records"
    # Fetch more per page as we need all to delete them
    params = {"type": "A", "name": domain_name, "per_page": 100} 
    response_data = cf_api_request("GET", endpoint, zone_id, api_token, params=params)
    if response_data and response_data.get("success"):
        records = response_data.get("result", [])
        print(f"  - 查询到 {len(records)} 条匹配的 'A' 记录。")
        return records
    else:
        print(f"  - 未能成功获取域名 {domain_name} 的 DNS 记录或未找到记录。")
        return []

def delete_cf_dns_record(zone_id, api_token, record_id):
    """删除指定的 Cloudflare DNS 记录"""
    endpoint = f"dns_records/{record_id}"
    print(f"    - 尝试删除记录 ID: {record_id}...")
    response_data = cf_api_request("DELETE", endpoint, zone_id, api_token)
    # Check success based on the helper function's return logic
    if response_data and response_data.get("success"):
        print(f"    - 成功删除记录 ID: {record_id}")
        return True
    else:
        print(f"    - 删除记录 ID: {record_id} 失败。")
        return False

def clear_cf_domain_a_records(zone_id, api_token, domain_name):
    """清除指定域名的所有 'A' 记录"""
    print(f"  - 开始清除域名 '{domain_name}' 的现有 'A' 记录...")
    existing_records = get_cf_dns_records(zone_id, api_token, domain_name)
    if not existing_records:
        print(f"  - 域名 '{domain_name}' 没有找到现有的 'A' 记录，无需清除。")
        return True

    deletion_results = []
    print(f"  - 准备删除 {len(existing_records)} 条记录...")
    for record in existing_records:
        record_id = record.get("id")
        if record_id:
            result = delete_cf_dns_record(zone_id, api_token, record_id)
            deletion_results.append(result)
            time.sleep(0.2) # Small delay between deletions
        else:
            print(f"警告：找到一条记录但缺少 ID: {record}")
            deletion_results.append(False)

    if all(deletion_results):
        print(f"  - 成功清除了 {len(deletion_results)} 条域名 '{domain_name}' 的 'A' 记录。")
        return True
    else:
        failures = deletion_results.count(False)
        print(f"警告：在清除域名 '{domain_name}' 的记录时遇到 {failures} 次失败。")
        return False

def create_cf_dns_record(zone_id, api_token, domain_name, ip_address):
    """创建一条 Cloudflare DNS 'A' 记录"""
    print(f"    - 尝试为域名 '{domain_name}' 创建指向 {ip_address} 的 'A' 记录...")
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
        print(f"    - 成功创建记录: {domain_name} -> {ip_address}")
        return True
    else:
        print(f"    - 创建记录失败: {domain_name} -> {ip_address}")
        return False

# --- 主要逻辑 ---

def process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token):
    """
    获取、筛选 IP，验证凭据，清理旧记录，并为每个选定 IP 创建新的 Cloudflare DNS 记录。
    """
    # <<< Step 1: Verify Credentials (Integrated) >>>
    if not verify_cf_credentials(cf_zone_id, cf_api_token):
        return # Stop execution if verification fails

    print(f"\n开始从 {raw_url} 获取 IP 数据...")
    ips_by_country = defaultdict(list)

    try:
        response = requests.get(raw_url, timeout=30)
        response.raise_for_status()

        print("成功获取数据，开始处理...")
        lines = response.text.splitlines()
        processed_lines = 0
        found_ips_count = 0

        ip_pattern = re.compile(IPV4_REGEX) # Compile regex

        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                ip = parts[0]
                port = parts[1]
                country_code = parts[2]

                # Filter: Port 443, Target Country, Valid IPv4
                if port == "443" and country_code in TARGET_COUNTRIES:
                    if ip_pattern.match(ip): # Use regex validation
                         ips_by_country[country_code].append(ip)
                         found_ips_count += 1
                    else:
                        print(f"警告: 跳过格式无效的 IPv4 地址 '{ip}' 在行: {line}")
            processed_lines += 1

        print(f"处理完成 {processed_lines} 行数据。找到 {found_ips_count} 个符合条件的 IP。")

        if not ips_by_country:
            print("未找到任何符合条件的 IP 地址可用于更新。")
            return

        # Process each country: Select IPs, Clear old records, Create new records
        for country_code, available_ips in ips_by_country.items():
            print(f"\n--- 处理国家: {country_code} (找到 {len(available_ips)} 个有效 IP) ---")

            domain_name = DOMAIN_MAP.get(country_code)
            if not domain_name:
                print(f"错误：未在 DOMAIN_MAP 中找到国家代码 {country_code} 的域名映射。跳过此国家。")
                continue

            if not available_ips:
                print(f"国家 {country_code} 没有可用的有效 IP 地址，跳过 DNS 更新。")
                # Optional: Clear old records even if no new IPs? Decide based on desired behavior.
                # print(f"  - 尝试清理域名 '{domain_name}' 的旧记录...")
                # clear_cf_domain_a_records(cf_zone_id, cf_api_token, domain_name)
                continue

            # <<< Step 2: Select up to NUM_IPS_PER_COUNTRY IPs >>>
            num_to_select = min(NUM_IPS_PER_COUNTRY, len(available_ips))
            selected_ips = random.sample(available_ips, num_to_select)
            print(f"为 '{domain_name}' 随机选择了 {len(selected_ips)} 个 IP: {selected_ips}")

            # <<< Step 3: Clear existing 'A' records for this domain >>>
            if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, domain_name):
                 print(f"警告: 清除域名 '{domain_name}' 的旧记录时遇到问题。将尝试创建新记录，但可能导致记录重复。")
                 # Consider stopping here if clean slate is critical:
                 # continue

            # <<< Step 4: Create new 'A' record for each selected IP >>>
            print(f"  - 开始为域名 '{domain_name}' 创建 {len(selected_ips)} 条新的 'A' 记录...")
            creation_results = []
            if selected_ips:
                for ip_addr in selected_ips:
                    result = create_cf_dns_record(cf_zone_id, cf_api_token, domain_name, ip_addr)
                    creation_results.append(result)
                    time.sleep(0.2) # Small delay between creations

                success_count = creation_results.count(True)
                failure_count = len(creation_results) - success_count
                print(f"  - 为域名 '{domain_name}' 创建记录完成: {success_count} 成功, {failure_count} 失败。")
            else:
                 print(f"  - 没有为 {country_code} 选择到 IP，不创建新记录。")

            # Optional delay between processing different countries/domains if needed
            # time.sleep(1)

    except requests.exceptions.Timeout:
        print(f"错误：获取 raw URL ({raw_url}) 超时。")
    except requests.exceptions.RequestException as e:
        print(f"错误：获取 raw URL 时出错: {e}")
    except Exception as e:
        print(f"处理数据或更新 DNS 时发生意外错误: {e}")
        import traceback
        traceback.print_exc() # Print detailed stack trace for debugging

# --- 主程序入口 ---

if __name__ == "__main__":
    # Get config from environment variables
    raw_url = os.environ.get("RAW_URL")
    cf_zone_id = os.environ.get("CF_ZONE_ID")
    cf_api_token = os.environ.get("CF_API_TOKEN")

    print("--- DNS 更新脚本 (清理并创建多条记录模式) 启动 ---")
    # Use current time based on the system where the script runs
    print(f"当前时间: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}") 


    missing_vars = []
    if not raw_url: missing_vars.append("RAW_URL")
    if not cf_zone_id: missing_vars.append("CF_ZONE_ID")
    if not cf_api_token: missing_vars.append("CF_API_TOKEN")

    if missing_vars:
        print(f"错误：以下环境变量未设置: {', '.join(missing_vars)}")
    else:
        print("所有必需的环境变量已找到。")
        print(f"源 URL: {raw_url}")
        print(f"Cloudflare Zone ID: {cf_zone_id}")
        print(f"目标域名映射: {DOMAIN_MAP}")
        print(f"每个域名将清理旧记录并创建最多 {NUM_IPS_PER_COUNTRY} 条新记录。")
        
        # Execute main logic
        process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token)

    print("--- DNS 更新脚本结束 ---")
