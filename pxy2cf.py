import requests
import os
import random
import json # <<< Import json library
from collections import defaultdict
import time
import re

# --- 配置 (部分移至环境变量) ---
# Cloudflare API 的基础 URL
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
# 国家代码到域名的映射 - <<< REMOVED FROM HERE, will be loaded from env var >>>
# TARGET_COUNTRIES is still useful if DOMAIN_MAP_JSON contains more than needed
TARGET_COUNTRIES = ["PL", "AE", "CA"]
# 每个国家随机选择的端口为443的IP数量上限
NUM_IPS_PER_COUNTRY = 5
# IPv4 Regex for validation
IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
# Cloudflare Proxied status
PROXY_STATUS = False
# DNS Record TTL
RECORD_TTL = 60

# --- Cloudflare API 函数 ---
# (verify_cf_credentials, cf_api_request, get_cf_dns_records,
#  delete_cf_dns_record, clear_cf_domain_a_records, create_cf_dns_record 函数保持不变)
# --- （为简洁起见，省略了这些函数的代码，它们和上一个版本完全相同） ---
def cf_api_request(method, endpoint, zone_id, api_token, params=None, data=None):
    """统一处理 Cloudflare API 请求"""
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
                 print(f"错误：Cloudflare API 操作未成功 ({method} {url}).")
                 print(f"响应: {response_data}")
                 return None
             return response_data
        except json.JSONDecodeError:
            if response.status_code == 200 and method.upper() in ['DELETE', 'PUT', 'GET']:
                if method.upper() == 'GET' and endpoint == "":
                     print(f"错误: 获取 Zone 信息时响应非 JSON。")
                     return None
                # For successful DELETE/PUT without JSON body
                print(f"信息: {method} 请求成功，状态码 {response.status_code}，无JSON响应体或非标准成功响应。")
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

def verify_cf_credentials(zone_id, api_token):
    """验证 Cloudflare API Token 和 Zone ID 是否有效"""
    print("开始验证 Cloudflare 凭据...")
    endpoint = "" 
    response_data = cf_api_request("GET", endpoint, zone_id, api_token)
    if response_data and response_data.get("success"):
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
        return False

def get_cf_dns_records(zone_id, api_token, domain_name):
    """获取指定域名的所有 Cloudflare DNS 'A' 记录"""
    print(f"  - 正在查询域名 '{domain_name}' 的现有 'A' 记录 (用于清理)...")
    endpoint = "dns_records"
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
            time.sleep(0.2) 
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
# <<< Modified function signature to accept domain_map >>>
def process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, domain_map):
    """
    获取、筛选 IP，验证凭据，清理旧记录，并为每个选定 IP 创建新的 Cloudflare DNS 记录。
    使用从环境变量加载的 domain_map。
    """
    if not verify_cf_credentials(cf_zone_id, cf_api_token):
        return 

    print(f"\n开始从 {raw_url} 获取 IP 数据...")
    ips_by_country = defaultdict(list)

    try:
        response = requests.get(raw_url, timeout=30)
        response.raise_for_status()

        print("成功获取数据，开始处理...")
        lines = response.text.splitlines()
        processed_lines = 0
        found_ips_count = 0
        ip_pattern = re.compile(IPV4_REGEX)

        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                ip = parts[0]
                port = parts[1]
                country_code = parts[2]
                
                # Filter based on TARGET_COUNTRIES and check if country is in domain_map
                if port == "443" and country_code in TARGET_COUNTRIES and country_code in domain_map:
                    if ip_pattern.match(ip):
                         ips_by_country[country_code].append(ip)
                         found_ips_count += 1
                    else:
                        print(f"警告: 跳过格式无效的 IPv4 地址 '{ip}' 在行: {line}")
            processed_lines += 1

        print(f"处理完成 {processed_lines} 行数据。找到 {found_ips_count} 个符合条件的 IP。")

        if not ips_by_country:
            print("未找到任何符合条件的 IP 地址可用于更新。")
            return

        for country_code, available_ips in ips_by_country.items():
            print(f"\n--- 处理国家: {country_code} (找到 {len(available_ips)} 个有效 IP) ---")

            # <<< Use domain_map argument here >>>
            domain_name = domain_map.get(country_code) 
            # Redundant check as we filtered earlier, but safe
            if not domain_name: 
                print(f"错误：未能从加载的 domain_map 中找到国家代码 {country_code} 的域名。跳过。")
                continue

            if not available_ips:
                print(f"国家 {country_code} 没有可用的有效 IP 地址，跳过 DNS 更新。")
                continue

            num_to_select = min(NUM_IPS_PER_COUNTRY, len(available_ips))
            selected_ips = random.sample(available_ips, num_to_select)
            print(f"为 '{domain_name}' 随机选择了 {len(selected_ips)} 个 IP: {selected_ips}")

            if not clear_cf_domain_a_records(cf_zone_id, cf_api_token, domain_name):
                 print(f"警告: 清除域名 '{domain_name}' 的旧记录时遇到问题。将尝试创建新记录，但可能导致记录重复。")

            print(f"  - 开始为域名 '{domain_name}' 创建 {len(selected_ips)} 条新的 'A' 记录...")
            creation_results = []
            if selected_ips:
                for ip_addr in selected_ips:
                    result = create_cf_dns_record(cf_zone_id, cf_api_token, domain_name, ip_addr)
                    creation_results.append(result)
                    time.sleep(0.2)

                success_count = creation_results.count(True)
                failure_count = len(creation_results) - success_count
                print(f"  - 为域名 '{domain_name}' 创建记录完成: {success_count} 成功, {failure_count} 失败。")
            else:
                 print(f"  - 没有为 {country_code} 选择到 IP，不创建新记录。")

    except requests.exceptions.Timeout:
        print(f"错误：获取 raw URL ({raw_url}) 超时。")
    except requests.exceptions.RequestException as e:
        print(f"错误：获取 raw URL 时出错: {e}")
    except Exception as e:
        print(f"处理数据或更新 DNS 时发生意外错误: {e}")
        import traceback
        traceback.print_exc()

# --- 主程序入口 ---

if __name__ == "__main__":
    # Get config from environment variables
    raw_url = os.environ.get("RAW_URL")
    cf_zone_id = os.environ.get("CF_ZONE_ID")
    cf_api_token = os.environ.get("CF_API_TOKEN")
    # <<< Get DOMAIN_MAP from environment variable >>>
    domain_map_json_str = os.environ.get("DOMAIN_MAP_JSON")

    print("--- DNS 更新脚本 (清理并创建多条记录模式 - DOMAIN_MAP from Secret) 启动 ---")
    print(f"当前时间: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    # Check required environment variables
    missing_vars = []
    if not raw_url: missing_vars.append("RAW_URL")
    if not cf_zone_id: missing_vars.append("CF_ZONE_ID")
    if not cf_api_token: missing_vars.append("CF_API_TOKEN")
    if not domain_map_json_str: missing_vars.append("DOMAIN_MAP_JSON") # <<< Check new variable

    if missing_vars:
        print(f"错误：以下环境变量未设置: {', '.join(missing_vars)}")
    else:
        # <<< Parse DOMAIN_MAP_JSON >>>
        try:
            loaded_domain_map = json.loads(domain_map_json_str)
            if not isinstance(loaded_domain_map, dict):
                 raise ValueError("DOMAIN_MAP_JSON 解析结果不是一个字典。")
            print("成功从环境变量加载并解析 DOMAIN_MAP_JSON。")
            print(f"加载的域名映射: {loaded_domain_map}") # Print loaded map for confirmation

            # Execute main logic, passing the loaded map
            process_ips_and_update_dns(raw_url, cf_zone_id, cf_api_token, loaded_domain_map)

        except json.JSONDecodeError as e:
            print(f"错误：无法将 DOMAIN_MAP_JSON 解析为有效的 JSON: {e}")
            print(f"请检查 GitHub Secret 'DOMAIN_MAP_JSON' 的值是否为有效的 JSON 字符串，例如：")
            print('{"PL": "pl.yourdomain.com", "AE": "ae.yourdomain.com", ...}')
        except ValueError as e:
             print(f"错误: {e}")


    print("--- DNS 更新脚本结束 ---")
