import requests

def get_proxy_ips(raw_url, output_file):
    """
    从 raw URL 获取代理 IP，并按照指定格式写入文件。

    Args:
        raw_url (str): 包含代理 IP 信息的 raw URL。
        output_file (str): 输出文件名。
    """
    try:
        response = requests.get(raw_url)
        response.raise_for_status()  # 检查请求是否成功

        proxy_ips = []
        for line in response.text.splitlines():
            parts = line.split(",")
            if len(parts) >= 4 and parts[2] == "PL":
                proxy_ips.append(f"{parts[0]}:{parts[1]}")

        with open(output_file, "w") as f:
            for ip in proxy_ips:
                f.write(ip + "\n")

        print(f"成功获取 {len(proxy_ips)} 个代理 IP，并写入 {output_file}")

    except requests.exceptions.RequestException as e:
        print(f"获取 raw URL 时出错: {e}")
    except Exception as e:
        print(f"处理数据时出错: {e}")

if __name__ == "__main__":
    raw_url = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt"  # 替换为您的 raw URL
    output_file = "proxyip.txt"
    get_proxy_ips(raw_url, output_file)
