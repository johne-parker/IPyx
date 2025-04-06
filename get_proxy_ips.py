import requests
import json

def get_proxy_ips(url):
    """从远程 URL 读取数据，提取符合条件的数据，并转换为 JSON 格式。"""
    try:
        response = requests.get(url)
        response.raise_for_status()  # 检查 HTTP 错误
        data = response.text.splitlines()

        pl_ips = []
        for line in data:
            parts = line.split(",")
            if len(parts) >= 4 and "PL" in parts[3]:
                pl_ips.append(f"{parts[0]}:{parts[1]}")

        return json.dumps(pl_ips)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None

if __name__ == "__main__":
    url = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt"  # 替换为您的远程 URL
    json_data = get_proxy_ips(url)

    if json_data:
        with open("proxyip.json", "w") as f:
            f.write(json_data)
        print("proxyip.json generated successfully.")
    else:
        print("Failed to generate proxyip.json.")
