import requests
from bs4 import BeautifulSoup

# 指定网页 URL
url = "https://ip.164746.xyz/"

def fetch_ips(url):
    try:
        # 获取网页内容
        response = requests.get(url)
        response.raise_for_status()
        
        # 解析 HTML
        soup = BeautifulSoup(response.text, "html.parser")
        
        # 找到表格中第一列的 IP 地址
        ip_list = []
        table = soup.find("table")  # 假设网页只有一个表格
        if table:
            rows = table.find_all("tr")[1:]  # 跳过表头
            for row in rows:
                ip_column = row.find_all("td")[0]  # 第一列
                if ip_column:
                    ip = ip_column.text.strip().replace("★", "")  # 去除特殊字符
                    ip_list.append(ip)
        return ip_list
    except Exception as e:
        print(f"Error occurred: {e}")
        return []

# 提取 IP 并写入文件
def write_ips_to_file(ip_list, filename="ip.txt"):
    try:
        with open(filename, "w") as f:
            for ip in ip_list:
                f.write(ip + "\n")
        print(f"Successfully wrote {len(ip_list)} IPs to {filename}")
    except Exception as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    ips = fetch_ips(url)
    if ips:
        write_ips_to_file(ips)
    else:
        print("No IP addresses found.")
