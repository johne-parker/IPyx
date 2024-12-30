import requests
from bs4 import BeautifulSoup

# 指定网页 URL
url = "https://ip.164746.xyz/"

def fetch_ips(url):
    try:
        # 获取网页内容
        response = requests.get(url)
        if response.status_code == 200:
    soup = BeautifulSoup(response.text, "html.parser")

    # 提取表格中的第一列 IP 地址
    table = soup.find("table")  # 找到第一个表格
    if table:
        rows = table.find_all("tr")[1:]  # 跳过表头
        ips = [row.find("td").get_text(strip=True) for row in rows if row.find("td")]

        # 打印提取的 IP 地址
        print("提取到的 IP 地址：", ips)

        # 写入到 ip.txt 文件
        with open("ip.txt", "w") as f:
            for ip in ips:
                f.write(ip + "\n")
    else:
        print("未找到表格")
else:
    print(f"无法访问网页，状态码: {response.status_code}")

if __name__ == "__main__":
    ips = fetch_ips(url)
    if ips:
        write_ips_to_file(ips)
    else:
        print("No IP addresses found.")
