import requests
from bs4 import BeautifulSoup

# 获取网页内容
url = "https://ip.164746.xyz/"
response = requests.get(url)

# 检查是否成功获取网页
if response.status_code == 200:
    soup = BeautifulSoup(response.text, "html.parser")

    # 提取表格中的第一列 IP 地址
    table = soup.find("table")  # 找到第一个表格
    if table:
        rows = table.find_all("tr")[1:]  # 跳过表头
        ips = []
        for row in rows:
            cell = row.find("td")
            if cell:
                ip = cell.get_text(strip=True)
                ip = ip.replace("★", "").strip()  # 去除特殊符号和多余空格
                ips.append(ip)

        # 打印提取的 IP 地址（供调试用）
        print("提取到的 IP 地址：", ips)

        # 写入到 ip.txt 文件
        try:
            with open("ip.txt", "w", encoding="utf-8") as f:
                for ip in ips:
                    f.write(f"{ip}:443#WZYX\n")
            print("IP 地址成功写入到 ip.txt 文件！")
        except Exception as e:
            print(f"写入 ip.txt 文件时出现错误：{e}")
    else:
        print("未找到表格")
else:
    print(f"无法访问网页，状态码: {response.status_code}")
