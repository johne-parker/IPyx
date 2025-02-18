import requests
from bs4 import BeautifulSoup
import os
import subprocess

def check_git_changes():
    """检查 Git 是否有更改"""
    try:
        result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, check=True)
        return bool(result.stdout.strip())  # 如果有输出，则表示有更改
    except subprocess.CalledProcessError as e:
        print(f"检查 Git 状态时出错：{e}")
        return False

def commit_changes():
    """提交更改"""
    try:
        subprocess.run(['git', 'add', 'ip.txt'], check=True)
        subprocess.run(['git', 'commit', '-m', '更新 ip.txt'], check=True)
        print("IP 地址已成功提交！")
    except subprocess.CalledProcessError as e:
        print(f"提交更改时出错：{e}")

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

            if check_git_changes():  # 检查是否有更改
                commit_changes()  # 提交更改
            else:
                print("ip.txt 文件没有变化，无需提交。")

        except Exception as e:
            print(f"写入 ip.txt 文件时出现错误：{e}")
    else:
        print("未找到表格")
else:
    print(f"无法访问网页，状态码: {response.status_code}")
