import requests
import json
import os
import sys # 引入 sys 模組以便在發生嚴重錯誤時退出

# --- 配置 ---
# 要提取的國家/地區代碼列表
TARGET_COUNTRIES = ["PL", "AE", "CA", "TW", "DE", "RU", "JP", "KR", "SG"]

# 要附加到每個 IP:端口 之後的後綴
SUFFIX = "#Nautica"

# --- 主腳本 ---

def fetch_and_write_ips(url, countries, suffix):
    """
    從指定的 URL 獲取 JSON 數據，提取指定國家的 IP 地址，
    在每個 IP 後附加後綴，並將結果寫入對應的 .txt 文件。

    Args:
        url (str): 要獲取數據的遠程 JSON 文件的 URL。
        countries (list): 要處理的國家/地區代碼列表。
        suffix (str): 要附加到每個 IP 地址後面的字符串。
    """
    if not url:
        print("錯誤：傳入的 URL 為空或無效。")
        return False # 返回失敗狀態

    print(f"正在從以下 URL 獲取數據: {url}")
    try:
        # 發送 GET 請求獲取文件內容，設定超時時間
        response = requests.get(url, timeout=15)
        # 檢查請求是否成功 (狀態碼 200 OK)
        response.raise_for_status()
        print("成功獲取數據。")

    except requests.exceptions.Timeout:
        print(f"錯誤：請求超時 ({url})")
        return False
    except requests.exceptions.ConnectionError:
        print(f"錯誤：無法連接到伺服器 ({url})")
        return False
    except requests.exceptions.HTTPError as e:
        # 顯示更詳細的 HTTP 錯誤信息
        print(f"錯誤：HTTP 錯誤 - {e.response.status_code} {e.response.reason} ({url})")
        # 可以選擇打印響應體以獲取更多錯誤細節
        # print(f"響應內容: {e.response.text}")
        return False
    except requests.exceptions.RequestException as e:
        # 捕捉其他 requests 可能的錯誤
        print(f"錯誤：獲取 URL 時發生問題: {e}")
        return False

    try:
        # 解析 JSON 數據
        data = response.json()
        print("成功解析 JSON 數據。")
    except json.JSONDecodeError as e:
        print(f"錯誤：解析 JSON 數據失敗: {e}")
        print("------ 收到的部分文本內容 ------")
        print(response.text[:500] + "...") # 顯示部分原始文本以助除錯
        print("------------------------------")
        return False
    except Exception as e:
        print(f"解析 JSON 時發生未預期的錯誤: {e}")
        return False

    # 處理每個目標國家/地區
    print("-" * 30) # 分隔線
    all_successful = True # 追蹤是否有任何寫入失敗
    for country_code in countries:
        print(f"處理國家/地區: {country_code}")
        if country_code in data:
            ip_list = data[country_code]
            # 確保獲取到的是一個列表
            if isinstance(ip_list, list):
                filename = f"{country_code}.txt"
                try:
                    # 使用 'w' 模式打開文件 (自動創建或覆蓋)
                    with open(filename, 'w', encoding='utf-8') as f:
                        for ip_port in ip_list:
                            # 確保 ip_port 是字符串類型，以防 JSON 中有非字符串值
                            if isinstance(ip_port, str):
                                # 在寫入時附加後綴
                                f.write(f"{ip_port}{suffix}\n")
                            else:
                                print(f"!! 警告：在 '{country_code}' 列表中找到非字符串項目，已跳過: {ip_port}")
                    print(f"-> 成功將處理後的 IP 地址寫入到 {filename}")
                except IOError as e:
                    print(f"!! 錯誤：無法寫入文件 {filename}: {e}")
                    all_successful = False # 標記為失敗
                except Exception as e:
                    # 捕捉寫入文件時其他可能的錯誤
                    print(f"!! 寫入 {filename} 時發生未預期的錯誤: {e}")
                    all_successful = False # 標記為失敗
            else:
                print(f"!! 警告：國家/地區 '{country_code}' 對應的值不是一個列表，已跳過。找到的類型: {type(ip_list)}")
        else:
            print(f"!! 警告：在 JSON 數據中未找到國家/地區代碼 '{country_code}'。")
        print("-" * 10) # 每個國家之間的小分隔

    print("-" * 30)
    return all_successful # 返回整體處理是否成功

# --- 主執行區 ---
if __name__ == "__main__":
    print("開始執行 IP 地址提取腳本...")

    # 從環境變數讀取 GitHub Raw URL
    # 在 GitHub Actions 中，你需要設定一個名為 'REMOTE_JSON_URL' 的 Secret 或 Variable
    github_raw_url = os.environ.get('REMOTE_JSON_URL')

    if not github_raw_url:
        print("關鍵錯誤：環境變數 'REMOTE_JSON_URL' 未設定或為空。")
        print("請在 GitHub Actions 的 Secrets 或 Variables 中設定此變數，其值應為 JSON 文件的 Raw URL。")
        sys.exit(1) # 退出腳本，返回非零狀態碼表示錯誤

    # 調用主函數處理數據
    success = fetch_and_write_ips(github_raw_url, TARGET_COUNTRIES, SUFFIX)

    if success:
        print("腳本執行完畢，所有找到的國家/地區數據已成功處理。")
        sys.exit(0) # 正常退出
    else:
        print("腳本執行期間遇到錯誤，部分文件可能未成功寫入。")
        sys.exit(1) # 退出並表示有錯誤發生
