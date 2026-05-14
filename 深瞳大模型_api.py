# -*- coding: utf-8 -*-
import requests
import json
import sys

# ================= 配置区域 =================
BASE_URL = "http://10.250.186.247:20201"
APP_KEY = "9FZT8-SC002-PV6P1-UTK2Z-0106"
SECRET = "multibot@@zhiwei"
# ===========================================

def get_authorization_token():
    """获取 Token - 兼容 Python 2/3 的格式化方式"""
    token_url = BASE_URL + "/ds/api/v1/external/appKey/getToken"
    params = {
        "appkey": APP_KEY,
        "secret": SECRET
    }
    try:
        # 显式设置超时，防止脚本挂死
        response = requests.get(token_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and data.get("data"):
            return data["data"]
    except Exception:
        pass
    return None

def get_chat_response(query_text):
    """请求接口并合并流式内容"""
    token = get_authorization_token()
    if not token:
        return "Error: Token acquisition failed."

    chat_url = BASE_URL + "/ds/api/v1/external/bot/api/chatPreview"
    headers = {
        "Authorization": token,
        "user_id": "dwliubo",
        "tenant_id": "zyxx",
        "Content-Type": "application/json"
    }
    
    payload = {
        "uuid": "2780eb6218c34915bc8b8ec4535a716b",
        "query": [{"role": "user", "content": query_text}],
        "clientId": "2as9fsas9f-9edb-45b9-ab70-38028a36fdfe",
        "dialogId": "ks9d3565-9d05-4c4c-93f6-99ebec96339f",
        "channelId": "DS"
    }

    full_text = ""
    try:
        # 使用流式请求
        r = requests.post(chat_url, headers=headers, data=json.dumps(payload), stream=True, timeout=60)
        for line in r.iter_lines():
            if not line:
                continue
            
            line_str = line.decode('utf-8').strip()
            if line_str.startswith("data:"):
                content_json = line_str[5:].strip()
                
                if content_json == "[DONE]":
                    break
                
                try:
                    data_obj = json.loads(content_json)
                    msg = data_obj.get("content", "")
                    if msg:
                        full_text += msg
                except:
                    continue
        return full_text.strip()
    except Exception as e:
        return "Error: " + str(e)

if __name__ == "__main__":
    # 获取动态输入
    if len(sys.argv) > 1:
        # 将命令行参数合并为一个字符串
        user_input = " ".join(sys.argv[1:])
    else:
        user_input = "你好"

    result = get_chat_response(user_input)
    print(result)