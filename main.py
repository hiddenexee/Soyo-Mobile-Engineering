import json
import random
import secrets
import time
import uuid
import hashlib
import requests
#SM-M366BZOD-35

def create_device():
    return {
        'Host': 'api.souluapp.com',
        'Country': 'TR',
        'Language': 'tr',
        'Mcc': '-1',
        'Appversionname': '1.9.4',
        'Appversioncode': '10135',
        'Apilevel': '25',
        'Packagename': 'com.haflla.soulu',
        'Packagechannel': 'soulu_palmstore',
        'Curpackagechannel': 'soulu_palmstore',
        'Appplatform': '1',
        'Authorization': '',
        'Deviceid': f'{uuid.uuid4()}',
        'Androidid': secrets.token_hex(8),
        'Brand': 'samsung',
        'Model': 'SM-G610F',
        'Sdkint': '25',
        'Nettype': 'WIFI',
        'Systemcountry': 'TR',
        'Systemlanguage': 'tr',
        'Referrersdk': 'adjust',
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': 'okhttp/3.14.9'
    }

def login(email: str, password: str):
    headers = create_device()

    response = requests.post(
        'https://api.souluapp.com/api/user/snackUser/login',
        headers=headers,
        json={
            'email': email,
            'password': hashlib.md5(password.encode()).hexdigest()
        }
    ).json()

    if response["code"] == 1:
        print("Giriş yapıldı")
        auth = response["body"]["token"]
        headers["Authorization"] = auth

        with open("session.json", "w", encoding="utf-8") as file:
            json.dump(headers, file, ensure_ascii=False, indent=4)

        return headers
    else:
        print(f"Giriş yapılamadı: {response}")
        return None

def user_list(headers: dict, limit: int = 100):
    user_ids = set()

    while len(user_ids) < limit:
        response = requests.get(
            'https://api.souluapp.com/api/content/recommendStream/list',
            params={'type': 'recommend'},
            headers=headers
        ).json()

        for i in response.get("body", []):
            user_ids.add(i["userId"])

        print(f"Toplanan kullanıcı sayısı: {len(user_ids)}")
        time.sleep(2)

    with open("user_ids.txt", "a+") as f:
        for uid in user_ids:
            f.write(f"{uid}\n")

    return list(user_ids)

def hi(headers: dict):
    users = user_list(headers)
    print(f"{len(users)} adet kullanıcı toplandı. Hi gönderiliyor...")
    for userid in users:
        try:
            response = requests.post(
                'https://api.souluapp.com/api/user/accost/sends',
                headers=headers,
                json={
                    'listOrder': '1',
                    'refer': 'home_recommend',
                    'toUserIdList': [
                        userid
                    ]
                }
            ).json()
            if response["code"] == 1:
                print(f"[{userid}] Hi, gönderildi")
            elif response["code"] == 120081:
                print("100 Kişi limiti doldu!")
                break
            else:
                print(f"Hata oluştu: {response}")
            time.sleep(random.uniform(0.3, 1))
        except Exception as e:
            print(f"hi error: {e}")

def start() -> None:
    headers = login("user", "pass")
    if headers is not None:
        hi(headers)

if __name__ == '__main__':
    start()
