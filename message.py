import time
import frida
import asyncio

'''
from aichat import SimpleOllamaBot

bot = SimpleOllamaBot()

def chat(message: str):
    result = bot.message(message)
    return result
'''

TARGET_APP = "com.haflla.soulu"
JS_SCRIPT = "soyou.js"

def on_message(message, data):
    if message["type"] == "send":
        print("[JS SEND]", message["payload"])
    elif message["type"] == "error":
        print("[JS ERROR]", message["stack"])
    else:
        print(message)

async def main():
    device = frida.get_usb_device(timeout=5)
    pid = device.spawn([TARGET_APP])
    session = device.attach(pid)

    with open(JS_SCRIPT, "r", encoding="utf-8") as f:
        script = session.create_script(f.read())

    script.on("message", on_message)
    script.load()
    device.resume(pid)

    time.sleep(10)

    with open("user_ids.txt", "r", encoding="utf-8") as f:
        user_ids = [line.strip() for line in f if line.strip()]

    while True:
        for uid in user_ids:
            print(f"\n=== Kullanıcı {uid} için mesaj kontrolü ===")
            try:
                result = script.exports_sync.getc2cmessages(uid, 5)
                if len(result) > 0:
                    last_msg = result[0]
                    if not last_msg["self"]:
                        print("[NEW MESSAGE]", last_msg["text"])
                        ai_message = "test ai chat" #chat(last_msg["text"])
                        #print(ai_message)
                        script.exports_sync.sendtextmessage(uid, ai_message)
            except Exception as e:
                print("[PYTHON ERROR]", e)
            time.sleep(0.5)

if __name__ == "__main__":
    asyncio.run(main())

