# ⚠️ 故意有漏洞:展示 SAST 對 Python 的偵測,請勿用於正式環境。
import os
import sqlite3


def export(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # 漏洞:f-string 內插組 SQL
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchall()


def convert(filename):
    # 漏洞:os.system 帶入使用者輸入 → 命令注入
    os.system("libreoffice --convert-to pdf " + filename)
