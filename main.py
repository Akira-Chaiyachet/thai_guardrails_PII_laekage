# main.py
import os
import csv
import datetime
from src.core.detectors import PII_Detector
from src.core.anonymizer import PII_Anonymizer

LOG_DIR = "tests"
LOG_FILE = os.path.join(LOG_DIR, "pii_detection_log.tsv")
TOKEN_LOG_FILE = os.path.join(LOG_DIR, "token_debug_log.tsv")


def setup_logger():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8", newline="") as f:
            csv.writer(f, delimiter="\t").writerow(
                ["Timestamp", "Original_Text", "Sanitized_Text", "Detected_Items"]
            )

    if not os.path.exists(TOKEN_LOG_FILE):
        with open(TOKEN_LOG_FILE, "w", encoding="utf-8", newline="") as f:
            csv.writer(f, delimiter="\t").writerow(
                ["Timestamp", "Original_Text", "Raw_Tokens"]
            )


def log_token_debug(original, detector):
    """ฟังก์ชันแอบดู Token (ฉบับรองรับ Hugging Face Pipeline)"""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ดึง Tokenizer จาก Pipeline โดยตรง
        tokenizer = detector.nlp_pipeline.tokenizer

        # สั่งตัดคำ (Tokenize)
        tokens = tokenizer.tokenize(original)

        # แปลงเป็น String
        token_str = " | ".join(tokens)

        print(f"\n✂️  [Token Check]: {token_str}")  # โชว์หน้าจอด้วย

        with open(TOKEN_LOG_FILE, "a", encoding="utf-8", newline="") as f:
            csv.writer(f, delimiter="\t").writerow([timestamp, original, token_str])

    except Exception as e:
        print(f"⚠️ บันทึก Token Log ไม่สำเร็จ: {e}")


def log_result(original, sanitized, findings):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detected_str = ", ".join([f"{item['type']}:{item['value']}" for item in findings])
    with open(LOG_FILE, "a", encoding="utf-8", newline="") as f:
        csv.writer(f, delimiter="\t").writerow(
            [timestamp, original, sanitized, detected_str]
        )


def main():
    print("⏳ กำลังเตรียมระบบ PII Guardrails (WangchanBERTa LST20 Mode)...")
    detector = PII_Detector()
    anonymizer = PII_Anonymizer()
    setup_logger()

    print("\n" + "=" * 50)
    print("🚀 PII Guardrails System พร้อมใช้งาน!")
    print(f"📝 Main Log: {LOG_FILE}")
    print(f"🐛 Token Log: {TOKEN_LOG_FILE}")
    print("=" * 50 + "\n")

    while True:
        try:
            user_input = input(">> กรอกข้อความ: ").strip()
            if user_input.lower() in ["exit", "quit", "ออก"]:
                break
            if not user_input:
                continue

            # 1. ดูการตัดคำ (Tokenize)
            log_token_debug(user_input, detector)

            # 2. ตรวจจับ
            findings = detector.detect(user_input)

            # 3. ปิดบังข้อมูล
            sanitized_text = anonymizer.anonymize(user_input, findings)

            print(f"\n✅ ผลลัพธ์: {sanitized_text}")
            if findings:
                for item in findings:
                    print(f"   - [{item['type']}] {item['value']}")
            else:
                print("   (ไม่พบ PII)")

            log_result(user_input, sanitized_text, findings)
            print("-" * 30)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
