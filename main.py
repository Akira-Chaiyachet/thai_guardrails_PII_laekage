# main.py
from src.core.detectors import PII_Detector

def test_system():
    detector = PII_Detector()
    input_text = "สวัสดีครับ ผมชื่อสมชาย มีเงิน 1479300026261 บาท เบอร์โทร 0812345678 ส่วนอันนี้เลขมั่ว 1234567890123"
    
    print(f"ข้อความเข้า: {input_text}\n")
    print("--- ผลการตรวจสอบ ---")
    
    results = detector.detect(input_text)
    
    for item in results:
        print(f"เจอ: {item['type']}")
        print(f"ค่า: {item['value']}")
        print(f"ตำแหน่ง: {item['start']}-{item['end']}")
        print("-" * 20)

if __name__ == "__main__":
    test_system()