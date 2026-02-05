import os
import csv
import datetime
import time
from tqdm import tqdm  # ใช้ตัวนี้ตัวเดียวพอครับ
from src.core.detectors import PII_Detector
from src.core.anonymizer import PII_Anonymizer

# --- ตั้งค่า ---
INPUT_FILE = "dataset.tsv"       
OUTPUT_DIR = "tests"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "batch_test_results.tsv")
LIMIT_ROWS = 1000             

def setup_output():
    """เตรียมไฟล์ Output พร้อมเขียน Header"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(["Timestamp", "File_ID", "Original_Text", "Sanitized_Text", "Detected_Items"])

def process_line(line):
    """แยก FileID กับ Text"""
    parts = line.strip().split(maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    elif len(parts) == 1:
        return "Unknown", parts[0]
    else:
        return None, None

def main():
    print("="*60)
    print("🧪 PII Guardrails - Batch Testing System")
    print(f"📂 Reading from: {INPUT_FILE}")
    print(f"💾 Saving to:   {OUTPUT_FILE}")
    print("="*60 + "\n")

    # 1. โหลดโมเดล
    detector = PII_Detector()
    anonymizer = PII_Anonymizer()
    
    # 2. เตรียมไฟล์
    if not os.path.exists(INPUT_FILE):
        print(f"❌ ไม่พบไฟล์ {INPUT_FILE}")
        return
    
    setup_output()
    
    # 3. อ่านข้อมูล
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    if LIMIT_ROWS:
        lines = lines[:LIMIT_ROWS]
        print(f"⚠️ Limit set to: {LIMIT_ROWS} rows")

    total_pii_found = 0
    start_time = time.time()

    # 4. เริ่มรัน Loop
    print("\n🚀 Start Processing...")
    # เรียกใช้ tqdm ตรงๆ โดยไม่มีการ import ซ้ำซ้อน
    for line in tqdm(lines, desc="Processing", unit="row"):
        file_id, text = process_line(line)
        
        if not text: continue

        # --- Core Logic ---
        try:
            findings = detector.detect(text)
            sanitized_text = anonymizer.anonymize(text, findings)
            
            if findings:
                total_pii_found += 1

            # บันทึกผล
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            detected_str = ", ".join([f"{item['type']}:{item['value']}" for item in findings])
            
            with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([timestamp, file_id, text, sanitized_text, detected_str])
        
        except Exception as e:
            print(f"\n❌ Error row {file_id}: {e}")
            continue

    end_time = time.time()
    duration = end_time - start_time

    print("\n" + "="*60)
    print("✅ Testing Completed!")
    print(f"⏱️  Time taken: {duration:.2f} seconds")
    print(f"📊 Processed:  {len(lines)} rows")
    print(f"🔍 PII Found in: {total_pii_found} rows")
    print(f"📁 Check results at: {OUTPUT_FILE}")
    print("="*60)

if __name__ == "__main__":
    main()