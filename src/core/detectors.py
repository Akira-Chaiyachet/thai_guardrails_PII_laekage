# src/core/detectors.py
import re
from typing import List, Dict
from src.core.utils import verify_thai_id

class PII_Detector:
    def __init__(self):
        # 1. อัปเกรด Regex เบอร์โทร: รองรับ +66, 66 หรือ 0 นำหน้า
        self.phone_pattern = re.compile(r'(\+66|66|0)[689]\d{8}')
        
        self.id_card_pattern = re.compile(r'\d{13}')

        # คำที่บ่งบอกว่า "ไม่ใช่" บัตรประชาชน (False Positive Indicators)
        # ถ้าเจอคำพวกนี้อยู่ "หลัง" ตัวเลข -> สันนิษฐานว่าเป็นเงิน
        self.ignore_after = ["บาท", "สตางค์", "point", "แต้ม", "คะแนน"]
        
        # ถ้าเจอคำพวกนี้อยู่ "หน้า" ตัวเลข -> สันนิษฐานว่าเป็นราคาหรือรหัสอื่น
        self.ignore_before = ["ราคา", "ยอด", "ชำระ", "รวม", "หมายเลขตั๋ว", "รหัสจอง"]

    def _check_context(self, text: str, start: int, end: int) -> bool:
        """
        ตรวจสอบบริบทแวดล้อม: คืนค่า True ถ้าคิดว่าเป็น False Positive (ไม่ควรจับ)
        """
        window_size = 15 # มองไปข้างหน้าและข้างหลัง 15 ตัวอักษร
        
        # 1. มองไปข้างหลัง (Look Ahead)
        post_text = text[end : min(len(text), end + window_size)]
        for keyword in self.ignore_after:
            if keyword in post_text:
                return True # เจอคำว่า "บาท" -> ตัดทิ้งเลย
                
        # 2. มองไปข้างหน้า (Look Behind)
        pre_text = text[max(0, start - window_size) : start]
        for keyword in self.ignore_before:
            if keyword in pre_text:
                return True # เจอคำว่า "ราคา" -> ตัดทิ้งเลย
                
        return False

    def detect(self, text: str) -> List[Dict]:
        findings = []

        # --- ตรวจจับเบอร์โทรศัพท์ ---
        for match in self.phone_pattern.finditer(text):
            findings.append({
                "type": "PHONE_NUMBER",
                "value": match.group(),
                "start": match.start(),
                "end": match.end(),
                "score": 1.0
            })

        # --- ตรวจจับเลขบัตรประชาชน ---
        for match in self.id_card_pattern.finditer(text):
            candidate = match.group()
            
            # Step A: ตรวจสอบสูตรคณิตศาสตร์ (Check Digit)
            if not verify_thai_id(candidate):
                continue # สูตรผิด -> ไม่ใช่บัตรแน่ๆ

            # Step B: ตรวจสอบบริบท (Context Check) - *Logic ใหม่*
            if self._check_context(text, match.start(), match.end()):
                continue # บริบทบอกว่าเป็นเงิน/ราคา -> ข้ามไป ไม่จับ

            findings.append({
                "type": "THAI_ID",
                "value": candidate,
                "start": match.start(),
                "end": match.end(),
                "score": 1.0
            })
        
        return sorted(findings, key=lambda x: x['start'])