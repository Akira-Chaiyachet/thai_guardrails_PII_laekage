# src/core/detectors.py
import re
from typing import List, Dict
from src.core.utils import verify_thai_id

class PII_Detector:
    def __init__(self):
        # Regex สำหรับเบอร์มือถือไทย: ขึ้นต้นด้วย 06, 08, 09 ตามด้วยเลข 8 หลัก
        self.phone_pattern = re.compile(r'0[689]\d{8}')
        
        # Regex สำหรับเลขบัตรประชาชน: เลข 13 หลักติดกัน
        self.id_card_pattern = re.compile(r'\d{13}')

    def detect(self, text: str) -> List[Dict]:
        findings = []

        # 1. ตรวจจับเบอร์โทรศัพท์
        for match in self.phone_pattern.finditer(text):
            findings.append({
                "type": "PHONE_NUMBER",
                "value": match.group(),
                "start": match.start(),
                "end": match.end(),
                "score": 1.0 # มั่นใจ 100% เพราะ Pattern ชัด
            })

        # 2. ตรวจจับเลขบัตรประชาชน
        for match in self.id_card_pattern.finditer(text):
            candidate = match.group()
            # สำคัญ: ต้องผ่านการตรวจ Check Digit ก่อนถึงจะนับว่าเป็น PII จริง
            if verify_thai_id(candidate):
                findings.append({
                    "type": "THAI_ID",
                    "value": candidate,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0
                })
        
        # เรียงลำดับตามตำแหน่งที่เจอในประโยค
        return sorted(findings, key=lambda x: x['start'])