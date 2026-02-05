# src/core/anonymizer.py
from typing import List, Dict

class PII_Anonymizer:
    def anonymize(self, text: str, findings: List[Dict]) -> str:
        """
        แทนที่ข้อความ PII ด้วย Placeholder เช่น <PHONE_NUMBER>
        """
        # เราจะแปลง String เป็น List ของตัวอักษรเพื่อให้แก้ไขง่าย
        text_list = list(text)
        
        # วนลูปย้อนหลัง (Reverse) เพื่อไม่ให้ Index เพี้ยนเวลาเราแก้ข้อความข้างหน้า
        # (เทคนิคสำคัญ: ถ้าแก้จากหน้าไปหลัง ตำแหน่งตัวหลังจะเลื่อน)
        for item in sorted(findings, key=lambda x: x['start'], reverse=True):
            start = item['start']
            end = item['end']
            pii_type = item['type']
            
            # สร้าง Placeholder เช่น <PHONE_NUMBER>
            placeholder = f"<{pii_type}>"
            
            # แทนที่ข้อความในช่วงนั้นด้วย Placeholder
            # เช่น text[50:60] = "<PHONE_NUMBER>"
            text_list[start:end] = list(placeholder)
            
        return "".join(text_list)