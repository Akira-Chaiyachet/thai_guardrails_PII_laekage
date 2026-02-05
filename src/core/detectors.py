# src/core/detectors.py
import re
from typing import List, Dict, Optional
from src.core.utils import verify_thai_id
from transformers import pipeline
from src.core.utils import verify_thai_id
# เช็คว่ามี AttaCut ไหม
try:
    from attacut import tokenize as attacut_tokenize
    USING_ATTACUT = True
    print("✅ Using AttaCut (AI Tokenizer)")
except ImportError:
    from pythainlp import word_tokenize
    USING_ATTACUT = False
    print("⚠️ AttaCut not found, using PyThaiNLP (NewMM)")

class PII_Detector:
    def __init__(self):
        # 1. Hard Rules (Regex)
        self.phone_pattern = re.compile(r'(\+66|66|0)[689]\d{8}')
        self.id_card_pattern = re.compile(r'\d{13}')
        self.ignore_after = ["บาท", "สตางค์", "point", "แต้ม", "คะแนน", "คน"]
        self.ignore_before = ["ราคา", "ยอด", "ชำระ", "รวม", "หมายเลขตั๋ว", "รหัสจอง"]

        # ---------------------------
        # 2. Context Triggers
        # ---------------------------
        self.context_triggers = [
            "ชื่อ", "นามสกุล", 
            "นาย", "นาง", "นางสาว", "น.ส.", 
            "เด็กชาย", "เด็กหญิง", "ด.ช.", "ด.ญ.", 
            "พล.อ.", "พล.ต.อ.", "พ.ต.อ.", "ร.ต.อ.", 
            "อาจารย์", "อ.", "ดร.", "ทนาย", "หมอ", "แพทย์", 
            "ผู้ว่า", "กำนัน", "ผู้ใหญ่บ้าน"
        ]
        
        # ⛔ Forbidden Next Tokens: ถ้าคำถัดไปเป็นพวกนี้ "ห้ามจับ"
        # (อัปเดต Patch 9: เพิ่ม ทนาย, นายทุน, โรงแรม, ม่านรูด)
        self.forbidden_next_tokens = {
            # สรรพนาม
            "เขา", "ผม", "ฉัน", "ดิฉัน", "หนู", "มัน", "แก", "เธอ", "คุณ", "เรา", "ท่าน",
            # ตำแหน่ง/อาชีพ/ยศ
            "ตำรวจ", "ทหาร", "นายก", "อำเภอ", "ราชการ", "สาธารณสุข", 
            "แพทย์", "พยาบาล", "ผู้", "ดาบ", "สิบ", "ช่าง", "ปลัด",
            "สถานี", "กอง", "หมู่", "ตรวจ", "ด่าน", "ท่า", "ประกัน", "อดีต", "รอง",
            "จังหวัด", "เมือง", "ตำบล", "อบต", "เทศบาล", "เขต", "แขวง", "อบต.",
            "ทนาย", "ทนายความ", "นายทุน", # +ทนาย, นายทุน
            # เครือญาติ/คำเรียกทั่วไป
            "พ่อ", "แม่", "ปู่", "ย่า", "ตา", "ยาย", "ลุง", "ป้า", "น้า", "อา",
            "พี่", "น้อง", "ลูก", "หลาน", "ครู", "พระ", "เจ้า", "คน",
            # สถานที่/สิ่งของ/คำสุภาพ/ความเชื่อ
            "วัด", "โรงเรียน", "บ้าน", "ร้าน", "ตลาด", "สำนัก", "สโมสร", "สวน", "ป่า", "เขื่อน",
            "น้ำพริก", "ขนม", "อาหาร", "สินค้า", "พระธาตุ", "ห้วย", "ถ้ำ", "ปาก", "ตะเคียน",
            "โรงแรม", "ม่านรูด", "รีสอร์ท", # +โรงแรม
            "อภัย", "โทษ", "แม่นาย"
        }

        # ⛔ Stop Words: เจอคำพวกนี้ให้ "ตัดจบชื่อ" ทันที
        # (อัปเดต Patch 9: เพิ่ม ความ, อื่น, คู่กรณี, ปรับ, นอก, ระบบ)
        self.stop_words = {
             # คำลงท้าย/คำสร้อย
             "ครับ", "ค่ะ", "นะ", "จ้ะ", "จ้า", "นี้", "นั้น", "นู้น", 
             "เนี่ย", "อ่ะ", "หรอก", "เอง", "ด้วย", "ล่ะ", "สิ", "อือ", "อืม",
             "บ้าง", "มั้ย", "ไหม", "เหรอ", "หนิ", "ไง", "เถอะ", "นะฮะ", "ฮะ",
             
             # คำเชื่อม/บุพบท
             "ได้", "ที่", "แล้ว", "เลย", "ไม่", "มี", "เป็น", "คือ", "แทน",
             "ไป", "มา", "จะ", "ให้", "ของ", "ทาง", "การ", "ใน", "และ", "กับ", "หรือ", "แต่", "ก็", "ซึ่ง", "โดย", "เพื่อ", "ว่า", "จน", "แบบ", "เช่น",
             "ก่อน", "หลัง", "เมื่อ", "ตอน", "ช่วง", "ขณะ", "เดี๋ยว", "ระหว่าง", "อยู่", "นอก", # +นอก
             
             # คำนามทั่วไป/ลักษณะนาม/คำขยาย
             "อายุ", "วัย", "ปี", "ชาว", "ผู้", "คน", "ราย", "ศพ", "ญาติ", 
             "ชื่อ", "นามสกุล", "ชื่อเล่น", "สมมุติ", "สมมติ", "จริง", "ใหญ่", "เล็ก", "หมด", 
             "หนึ่ง", "สอง", "สาม", "จำนวน", "แห่ง", "เอกซเรย์", "หัวใจ", "รูป", "ด่าน", "อบต", "อบต.",
             "ความ", "อื่น", "อื่นๆ", "คู่กรณี", "ระบบ", # +ความ, อื่น, คู่กรณี, ระบบ
             
             # กริยา (Verbs)
             "ยืน", "นั่ง", "นอน", "เดิน", "วิ่ง", "จอด", "ปีน", "เต้น", "รำ", "เดินทาง",
             "ขอ", "ให้", "รับ", "ส่ง", "มอบ", "ยื่น", "โยน",
             "ต้องการ", "อยาก", "ชอบ", "รัก", "เกลียด", "กลัว", "แกล้ง",
             "ขาด", "เกิน", "เหลือ", "พอ", "ปรับ", # +ปรับ
             "ให้การ", "รับสารภาพ", "ปฏิเสธ", "ก่อเหตุ", "ลงมือ", "อ้าง", "ปิดล้อม",
             "ขับ", "ขี่", "พา", "นำ",
             "กล่าว", "บอก", "เผย", "แจ้ง", "ระบุ", "เล่า", "ถาม", "ตอบ", "คุย", "เคลียร์", "พูด",
             "ทราบ", "แถลง", "ตรง", "จุด", "อัน",
             "หนี", "หลบหนี", "มอบตัว", "จับ", "รวบ", "คุม", "ขัง", "ย้อน", "กลับ", "คืน",
             "โดน", "ถูก", "ยิง", "แทง", "ฆ่า", "ทำร้าย", "ชก", "ตบ", "ตี", "ฟัน", "ต่อสู้", "ขัดขืน",
             "เห็น", "มอง", "ดู", "เจอ", "พบ", "สังเกต", 
             "ผุด", "สร้าง", "ทำ", "มี", "ได้", "เสีย", "ตาย",
             "สวม", "ใส่", "ถอด", "ยุ่ง", "ถ่าย", "ร้าย", "ผูก", "คอ"
        }

        # ⛔ Compound Blacklist
        self.ignore_compounds = [
            "นายก", "นายอำเภอ", "นายหน้า", "นายจ้าง", "นายช่าง", 
            "นายแบบ", "นายท่า", "นายด่าน", "นายกอง", "เจ้านาย", 
            "นายตรวจ", "นายสถานี", "นายประกัน", "นายทะเบียน",
            "นายตำรวจ", "นายร้อย", "นายสิบ", "นายดาบ", "นายพล", "นายทหาร", "นายแพทย์", "นายทุน", # +นายทุน
            "นางฟ้า", "นางแบบ", "นางเอก", "นางรำ", "นางนวล", 
            "นางงาม", "นางไม้", "นางพยาบาล", "นางยักษ์", "นางร้าย", "นางตะเคียน",
            "นางสาวไทย", "นางสนม", "นางบำเรอ", "นางโลม",
            "แม่นาย",
            "หมอชิต", "หมอลำ", "หมอหุง", "หมอผี", "หมอดู", "หมอความ",
            "ทนายหน้าหอ", "ผู้ว่าจ้าง", "ผู้สื่อข่าว", "ชื่อเล่น", "ชื่อจริง"
        ]

        self.custom_names = {
            "เมย์", "ธนาทร", "สมชาย", "เจฟ", "ซาเตอร์", 
            "ชาญเจริญยิ่ง", "มงคลคุณเพียร"
        }

        print("⏳ กำลังโหลดโมเดล AI (WangchanBERTa - LST20)...")
        self.nlp_pipeline = pipeline(
            "token-classification", 
            model="thanaphatt1/WangchanBERTa-LST20",
            aggregation_strategy="simple",
            framework="pt"
        )
        print("✅ โหลดโมเดลเสร็จสิ้น!")

        self.type_mapping = {"PER": "PERSON", "B_PER": "PERSON", "I_PER": "PERSON", "person": "PERSON"}
        self.prefixes = ["นาย", "นาง", "นางสาว", "เด็กชาย", "เด็กหญิง", "ด.ช.", "ด.ญ.", "คุณ", "ผม", "ดิฉัน", "ฉัน", "กระผม", "พี่", "น้า", "อา", "ลุง", "ป้า"]
        self.prefixes.sort(key=len, reverse=True)

    def _check_context(self, text: str, start: int, end: int) -> bool:
        window_size = 15
        post_text = text[end : min(len(text), end + window_size)]
        for keyword in self.ignore_after:
            if keyword in post_text: return True
        pre_text = text[max(0, start - window_size) : start]
        for keyword in self.ignore_before:
            if keyword in pre_text: return True
        return False

    def detect(self, text: str) -> List[Dict]:
        findings = []

        # 1. Dictionary
        for name in self.custom_names:
            pattern = re.compile(re.escape(name), re.IGNORECASE)
            for match in pattern.finditer(text):
                findings.append({"type": "PERSON", "value": match.group(), "start": match.start(), "end": match.end(), "score": 1.0})

        # 2. Context Rules
        context_findings = self._detect_by_context(text)
        for cf in context_findings:
            if not self._is_overlap(cf['start'], cf['end'], findings):
                findings.append(cf)

        # 3. Hard Rules
        for match in self.phone_pattern.finditer(text):
            if not self._is_overlap(match.start(), match.end(), findings):
                findings.append({"type": "PHONE_NUMBER", "value": match.group(), "start": match.start(), "end": match.end(), "score": 1.0})
        for match in self.id_card_pattern.finditer(text):
            candidate = match.group()
            # 👇 ตรงนี้แหละครับที่มันเรียกใช้สูตรคำนวณ
            if verify_thai_id(candidate) and not self._check_context(text, match.start(), match.end()) and not self._is_overlap(match.start(), match.end(), findings):
                findings.append({"type": "THAI_ID", "value": candidate, "start": match.start(), "end": match.end(), "score": 1.0})
        # 4. AI
        try:
            padded_text = " " + text 
            ai_results = self.nlp_pipeline(padded_text)
        except:
            ai_results = []

        for item in ai_results:
            raw_tag = item.get('entity_group') or item.get('entity')
            start = max(0, item['start'] - 1) 
            end = max(0, item['end'] - 1)
            score = item['score']

            my_type = self.type_mapping.get(raw_tag)
            if not my_type or my_type != "PERSON": continue
            if self._is_overlap(start, end, findings): continue
            
            real_word = text[start:end]
            blacklist_ai = [
                "ตำบล", "อำเภอ", "จังหวัด", "วัด", "โรงเรียน", "บ้าน", "ถนน", "ซอย", 
                "น้ำพริก", "สำนัก", "สโมสร", "พระธาตุ", "ห้วย", "สวน", "ป่า", "เขื่อน", "ร้าน"
            ]
            if any(x in real_word for x in blacklist_ai): continue

            cleaned_entity = self._process_entity(real_word, start, my_type, score)
            if cleaned_entity:
                cleaned_entity['end'] = cleaned_entity['start'] + len(cleaned_entity['value'])
                findings.append(cleaned_entity)

        return sorted(findings, key=lambda x: x['start'])

    def _detect_by_context(self, text: str) -> List[Dict]:
        results = []
        
        for trigger in self.context_triggers:
            for match in re.finditer(re.escape(trigger), text):
                # ... (ส่วนหา Trigger เหมือนเดิม) ...
                trigger_start = match.start()
                trigger_end = match.end()

                # Check 1: ตัวเลขนำหน้า
                pre_chunk = text[max(0, trigger_start-10) : trigger_start].strip()
                if pre_chunk and pre_chunk[-1].isdigit(): continue

                # Check 2: Blacklist คำซ้อน
                check_window = text[trigger_start : trigger_start + 25]
                is_ignored = False
                for compound in self.ignore_compounds:
                    if check_window.startswith(compound):
                        is_ignored = True
                        break
                if is_ignored: continue

                # Tokenize
                remaining_text = text[trigger_end:]
                offset = 0
                while offset < len(remaining_text) and remaining_text[offset].isspace():
                    offset += 1
                target_text = remaining_text[offset:]
                if not target_text: continue

                if USING_ATTACUT:
                    tokens = attacut_tokenize(target_text)
                else:
                    from pythainlp import word_tokenize
                    tokens = word_tokenize(target_text, engine="newmm")

                if not tokens: continue

                # Fix: นาง + สาว -> นางสาว
                first_token = tokens[0]
                extra_offset = 0
                if trigger == "นาง" and first_token == "สาว":
                    if len(tokens) > 1:
                        extra_offset = len(first_token)
                        tokens = tokens[1:] 
                        first_token = tokens[0]
                    else: continue

                # 🛑 FIX 1: ถ้าคำแรกเป็น Forbidden -> เลิกจับ Trigger นี้เลย (ไม่ใช่แค่ continue)
                # เพราะแสดงว่า Trigger นี้ไม่ได้นำหน้าชื่อคน (เช่น นายก อบต.)
                is_forbidden = False
                for forbidden in self.forbidden_next_tokens:
                    if forbidden in first_token: 
                        is_forbidden = True
                        break
                if is_forbidden: continue # Break out for this trigger instance

                # 🛑 FIX 2: ถ้าคำแรกเป็น Stop Word -> เลิกจับ (เช่น นาย ปิดล้อม)
                if first_token in self.stop_words: continue

                # ถ้าคำสั้นเกินไป
                if len(first_token) < 2: continue

                # --- MERGE LOGIC ---
                full_name_parts = []
                for token in tokens:
                    if token in self.stop_words: break
                    
                    if "อายุ" in token: 
                        token = token.split("อายุ")[0]
                        if token: full_name_parts.append(token)
                        break
                    
                    if not any(c.isalnum() for c in token) and not token.isspace(): break
                    if any(c.isdigit() for c in token): break
                    
                    if any(f in token for f in self.forbidden_next_tokens): break
                    
                    if len(full_name_parts) >= 8: break
                    
                    full_name_parts.append(token)

                if not full_name_parts: continue
                
                final_name = "".join(full_name_parts).strip()
                
                if len(final_name) < 2: continue
                
                if final_name in ["สาว", "ชาย", "หญิง", "มานะ", "เดินทาง", "เสียชีวิต", "บาดเจ็บ", "เกิดเหตุ", "ขอ", "อภัย", "ปิดล้อม"]:
                    continue

                real_start = trigger_end + offset + extra_offset
                real_end = real_start + len(final_name)

                results.append({
                    "type": "PERSON",
                    "value": final_name,
                    "start": real_start,
                    "end": real_end,
                    "score": 0.98
                })
                
        return results

    def _is_overlap(self, start, end, current_findings):
        for f in current_findings:
            if (start < f['end']) and (end > f['start']):
                return True
        return False

    def _process_entity(self, entity_text: str, start_index: int, entity_type: str, score: float) -> Optional[Dict]:
        while True:
            found_prefix = False
            for prefix in self.prefixes:
                if entity_text.startswith(prefix):
                    cut_len = len(prefix)
                    entity_text = entity_text[cut_len:].lstrip()
                    start_index += cut_len
                    found_prefix = True
                    break
            if not found_prefix: break
        
        if len(entity_text) < 2: return None
        return {"type": entity_type, "value": entity_text, "start": start_index, "score": float(score)}