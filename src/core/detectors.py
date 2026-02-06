# src/core/detectors.py
import re
from typing import List, Dict, Optional
from src.core.utils import verify_thai_id
from transformers import pipeline

# ---------------------------------------------------------
# 🛠️ LOAD LIBRARIES & MODELS
# ---------------------------------------------------------

# 1. Tokenizer (ตัดคำ)
try:
    from attacut import tokenize as attacut_tokenize
    USING_ATTACUT = True
    print("✅ Using AttaCut (AI Tokenizer)")
except ImportError:
    from pythainlp import word_tokenize
    USING_ATTACUT = False
    print("⚠️ AttaCut not found, using PyThaiNLP (NewMM)")

# 2. POS Tagger (เช็คชนิดคำ: นาม, กริยา, สรรพนาม)
try:
    from pythainlp.tag import pos_tag
    print("✅ Using PyThaiNLP POS Tagger (Perceptron/Orchid)")
except ImportError:
    raise ImportError("❌ กรุณาติดตั้ง pythainlp: pip install pythainlp")

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
        
        # ⛔ Forbidden Next Tokens: คำที่ห้ามขึ้นต้นเป็นชื่อคนเด็ดขาด!
        self.forbidden_next_tokens = {
            # สรรพนาม
            "เขา", "ผม", "ฉัน", "ดิฉัน", "หนู", "มัน", "แก", "เธอ", "คุณ", "เรา", "ท่าน", "แต่ละ",
            # ตำแหน่ง/อาชีพ/ยศ/กลุ่มคน
            "ตำรวจ", "ทหาร", "นายก", "อำเภอ", "ราชการ", "สาธารณสุข", 
            "แพทย์", "พยาบาล", "ผู้", "ดาบ", "สิบ", "ช่าง", "ปลัด",
            "สถานี", "กอง", "หมู่", "ตรวจ", "ด่าน", "ท่า", "ประกัน", "อดีต", "รอง",
            "สภ", "สภ.", "สน", "สน.", "บริษัท", "หจก", "หจก.", 
            "จังหวัด", "เมือง", "ตำบล", "อบต", "เทศบาล", "เขต", "แขวง", "อบต.",
            "ทนาย", "ทนายความ", "นายทุน", "นายหน้า", "หนัง",
            "นัก", "นักเรียน", "นักศึกษา", "นักข่าว", "นักสังคม", 
            "ผู้ต้องหา", "จำเลย", "คนร้าย", "ผู้ก่อเหตุ", "อธิบดี","แอดมิน", "ประธาน",
            # เครือญาติ/คำเรียกทั่วไป
            "พ่อ", "แม่", "ปู่", "ย่า", "ตา", "ยาย", "ลุง", "ป้า", "น้า", "อา",
            "พี่", "น้อง", "ลูก", "หลาน", "ครู", "พระ", "เจ้า", "คน",
            # สถานที่/สิ่งของ/คำสุภาพ/ความเชื่อ/ของกิน
            "วัด", "โรงเรียน", "บ้าน", "ร้าน", "ตลาด", "สำนัก", "สโมสร", "สวน", "ป่า", "เขื่อน",
            "น้ำพริก", "ขนม", "อาหาร", "สินค้า", "พระธาตุ", "ห้วย", "ถ้ำ", "ปาก", "ตะเคียน",
            "โรงแรม", "ม่านรูด", "รีสอร์ท", "โรงพยาบาล", "รพ", "รพ.","โรงพัก",
            "หาด", "น้ำตก", "ก๋วยเตี๋ยว", "หนอง", "ฟาร์ม", # +หนอง, ฟาร์ม
            "เจ้าแม่", "ศาล", # +เจ้าแม่
            "อภัย", "โทษ", "แม่นาย", ".", "..",
            # คำขยาย/คำบอกเวลา
            "ดัง", "เสียง", "ขึ้น", "นอกเหนือ", "เก่า", "ใหม่" # +เก่า
        }

        # ⛔ Stop Words: เจอคำพวกนี้ให้ "ตัดจบชื่อ" ทันที
        self.stop_words = {
             # คำลงท้าย/คำสร้อย
             "ครับ", "ค่ะ", "นะ", "จ้ะ", "จ้า", "นี้", "นั้น", "นู้น", 
             "เนี่ย", "อ่ะ", "หรอก", "เอง", "ด้วย", "ล่ะ", "สิ", "อือ", "อืม",
             "บ้าง", "มั้ย", "ไหม", "เหรอ", "หนิ", "ไง", "เถอะ", "นะฮะ", "ฮะ", "นี่",
             "ง่ะ", "อีก", "ครั้ง", "เลย", "ค่อนข้าง", "เรียบร้อย","ก็", "แล้ว", "กัน",

             # คำเชื่อม/บุพบท/กฎหมาย
             "ได้", "ที่", "แล้ว", "เลย", "ไม่", "มี", "เป็น", "คือ", "แทน",
             "ไป", "มา", "จะ", "ให้", "ของ", "ทาง", "การ", "ใน", "และ", "กับ", "หรือ", "แต่", "ก็", "ซึ่ง", "โดย", "เพื่อ", "ว่า", "จน", "แบบ", "เช่น", 
             "ฐาน", "ข้อหา", "คดี", "ความ", "คณะ", "ถึง", # +ถึง (อนุทินถึง)
             "ก่อน", "หลัง", "เมื่อ", "ตอน", "ช่วง", "ขณะ", "เดี๋ยว", "ระหว่าง", "อยู่", "นอก", "เพราะ","ยัง", "คง",
             
             # คำนามทั่วไป/อาชีพ/ตำแหน่ง
             "อายุ", "วัย", "ปี", "ชาว", "ผู้", "คน", "ราย", "ศพ", "ญาติ", "ภรรยา", "สามี", "เพื่อน", # +เพื่อน
             "ชื่อ", "นามสกุล", "ชื่อเล่น", "สมมุติ", "สมมติ", "จริง", "ใหญ่", "เล็ก", "หมด", "พร้อม", "เต็ม", "มาก", "ยิ่ง",
             "หนึ่ง", "สอง", "สาม", "จำนวน", "แห่ง", "เอกซเรย์", "หัวใจ", "รูป", "ด่าน", "อบต", "อบต.",
             "อื่น", "อื่นๆ", "คู่กรณี", "ระบบ", "นาม","นามสมมุติ", "นามสมมติ",
             "นัก", "นักสังคม", "สงเคราะห์", "ชำนาญ", "ชำนาญการ", "อธิบดี",
             "นายทุน", "กองหลัง", "ผู้รักษาประตู", 
             "มือ", "มือปราบ", "มือยิง", "แอดมิน", "ประธาน", "ชุมชน", "ตำแหน่ง",
             
             # กริยา (Verbs) - อัดเข้าไปให้หมด
             "ยืน", "นั่ง", "นอน", "เดิน", "วิ่ง", "จอด", "ปีน", "เต้น", "รำ", "เดินทาง",
             "ขอ", "ให้", "รับ", "ส่ง", "มอบ", "ยื่น", "โยน", "เชื่อ", "ปัก", "รู้", "ทราบ",
             "ต้องการ", "อยาก", "ชอบ", "รัก", "เกลียด", "กลัว", "แกล้ง", "กำลัง",
             "ขาด", "เกิน", "เหลือ", "พอ", "ปรับ", "ตั้ง", "ข้อ", "เกิด", # +เกิด
             "ให้การ", "รับสารภาพ", "ปฏิเสธ", "ก่อเหตุ", "ลงมือ", "อ้าง", "ปิดล้อม", "หยุด", "ชะงัก", "ลุก","ชัก", "ออก", "ใส่", "ไว้",
             "ขับ", "ขี่", "พา", "นำ", "ถือ", "ชวน", "เตือน", "เคย", # +ถือ, ชวน, เตือน, เคย
             "กล่าว", "บอก", "เผย", "แจ้ง", "ระบุ", "เล่า", "ถาม", "ตอบ", "คุย", "เคลียร์", "พูด",
             "แถลง", "ตรง", "จุด", "อัน",
             "หนี", "หลบหนี", "มอบตัว", "จับ", "รวบ", "คุม", "ขัง", "ย้อน", "กลับ", "คืน",
             "โดน", "ถูก", "ยิง", "แทง", "ฆ่า", "ทำร้าย", "ชก", "ตบ", "ตี", "ฟัน", "ต่อสู้", "ขัดขืน", "บาดเจ็บ", "เจ็บ", # +บาดเจ็บ
             "เห็น", "มอง", "ดู", "เจอ", "พบ", "สังเกต", "ถ่าย", "ภาพ",
             "ผุด", "สร้าง", "ทำ", "มี", "ได้", "เสีย", "ตาย", "สามารถ", # +สามารถ
             "สวม", "ใส่", "ถอด", "ยุ่ง", "ร้าย", "ผูก", "คอ",
             "เหมือน", "คล้าย", "ดั่ง", "ราว"
        }

        # ⛔ Compound Blacklist
        self.ignore_compounds = [
            "นายก", "นายอำเภอ", "นายหน้า", "นายจ้าง", "นายช่าง", 
            "นายแบบ", "นายท่า", "นายด่าน", "นายกอง", "เจ้านาย", 
            "นายตรวจ", "นายสถานี", "นายประกัน", "นายทะเบียน",
            "นายตำรวจ", "นายร้อย", "นายสิบ", "นายดาบ", "นายพล", "นายทหาร", "นายแพทย์", "นายทุน", "นายหนัง",
            "นางฟ้า", "นางแบบ", "นางเอก", "นางรำ", "นางนวล", 
            "นางงาม", "นางไม้", "นางพยาบาล", "นางยักษ์", "นางร้าย", "นางตะเคียน",
            "นางสาวไทย", "นางสนม", "นางบำเรอ", "นางโลม",
            "แม่นาย",
            "หมอชิต", "หมอลำ", "หมอหุง", "หมอผี", "หมอดู", "หมอความ",
            "ทนายหน้าหอ", "ผู้ว่าจ้าง", "ผู้สื่อข่าว", "ชื่อเล่น", "ชื่อจริง", "ชื่อเก่า" # +ชื่อเก่า
        ]

        self.custom_names = {
            "ธนาทร", "สมชาย", "เจฟ", "ซาเตอร์", 
            "ชาญเจริญยิ่ง", "มงคลคุณเพียร", "พยัคฆ์อรุณ" 
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

        # 1. Dictionary Matching
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
            if verify_thai_id(candidate) and not self._check_context(text, match.start(), match.end()) and not self._is_overlap(match.start(), match.end(), findings):
                findings.append({"type": "THAI_ID", "value": candidate, "start": match.start(), "end": match.end(), "score": 1.0})

        # 4. AI (WangchanBERTa) - ตัวที่ชอบจับผิด!
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
            
            # ⛔ BLACKLIST AI: คำที่ AI ชอบมั่วจับว่าเป็นคน ใส่ตรงนี้!
            blacklist_ai = [
                # สถานที่ / หน่วยงาน
                "ตำบล", "อำเภอ", "จังหวัด", "วัด", "โรงเรียน", "มหาวิทยาลัย", "คณะ",
                "บ้าน", "ถนน", "ซอย", "แยก", "ด่าน", "ท่า", "สถานี",
                "โรงพยาบาล", "รพ", "รพ.", "คลินิก", "อนามัย",
                "น้ำพริก", "สำนัก", "สโมสร", "พระธาตุ", "ห้วย", "สวน", "ป่า", "เขื่อน", "ร้าน", "ห้าง",
                "ตลาด", "หาด", "น้ำตก", "ภู", "ดอย", "เกาะ", "ถ้ำ", "ทุ่ง",
                
                # อาหาร / ของกิน (ตัวดีเลย)
                "ก๋วยเตี๋ยว", "ข้าว", "แกง", "ผัด", "ต้ม", "ยำ", "ตำ", "ทอด", "ปิ้ง", "ย่าง",
                "ขนม", "น้ำ", "กาแฟ", "ชา", "หมู", "ไก่", "เนื้อ", "ปลา", "ลูกชิ้น",
                
                # อื่นๆ
                "เจ้าแม่", "ศาล", "สามารถ"
            ]
            
            # เช็คว่ามีคำใน Blacklist ผสมอยู่ไหม (เช่น "ก๋วยเตี๋ยวเรือ" มีคำว่า "ก๋วยเตี๋ยว")
            if any(x in real_word for x in blacklist_ai): continue
            
            # เช็คความยาว (ชื่อคนต้องยาวกว่า 1 ตัวอักษร)
            if len(real_word) < 2: continue

            cleaned_entity = self._process_entity(real_word, start, my_type, score)
            if cleaned_entity:
                cleaned_entity['end'] = cleaned_entity['start'] + len(cleaned_entity['value'])
                findings.append(cleaned_entity)

        return sorted(findings, key=lambda x: x['start'])

    def _detect_by_context(self, text: str) -> List[Dict]:
        results = []
        
        for trigger in self.context_triggers:
            for match in re.finditer(re.escape(trigger), text):
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

                # 🛑 FIX 1: Forbidden check on first token
                is_forbidden = False
                for forbidden in self.forbidden_next_tokens:
                    if forbidden in first_token: 
                        is_forbidden = True
                        break
                if is_forbidden: continue

                # 🛑 FIX 2: Stop word check on first token
                if first_token in self.stop_words: continue

                if len(first_token) < 2: continue

                # 🚀 POS TAGGING INJECTION 🚀
                # ส่ง tokens ไปให้ PyThaiNLP แปะป้ายว่าคำไหนเป็น Noun, Verb, Pronoun
                # corpus='orchid' จะให้ tag เช่น PPRS (สรรพนาม), VACT (กริยา)
                try:
                    pos_results = pos_tag(tokens, engine='perceptron', corpus='orchid')
                except:
                    # กรณี POS พัง ให้ใช้ tokens เดิมแล้วแปะ tag ว่างๆ
                    pos_results = [(t, '') for t in tokens]

                # --- MERGE LOGIC (Updated with POS) ---
                full_name_parts = []
                
                for token, tag in pos_results:
                    # 1. Manual Stop words (Safety Net)
                    if token in self.stop_words: break
                    
                    # 2. POS Check (Grammar Logic)
                    # PPRS = สรรพนาม (เขา, ผม, มัน) -> หยุดทันที
                    if tag == 'PPRS': break 
                    
                    # VACT = กริยาการกระทำ (วิ่ง, ตี, ฆ่า) -> หยุดทันที
                    if tag == 'VACT' and len(token) > 1: break
                    
                    # JSBR/JCRG = คำเชื่อม (จน, เพราะ, และ)
                    if tag in ['JSBR', 'JCRG', 'RPRE'] and token in ["จน", "และ", "หรือ", "แต่", "ของ"]: break

                    # 3. Regular rules
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