# src/core/utils.py

def verify_thai_id(id_number: str) -> bool:
    """
    ตรวจสอบความถูกต้องของเลขบัตรประชาชนไทย 13 หลัก ตามสูตร Check Digit มาตรฐาน
    """
    # 1. ต้องเป็นตัวเลขล้วน และยาว 13 ตัว
    if not id_number.isdigit() or len(id_number) != 13:
        return False

    # 2. สูตรคำนวณ Check Digit
    # เอาเลข 12 หลักแรก มาคูณกับน้ำหนัก (13, 12, ..., 2)
    digits = [int(d) for d in id_number]
    sum_score = sum(digits[i] * (13 - i) for i in range(12))
    
    # คำนวณเลขหลักสุดท้ายที่ควรจะเป็น
    check_digit = (11 - (sum_score % 11)) % 10
    
    # 3. เปรียบเทียบกับเลขหลักสุดท้ายของจริง
    return check_digit == digits[12]