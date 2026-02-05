def verify_thai_id(id_number: str) -> bool:
    """
    ตรวจสอบความถูกต้องของเลขบัตรประชาชนไทย (13 หลัก)
    ตามอัลกอริทึม Check Digit (Mod 11)
    """
    # 1. ต้องเป็นตัวเลขล้วนและยาว 13 หลัก
    if not id_number.isdigit() or len(id_number) != 13:
        return False

    # 2. หลักแรกต้องไม่ใช่ 0 และไม่เกิน 8 (ตามประเภทบุคคล)
    if id_number[0] not in '12345678':
        return False

    # 3. คำนวณ Check Digit
    try:
        digits = [int(d) for d in id_number]
        sum_val = 0
        for i in range(12):
            sum_val += digits[i] * (13 - i)
        
        check_digit = (11 - (sum_val % 11)) % 10
        
        # เทียบกับหลักสุดท้าย
        return check_digit == digits[12]
        
    except ValueError:
        return False