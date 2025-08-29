#!/usr/bin/env python3

import re
import json
import csv
import sys
from typing import Dict, List, Tuple, Any

class FlixkartPIIDetector:
    
    def __init__(self):
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w.]+@[\w.]+\b|\b\d{10}@[a-zA-Z]+\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        self.name_fields = ['name', 'first_name', 'last_name']
        self.combinatorial_fields = ['name', 'first_name', 'last_name', 'email', 'address', 'device_id', 'ip_address']
    
    def is_standalone_pii(self, field, value):
        if not value or len(str(value).strip()) < 3:
            return False
            
        value_str = str(value).strip()
        
        if field == 'phone' or self.phone_pattern.match(value_str):
            return True
        
        if field == 'aadhar' or self.aadhar_pattern.match(value_str):
            return True
            
        if field == 'passport' or self.passport_pattern.match(value_str):
            return True
            
        if field == 'upi_id' or self.upi_pattern.match(value_str):
            return True
            
        return False
    
    def is_valid_name(self, name_str):
        if not name_str or len(name_str.strip()) < 2:
            return False
        
        words = name_str.strip().split()
        if len(words) < 2:
            return False
            
        for word in words:
            if not re.match(r'^[A-Za-z.]+$', word):
                return False
        
        return True
    
    def is_valid_email(self, email_str):
        return bool(self.email_pattern.match(str(email_str)))
    
    def is_valid_address(self, addr_str):
        if not addr_str or len(str(addr_str)) < 10:
            return False
        addr = str(addr_str)
        return ',' in addr and (bool(re.search(r'\d', addr)) or len(addr.split()) >= 4)
    
    def has_combinatorial_pii(self, data):
        pii_fields_present = []
        
        for field, value in data.items():
            if not value:
                continue
                
            if field in ['name'] and self.is_valid_name(value):
                pii_fields_present.append('name')
            elif field in ['first_name', 'last_name'] and len(str(value).strip()) >= 2:
                if 'name_parts' not in pii_fields_present:
                    pii_fields_present.append('name_parts')
            elif field == 'email' and self.is_valid_email(value):
                pii_fields_present.append('email')
            elif field == 'address' and self.is_valid_address(value):
                pii_fields_present.append('address')
            elif field in ['device_id', 'ip_address'] and len(str(value).strip()) >= 5:
                pii_fields_present.append('device_info')
        
        return len(pii_fields_present) >= 2
    
    def detect_pii_in_record(self, data):
        has_standalone = False
        has_combinatorial = False
        pii_fields = {}
        
        for field, value in data.items():
            if self.is_standalone_pii(field, value):
                has_standalone = True
                pii_fields[field] = self.mask_value(field, value)
        
        if self.has_combinatorial_pii(data):
            has_combinatorial = True
            for field, value in data.items():
                if field in self.combinatorial_fields and value and field not in pii_fields:
                    if field in ['name'] and self.is_valid_name(value):
                        pii_fields[field] = self.mask_value(field, value)
                    elif field in ['first_name', 'last_name'] and len(str(value).strip()) >= 2:
                        pii_fields[field] = self.mask_value(field, value)
                    elif field == 'email' and self.is_valid_email(value):
                        pii_fields[field] = self.mask_value(field, value)
                    elif field == 'address' and self.is_valid_address(value):
                        pii_fields[field] = self.mask_value(field, value)
                    elif field in ['device_id', 'ip_address']:
                        pii_fields[field] = '[REDACTED]'
        
        return has_standalone or has_combinatorial, pii_fields
    
    def mask_value(self, field, value):
        value_str = str(value).strip()
        
        if field == 'phone' or self.phone_pattern.match(value_str):
            if len(value_str) == 10:
                return f"{value_str[:2]}XXXXXX{value_str[-2:]}"
            return f"{value_str[:2]}{'X' * (len(value_str) - 4)}{value_str[-2:]}"
        
        if field == 'aadhar':
            clean_num = re.sub(r'[^\d]', '', value_str)
            if len(clean_num) == 12:
                return f"{clean_num[:2]}XXXXXXXX{clean_num[-2:]}"
            return '[REDACTED]'
        
        if field in ['name', 'first_name', 'last_name']:
            words = value_str.split()
            masked_words = []
            for word in words:
                if len(word) > 1:
                    masked_words.append(f"{word[0]}{'X' * (len(word) - 1)}")
                else:
                    masked_words.append('X')
            return ' '.join(masked_words)
        
        if field == 'email':
            if '@' in value_str:
                user, domain = value_str.split('@', 1)
                masked_user = f"{user[0]}{'X' * (len(user) - 1)}" if len(user) > 1 else 'X'
                return f"{masked_user}@{domain}"
            return '[REDACTED]'
        
        return '[REDACTED]'

def fix_malformed_json(json_str):

    import re

    fixed = json_str.strip().rstrip('"')

    fixed = re.sub(r':\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*([,}])', r': "\1"\2', fixed)

    fixed = re.sub(r':\s*(\d{4}-\d{2}-\d{2})\s*([,}])', r': "\1"\2', fixed)
    return fixed

def detect_pii_in_raw_string(raw_str):
    """Detect PII in raw string when JSON parsing fails"""
    detector = FlixkartPIIDetector()
    # Check for phone numbers
    if detector.phone_pattern.search(raw_str):
        return True
    # Check for aadhar numbers  
    if detector.aadhar_pattern.search(raw_str):
        return True
    # Check for passport numbers
    if detector.passport_pattern.search(raw_str):
        return True
    # Check for UPI IDs
    if detector.upi_pattern.search(raw_str):
        return True
    # Check for emails
    if detector.email_pattern.search(raw_str):
        return True
    return False

def redact_pii_in_raw_string(raw_str):
    """Redact PII in raw string when JSON parsing fails"""
    import re
    detector = FlixkartPIIDetector()
    redacted = raw_str
    
    # Redact phone numbers
    for match in detector.phone_pattern.finditer(raw_str):
        phone = match.group()
        if len(phone) == 10:
            masked = f"{phone[:2]}XXXXXX{phone[-2:]}"
        else:
            masked = f"{phone[:2]}{'X' * (len(phone) - 4)}{phone[-2:]}"
        redacted = redacted.replace(phone, masked)
    
    # Redact aadhar numbers
    for match in detector.aadhar_pattern.finditer(raw_str):
        aadhar = match.group()
        clean_num = re.sub(r'[^\d]', '', aadhar)
        if len(clean_num) == 12:
            masked = f"{clean_num[:2]}XXXXXXXX{clean_num[-2:]}"
            redacted = redacted.replace(aadhar, masked)
    
    # Redact passport numbers
    redacted = detector.passport_pattern.sub('[REDACTED]', redacted)
    
    # Redact UPI IDs
    redacted = detector.upi_pattern.sub('[REDACTED]', redacted)
    
    # Redact emails
    redacted = detector.email_pattern.sub('[REDACTED]', redacted)
    
    return redacted

def process_csv_file(input_file):
    detector = FlixkartPIIDetector()
    output_file = f"redacted_output_dhananjay_garg.csv"
    
    total_records = 0
    pii_records = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
                
                for row in reader:
                    total_records += 1
                    
                    try:
                        record_id = row.get('record_id', '')
                        data_json = row.get('data_json', '{}')
                        
                        if not data_json.strip():
                            writer.writerow([record_id, '{}', False])
                            continue
                        
                        try:
                            data = json.loads(data_json)
                        except json.JSONDecodeError:
                            # Try to fix common JSON issues
                            fixed_json = fix_malformed_json(data_json)
                            try:
                                data = json.loads(fixed_json)
                            except:
                                # If still can't parse, scan the raw string for PII and redact it
                                has_pii_raw = detect_pii_in_raw_string(data_json)
                                if has_pii_raw:
                                    pii_records += 1
                                    redacted_raw = redact_pii_in_raw_string(data_json)
                                    writer.writerow([record_id, redacted_raw, True])
                                else:
                                    writer.writerow([record_id, data_json, False])
                                continue
                        
                        has_pii, pii_fields = detector.detect_pii_in_record(data)
                        
                        if has_pii:
                            pii_records += 1
                            redacted_data = data.copy()
                            for field, masked_value in pii_fields.items():
                                if field in redacted_data:
                                    redacted_data[field] = masked_value
                            
                            redacted_json = json.dumps(redacted_data, separators=(',', ':'))
                            writer.writerow([record_id, redacted_json, True])
                        else:
                            writer.writerow([record_id, data_json, False])
                    except Exception as e:
                        writer.writerow([row.get('record_id', ''), '{}', False])
                        continue
    
    except FileNotFoundError:
        print(f"Error: File {input_file} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)
    
    print(f"Processing completed successfully")
    print(f"Total records: {total_records}")
    print(f"PII records found: {pii_records}")
    print(f"Output saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_dhananjay_garg.py <input_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    process_csv_file(input_file)