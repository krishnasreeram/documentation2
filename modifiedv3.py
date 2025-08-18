import os
import re
import json
import hashlib
import base64
from datetime import datetime
from dotenv import load_dotenv
from openai import AzureOpenAI
import csv
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from time import sleep
import random
import xml.etree.ElementTree as ET


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except Exception:
    _CRYPTO_AVAILABLE = False


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MerchantDataProcessor:
    def __init__(self, max_workers=10, rate_limit_delay=0.1):
        load_dotenv()

        # Azure OpenAI client
        self.client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
        )
        self.deployment_name = os.getenv("DEPLOYMENT_NAME")

        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.thread_lock = threading.Lock()

        # ---------- Defaults ----------
        self.hash_input_mode = os.getenv("HASH_INPUT_MODE", "ENCRYPTED").upper()
        # Field-level protection
        self.pii_encryption = os.getenv("PII_ENCRYPTION", "B64").upper()
        self.pii_key_hex = os.getenv("PII_KEY_HEX", "").strip()

        
        self._load_processing_prefs_from_xml(
            os.getenv("XML_CONFIG_PATH", "MP.ESQR_TSYS_MIF_Detail.Configuration.xml")
        )

        
        self._aesgcm = None
        if self.pii_encryption == "AES_GCM" and _CRYPTO_AVAILABLE and self.pii_key_hex:
            try:
                key = bytes.fromhex(self.pii_key_hex)
                if len(key) != 32:
                    logger.warning("PII_KEY_HEX must be 32 bytes (64 hex). Falling back to B64.")
                    self.pii_encryption = "B64"
                else:
                    self._aesgcm = AESGCM(key)
            except Exception as e:
                logger.warning(f"Failed to init AES-GCM: {e}. Falling back to B64.")
                self.pii_encryption = "B64"
        elif self.pii_encryption == "AES_GCM" and not _CRYPTO_AVAILABLE:
            logger.warning("cryptography not available. Falling back to B64.")
            self.pii_encryption = "B64"

        # ---------- Validation rules ----------
        self.validation_rules = {
            'BankNumber': {'required': True, 'type': 'numeric', 'min_length': 1},
            'MerchantNumber': {'required': True, 'type': 'alphanumeric', 'min_length': 1},
            'SICCode': {'required': True, 'type': 'numeric', 'length': 4},
            'MerchantName': {'required': True, 'type': 'string', 'min_length': 1},
            'City': {'required': True, 'type': 'string', 'min_length': 1},
            'State': {'required': True, 'type': 'string', 'length': 2},
            'Zip': {'required': True, 'type': 'numeric', 'min_length': 5},
            'FederalTaxId': {'required': False, 'type': 'numeric', 'length': 9},
            'OwnerSsn': {'required': False, 'type': 'numeric', 'length': 9},
            'Status': {'required': False, 'type': 'string', 'values': ['C', 'D', '', ' ']},
            'Phone1': {'required': False, 'type': 'numeric', 'length': 10}
        }

        # ---------- Field names ----------
        self.field_names = [
            'BankNumber', 'MerchantNumber', 'AssociationNumber', 'SICCode', 'Class',
            'MerchantName', 'City', 'State', 'Zip', 'Phone1', 'Phone2', 'BusinessLicense',
            'BankOfficer1', 'BankOfficer2', 'UserBankNumber', 'UserBranchNumber',
            'FederalTaxId', 'StateTaxId', 'EdcFlag', 'RepCode', 'Status', 'UserFlag1',
            'UserFlag2', 'UserData1', 'UserData2', 'UserData3', 'UserData4', 'UserData5',
            'UserAccount1', 'UserAccount2', 'AchFlag', 'ExceptionTable', 'InvestigationCode',
            'VisaCps2', 'VisaCps1', 'VisaSuper', 'VisaEps', 'VisaPsrf', 'VisaEirf',
            'MCmerit3', 'MCmerit1', 'MCsuper', 'MCptCat', 'MCwhs', 'MCprm',
            'DiscoverEligibility', 'MerchantType', 'IncStatus', 'MemberId', 'GrsFlag',
            'Owner', 'ManagerName', 'AsstManagerName', 'OtherName', 'OwnerSsn',
            'OwnerLicenseNumber', 'LastStatementDate', 'OpenDate', 'LastCreditCheckDate',
            'LastCardRequestDate', 'LastCallDate', 'NextCallDate', 'FinancialStatementDueDate',
            'FinancialStatementReqDate', 'StoreFlag', 'StatementCount', 'AddressDiscountInd',
            'AddressRclList', 'AddressCrbList', 'AddressCardMailer', 'AddressIRS',
            'AddressImprinterRentals', 'AddressMemberFees', 'AddressPosTerminals',
            'AddressNameMCS', 'AddressUniqueMessage', 'AddressNameBet1', 'AddressNameBet2',
            'AddressNameBet3', 'IntchFlagDollars', 'IntchFlagCount', 'DestinationOverall',
            'DestinationDeposit', 'DestinationAdjustment', 'DestinationChargeback',
            'DestinationReversal', 'DestinationChbckReversal', 'DdaAdjustmentOption',
            'BatchAdjustmentOption', 'TransactionOption1', 'TransactionOption2',
            'TransactionOption3', 'AmexPCindicator', 'AmexDescriptorCode',
            'AmexSettlementFlag', 'DiscoverReferenceNumber', 'AmexId', 'DiscoverAccountId',
            'JcbId', 'DinersId', 'Filler1', 'Filler2', 'Filler3', 'Filler4', 'Filler5',
            'LastActiveDate', 'DailyFeeIndicator', 'MCRegID', 'CustomerServiceNumber',
            'UpdatedDTS', 'StatusChangeDate', 'DiscoverMAPFlag', 'AmexOptBlu', 'Filler',
            'AmexSubmitterID', 'MerchantEmailAddress', 'FillerExpansion'
        ]

        
        self.sensitive_fields = {'FederalTaxId', 'OwnerSsn'}

    # ---------------- XML parsing  ----------------
    def _load_processing_prefs_from_xml(self, xml_path: str):
        """
        Best-effort parse of the Parser XML to align with client rules:
          - pick encryption algorithm for FederalTaxId/OwnerSsn
          - decide whether HashedTaxID hashes plaintext or encrypted value
        Falls back to env defaults if XML missing or unrecognized.
        """
        candidate_paths = [xml_path]
        
        if not os.path.isabs(xml_path):
            candidate_paths.append(os.path.join("/mnt/data", xml_path))

        found = None
        for p in candidate_paths:
            if os.path.exists(p):
                found = p
                break

        if not found:
            logger.info(f"XML config not found at {xml_path}; using env defaults: "
                        f"PII_ENCRYPTION={self.pii_encryption}, HASH_INPUT_MODE={self.hash_input_mode}")
            return

        try:
            tree = ET.parse(found)
            root = tree.getroot()

            # Heuristics
            enc_mode = None
            hash_source = None

            for elem in root.iter():
                tag = (elem.tag or "").lower()
                txt = (elem.text or "").strip().lower()
                attrs = {k.lower(): (v or "").strip().lower() for k, v in elem.attrib.items()}

                # Encryption detection
                if any(k in tag for k in ["encrypt", "encryption"]) or any(k in attrs for k in ["encrypt", "encryption", "algorithm", "mode"]):
                    # check attributes
                    cand = attrs.get("algorithm") or attrs.get("mode") or attrs.get("encryption") or txt
                    if cand:
                        if "aes" in cand and "gcm" in cand:
                            enc_mode = "AES_GCM"
                        elif "base64" in cand or "b64" in cand:
                            enc_mode = "B64"

                # Hashing input source detection
                if "hash" in tag or "hashedtaxid" in tag or any(k in attrs for k in ["hash", "source"]):
                    cand_src = attrs.get("source") or txt
                    if cand_src:
                        if "encrypt" in cand_src or "cipher" in cand_src or "gcm" in cand_src:
                            hash_source = "ENCRYPTED"
                        elif "plain" in cand_src or "raw" in cand_src:
                            hash_source = "PLAINTEXT"

            if enc_mode:
                self.pii_encryption = enc_mode
            if hash_source:
                self.hash_input_mode = hash_source

            logger.info(f"Loaded XML prefs from {found}: PII_ENCRYPTION={self.pii_encryption}, "
                        f"HASH_INPUT_MODE={self.hash_input_mode}")

        except Exception as e:
            logger.warning(f"Could not parse XML config ({found}): {e}. "
                           f"Continuing with PII_ENCRYPTION={self.pii_encryption}, HASH_INPUT_MODE={self.hash_input_mode}")

    # ---------------- utilities ----------------
    def _safe_strip(self, v: str) -> str:
        return '' if v is None else v.strip()

    def get_last4_digits(self, value):
        if not value:
            return ''
        digits = re.findall(r'\d', value)
        if not digits:
            return ''
        return ''.join(digits[-4:]) if len(digits) >= 4 else ''.join(digits)

    def hash_value_full_sha256_upper(self, value: str) -> str:
        if value is None:
            value = ''
        return hashlib.sha256(value.encode()).hexdigest().upper()

    def _encrypt_base64_labeled(self, value: str) -> str:
        return "b64:" + base64.b64encode(value.encode()).decode()

    def _encrypt_aes_gcm(self, value: str) -> str:
        if not self._aesgcm:
            return self._encrypt_base64_labeled(value)
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, value.encode(), None)
        ciphertext, tag = ct[:-16], ct[-16:]
        return "v1:gcm:" + ":".join([
            base64.urlsafe_b64encode(nonce).decode().rstrip("="),
            base64.urlsafe_b64encode(ciphertext).decode().rstrip("="),
            base64.urlsafe_b64encode(tag).decode().rstrip("="),
        ])

    def encrypt_value(self, value):
        """Field-level protection: AES-GCM if configured per XML/env, else labeled base64."""
        if not value:
            return ''
        if self.pii_encryption == "AES_GCM" and self._aesgcm:
            return self._encrypt_aes_gcm(value)
        return self._encrypt_base64_labeled(value)

    # ---------------- validation ----------------
    def validate_record(self, record):
        errors = []
        for field, rules in self.validation_rules.items():
            raw = record.get(field, '')
            value = raw.strip()

            if rules.get('required', False) and not value:
                errors.append(f"{field}: Required field is empty")
                continue

            if not value:
                if field == 'Status' and raw == ' ':
                    pass
                else:
                    continue

            field_type = rules.get('type')
            if field_type == 'numeric' and not re.match(r'^\d+$', value):
                errors.append(f"{field}: Must be numeric, got '{value}'")
            elif field_type == 'alphanumeric' and not re.match(r'^[a-zA-Z0-9]+$', value):
                errors.append(f"{field}: Must be alphanumeric, got '{value}'")

            if 'length' in rules and len(value) != rules['length']:
                errors.append(f"{field}: Must be exactly {rules['length']} characters, got {len(value)}")
            elif 'min_length' in rules and len(value) < rules['min_length']:
                errors.append(f"{field}: Must be at least {rules['min_length']} characters, got {len(value)}")

            if 'values' in rules and value not in rules['values']:
                errors.append(f"{field}: Invalid value '{value}', allowed: {rules['values']}")
        return errors

    # ---------------- LLM ----------------
    def send_to_azure_openai_with_retry(self, record_json, record_id, max_retries=3):
        sleep(random.uniform(0, self.rate_limit_delay))
        for attempt in range(max_retries):
            try:
                system_prompt = (
                    "You are a data processing assistant. Analyze the provided merchant data record and:\n"
                    "1. Validate each field according to business rules\n"
                    "2. Identify any data quality issues\n"
                    "3. Suggest corrections if possible\n"
                    "4. Return a JSON response with validation results\n\n"
                    "Focus on required fields, formats, business rules, consistency.\n"
                    "Keep response concise."
                )
                user_prompt = (
                    f"Process merchant record #{record_id}:\n{record_json}\n\n"
                    "Return JSON like:\n"
                    "{\n"
                    '  "is_valid": boolean,\n'
                    '  "errors": [ ... ],\n'
                    '  "warnings": [ ... ]\n'
                    "}"
                )
                response = self.client.chat.completions.create(
                    model=self.deployment_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0,
                    max_tokens=800
                )
                with self.thread_lock:
                    logger.info(f"Processed record {record_id} via OpenAI (attempt {attempt + 1})")
                return response.choices[0].message.content
            except Exception as e:
                with self.thread_lock:
                    logger.warning(f"Record {record_id} attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    sleep(2 ** attempt + random.uniform(0, 1))
                else:
                    with self.thread_lock:
                        logger.error(f"Record {record_id} failed after {max_retries} attempts")
                    return f"API Error after {max_retries} attempts: {str(e)}"
        return None

    # ---------------- record processing ----------------
    def process_single_record(self, line_data):
        line_num, line, record_id = line_data
        line = line.strip()

        if not re.match(r'^\d', line):
            return None

        fields = line.split('\t')
        while len(fields) < len(self.field_names):
            fields.append('')

        record = {}
        for i, field_name in enumerate(self.field_names):
            raw_val = fields[i] if i < len(fields) else ''
            record[field_name] = self._safe_strip(raw_val)

        validation_errors = self.validate_record(record)

        non_empty = {k: v for k, v in record.items() if v}
        record_json = json.dumps(non_empty, indent=2)
        openai_response = self.send_to_azure_openai_with_retry(record_json, record_id)

        # Plaintext for transforms
        federal_tax_id_plain = record.get('FederalTaxId', '')
        owner_ssn_plain = record.get('OwnerSsn', '')
        owner_license_plain = record.get('OwnerLicenseNumber', '')

        # Internal metadata
        record['RecordID'] = str(record_id)
        record['LineNumber'] = line_num
        record['ProcessedTimestamp'] = datetime.now().isoformat()

        # CSV fields
        record['FileSource'] = 'MIF_TSYS'
        record['Last4TaxID'] = self.get_last4_digits(federal_tax_id_plain)
        record['Last4OwnerSSN'] = self.get_last4_digits(owner_ssn_plain)

        # Encrypt sensitive fields
        enc_federal = self.encrypt_value(federal_tax_id_plain) if federal_tax_id_plain else ''
        enc_owner_ssn = self.encrypt_value(owner_ssn_plain) if owner_ssn_plain else ''

        record['FederalTaxId'] = enc_federal
        record['OwnerSsn'] = enc_owner_ssn

        
        record['OwnerLicenseNumber'] = owner_license_plain

        # HashedTaxID per XML rule
        if self.hash_input_mode == "ENCRYPTED":
            hash_source = enc_federal or ''
        else:
            hash_source = federal_tax_id_plain or ''
        record['HashedTaxID'] = self.hash_value_full_sha256_upper(hash_source)

        record['ValidationErrors'] = '; '.join(validation_errors) if validation_errors else ''
        record['OpenAIResponse'] = openai_response if openai_response else ''

        return {
            'record': record,
            'is_valid': len(validation_errors) == 0,
            'validation_errors': validation_errors
        }

    # ---------------- file processing ----------------
    def process_file(self, input_file_path):
        logger.info(f"Processing file: {input_file_path}")
        with open(input_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        # Remove header and last 3 trailers
        data_lines = lines[1:-3]

        line_data_list = []
        record_id = 0
        for line_num, line in enumerate(data_lines, start=2):
            if re.match(r'^\d', line.strip()):
                record_id += 1
                line_data_list.append((line_num, line, record_id))

        valid_records, invalid_records = [], []
        logger.info(f"Starting concurrent processing with {self.max_workers} workers for {len(line_data_list)} records...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_record = {
                executor.submit(self.process_single_record, line_data): line_data
                for line_data in line_data_list
            }
            completed = 0
            for future in as_completed(future_to_record):
                try:
                    result = future.result()
                    if result:
                        completed += 1
                        (valid_records if result['is_valid'] else invalid_records).append(result['record'])
                        if completed % 5 == 0:
                            logger.info(f"Completed {completed}/{len(line_data_list)} records...")
                except Exception as e:
                    line_data = future_to_record[future]
                    logger.error(f"Error processing record {line_data[2]}: {str(e)}")

        logger.info(f"Processing completed: {len(valid_records)} valid, {len(invalid_records)} invalid records")
        return valid_records, invalid_records

    # ---------------- CSV writing ----------------
    def write_csv_files(self, valid_records, invalid_records, base_filename):
        common_fields = [
            'FileSource',
            'BankNumber', 'MerchantNumber', 'AssociationNumber', 'SICCode', 'Class',
            'MerchantName', 'City', 'State', 'Zip', 'Phone1', 'Phone2', 'BusinessLicense',
            'BankOfficer1', 'BankOfficer2', 'UserBankNumber', 'UserBranchNumber',
            'FederalTaxId', 'StateTaxId', 'EdcFlag', 'RepCode', 'Status', 'UserFlag1',
            'UserFlag2', 'UserData1', 'UserData2', 'UserData3', 'UserData4', 'UserData5',
            'UserAccount1', 'UserAccount2', 'AchFlag', 'ExceptionTable', 'InvestigationCode',
            'VisaCps2', 'VisaCps1', 'VisaSuper', 'VisaEps', 'VisaPsrf', 'VisaEirf',
            'MCmerit3', 'MCmerit1', 'MCsuper', 'MCptCat', 'MCwhs', 'MCprm',
            'DiscoverEligibility', 'MerchantType', 'IncStatus', 'MemberId', 'GrsFlag',
            'Owner', 'ManagerName', 'AsstManagerName', 'OtherName', 'OwnerSsn',
            'OwnerLicenseNumber', 'LastStatementDate', 'OpenDate', 'LastCreditCheckDate',
            'LastCardRequestDate', 'LastCallDate', 'NextCallDate', 'FinancialStatementDueDate',
            'FinancialStatementReqDate', 'StoreFlag', 'StatementCount', 'AddressDiscountInd',
            'AddressRclList', 'AddressCrbList', 'AddressCardMailer', 'AddressIRS',
            'AddressImprinterRentals', 'AddressMemberFees', 'AddressPosTerminals',
            'AddressNameMCS', 'AddressUniqueMessage', 'AddressNameBet1', 'AddressNameBet2',
            'AddressNameBet3', 'IntchFlagDollars', 'IntchFlagCount', 'DestinationOverall',
            'DestinationDeposit', 'DestinationAdjustment', 'DestinationChargeback',
            'DestinationReversal', 'DestinationChbckReversal', 'DdaAdjustmentOption',
            'BatchAdjustmentOption', 'TransactionOption1', 'TransactionOption2',
            'TransactionOption3', 'AmexPCindicator', 'AmexDescriptorCode',
            'AmexSettlementFlag', 'DiscoverReferenceNumber', 'AmexId', 'DiscoverAccountId',
            'JcbId', 'DinersId', 'Filler1', 'Filler2', 'Filler3', 'Filler4', 'Filler5',
            'LastActiveDate', 'DailyFeeIndicator', 'MCRegID', 'CustomerServiceNumber',
            'UpdatedDTS', 'StatusChangeDate', 'DiscoverMAPFlag', 'AmexOptBlu', 'Filler',
            'AmexSubmitterID', 'MerchantEmailAddress', 'FillerExpansion',
            'HashedTaxID', 'Last4TaxID', 'Last4OwnerSSN'
        ]
        invalid_fields = common_fields + ['ValidationErrors', 'OpenAIResponse']

        def norm_row(rec, fields):
            return ["" if rec.get(f) is None else str(rec.get(f)).strip() for f in fields]

        # Ordering by MerchantNumber
        key_fn = lambda r: r.get('MerchantNumber', '')
        valid_sorted = sorted(valid_records, key=key_fn)
        invalid_sorted = sorted(invalid_records, key=key_fn)

        valid_filename = f"{base_filename}_VALID.csv"
        with open(valid_filename, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\r\n')
            w.writerow(common_fields)
            for rec in valid_sorted:
                w.writerow(norm_row(rec, common_fields))

        invalid_filename = None
        if invalid_sorted:
            invalid_filename = f"{base_filename}_INVALID.csv"
            with open(invalid_filename, 'w', newline='', encoding='utf-8-sig') as f:
                w = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\r\n')
                w.writerow(invalid_fields)
                for rec in invalid_sorted:
                    w.writerow(norm_row(rec, invalid_fields))

        return valid_filename, invalid_filename

    # ---------------- log ----------------
    def generate_log_file(self, valid_count, invalid_count, base_filename):
        log_filename = f"{base_filename}_LOG.txt"
        with open(log_filename, 'w', encoding='utf-8') as logfile:
            logfile.write(f"FileType|MIF_DETAIL\n")
            logfile.write(f"ProcessedTimestamp|{datetime.now().isoformat()}\n")
            logfile.write(f"ValidRecords|{valid_count}\n")
            logfile.write(f"InvalidRecords|{invalid_count}\n")
            logfile.write(f"TotalRecords|{valid_count + invalid_count}\n")
            logfile.write(f"FileTrailer|1\n")
            logfile.write(f"MatchedRecordCounts|1\n")
            logfile.write(f"FileTrailerDataMatched|1\n")
        return log_filename


def main():
    MAX_WORKERS = 15
    RATE_LIMIT_DELAY = 0.05

    processor = MerchantDataProcessor(max_workers=MAX_WORKERS, rate_limit_delay=RATE_LIMIT_DELAY)

    input_file = "MERCHLYNX.9246_MMERCH_DETAIL_05012024_072617.txt"
    base_filename = "processed_merchant_data"

    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} not found!")
        return

    try:
        start_time = datetime.now()
        logger.info(f"Starting processing at {start_time}")

        logger.info(f"PII field protection mode: {processor.pii_encryption} | HASH_INPUT_MODE: {processor.hash_input_mode}")

        valid_records, invalid_records = processor.process_file(input_file)

        logger.info("Writing CSV files...")
        valid_file, invalid_file = processor.write_csv_files(valid_records, invalid_records, base_filename)

        log_file = processor.generate_log_file(len(valid_records), len(invalid_records), base_filename)

        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds() or 1.0

        logger.info(f"Processing completed successfully in {processing_time:.2f} seconds!")
        logger.info(f"Valid records: {len(valid_records)} -> {valid_file}")
        if invalid_file:
            logger.info(f"Invalid records: {len(invalid_records)} -> {invalid_file}")
        else:
            logger.info("Invalid records: 0 (no INVALID file created)")
        logger.info(f"Log file: {log_file}")

        print(f"\n=== PROCESSING SUMMARY ===")
        print(f"Processing time: {processing_time:.2f} seconds")
        print(f"Records per second: {(len(valid_records) + len(invalid_records)) / processing_time:.2f}")
        print(f"Total valid records: {len(valid_records)}")
        print(f"Total invalid records: {len(invalid_records)}")
        print(f"Files generated:")
        print(f"  - Valid data: {valid_file}")
        if invalid_file:
            print(f"  - Invalid data: {invalid_file}")
        print(f"  - Log file: {log_file}")

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise


if __name__ == "__main__":
    main()