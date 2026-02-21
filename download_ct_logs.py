#!/usr/bin/env python3
# Built in Python 3.12.3
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2025-2026 AskKemp.com"
__license__ = "agpl-3.0"

import json
import os
import logging
import base64
import requests
from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, GreedyBytes, GreedyRange, Terminated
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
import tqdm  # on screen progress bar
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from OpenSSL import crypto  # fallback parsing - warning: module is pending deprecation
import gzip
import logging.handlers
import shutil
import uuid
import datetime
import sys
import time
import signal
import argparse
import traceback
#import ua_generator  # https://github.com/iamdual/ua-generator
from pathlib import Path
from pkilint import loader, report
import pkilint.pkix
import io

#
# Hardcoded config
#
# - This is used to set the S3 bucket name and DynamoDB table name.

# Dynamodb table name
CT_STATE_TABLE = "CT_STATE_TABLE"

# S3 bucket name
S3_BUCKET = "ct-results"

# AWS Boto3 setup (DynamoDB and S3)
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:9043',  # used when using not AWS but instead S3 replacement
    region_name='None',
    aws_access_key_id='None',
    aws_secret_access_key='None'
)

s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:9000',
    aws_access_key_id='myuseraccesskey',
    aws_secret_access_key='myusersecretkey',
)

#
# Logging Configuration #1
#
# - stdoutlogger writes to standard out
stdoutlogger = logging.getLogger('root')
stdoutlogger.setLevel(logging.INFO)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
stdoutlogger.addHandler(stdout_handler)

# log rotation code from https://docs.python.org/3/howto/logging-cookbook.html#using-a-rotator-and-namer-to-customize-log-rotation-processing
def namer(name: str) -> str:
    """Appends .gz to the filename for log rotation."""
    return name + ".gz"

def rotator(source: str, dest: str) -> None:
    """Rotates and compresses the log file and uploads the compressed file to S3.
    
    Args:
        source (str) Source filename to rotate. Appears to be the full file path.
        dest (str) Destination filename to rotate to.

    Returns:
        None
    """
    dest_filename = Path(dest).name # str e.g. ct_0f50af63-b4f4-4db8-877e-5ff33a248e2a.log.1.gz
    dest_filename = dest_filename.replace('.log.1.gz', '')

    with open(source, 'rb') as f_in:
        with gzip.open(dest, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    short_uuid = str(uuid.uuid4())[:4] # needed to create unique filename to prevent accidental overwriting in S3
    upload_key_name = (
        f"{dest_filename}-{short_uuid}-"
        f"{datetime.datetime.now().strftime('%Y-%m-%dT%H')}.gz"  # including date time in the filename for possible future debugging
    )  # e.g. ct_00b87e75-e301-4572-8db2-02d678370325-0da4-2025-09-18T19.gz
    stdoutlogger.info(f"Uploading {upload_key_name} to S3 bucket {S3_BUCKET}")
    try:
        s3.upload_file(dest, S3_BUCKET, upload_key_name)
    except EndpointConnectionError as e:
        stdoutlogger.critical(f"\nUpload of {source} failed to S3 bucket {S3_BUCKET}! This file will need to be manually uploaded to S3. The reported error is: {e}")
        stdoutlogger.critical(f"Exiting...")
        sys.exit(1)
    # Check if the file exists in S3 after upload
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=upload_key_name)
        stdoutlogger.info(f"Validated successful upload of {upload_key_name} to S3 bucket {S3_BUCKET}")
    except ClientError as e:
        stdoutlogger.critical(f"\nWhen checking to see if the file successfully uploaded, verification failed for {upload_key_name} to S3. The reported error is: {e}")
        stdoutlogger.critical(f"Exiting...")
        sys.exit(1)
    os.remove(source)

# Create a new directory
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

# Unique log file name for this instance of the script
unique_name = "ct_" + str(uuid.uuid4()) + ".log"
log_file = log_dir / unique_name # type pathlib.PosixPath

# maxBytes controls the size of the file when it gets rotated
# Should consider how long OS or Docker will kindly wait for process to terminate
# Because the log needs to be rotated and uploaded to S3 before Docker kill timeout is hit
rh = logging.handlers.RotatingFileHandler(
    log_file, # type pathlib.PosixPath. Supported since Python 3.6.
    maxBytes = 1024 * 1024 * 500,  # Rotate after 500MB and GZIP will be about 50MB
    backupCount = 1,  # Number of backup files to keep
)
rh.rotator = rotator
rh.namer = namer

#
# Logging Configuration #2
#
# - ctlogging writes to files which are rotated automatically and uploaded to S3
ctlogging = logging.getLogger('ctlog')
ctlogging.setLevel(logging.INFO)
ctlogging.addHandler(rh)
ctlogging.propagate = False # important to prevent logs from also going to stdoutlogger which puts this also on stdout
f = logging.Formatter('%(message)s')
rh.setFormatter(f)

# To see specifics on new session creation for requests/urllib3
# log = logging.getLogger('urllib3')
# log.setLevel(logging.DEBUG)


#
# Signal
#
# - To prevent data loss, when signal occurs, force log rotation which causes current output log to be uploaded to s3
def interrupt_handler(signum: int, frame) -> None:
    """
    Custom handler to deal with when a signal is received. It causes the logs to rotate which forces the current
    output log to be uploaded to s3. Without this, the currently written log would be lost because it never
    makes it to s3.
    """
    stdoutlogger.critical(
        f'Gracefully shutting down due to signal {signum} ({signal.Signals(signum).name}). PLEASE WAIT.'
    )
    print(
        f'Gracefully shutting down due to signal {signum} ({signal.Signals(signum).name}). PLEASE WAIT.'
    )
    rh.doRollover()  # Force last log to rotate which causes it to go to S3
    time.sleep(1)
    sys.exit(0)

signal.signal(signal.SIGINT, interrupt_handler)

def create_session(proxy_session_settings: dict = None) -> requests.Session:
    """
    Create requests session

    Args:
     - pool_connections allow cache connection to host so a new tls connection does not have to be built for each request which make downloads faster
     - Note: it seems if you can get a session that returns a high step count (RFC 6962) then you can keep that session for a very long time even if a new session would return a much lower step size
     - Future: Maybe use drop in replacement for requests to allow for rate limiting per CT domain: https://github.com/JWCook/requests-ratelimiter
     - Creates random desktop user agent for the session using ua_generator (disabled)
     - User repo url as user agent (enabled)

     Returns:
       session (<class 'requests.sessions.Session'>)
    """
    session = requests.Session()
    if proxy_session_settings:  # use proxy
        if not isinstance(proxy_session_settings, dict):  # input has to be correct format
            raise RuntimeError("Proxy setting are not in correct dict format. Exiting.")
        session.proxies = proxy_session_settings

    session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=10))

    # The session will have a single randomly generated UA
    # digicert immediately HTTP 429 when using this type of UA
    #session.headers = ua_generator.generate(device='desktop', browser=('chrome', 'edge')).headers.get()

    # digicert does NOT thottle when using this UA
    session.headers = {
    #    "Content-Type": "application/ocsp-request",
    #    "Connection": "close", # For debuging. Closing the connection will cut rate of certificate download IN HALF!
        "User-Agent": "https://github.com/askkemp/Python-Certificate-Transparency-Log-Downloader",
    }
    return session


def pki_validation(cert_as_der: bytes, fingerprint: str) -> bool:
    """
    Run PKI lint checks against a certificate and detect fatal findings.
    The purpose of this function is to help with debugging parsing failures.
    Code from https://github.com/digicert/pkilint/blob/main/pkilint/bin/lint_pkix_cert.py

    Args:
        cert_as_der (bytes) certificate in DER format. Used for debugging
        fingerprint (str)

    Returns:
        bool: True if a fatal finding is detected, otherwise False.
    """
    found_fatal = False
    doc_validator = pkilint.pkix.certificate.create_pkix_certificate_validator_container(
        pkilint.pkix.certificate.create_decoding_validators(
            pkilint.pkix.name.ATTRIBUTE_TYPE_MAPPINGS, pkilint.pkix.extension.EXTENSION_MAPPINGS
        ),
        [
            pkilint.pkix.certificate.create_issuer_validator_container([]),
            pkilint.pkix.certificate.create_validity_validator_container(),
            pkilint.pkix.certificate.create_subject_validator_container([]),
            pkilint.pkix.certificate.create_extensions_validator_container([]),
            pkilint.pkix.certificate.create_spki_validator_container([]),
        ],
    )

    cert_lint = pkilint.loader.RFC5280CertificateDocumentLoader().load_der_document(cert_as_der)
    results = doc_validator.validate(cert_lint.root)

    for result in results:
        finding = result.finding_descriptions
        if finding:
            for item in finding:
                if "FATAL" in str(item):
                    stdoutlogger.info(f'PKI validation failure: {fingerprint}: {item}')
                    found_fatal = True
    return found_fatal


def collect_certificate_metadata_PyOpenSSL_fallback(cert_as_der: bytes) -> dict:
    """
    Using PyOpenSSL module to dump metadata from certificate. This module is not as strict
    as pyca/cryptography meaning it will parse data which pyca/cryptography will not.

    e.g. fa:9e:71:92:68:cf:aa:05:d8:e8:c3:46:7b:c2:bd:a5:4b:1a:18:3b will not parse with
    pyca/cryptography but will parse with PyOpenSSL crypto. pkilint finds a fatal issue
    with the extensions to it makes sense that it is not a RFC compliant cert.

    Warning: The OpenSSL.crypto module is pending deprecation.
    See https://www.pyopenssl.org/en/latest/api/crypto.html
    Last checked correctly working with version PyOpenSSL 25.3.0 (Sep 17, 2025)

    Args:
        cert_as_der (bytes) certificate in DER format. Used for debugging

    Returns:
        dict
        - fingerprint
        - common_name from subject
        - subjectAltName_DNS = list of domains extracted from subjectAltName DNS
    """
    temp_dict = {}
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_as_der)
    subject = certificate.get_subject()
    temp_dict["common_name"] = subject.CN
    temp_dict["fingerprint"] = certificate.digest("sha1")
    # issuer = certificate.get_issuer()
    # sn = certificate.get_serial_number()
    # extension_count = certificate.get_extension_count()

    all_domains = set()
    for i in range(certificate.get_extension_count()):
        ext = certificate.get_extension(i)
        ext_name = ext.get_short_name()
        if ext_name == b"subjectAltName":
            ext_dat = ext.get_data()
            SAN = ext.__str__()
            if SAN:
                for entry in SAN.split(', '):
                    if entry.startswith('DNS:'):
                        all_domains.add(entry.replace('DNS:', ''))

    temp_dict["subjectAltName_DNS"] = list(all_domains)
    return temp_dict


def collect_certificate_metadata(cert_as_der: bytes) -> dict:
    """
    Extract metadata from a DER certificate.

    Args:
        cert_as_der (bytes): Certificate in DER format.

    Returns:
        dict: Metadata including fingerprint, issuer, subject, validity,
        common name, and subjectAltName values.

    Notes:
        If strict parsing with pyca/cryptography fails, this function prints
        the DER bytes for debugging, rolls logs, and exits the process.
    """

    temp_dict = {}

    try:
        # Load certificate
        cert = x509.load_der_x509_certificate(cert_as_der) # input is bytes
    except ValueError as e:
        # Extremely rare there are certs that cannot be parsed. 
        # https://github.com/pyca/cryptography/issues/9253
        # https://ct.cloudflare.com/logs/nimbus2025/ct/v1/get-entries?start=684843008&end=684844031 in this batch is one that causes the below exception
        # error parsing asn1 value: ParseError { kind: ExtraData, location: ["Certificate::signature_alg"] }
        # {'common_name': 'cPanel, Inc. Certification Authority', 'fingerprint': b'5F:24:80:0B:AA:47:8A:AB:9C:B9:A6:84:3B:11:11:37:24:AB:5B:DB:C7:AB:C4:B0:20:7A:7E:8D:08:57:3C:B5'}
        # and that cert is not even in crt.sh and pylint errors on it so it must be super busted
        stdoutlogger.error(
            f"\n{e}: Unable to parse certificate bytes with pyca/cryptography. THIS SHOULD NOT EVER HAPPEN. Printing DER bytes to stdout for debugging."
        )
        print("\n-----BEGIN CERT_DER_BASE64-----")
        print(base64.b64encode(cert_as_der).decode("ascii"))
        print("-----END CERT_DER_BASE64-----")
        rh.doRollover()
        sys.exit(1)
   
    # Metadata
    temp_dict["fingerprint"] = cert.fingerprint(hashes.SHA1()).hex(":")  # e.g. d0:d9:47:88:32:eb:66:ae:c7:5b:b2:9e:92:64:6b:59:77:8e:9d:30
    temp_dict["issuer"] = cert.issuer.rfc4514_string()  # e.g. CN=Amazon RSA 2048 M02,O=Amazon,C=US
    temp_dict["subject"] = cert.subject.rfc4514_string()  # e.g. CN=*.dlzmt2ncmky0v.amplifyapp.com
    temp_dict["not_valid_before"] = cert.not_valid_before_utc  # e.g. 2023-06-24 00:00:00+00:00
    temp_dict["not_valid_after"] = cert.not_valid_after_utc  # e.g. 2024-07-22 23:59:59+00:00

    # Get CommonName value
    # - RFC 2818 deprecates the use of the Common Name (CN) field in HTTPS certificates for subject name verification.
    try:
        temp_dict["cn"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value # e.g. *.dlzmt2ncmky0v.amplifyapp.com
    except Exception: # Sometimes the CN does not extract even though crt.sh shows one. e.g., 5a:af:57:73:cc:e0:20:f6:d6:12:46:16:98:98:b3:5d:80:d7:8e:f8
        fatal_check = pki_validation(cert_as_der, temp_dict["fingerprint"])
        if fatal_check:
            temp_dict["validation"] = "Fatal"
        temp_dict["cn"] = collect_certificate_metadata_PyOpenSSL_fallback(cert_as_der)["common_name"]

    # Get the subjectAltName extension from the certificate
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # Get the dNSName entries from the SAN extension
        temp_dict["subjectAltName"] = ext.value.get_values_for_type(x509.DNSName) # e.g. ["*.dlzmt2ncmky0v.amplifyapp.com", "dlzmt2ncmky0v.amplifyapp.com"]
    except Exception: # pyca is very strict on parsing so sometimes must fall back to deprecated PyOpenSSL
        fatal_check = pki_validation(cert_as_der, temp_dict["fingerprint"])
        if fatal_check:
            temp_dict["validation"] = "Fatal"
        temp_dict["subjectAltName"] = collect_certificate_metadata_PyOpenSSL_fallback(cert_as_der)["subjectAltName_DNS"]

    # OUTPUT
    return temp_dict

def tile_process_log_entry(tile: bytes, expected_entries: int) -> None:
    """
    Parse and process entries from a Static CT data tile.

    Reads each tile entry in wire order, determines the entry type (x509 vs precert),
    extracts the certificate payload, builds metadata with collect_certificate_metadata,
    and writes JSON output to ctlogging.

    The expected entry encoding is based on sunlight ReadTileLeaf:
    https://github.com/FiloSottile/sunlight/blob/2eedfb66eed20212850e0b907191a0ee51779652/tile.go#L157

    Args:
        tile (bytes) - Raw bytes for one static CT data tile.
        expected_entries (int) - Number of entries expected in the tile. For now this is 256 (full tile)

    Returns:
        None
    """

    def _read_exact(buf: io.BytesIO, n: int) -> bytes:
        data = buf.read(n)
        if len(data) != n:
            raise EOFError(f"Unexpected end of tile reading {n} bytes")
        return data
    
    def _read_u16(buf: io.BytesIO) -> int:
        return int.from_bytes(_read_exact(buf, 2), "big")
    
    def _read_u24_bytes(buf: io.BytesIO) -> bytes:
        payload_length = int.from_bytes(_read_exact(buf, 3), "big")
        return _read_exact(buf, payload_length)
    
    def _read_u16_len_bytes(buf: io.BytesIO) -> bytes:
        payload_length = _read_u16(buf) # First buf.read moves the stream position forward by 2 bytes to read the length
        return _read_exact(buf, payload_length) # Then read the payload of that length
    
    buf = io.BytesIO(tile) # load tile bytes into buffer

    # Decode exactly the number of entries expected for this tile (full=256, partial=.p/W).
    for _ in range(expected_entries):
        entry_start = buf.tell() #  current file position used for debugging
        try:
            # 1) Timestamp (uint64 big-endian)
            timestamp = int.from_bytes(bytes=buf.read(8), byteorder="big")  # Must use becuase buf.read moves the stream position forward each time
            # 2) Entry type (uint16): 0=x509_entry, 1=precert_entry.
            entry_type = int.from_bytes(bytes=buf.read(2), byteorder="big")
            if entry_type == 0: # x509_entry
                # 3a) X509 leaf cert bytes (u24 length-prefixed).
                cert_der = _read_u24_bytes(buf)
                # 4) CTExtensions blob (u16 length-prefixed).
                ext_bytes = _read_u16_len_bytes(buf)
                # 5) Chain fingerprints blob (u16 length-prefixed; 32-byte chunks).
                chain_bytes = _read_u16_len_bytes(buf)
                precert_der = None
            elif entry_type == 1: # precert_entry
                # 3b) Precert issuer key hash (32 bytes).
                issuer_hash = int.from_bytes(bytes=buf.read(32), byteorder="big")  # Must use becuase buf.read moves the stream position forward each time
                # 4) Main cert/precert blob (u24 length-prefixed).
                cert_der = _read_u24_bytes(buf)
                # 5) CTExtensions blob (u16 length-prefixed).
                ext_bytes = _read_u16_len_bytes(buf)
                # 6) Explicit pre-certificate bytes (u24 length-prefixed).
                precert_der = _read_u24_bytes(buf)
                # 7) Chain fingerprints blob (u16 length-prefixed; 32-byte chunks).
                chain_bytes = _read_u16_len_bytes(buf)
            else:
                stdoutlogger.critical(f"Unknown entry_type {entry_type} at offset {entry_start}. Something is seriously wrong!")
                rh.doRollover()
                sys.exit(1)

            payload = precert_der if precert_der is not None else cert_der
            cert_as_der = payload
            metadata = collect_certificate_metadata(cert_as_der)
            ctlogging.info(json.dumps(metadata, default=str))
            #print(metadata)
        except Exception as e:
            stdoutlogger.critical(f"Failed to parse tile entry starting at offset {entry_start}: {e}")
            rh.doRollover()
            sys.exit(1)
    return
        


def rfc6962_process_log_entry(entry: dict, url: str) -> None:
    """
    Given an entry from the CT log, determine the entry type and where the certificate data is located.
    Once determined, it sends the certificate to have the metadata created/extracted (collect_certificate_metadata).
    The output from collect_certificate_metadata is then written to file

    Args:
        entry (dict) containing the keys leaf_input and extra_data.
            The location of the certificate is dependent on the log entry type. See code comments for details.
            e.g. and entry is one item from the list at https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=5
        url (str) is the url of the ct log. Only used for error reporting

    Returns:
        None
    """

    #
    # Define Merkle tree headers and certificates structure
    #
    # - RFC https://datatracker.ietf.org/doc/html/rfc6962#section-3.4
    # - Previous work
    #   - https://github.com/rajivchocolate/CTLogInspector/blob/main/lambdas/ct_log_processing.py#L35
    #   - https://github.com/CaliDog/Axeman/blob/master/axeman/certlib.py#L17
    MerkleTreeHeader = Struct(
        "Version" / Byte,
        "MerkleLeafType" / Byte,
        "Timestamp" / Int64ub,
        "LogEntryType" / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),  # x509_entry or precert_entry
        "Entry" / GreedyBytes,  # signed_entry
    )
    Certificate = Struct("Length" / Int24ub, "CertData" / Bytes(lambda ctx: ctx.Length))
    CertificateChain = Struct("ChainLength" / Int24ub, "Chain" / GreedyRange(Certificate))
    PreCertEntry = Struct(
        "LeafCert" / Certificate,
        "CertificateChain" / CertificateChain,
        Terminated
    )
    
    try:
        leaf_input = base64.b64decode(entry['leaf_input'])  # The base64-encoded MerkleTreeLeaf structure.
        extra_data = base64.b64decode(entry['extra_data'])  # The base64-encoded unsigned data pertaining to the log entry. In the case of an X509ChainEntry, this is the "certificate_chain".  In the case of a PrecertChainEntry, this is the whole "PrecertChainEntry".

        mth = MerkleTreeHeader.parse(leaf_input)
        if mth.LogEntryType == "X509LogEntryType":
            # Parse
            cert_as_der = Certificate.parse(mth.Entry).CertData
            metadata = collect_certificate_metadata(cert_as_der)

        elif mth.LogEntryType == "PrecertLogEntryType": 
            # Parse
            PrecertChainEntry = PreCertEntry.parse(extra_data) #construct.lib.containers.Container
            cert_as_der = PrecertChainEntry.LeafCert.CertData
            # Extract metadata from certificate
            metadata = collect_certificate_metadata(cert_as_der)

        else:
            stdoutlogger.critical(f"\nUNKNOWN CT Log Entry Type: {mth.LogEntryType}.... Something is very wrong.")
            rh.doRollover()
            sys.exit(1)

        ctlogging.info(json.dumps(metadata, default=str))
        return

    except Exception as e:
        stdoutlogger.critical(f"\nrfc6962_process_log_entry - {str(e)}: Unable to process {url}")
        print(traceback.format_exc())
        rh.doRollover()
        sys.exit(1)


def rfc6962_fetch_and_process_ct_log_entries(s: requests.Session, ct_log_url: str, start: int, end: int) -> tuple[bool, int]:
    """
    Performs the download of the CT log (RFC 6962).

    Args:
        s (<class 'requests.sessions.Session'>) - requests session
        ct_log_url (str) - e.g. https://ct.googleapis.com/logs/argon2020/
        start (int) - used in requests params as first log entry to receive
        end (int) - used in requests params as last log entry to receive

    Returns:
        tuple of (throttled, len(log_entries))
        len(log_entries) (int) - Number of entries returned in the request. Later used to validate the start/end params return matches the request
        throttled (bool) - True for retryable request failures (e.g. 429/500/501/400/404 or transport errors).
    """
    entries_url = f"{ct_log_url}ct/v1/get-entries" # e.g. https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=5
    stdoutlogger.debug(f'{ct_log_url}ct/v1/get-entries?start={start}&end={end}')
    params = {'start': start, 'end': end} # start will be the last known position that was downloaded. end is dynamically determined.
    throttled = False
    try:
        response = s.get(entries_url, params=params, timeout=5)
        if response.status_code == 200:
            throttled = False
            log_entries = response.json()['entries']
            stdoutlogger.debug(f'Number entries returned from CT url: {len(log_entries)}')
            for entry in log_entries:
                 rfc6962_process_log_entry(entry, ct_log_url)
            return (throttled, len(log_entries))
        elif response.status_code == 429: # Too Many Requests
            stdoutlogger.warning(f"HTTP {response.status_code} on {ct_log_url}")
            throttled = True
            return (throttled, 0)
        elif response.status_code == 500: # Internal Server Error
            stdoutlogger.warning(f"HTTP {response.status_code} on {ct_log_url}")
            throttled = True
            return (throttled, 0)
        elif response.status_code == 501: # Not Implemented
            stdoutlogger.warning(f"HTTP {response.status_code} on {ct_log_url}")
            throttled = True
            return (throttled, 0)
        elif response.status_code == 400: # Bad Request
            stdoutlogger.warning(f"HTTP {response.status_code} on {ct_log_url}")
            throttled = True
            return (throttled, 0)
        elif response.status_code == 404: # Not Found
            # <html><head><title>CT Log</title></head><body><h1>NOT FOUND</h1></body></html>
            # - tried it again and it was not a 404 and returned correct data
            stdoutlogger.warning(f"HTTP {response.status_code} on {ct_log_url}")
            throttled = True
            return (throttled, 0)
        else:
            stdoutlogger.critical(
                f"Response code of {response.status_code} not dealt with in code. Unable to process {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
            stdoutlogger.critical(response.text)
            rh.doRollover()
            sys.exit(1) # because I need to add code to deal with it
    except requests.exceptions.ReadTimeout as e:
        stdoutlogger.error(f"rfc6962_fetch_and_process_ct_log_entries - {e}: Timeout on {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ConnectionError as e:
        stdoutlogger.error(f"rfc6962_fetch_and_process_ct_log_entries - {e}: General ConnectionError on {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ChunkedEncodingError as e:
        stdoutlogger.error(f"rfc6962_fetch_and_process_ct_log_entries - {e}: ChunkedEncodingError (response ended prematurely) on {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
        throttled = True
        return (throttled, 0)
    except Exception as e:
        stdoutlogger.critical(f"rfc6962_fetch_and_process_ct_log_entries - {e}: Unable to process {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
        print(traceback.format_exc())
        rh.doRollover()
        sys.exit(1)

def tile_fetch_and_process_ct_log_entries(s: requests.Session, url: str, tile_index: int) -> tuple[bool, int]:
    """
    Download and process a single static CT data tile.

    Builds the tile path from tile_index using the static-ct/tlog base-1000 path
    encoding, requests the tile bytes, and on success passes the bytes to
    tile_process_log_entry for parsing and metadata logging.

    Args:
        s (<class 'requests.sessions.Session'>) - requests session
        url (str) - CT monitoring URL. e.g. https://mon.willow.ct.letsencrypt.org/2027h2/
        tile_index (int) - tile index to fetch from /tile/data/ e.g. 1234067

    Returns:
        tuple of (throttled, tile_bytes_len)
        throttled (bool) - True when a retryable request failure happened.
        tile_bytes_len (int) - Number of bytes returned when HTTP 200 succeeds, else 0.
    """

    # https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md states:
    #   <N> is the index of the tile within the level. It MUST be a non-negative integer encoded into zero-padded 3-digit path elements. 
    #   All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as x001/x234/067. 
    #   (This allows storing tile resources efficiently in a filesystem without file/directory conflicts, and serving them directly.)
    # Below modeled after https://github.com/crtsh/ct_monitor/blob/master/ct/staticGetEntries.go#L134
    base = 1000
    encoder = f"{tile_index % base:03d}" # format as a decimal integer (d) with at least 3 digits, padding with leading zeros (0) if needed
    while tile_index >= base:
        tile_index //= base
        encoder = f"x{tile_index % base:03d}/{encoder}"
    path_layout = encoder
        
    # From https://github.com/C2SP/C2SP/blob/main/static-ct-api.md
	#   Full tile:   /tile/data/<N>        (256 entries)
	#   Partial tile:/tile/data/<N>.p/<W>  (last tile snapshot with W entries) - NOT supported in my code to avoid complexity of dealing with partial tiles.
    #   The entries in a data tile match the entries in the corresponding "level 0" tile. 
    #   Clients SHOULD include gzip and identity in their Accept-Encoding headers.
    tile_url = url.rstrip("/") + "/tile/data/" + path_layout
    throttled = False
    try:
        response = s.get(tile_url, timeout=5, headers={"Accept-Encoding": "gzip, identity"})
        if response.status_code == 200:
            throttled = False
            stdoutlogger.debug(f'Bytes returned from CT url: {len(response.content)}')
            tile_process_log_entry(response.content, expected_entries=256)  # expected_entries allows for future extension to deal with partial tiles
            return (throttled, len(response.content))
        elif response.status_code == 500: # Internal Server Error
            stdoutlogger.warning(f"HTTP {response.status_code} on {tile_url}")
            throttled = True
            return (throttled, 0)
        else:
            stdoutlogger.critical(f"Response code of {response.status_code} not dealt with in this code. Unable to process tile_url {tile_url}.")
            stdoutlogger.critical(response.text)
            rh.doRollover()
            sys.exit(1) # because I need to add code to deal with it
    except requests.exceptions.ReadTimeout as e:
        stdoutlogger.error(f"tile_fetch_and_process_ct_log_entries - {e}: Timeout on tile_url {tile_url}")
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ConnectionError as e:
        stdoutlogger.error(f"tile_fetch_and_process_ct_log_entries - {e}: General ConnectionError on tile_url {tile_url}")
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ChunkedEncodingError as e:
        stdoutlogger.error(f"tile_fetch_and_process_ct_log_entries - {e}: ChunkedEncodingError (response ended prematurely) on tile_url {tile_url}")
        throttled = True
        return (throttled, 0)
    except Exception as e:
        stdoutlogger.critical(f"tile_fetch_and_process_ct_log_entries - {e}: Unable to process tile_url {tile_url}")
        print(traceback.format_exc())
        rh.doRollover()
        sys.exit(1)


def start_ct_process(input_ct_url: str, remove_progress_bar: bool = False) -> None:
    """
    Kick off CT download and parsing for one CT URL.
    
    Uses DynamoDB state to look up the URL, determine `ct_log_type`
    (`tiled` or `rfc6962`), and track progress (`current_position`).

    For RFC 6962 logs, it dynamically adjusts the step size to match the number of entries returned to ensure nothing is missed.

    Args:
        input_ct_url (str) e.g. https://ct.googleapis.com/logs/eu1/solera2025h2/ (must have final /)
        remove_progress_bar (bool) True to remove on screen progress bar.

    Returns:
        None
    """
    # Input URL validation
    if not input_ct_url.endswith('/'):
        stdoutlogger.critical("CT URL must end with '/'. e.g. https://ct.googleapis.com/logs/eu1/solera2025h2/ ")
        sys.exit(1)

    # init requests session
    session = create_session()

    state_table = dynamodb.Table(CT_STATE_TABLE) # tracks download progress per CT URL
    response = state_table.scan()
    ct_log_urls = [item['url'] for item in response['Items']]

    throttled = False
    found_ct_url_match = False
    for ct_log_url in ct_log_urls:
        if ct_log_url != input_ct_url:
            continue
        found_ct_url_match = True

        # Fetch state from DynamoDB
        state = state_table.get_item(Key={'url': ct_log_url}).get('Item', {})
        ct_log_type = state.get("ct_log_type") # tiled or rfc6962
        start_position = int(state.get("current_position")) # Download progress. Equal to start parameter in URL.
        tree_size = int(state.get("tree_size")) # last available item at the CT URL. e.g. the final end parameter value
        stdoutlogger.info(f"Starting to process CT URL: {ct_log_url}. Type: {ct_log_type}. Current position: {start_position}. Tree size: {tree_size}.")

        # on screen progress bar settings
        pbar = tqdm.tqdm(total=tree_size, initial=start_position, mininterval=1, disable=remove_progress_bar) # on screen progress bar
        pbar.set_description(f'{ct_log_url} [{ct_log_type}]')

        #
        # Type: static tiled
        #
        if ct_log_type == "tiled":
                  
            # Determine if the download is already complete before starting
            if start_position >= tree_size:
                stdoutlogger.info(f"\n\nCT log {ct_log_url} complete!!!")
                print(f"\n\nCT log {ct_log_url} complete!!!\n")
                rh.doRollover()
                sys.exit(0)
                      
            stdoutlogger.debug(f"Downloading entries [{start_position}, {tree_size}).")
            # Static-ct data tiles hold up to 256 leaves each
            starting_tile = start_position // 256 # 0
            last_tile = (tree_size - 1) // 256 # (4599 - 1) // 256 = 17
            total_tiles_to_fetch = last_tile - starting_tile + 1
            stdoutlogger.info(f"Starting at tile {starting_tile}. Must fetch total tile count of {total_tiles_to_fetch} containing total entries of {tree_size - start_position}.")

            # Iterate tile-by-tile from first required tile to last required tile. But ignore the partial tile.
            # If a request is throttled/failed, retry the same tile_idx until it succeeds.
            tile_idx = starting_tile
            while tile_idx <= last_tile:
                current_position = tile_idx * 256 # each tile has 256 entries, so tile 0 starts at 0, tile 1 starts at 256, etc.
                current_tile_end = current_position + 256
           
                # The latest and greatest tile may be partial and url .p/<W> is for that case. BUT!
                # But I dont want to deal with partial tiles so if the width is off, then it is a partial tile so then stop.
                if current_tile_end > tree_size:
                    width = tree_size - current_position
                    if width <= 256:
                        stdoutlogger.warning(f"Tile {tile_idx} of {last_tile} is partial (has a width of {width} instead of 256). Stopping to avoid complexity of dealing with partial tiles. Wait a while for the partial tile to be filled. Then run --update-tree-size and rerun this script.")
                        rh.doRollover()
                        sys.exit(0)
             
                # Go fetch bytes from CT URL for this tile
                throttled, tile_bytes_len = tile_fetch_and_process_ct_log_entries(session, ct_log_url, tile_idx)

                if throttled == True:
                    sleep_time_sec = 220
                    stdoutlogger.error(f"THROTTLED!!... closing session. Creating new session. Sleeping for {sleep_time_sec} seconds")
                    session.close() # Release the connection back into the pool - https://requests.readthedocs.io/en/latest/_modules/requests/sessions/
                    time.sleep(sleep_time_sec)
                    session = create_session() # start with completely new session
                    continue # retry the same tile_idx with new session

                # Update what has been completed
                state_table.update_item(
                    Key={'url': ct_log_url},
                    UpdateExpression="SET current_position = :pos",
                    ExpressionAttributeValues={':pos': current_tile_end}
                )
           
                # Progress message per tile after successful parse/write of this tile.
                stdoutlogger.debug(f"Fetched tile {tile_idx} (entries {current_position}-{current_tile_end})")
                pbar.update(256)
                tile_idx += 1 # If successful, go to next tile_idx
       
       
        #
        # Type: RFC 6962 - "Classic" CT logs
        #
        if ct_log_type == "rfc6962":

            max_range_step = 1024 # This changes dynamically to match the number of results returned to ensure nothing is missed
            current_position = start_position # current starts here
    
            while current_position < tree_size:
                stop = current_position + max_range_step - 1 # the end position for the log download request
                stdoutlogger.debug(f'current_position:{current_position} to position: {stop}')
                try:
                    throttled, returned_result_count = rfc6962_fetch_and_process_ct_log_entries(session, 
                                                                                        ct_log_url, 
                                                                                        current_position, 
                                                                                        stop)
                    
                    if throttled == True:
                        current_position = current_position # i.e. nothing was retrieved so allow for another try of the same start point
                        sleep_time_sec = 220
                        stdoutlogger.error(f"\nTHROTTLED!!... closing session. Creating new session. Sleeping for {sleep_time_sec} seconds")
                        session.close() # Release the connection back into the pool - https://requests.readthedocs.io/en/latest/_modules/requests/sessions/
                        time.sleep(sleep_time_sec)
                        session = create_session() # start with completely new session
                        continue # retry the same start point with new session
    
                    # The number of returned results should be equal to what was determined to be the max
                    # number of results the CT URL would provide per request. If a different number of
                    # results are returned, then something has changed. This changing seems to be normal
                    # behavior
                    if returned_result_count != max_range_step and throttled == False:
                        stdoutlogger.warning(f"Max step determined as {max_range_step} but only got back {returned_result_count}.")
                        # Change step size to be whatever the CT URL provided. This seems to vary greatly.
                        max_range_step = returned_result_count
                        # Calculate next current_position based on how many logs actually came back
                        current_position = current_position + returned_result_count
                        stdoutlogger.warning(f"No worries! Adjusting max step to be {returned_result_count} and next loop starts at tree position {current_position}.")
                    elif throttled == False:
                        # update current_position to start at new position
                        current_position = current_position + max_range_step
    
                    # Update what has been completed
                    state_table.update_item(
                        Key={'url': ct_log_url},
                        UpdateExpression="SET current_position = :pos",
                        ExpressionAttributeValues={':pos': current_position}
                    )
                    pbar.update(max_range_step)
    
                except EndpointConnectionError as e:
                    stdoutlogger.critical(f"\nDynamoDB connection error. Currently at {ct_log_url} CT tree position {current_position}. Reported error is: {str(e)}.")
                    stdoutlogger.critical(f"Because of the nature of this error, the current position may not have been saved to DynamoDB. Please verify before restarting.")
                    stdoutlogger.critical(f"Saving current log, uploading to S3, and then exiting...")
                    rh.doRollover()
                    sys.exit(1)
                except Exception as e:
                    stdoutlogger.critical(f"\nUnknown error at {ct_log_url} CT tree position {current_position}. Reported error is: {str(e)}")
                    stdoutlogger.critical(f"Saving current log, uploading to S3, and then exiting...")
                    rh.doRollover()
                    sys.exit(1)
            stdoutlogger.info(f"\n\nCT log {ct_log_url} complete!!!")
            print(f"\n\nCT log {ct_log_url} complete!!!\n")
            rh.doRollover()
            sys.exit(0)

    if found_ct_url_match == False:
        stdoutlogger.critical(
            f"The provided --ct_url was not found in DynamoDB table {CT_STATE_TABLE}: {input_ct_url}. Run --show-all-status to see list of URLs."
        )
        sys.exit(1)


def db_initialization() -> None:
    """
    Create the DynamoDB state table (if needed) and seed it with CT provider records.
    Existing rows for the same URL are overwritten (so be mindfull!)

    Pulls providers from the Google CT v3 log list and initializes both:
        - tiled/static providers from operators[].tiled_logs (using checkpoint)
        - RFC6962 providers from operators[].logs (using ct/v1/get-sth)

    For each accepted provider, inserts an item in DynamoDB with:
        - url
        - description
        - ct_log_type
        - tree_size
        - current_position (set to 0)

    Args:
            None

    Returns:
            None
    """
    stdoutlogger.info(f"Creating DynamoDB table: {CT_STATE_TABLE}")
    try:
        table = dynamodb.create_table(
            BillingMode='PAY_PER_REQUEST',
            TableName=CT_STATE_TABLE,
            KeySchema=[
            {
                'AttributeName': 'url',
                'KeyType': 'HASH'   #Partition_key
            },
            ],
            AttributeDefinitions=[
            {
                'AttributeName': 'url',
                'AttributeType': 'S'
            },
            ]
        )
        stdoutlogger.info(f"Finished creating table {table.table_name}. Status: {table.table_status}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            stdoutlogger.info(f"DynamoDB table already exists:{CT_STATE_TABLE}")
        else:
            stdoutlogger.critical(f'Unknown error when creating DynamoDB table: {e}')

    state_table = dynamodb.Table(CT_STATE_TABLE)
    ct_log_list_url = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    try:
        response = requests.get(ct_log_list_url)
        if response.status_code != 200:
            stdoutlogger.critical(
                f"Failed to fetch CT log listing from {ct_log_list_url}: HTTP Status Code {response.status_code}"
            )
            sys.exit(1)

        log_list_json = response.json()

        # First parse static tiled
        # Second parse rfc6962
        for operator in log_list_json.get("operators", []):
            for log in operator.get("tiled_logs", []): # static tilled
                ct_log_url = log.get("monitoring_url") # e.g. https://mon.willow.ct.letsencrypt.org/2027h2/
                description = log.get("description")
                stdoutlogger.info(f"Initializing tiled provider {ct_log_url}")
                log_type = log.get("log_type", None) # some have this while others do not. e.g. test
                if log_type == "test":
                    stdoutlogger.info(f"Ignoring CT tiled provider: {ct_log_url}. log_type: {log_type}")
                    continue
                try:
                    checkpoint_response = requests.get(f"{ct_log_url}checkpoint", timeout=5)
                    if checkpoint_response.status_code == 200:
                        #log.twig.ct.letsencrypt.org/2026h1
                        #64279235
                        #ewTUZ6fsXIRaHH7rNgAsZRRifCKEvbzqiuop49UnBcc=
                        #
                        #— log.twig.ct.letsencrypt.org/2026h1 o+fqRRtSsx+TRCW3yMS4og==
                        #— grease.invalid kt9/kevvRLAYuMh3t1jf/dxUydDYGbGTlN+veO/mcocZcGX2Dnyzv3wzoIzZcPfqlASlAsiVkuAb8+D6asGmkcBv
                        #— log.twig.ct.letsencrypt.org/2026h1 7q00RAAAAZxgcF8sBAMARzBFAiEAns4sBI6bvFWM7tIZSrsOy6v1W06gxgCxZkZXEyqlJGYCIF++NROpHhRcvDOOzQO4pQmf/d+lVzJPcsRKJy9ffjVr
                        #— log.twig.ct.letsencrypt.org/2026h1 Mt9KvMHmpQP5CKu2/PVfyKuZ2rpk5vNvWnq93gpTUYr/MoAJP/oqMamPNLJ24nLvmNbFUauKFL82AVbeQl+FGk+rjwk=
                        stdoutlogger.info(f"Successfully connected to tiled provider {ct_log_url} and got checkpoint response.")
                        lines = checkpoint_response.text.split("\n")
                        if len(lines) < 3:
                            stdoutlogger.info(f"Malformed checkpoint response from tiled provider {ct_log_url}. Response text: {checkpoint_response.text}")
                            continue
                        origin = lines[0].strip()
                        tree_size = int(lines[1].strip())
                        root_hash = lines[2].strip()
                        stdoutlogger.debug(f"origin: {origin} tree_size: {tree_size} root_hash: {root_hash} for tiled provider {ct_log_url}")
                        try:
                            state_table.put_item(Item={
                                'url': ct_log_url, # e.g. https://mon.twig.ct.letsencrypt.org/2026h1/
                                'description': description, # e.g. Let's Encrypt 'Twig2026h1'
                                'ct_log_type': 'tiled',
                                'tree_size': tree_size, 
                                'current_position': 0, # Will overwrite to zero
                            })
                            stdoutlogger.info(f"Initialized tiled provider {ct_log_url}")
                        except ClientError as e:
                            stdoutlogger.error(f"DynamoDB error for tiled provider {ct_log_url}: {e.response['Error']['Message']}")
                except Exception as e:
                    stdoutlogger.error(f"Requests error for tiled provider {ct_log_url}: {e}")
                    continue

            for log in operator.get("logs", []): # rfc6962
                ct_log_url = log.get("url")
                description = log.get("description")
                stdoutlogger.info(f"Initializing rfc6962 {ct_log_url}")
                state = log.get("state", None) # some have this while others do not. e.g. rejected
                if state:
                    for k, v in state.items():
                        state = k
                log_type = log.get("log_type", None) # some have this while others do not. e.g. test
                if state == "rejected" or log_type == "test":
                    stdoutlogger.info(
                        f"Ignoring CT rfc6962 provider: {ct_log_url}. State: {state} log_type: {log_type}"
                    )
                    continue
                try:
                    sth_response = requests.get(f"{ct_log_url}ct/v1/get-sth", timeout=5) # get tree size
                    if sth_response.status_code == 200:
                        sth_data = sth_response.json()
                        tree_size = sth_data.get('tree_size', 0)
                        try:
                            state_table.put_item(Item={
                                'url': ct_log_url, # e.g. https://ct.gdca.com.cn/
                                'description': description, # e.g. GDCA CT log #1
                                'ct_log_type': 'rfc6962',
                                'tree_size': tree_size, 
                                'current_position': 0, # Will overwrite to zero
                            })
                            stdoutlogger.info(f"Initialized rfc6962 {ct_log_url}")
                        except ClientError as e:
                            stdoutlogger.error(f"DynamoDB error for rfc6962 {ct_log_url}: {e.response['Error']['Message']}")
                    else:
                        stdoutlogger.error(f"Requests non-200 response code for rfc6962 {ct_log_url}. Response {sth_response.status_code}. Text: {sth_response.text}")
                except Exception as e:
                    stdoutlogger.error(f"Requests error for rfc6962 {ct_log_url}: {e}")
                    continue

        stdoutlogger.info("CT DynamoDB table initialization complete!")
    except Exception as e:
        stdoutlogger.error(f"Error: {e}")


def update_tree_size() -> None:
    """
    Update `tree_size` for each CT log in DynamoDB.

    Uses `checkpoint` for tiled logs and `ct/v1/get-sth` for rfc6962 logs.
    """
    state_table = dynamodb.Table(CT_STATE_TABLE)
    response = state_table.scan()
    for ct_record in response['Items']:
        previous_tree_size = ct_record.get('tree_size')
        ct_log_url = ct_record.get('url')
        ct_log_type = ct_record.get('ct_log_type')

        if ct_log_type == "tiled": 
            try:
                checkpoint_response = requests.get(f"{ct_log_url}checkpoint", timeout=5) # get tree size
                if checkpoint_response.status_code == 200:
                    lines = checkpoint_response.text.split("\n")
                    if len(lines) < 3:
                        stdoutlogger.error(f"Malformed checkpoint response from tiled provider {ct_log_url}. Response text: {checkpoint_response.text}")
                        continue
                    origin = lines[0].strip()
                    new_tree_size = int(lines[1].strip())
                    root_hash = lines[2].strip()
                    stdoutlogger.info(
                        f'Found {new_tree_size - previous_tree_size} more items. New tree size: {new_tree_size} old tree size: {previous_tree_size} url: {ct_log_url}'
                    )
                    try:
                        state_table.update_item(
                            Key={'url': ct_log_url},
                            UpdateExpression="SET tree_size = :pos",
                            ExpressionAttributeValues={':pos': new_tree_size}
                        )
                        stdoutlogger.info(f"Updated tree size for tiled provider {ct_log_url}")
                    except ClientError as e:
                        stdoutlogger.error(
                            f"DynamoDB error for tiled provider {ct_log_url}: {e.response['Error']['Message']}"
                        )
                else:
                    stdoutlogger.error(f"Requests non-200 response code for tiled provider {ct_log_url}. Response {checkpoint_response.status_code}. Text: {checkpoint_response.text}")
            except Exception as e:
                stdoutlogger.error(f"Requests error for tiled provider {ct_log_url}: {e}")
                continue

        if ct_log_type == "rfc6962":
            try:
                sth_response = requests.get(f"{ct_log_url}ct/v1/get-sth", timeout=5) # get tree size
                if sth_response.status_code == 200:
                    sth_data = sth_response.json()
                    new_tree_size = sth_data.get('tree_size', 0)
                    stdoutlogger.info(
                        f'Found {new_tree_size - previous_tree_size} more items. New tree size: {new_tree_size} old tree size: {previous_tree_size} url: {ct_log_url}'
                    )
                    try:
                        state_table.update_item(
                            Key={'url': ct_log_url},
                            UpdateExpression="SET tree_size = :pos",
                            ExpressionAttributeValues={':pos': new_tree_size}
                        )
                        stdoutlogger.info(f"Initialized {ct_log_url}")
                    except ClientError as e:
                        stdoutlogger.error(
                            f"DynamoDB error for {ct_log_url}: {e.response['Error']['Message']}"
                        )
                else:
                    stdoutlogger.error(f"Requests non-200 response code for {ct_log_url}. Response {sth_response.status_code}. Text: {sth_response.text}")
            except Exception as e:
                stdoutlogger.error(f"Requests error for {ct_log_url}: {e}")


def main () -> None:
    """Parse CLI arguments, run preflight checks, and dispatch requested action."""
    parser = argparse.ArgumentParser(
        description='Initialize and then parse Certificate Transparency logs'
    )
    parser.add_argument(
        '--init',
        action='store_true',
        dest='do_init',
        required=False,
        help='This will create all the initial DynamoDB tables and items within it. WARNING! Any values currently present within the DB will be overwritten. For example, the current position of the log processing will be reset to 0'
    )
    parser.add_argument(
        '--show-all-status',
        action='store_true',
        dest='show_all_status',
        required=False,
        help='Prints the download completion status of each CT provider'
    )
    parser.add_argument(
        '--update-tree-size',
        action='store_true',
        dest='update_tree_size',
        required=False,
        help='Updates the size of the tree for each CT provider. This is needed because the CT tree constantly increases.'
    )
    parser.add_argument(
        '--ct_url',
        action='store',
        dest='arg_ct_url',
        required=False,
        help='Perform download of given CT URL. e.g. "https://ct.googleapis.com/logs/argon2022/"'
    )
    parser.add_argument( # e.g. 2026-02-04T04:48:10+00:00: https://ct.googleapis.com/logs/eu1/xenon2027h1/ progress: 3.5% (694880/19799242)
        '--remove-progress-bar',
        action='store_true',
        dest='arg_remove_progress_bar',
        required=False,
        help='Removes showing the real-time progress bar.'
    )
    args = parser.parse_args()

    def preflight_checks(s3Check: bool = False, dynamodbCheck: bool = False, dynamodbTableCheck: bool = False) -> None:
        """Perform preflight checks to ensure the environment is set up correctly."""
        if s3Check:
            # Validate S3 connection by checking bucket existence
            try:
                s3.head_bucket(Bucket=S3_BUCKET)
            except ClientError:
                stdoutlogger.fatal(f"Preflight check failed! S3 client failed to connect to bucket name: '{S3_BUCKET}'")
                sys.exit(1)
            except EndpointConnectionError as e:
                stdoutlogger.fatal(f"Preflight check failed! S3 client failed to connect to endpoint or bucket '{S3_BUCKET}': {e}")
                sys.exit(1)
        
        if dynamodbCheck:
        # Validate DynamoDB connection by checking if any tables exist
            try:
                list(dynamodb.tables.all())
            except Exception as e:
                stdoutlogger.fatal(f"Preflight check failed! DynamoDB client failed to list any tables likely meaning there is a connection issue. Check URL, and credentials.")
                sys.exit(1)

        if dynamodbTableCheck:
            # Check if the DynamoDB table exists
            checkpassed = False
            for table in dynamodb.tables.all(): # if there are a TON of tables, this may be a bad idea
                if table.name == CT_STATE_TABLE:
                    checkpassed = True
            if checkpassed == False:
                stdoutlogger.fatal(f"DynamoDB table '{CT_STATE_TABLE}' does not exist. Please run with --init to create it.")
                sys.exit(1)
            
    #
    # Control
    #
    if args.do_init:
        print("")
        print("This will create all the DynamoDB tables and items within it.")
        print(f"WARNING! Any values currently present within the DynamoDB table '{CT_STATE_TABLE}' will be overwritten. For example, the current position of the log processing will be reset to 0.")
        print("")
        preflight_checks(dynamodbCheck=True)
        stdoutlogger.setLevel(logging.INFO)
        while True:
            user_input = input("Do you want to continue? (yes/no): ")
            if user_input.lower() in ["yes", "y"]:
                print("You said yes. Continuing...")
                print("---> You may see some HTTP errors for some of the providers and this is normal.\n")
                db_initialization()
                print("\n Complete. Now run --show-all-status to see the status of each CT provider.")
                break
            elif user_input.lower() in ["no", "n"]:
                print("Exiting...")
                sys.exit(0)
            else:
                print("Invalid input. Please enter yes/no.")
    
    elif args.show_all_status:
        preflight_checks(dynamodbCheck=True, dynamodbTableCheck=True)
        state_table = dynamodb.Table(CT_STATE_TABLE)
        response = state_table.scan()
        ct_log_urls = [item['url'] for item in response['Items']]

        # Use fixed-width columns so output stays aligned regardless of value length.
        col_pct = 15
        col_cur = 16
        col_end = 16
        col_type = 14
        print(f"{'PercentComplete':>{col_pct}} {'CurrentPosition':>{col_cur}} {'End(tree_size)':>{col_end}} {'LogType':<{col_type}} CTProviderURL")

        for ct_log_url in ct_log_urls:
            state = state_table.get_item(Key={'url': ct_log_url}).get('Item', {})
            start_position = int(state.get("current_position"))
            end_position = int(state.get("tree_size"))
            log_type = state.get("ct_log_type")
    
            try:
                percent_complete = round((start_position / end_position) * 100, 1)
            except ZeroDivisionError:
                percent_complete = 0
    
            print(
                f"{percent_complete:>{col_pct}.1f} "
                f"{start_position:>{col_cur}d} "
                f"{end_position:>{col_end}d} "
                f"{log_type:<{col_type}} "
                f"{ct_log_url}"
            )
    
    elif args.arg_ct_url:
        preflight_checks(s3Check=True, dynamodbCheck=True, dynamodbTableCheck=True)
        start_ct_process(input_ct_url=args.arg_ct_url, remove_progress_bar=args.arg_remove_progress_bar)
    
    elif args.update_tree_size:
        preflight_checks(dynamodbCheck=True, dynamodbTableCheck=True)
        update_tree_size()
    else:
        print("No arguments provided. Use --help to see options.")

if __name__ == '__main__':
    main()
