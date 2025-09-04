#!/usr/bin/env python3
# Built in Python 3.12.3
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2025 AskKemp.com"
__license__ = "agpl-3.0"

import json
import os
import logging
import base64
import requests
from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, GreedyBytes, GreedyRange, Terminated
import boto3
from botocore.exceptions import ClientError
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
import ua_generator  # https://github.com/iamdual/ua-generator
from pathlib import Path
from pkilint import loader, report
import pkilint.pkix

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
stdoutlogger.setLevel(logging.WARN)

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
    short_uuid = str(uuid.uuid4())[:4] # needed to prevent overwritting same file in S3
    upload_key_name = (
        f"{dest_filename}-{short_uuid}-"
        f"{datetime.datetime.now().strftime('%Y-%m-%dT%H')}.gz"  # including date in the filename for possible future debugging
    )  # e.g. ct_d2fe2110-4a6c-4dc0-a556-8e7556beaf4d-1a2b-2025-05-30.gz
    stdoutlogger.warning(f"Uploading {upload_key_name} to S3 bucket {S3_BUCKET}")
    s3.upload_file(dest, S3_BUCKET, upload_key_name)
    # Check if the file exists in S3 after upload
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=upload_key_name)
        stdoutlogger.info(f"Successfully uploaded {upload_key_name} to S3 bucket {S3_BUCKET}")
    except ClientError as e:
        stdoutlogger.error(f"Failed to verify upload of {upload_key_name} to S3: {e}")
        exit(1)
    os.remove(source)

# Create a new directory
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

# Unique log file name for this instance of the script
unique_name = "ct_" + str(uuid.uuid4()) + ".log"
log_file = log_dir / unique_name # type pathlib.PosixPath

# maxBytes controls the size of the file when it gets rotated
# Should consider how long OS or Docker will kindly wait for process to terminate
# 500000000 = 500MB which when rotated and gzip is about ~50MB
# 250000000 = 250MB
rh = logging.handlers.RotatingFileHandler(
    log_file, # type pathlib.PosixPath. Supported since Python 3.6.
    maxBytes=250000000,
    backupCount=1,  # Number of backup files to keep
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
     - pool_connections allow cache connection to host so a new tls conection does not have to be built for each request which make downloads faster
     - Note: it seems if you can get a session that returns a high step count then you can keep that session for a very long time even if a new session would return a much lower step size
     - Future: Maybe use drop in replacement for requests to allow for rate limiting per CT domain: https://github.com/JWCook/requests-ratelimiter
     - Creates random desktop user agent for the session using ua_generator

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
    session.headers = ua_generator.generate(device='desktop', browser=('chrome', 'edge')).headers.get()

    return session


def pki_validation(cert_as_der: bytes, fingerprint: str) -> bool:
    """
    Performs check on certificate and if there is a fatal finding, it logs critical
    The purpose of this function is to help with debuging of parsing failures.

    code from: https://github.com/digicert/pkilint/blob/main/pkilint/bin/lint_pkix_cert.py

    Args:
        cert_as_der (bytes) certificate in DER format. Used for debuging
        fingerprint (str)

    Returns:
        found_fatal (bool) - True if fatal error detected
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
                    stdoutlogger.critical(f'{fingerprint}: {item}')
                    found_fatal = True
    return found_fatal


def collect_certificate_metadata_PyOpenSSL_fallback(cert_as_der: bytes) -> dict:
    """
    Using PyOpenSSL module to dump metadata from certificate. This module is not as strict
    as pyca/cryptography meaning it will parse data which pyca/cryptography will not.

    e.g. fa:9e:71:92:68:cf:aa:05:d8:e8:c3:46:7b:c2:bd:a5:4b:1a:18:3b will not parse with
    pyca/cryptography but will parsae with PyOpenSSL crypto. pkilint finds a fatal issue
    with the extensions to it makes sense that it is not a RFC compliant cert.

    Warning: The OpenSSL.crypto module is pending deprecation.
    See https://www.pyopenssl.org/en/latest/api/crypto.html

    Args:
        cert_as_der (bytes) certificate in DER format. Used for debuging

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


def collect_certificate_metadata(cert, cert_as_der: bytes) -> dict:
    """
    Extracts metadata from the certificate and returns it as a dictionary

    Args:
        cert (cryptography.hazmat.bindings._rust.x509.Certificate)
        cert_as_der (bytes) certificate in DER format. Used for debuging

    Returns:
        Dictionary containing metadata of certificate
    """
    temp_dict = {}

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


def process_log_entry(entry: dict, url: str, current_position: int) -> None:
    """
    Given an entry from the CT log, determine the entry type and where the certificate data is located.
    Once determined, it sends the certificate to have the metadata created/extracted (collect_certificate_metadata).
    The output from collect_certificate_metadata is then written to file

    Args:
        entry (dict) containing the keys leaf_input and extra_data.
            The location of the certificate is dependent on the log entry type. See code comments for details.
            e.g. and entry is one item from the list at https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=5
        url (str) is the url of the ct log. Only used for error reporting
        current_position

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
            cert_data = Certificate.parse(mth.Entry).CertData
            try:
                # Load certificate
                cert = x509.load_der_x509_certificate(cert_data) # input is bytes
                cert_as_der = cert_data
                # Extract metadata from certificate
                metadata = collect_certificate_metadata(cert, cert_as_der)
                #print(metadata)
            except ValueError as e:
                # Extremely rarely there are certs that cannot be parsed. 
                # https://github.com/pyca/cryptography/issues/9253
                # https://ct.cloudflare.com/logs/nimbus2025/ct/v1/get-entries?start=684843008&end=684844031 in this batch is one that causes the below exception
                # error parsing asn1 value: ParseError { kind: ExtraData, location: ["Certificate::signature_alg"] }
                # {'common_name': 'cPanel, Inc. Certification Authority', 'fingerprint': b'5F:24:80:0B:AA:47:8A:AB:9C:B9:A6:84:3B:11:11:37:24:AB:5B:DB:C7:AB:C4:B0:20:7A:7E:8D:08:57:3C:B5'}
                # and that cert is not even in crt.sh and pylint errors on it so it must be super busted
                if "error parsing asn1 value" in str(e):
                    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                    stdoutlogger.error(
                        f"\n{e}: Unable to parse certificate with fingerprint {certificate.digest('sha256')} The input certificate is likely super busted and not to spec."
                    )
                    return
        elif mth.LogEntryType == "PrecertLogEntryType": 
            # Parse
            PrecertChainEntry = PreCertEntry.parse(extra_data) #construct.lib.containers.Container
            # Load certificate
            cert = x509.load_der_x509_certificate(PrecertChainEntry.LeafCert.CertData) # PrecertChainEntry
            cert_as_der = PrecertChainEntry.LeafCert.CertData
            # Extract metadata from certificate
            metadata = collect_certificate_metadata(cert, cert_as_der)
            #print(metadata)
        else:
            stdoutlogger.critical(f"\nUNKNOWN CT Log Entry Type: {mth.LogEntryType}.... Something is very wrong.")
            rh.doRollover()
            exit(1)

        ctlogging.info(json.dumps(metadata, default=str))
        return

    except Exception as e:
        stdoutlogger.critical(f"\nprocess_log_entry - {str(e)}: Unable to process {url}")
        print(traceback.format_exc())
        rh.doRollover()
        exit(1)


def fetch_and_process_ct_log_entries(s: requests.Session, ct_log_url: str, start: int, end: int) -> tuple:
    """
    Performs the download of the CT log.

    Args:
        s (<class 'requests.sessions.Session'>) - requests session
        ct_log_url (str) - e.g. https://ct.googleapis.com/logs/argon2020/
        start (int) - used in requests params as first log entry to receive
        end (int) - used in requests params as last log entry to receive

    Returns:
        tuple of (throttled, len(log_entries))
        len(log_entries) (int) - Number of enteries returned in the request. Later used to validate the start/end params return matches the request
        throttled (bool) - True if reponse code is 429.
    """
    entries_url = f"{ct_log_url}ct/v1/get-entries" # e.g. https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=5
    stdoutlogger.info(f'{ct_log_url}ct/v1/get-entries?start={start}&end={end}')
    params = {'start': start, 'end': end} # start will be the last known position that was downloaded. end is dynamically determined.
    throttled = False
    try:
        response = s.get(entries_url, params=params, timeout=5)
        if response.status_code == 200:
            throttled = False
            log_entries = response.json()['entries']
            stdoutlogger.info(f'Number enteries returned from CT url: {len(log_entries)}')
            for entry in log_entries:
                process_log_entry(entry, ct_log_url, start)
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
                f"\nReponse code of {response.status_code} not dealt with in code. Unable to process {ct_log_url}ct/v1/get-entries?start={start}&end={end}"
            )
            stdoutlogger.critical(response.text)
            rh.doRollover()
            exit(1) # because I need to add code to deal with it
    except requests.exceptions.ReadTimeout as e:
        stdoutlogger.error(
            f"\nfetch_and_process_ct_log_entries - {e}: Timeout on {ct_log_url}ct/v1/get-entries?start={start}&end={end}"
        )
        time.sleep(120)
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ConnectionError as e:
        stdoutlogger.error(
            f"\nfetch_and_process_ct_log_entries - {e}: General ConnectionError on {ct_log_url}ct/v1/get-entries?start={start}&end={end}"
        )
        time.sleep(120) # hopefully it will come back
        throttled = True
        return (throttled, 0)
    except requests.exceptions.ChunkedEncodingError as e:
        stdoutlogger.error(
            f"\nfetch_and_process_ct_log_entries - {e}: ChunkedEncodingError (response ended prematurely) on {ct_log_url}ct/v1/get-entries?start={start}&end={end}"
        )
        time.sleep(120)
        throttled = True
        return (throttled, 0)
    except Exception as e:
        stdoutlogger.critical(
            f"\nfetch_and_process_ct_log_entries - {e}: Unable to process {ct_log_url}ct/v1/get-entries?start={start}&end={end}"
        )
        print(traceback.format_exc())
        rh.doRollover()
        exit(1)


def start_ct_process(input_ct_url: str) -> None:
    """
    Kicks off CT download and parsing. Uses DyanamoDB to track the new start/end values to download for the CT URL.
    Validates that the number of enteries requested (start, end) is the same number of enteries returned and if
    not then it adjusts the step and re-requests anything that was missed.

    Args:
        input_ct_url (str) e.g. https://ct.googleapis.com/logs/eu1/solera2025h2/ (must have final /)

    Returns:
        None
    """
    # Input URL validation
    if not input_ct_url.endswith('/'):
        logging.error("CT URL must end with '/'. e.g. https://ct.googleapis.com/logs/eu1/solera2025h2/ ")
        exit(1)

    # init requests session
    session = create_session()

    state_table = dynamodb.Table(CT_STATE_TABLE) # tracks download progress per CT URL
    response = state_table.scan()
    ct_log_urls = [item['url'] for item in response['Items']]

    throttled = False
    for ct_log_url in ct_log_urls:
        if ct_log_url != input_ct_url:
            continue
        stdoutlogger.info(f"Now processing: {ct_log_url}")

        # Fetch state from DynamoDB
        state = state_table.get_item(Key={'url': ct_log_url}).get('Item', {})
        start_position = int(state.get("current_position")) # Download progress. Equal to start parameter in URL.
        end_position = int(state.get("tree_size")) # last available item at the CT URL. e.g. the final end parameter value
        max_range_step = 1024 # This changes dynamically to match the number of results returned to ensure nothing is missed
        current_position = start_position # current starts here

        # on screen progress bar settings
        pbar = tqdm.tqdm(total=end_position, initial=start_position) # on screen progress bar
        pbar.set_description(f'{ct_log_url}')

        while current_position < end_position:
            stop = current_position + max_range_step - 1 # the end position for the log download request
            stdoutlogger.info(f'current_position:{current_position} to position: {stop}')
            try:
                throttled, returned_result_count = fetch_and_process_ct_log_entries(session, 
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
                    #rh.doRollover()
                    #exit(1)
                    #break

                # The number of returned results shoudl be equal to what was determined to be the max
                # number of results the CT URL would provide per request. If a different number of
                # results are returned, then something has changed. This changing seems to be normal
                # behavior
                if returned_result_count != max_range_step and throttled == False:
                    stdoutlogger.error(f"\nMax step determined as {max_range_step} but only got back {returned_result_count}")
                    # Change step size to be whatever the CT URL provided. This seems to vary greatly.
                    max_range_step = returned_result_count
                    # Calculate next current_position based on how many logs actually came back
                    current_position = current_position + returned_result_count
                    stdoutlogger.error(f"\nAdjusting max step to be {returned_result_count} and next loop starts of {current_position}")
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
            except Exception as e:
                stdoutlogger.critical(f"\nError at {ct_log_url} position {current_position}: {str(e)}")
                rh.doRollover()
                exit(1)
        stdoutlogger.info(f"\n\nCT log {ct_log_url} complete!!!")
        print(f"\n\nCT log {ct_log_url} complete!!!\n")


def db_initialization() -> None:
    """Create DynamoDB table and initialize CT log URLs and metadata."""
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
        stdoutlogger.info("Finished creating table ", table.table_name ,". Status: ", table.table_status)
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
            exit(1)

        log_list_json = response.json()
        for operator in log_list_json.get("operators", []):
            for log in operator.get("logs", []):
                ct_log_url = log.get("url")
                description = log.get("description")
                stdoutlogger.info(f"Initializing {ct_log_url}")
                state = log.get("state", None) # some have this while others do not. e.g. rejected
                if state:
                    for k, v in state.items():
                        state = k
                log_type = log.get("log_type", None) # some have this while others do not. e.g. test
                if state == "rejected" or log_type == "test":
                    stdoutlogger.info(
                        f"Ignoring CT provider: {ct_log_url}. State: {state} log_type: {log_type}"
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
                                'tree_size': tree_size, 
                                'current_position': 0, # Will overwrite to zero
                            })
                            stdoutlogger.info(f"Initialized {ct_log_url}")
                        except ClientError as e:
                            stdoutlogger.error(f"DynamoDB error for {ct_log_url}: {e.response['Error']['Message']}")
                    else:
                        stdoutlogger.error(f"Requests non-200 response code for {ct_log_url}. Response {sth_response.status_code}. Text: {sth_response.text}")
                except Exception as e:
                    stdoutlogger.error(f"Requests error for {ct_log_url}: {e}")
                    continue

        stdoutlogger.info("CT DynamoDB table initialization complete!")
    except Exception as e:
        stdoutlogger.error(f"Error: {e}")


def update_tree_size() -> None:
    """Update the tree_size for each CT log in the DynamoDB table."""
    state_table = dynamodb.Table(CT_STATE_TABLE)
    response = state_table.scan()
    for ct_record in response['Items']:
        previous_tree_size = ct_record.get('tree_size')
        ct_log_url = ct_record.get('url')
        try:
            sth_response = requests.get(f"{ct_log_url}ct/v1/get-sth", timeout=5) # get tree size
            if sth_response.status_code == 200:
                sth_data = sth_response.json()
                new_tree_size = sth_data.get('tree_size', 0)
                stdoutlogger.error(
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
                stdoutlogger.error(f"Requests non-200 response code for {ct_log_url}: {e}")
        except Exception as e:
            stdoutlogger.error(f"Requests error for {ct_log_url}: {e}")


def main () -> None:
    """Contains all argument parsing"""
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
    args = parser.parse_args()

    def preflight_checks(s3Check: bool = False, dynamodbCheck: bool = False, dynamodbTableCheck: bool = False) -> None:
        """Perform preflight checks to ensure the environment is set up correctly."""
        if s3Check:
            # Validate S3 connection by checking bucket existence
            try:
                s3.head_bucket(Bucket=S3_BUCKET)
            except ClientError:
                stdoutlogger.fatal(f"S3 failed to connect to bucket name: {S3_BUCKET}")
                exit(1)
        
        if dynamodbCheck:
        # Validate DynamoDB connection by checking if any tables exist
            try:
                list(dynamodb.tables.all())
            except Exception as e:
                stdoutlogger.fatal(f"dynamodb failed to list any tables likely meaning there is a connection issue. Check URL, and credentials.")
                exit(1)

        if dynamodbTableCheck:
            # Check if the DynamoDB table exists
            checkpassed = False
            for table in dynamodb.tables.all(): # if there are a TON of tables, this may be a bad idea
                if table.name == CT_STATE_TABLE:
                    checkpassed = True
            if checkpassed == False:
                stdoutlogger.fatal(f"DynamoDB table '{CT_STATE_TABLE}' does not exist. Please run with --init to create it.")
                exit(1)
            
    #
    # Control
    #
    if args.do_init:
        print("")
        print("This will create all the DynamoDB tables and items within it.")
        print(f"WARNING! Any values currently present within the DyanamoDB table '{CT_STATE_TABLE}' will be overwritten. For example, the current position of the log processing will be reset to 0.")
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
                exit(0)
            else:
                print("Invalid input. Please enter yes/no.")
    
    elif args.show_all_status:
        preflight_checks(dynamodbCheck=True, dynamodbTableCheck=True)
        state_table = dynamodb.Table(CT_STATE_TABLE)
        response = state_table.scan()
        ct_log_urls = [item['url'] for item in response['Items']]
        print("PercentComplete\tCurrentPosition\tEnd(tree_size)\tURL")
        for ct_log_url in ct_log_urls:
            state = state_table.get_item(Key={'url': ct_log_url}).get('Item', {})
            start_position = int(state.get("current_position"))
            end_position = int(state.get("tree_size"))
    
            try:
                percent_complete = round((start_position / end_position) * 100, 1)
            except ZeroDivisionError:
                percent_complete = 0
    
            print(f"{percent_complete}\t{start_position}\t{end_position}\t{ct_log_url}")
    
    elif args.arg_ct_url:
        preflight_checks(s3Check=True, dynamodbCheck=True, dynamodbTableCheck=True)
        start_ct_process(input_ct_url=args.arg_ct_url)
    
    elif args.update_tree_size:
        preflight_checks(dynamodbCheck=True, dynamodbTableCheck=True)
        update_tree_size()
    else:
        print("No arguments provided. Use --help to see options.")

if __name__ == '__main__':
    main()
