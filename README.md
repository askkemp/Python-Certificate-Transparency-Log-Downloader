<p align="center">
  <img src="./logo.png" height="100" />
</p>

# Introduction
A Python 3.11+ monolithic script to download Certificate Transparency (CT) logs  (see [Certificate Transparency Project]( https://certificate.transparency.dev/ "Certificate Transparency Project")) and extract specific metadata. The below metadata is captured for each certificate:

```json
{
  "fingerprint": "1d:9d:c5:aa:a5:35:c8:37:c6:dc:44:10:89:b8:94:1e:fb:76:f7:6f",
  "issuer": "CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
  "subject": "CN=client.accountprotection.microsoft.com,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
  "not_valid_before": "2024-01-02 00:00:00+00:00",
  "not_valid_after": "2025-01-02 23:59:59+00:00",
  "cn": "client.accountprotection.microsoft.com",
  "subjectAltName": [
    "client.accountprotection.microsoft.com"
  ]
}
```

# Features
- Extracts domain name values from x509.DNSName, NameOID.COMMON_NAME, and subjectAltName
- Generates a SHA1 fingerprint of the certificate
- Extracts the certificate issuer and validates dates (before and after)
- Can be easily extended to extract additional metadata, as desired
- Each certificate's metadata is logged as JSON
- Ability to download from the CT provider of your choice
- Uses DynamoDB to store available CT providers, track current download position, and CT tree size
- Script will initialize the DynamoDB with a starting place of zero and the current tree size for each CT provider
- Script will update the current tree size into DynamoDB
- Uses S3 to store compressed archive of downloaded CT records
- When a signal is received (e.g. system shutdown, ctrl-c), the script will gracefully shutdown by uploading its current log to S3
- Provides on-screen progress bar that shows certificates processed per second and also estimates the time to completion
- Uses pyca/cryptography for parsing and falls back to PyOpenSSL Crypto when parsing fails on out-of-spec certificates
- Performs PKI linting when primary parsing fails and saves the failure results into the log
- Attempts to download as many records as possible per query

# Example of script running
The script is downloading and processing 1356 certificates per second from tiger2026h1. It estimates 11 hours until completion. The script is manually terminated with ctrl-c and the script properly shuts down and uploads its logs to S3.
```bash
$ python3 ./download_ct_logs.py --ct_url https://tiger2026h1.ct.sectigo.com/
https://tiger2026h1.ct.sectigo.com/:   1%|█▊      | 457728/57004106 [00:00<11:34:51, 1356.30it/s]
[ctrl-c pressed]
^Gracefully shutting down due to signal 2 (SIGINT). PLEASE WAIT.
Uploading ct_e6bcaf6a-ea8e-4c7c-b292-dbe673fa9a65-2025-07-24.gz to S3 bucket dev
```

# Quick start

### 1. Clone the repository and install requirements
```bash
git clone https://github.com/askkemp/Python-Certificate-Transparency-Log-Downloader.git
cd Python-Certificate-Transparency-Log-Downloader/
pip install -r requirements.txt
```

### 2. Setup DynamoDB (scylladb) and S3 (minio)
Use the included `dockerdocker-compose.yml` to spin up DynamoDB ([scylladb](https://www.scylladb.com/) ) and S3 ([MinIO](https://min.io/) ). 

**Caution**: Passwords and keys are hard coded or set to nothing. Change them to be more secure. 

```bash
$ sudo docker compose up -d
[+] Running 5/5
 ✔ Network python-certificate-transparency-log-downloader_default         Created  0.1s
 ✔ Volume "python-certificate-transparency-log-downloader_scylladb-data"  Created  0.0s
 ✔ Volume "python-certificate-transparency-log-downloader_minio-data"     Created  0.0s
 ✔ Container python-certificate-transparency-log-downloader-scylladb-1    Started  0.5s
 ✔ Container python-certificate-transparency-log-downloader-minio-1       Started  
 ```                                  

Generate acccess and secret keys for S3 (minio)
```bash
$ sudo docker exec -it python-certificate-transparency-log-downloader-minio-1   mc config host add myminio http://localhost:9000 minioadmin minioadmin
Added `myminio` successfully.
$ sudo docker exec -it python-certificate-transparency-log-downloader-minio-1   mc admin accesskey create myminio/ minioadmin  --access-key myuseraccesskey --secret-key myusersecretkey
Access Key: myuseraccesskey
Secret Key: myusersecretkey
Expiration: NONE
Name:
Description:
```
Create bucket where CT archives will be saved.
```bash
$ sudo docker exec -it python-certificate-transparency-log-downloader-minio-1 mc mb myminio/dev
Bucket created successfully `myminio/dev`.
```

### 3. Initilize the DynamoDB table and populate it with CT subscriber information
```bash
$ python3 ./download_ct_logs.py --init

This will create all the DynamoDB tables and items within it.
WARNING! Any values currently present within the DB will be overwritten. For example, the current position of the log processing will be reset to 0.

Do you want to continue? (yes)
You said yes. Continuing...
```

### 5. View status and pick a URL to download 
```bash
$ python3 ./download_ct_logs.py --show-all-status

PercentComplete CurrentPosition End(tree_size)  URL
...
0.0     0       2885    https://tiger2026h2.ct.sectigo.com/
0.0     0       59354392        https://oak.ct.letsencrypt.org/2026h1/
0.0     0       1627517377      https://ct.cloudflare.com/logs/nimbus2025/
0.0     0       36338772        https://tiger2026h1.ct.sectigo.com/
0.6     9521088 1653943153      https://yeti2025.ct.digicert.com/log/
0.0     0       26290   https://ct.googleapis.com/logs/us1/argon2026h2/
...
```

### 6. Start the download
```bash
$ python3 ./download_ct_logs.py --ct_url https://yeti2025.ct.digicert.com/log/
```

### 7. Update the max tree size as needed
This is needed because new certificates are constantly added.

## 8. View saved files
The files are saved to S3 (minio) and can be viewed by opening a web browser and going to https://localhost:9002/browser/dev. The user and password are found within the `docker-compose.yml` file.

```bash
$python3 ./download_ct_logs.py --update-tree-size
...
Found 902 more items. New tree size: 115846808 old tree size: 115845906 url: https://sphinx.ct.digicert.com/2026h1/
Found 0 more items. New tree size: 3822 old tree size: 3822 url: https://elephant2027h2.ct.sectigo.com/
Found 35 more items. New tree size: 1591655 old tree size: 1591620 url: https://oak.ct.letsencrypt.org/2026h2/
```

## Recommended Use
Run one instance of the script for each CT log you want downloaded. The results are real-time saved to disk and written to an S3 bucket during a log rotate. The CT download progress, as well as the max tree size, are maintained in DynamoDB.

Personally, I create a bunch of terminals in [tmux}(https://github.com/tmux/tmux/wiki) with each terminal running an instance of the script against a specific CT provider. I check on the progress of the logs about once a week. When the log is finished, I update the max tree size using the script and restart the download again.

The S3 objects can then be brought into ElasticSearch, [Tantivy](https://github.com/quickwit-oss/tantivy), or similar, to allow for quick searching of all certificate metadata.

## Help Menu
```bash
$ python3 ./download_ct_logs.py --help
usage: download_ct_logs.py [-h] [--init] [--show-all-status] [--update-tree-size] [--ct_url ARG_CT_URL]

Initialize and then parse Certificate Transparency logs

options:
  -h, --help           show this help message and exit
  --init               This will create all the initial DynamoDB tables and items within it. WARNING! Any values currently present within the DB will be overwritten. For example, the current position of the log processing will be reset to 0
  --show-all-status    Prints the download completion status of each CT provider
  --update-tree-size   Updates the size of the tree for each CT provider. This is needed because the CT tree constantly increases.
  --ct_url ARG_CT_URL  Perform download of given CT URL. e.g. "https://ct.googleapis.com/logs/argon2022/"

```

## Known issues
- Single threaded download per CT subscriber thus it will take a long time to download an entire provider's records. Each provider will take many weeks (if not months) to download.
- The fallback certificate parsing uses PyOpenSSL Crypto which is [pending deprecation](https://www.pyopenssl.org/en/latest/api/crypto.html " pending deprecation"). Although the primary certificate parsing is done with pyca/cryptography, it is very strict in what it will parse. If the certificate is out of specification, pyca/cryptography will not parse it. However, in most cases, PyOpenSSL Crypto will parse the out-of-spec certificate.
- The max number of records it will pull per HTTP request is based on the initial script running. It is not dynamic.
- CT providers sometimes rate limit and this script handles that by sleeping for small period of time before trying again. Proxy support can be added if rate limit is of concern.

## Built with
* Python 3.12
* [scylladb](https://www.scylladb.com/) - DynamoDB-Compatible API
* [MinIO](https://min.io/) - S3 Compatible Storage

## Related work
* [CertMonitor](https://github.com/dig-sec/CertMonitor "CertMonitor") - Uses Python3.11+ and is recently created
* [Axeman](https://github.com/CaliDog/Axeman "Axeman") - Uses Python3 with concurrency and multi-processing to download CT logs. It has not been updated in two years.
* [CTLogInspector](https://github.com/rajivchocolate/CTLogInspector "CTLogInspector") - Uses Python 3 + DynamoDB, SQS, S3, and Lambda to download CT
