import download_ct_logs
import datetime
from cryptography import x509
from OpenSSL import crypto  # fallback parsing - warning: module is pending deprecation

good_der_certificate = b'0\x82\x03\xa50\x82\x03K\xa0\x03\x02\x01\x02\x02\x10_owx\x89\xd7\x0e\xc5\x13\x96\x81\xbe\xa3A\x99\xd10\n\x06\x08*\x86H\xce=\x04\x03\x020;1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x1e0\x1c\x06\x03U\x04\n\x13\x15Google Trust Services1\x0c0\n\x06\x03U\x04\x03\x13\x03WE10\x1e\x17\r250528193425Z\x17\r250826203251Z0\x161\x140\x12\x06\x03U\x04\x03\x13\x0baskkemp.com0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04V\xfb\xac.^\xb3q\xc6\x14_T\x83\x864l\xbb\x03\xf8\xd7\x03\xaa\xeb=iF\x8d\xbf\x9a`\xc2\xb2\x9d:v\xdd\x8eL\x15)>\xfbJ?\x97Z,9\x8c\x9cU\xbbT\x82;\xe4\xdb\xdd*\xce\xa9P\x14\xe0\xc9\xa3\x82\x02T0\x82\x02P0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x800\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x010\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xacu\\f]\x14\xe0&\xa6]\xe7\xfd\xdfoo\xb2\xb0\x80:\x080\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\x90w\x925g\xc4\xff\xa8\xcc\xa9\xe6{\xd9\x80y{\xcc\x93\xf980^\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04R0P0\'\x06\x08+\x06\x01\x05\x05\x070\x01\x86\x1bhttp://o.pki.goog/s/we1/X280%\x06\x08+\x06\x01\x05\x05\x070\x02\x86\x19http://i.pki.goog/we1.crt0%\x06\x03U\x1d\x11\x04\x1e0\x1c\x82\x0baskkemp.com\x82\r*.askkemp.com0\x13\x06\x03U\x1d \x04\x0c0\n0\x08\x06\x06g\x81\x0c\x01\x02\x0106\x06\x03U\x1d\x1f\x04/0-0+\xa0)\xa0\'\x86%http://c.pki.goog/we1/peDXaqF3Tp8.crl0\x82\x01\x05\x06\n+\x06\x01\x04\x01\xd6y\x02\x04\x02\x04\x81\xf6\x04\x81\xf3\x00\xf1\x00v\x00\xcc\xfb\x0fj\x85q\te\xfe\x95\x9bS\xce\xe9\xb2|"\xe9\x85\\\r\x97\x8d\xb6\xa9~T\xc0\xfeL\r\xb0\x00\x00\x01\x97\x18\x9ay\xe6\x00\x00\x04\x03\x00G0E\x02!\x00\xf6\xb7\xa6u\x8e\x93\xe5e\x1bB\x0b\x04\x8e2\xf4\xecve\xdbul\xd9\xeas\x1b\xf6]\xe0\xcfM\xc2Y\x02 \\\xc3Vm.em\xd4\xfc\xb6\t\'\x18\x06"x\xef\x04\x1c^\xd8\xf1\xa5.\xf7\x82eg\xbe\xec9\xd8\x00w\x00\xdd\xdc\xca4\x95\xd7\xe1\x16\x05\xe7\x952\xfa\xc7\x9f\xf8=\x1cP\xdf\xdb\x00:\x14\x12v\n,\xac\xbb\xc8*\x00\x00\x01\x97\x18\x9ax\xe6\x00\x00\x04\x03\x00H0F\x02!\x00\xac\x9eh\x9f-0\xd4"\xed\x96\xfe8\x01\x1d\x7f\xa8:\xf3n\xf2\x8a\x83\xd7\xe5\xd2\x91\xc95\x05\x12\x16\x08\x02!\x00\x84\x83\x87\x11,O\x08~\x91N\xd8g4:\xdb\x19\t\xef\xfb\x8e\xad*\xdd<\xea\xa8\tV=\n\x13\x110\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\x000E\x02 \x13\xc8\xdf\xfb\xd6\n!E\x8f\x11\xb5\x0b\x0eX.\x82\xd2k\xf8\xc3\x91\x0f\xea\xe9\x86;e\xc2\x9e\x1462\x02!\x00\xfa$\x9ch4\x838|\\h\xb9\xb8\xfbn\n\x14\x1fX;*\xeb#w\xcf6\x8e\xe5\x9c\xb1\xa3\x07k'


def test_collect_certificate_metadata_PyOpenSSL_fallback():
    """
    Test collect_certificate_metadata_PyOpenSSL_fallback using a real DER certificate.
    """
    result = download_ct_logs.collect_certificate_metadata_PyOpenSSL_fallback(cert_as_der=good_der_certificate)
    assert isinstance(result, dict)
    assert "common_name" in result, "missing common_name in dictionary"
    assert "fingerprint" in result, "missing fingerprint in dictionary"
    assert "subjectAltName_DNS" in result, "missing subjectAltName_DNS in dictionary"
    assert isinstance(result["subjectAltName_DNS"], list)
    assert result.get("common_name") == "askkemp.com"
    assert result.get("fingerprint") == b"8D:51:69:65:98:A6:6D:90:7D:12:45:5B:D1:57:37:8F:72:9F:1C:AA"


def test_collect_certificate_metadata():
    """
    Test collect_certificate_metadata using a real DER certificate.
    """
    cert = x509.load_der_x509_certificate(good_der_certificate)
    result = download_ct_logs.collect_certificate_metadata(cert, good_der_certificate)
    assert isinstance(result, dict)
    assert "fingerprint" in result, "missing fingerprint in dictionary"
    assert "issuer" in result, "missing issuer in dictionary"
    assert "subject" in result, "missing subject in dictionary"
    assert "not_valid_before" in result, "missing not_valid_before in dictionary"
    assert "not_valid_after" in result, "missing not_valid_after in dictionary"
    isinstance("not_valid_before", datetime.datetime)
    isinstance("not_valid_after", datetime.datetime)
    assert "cn" in result, "missing cn in dictionary"
    assert "subjectAltName" in result, "missing subjectAltName in dictionary"
    assert isinstance(result["subjectAltName"], list)
    assert result.get("fingerprint") == "8d:51:69:65:98:a6:6d:90:7d:12:45:5b:d1:57:37:8f:72:9f:1c:aa"
    assert result.get("subject") == "CN=askkemp.com"
    assert result.get("cn") == "askkemp.com"
    assert result.get("issuer") == "CN=WE1,O=Google Trust Services,C=US"
    assert "askkemp.com" in result.get("subjectAltName")
    assert "*.askkemp.com" in result.get("subjectAltName")
    
def test_pki_validation():
    """
    Test pki_validation using a real DER certificate.
    """
    fingerprint = "test-fingerprint"
    result = download_ct_logs.pki_validation(good_der_certificate, "8D:51:69:65:98:A6:6D:90:7D:12:45:5B:D1:57:37:8F:72:9F:1C:AA")
    assert isinstance(result, bool)


test_collect_certificate_metadata_PyOpenSSL_fallback()
test_collect_certificate_metadata()
test_pki_validation()
