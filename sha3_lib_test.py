from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature, InvalidKey

pub_exp = 65537
bit_count = 2048
keys = rsa.generate_private_key(
    public_exponent=pub_exp,
    key_size=bit_count,
)

issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"{}".format("LV")),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{}".format("Riga")),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{}".format("LU")),
    x509.NameAttribute(NameOID.GIVEN_NAME, u"{}".format("Edgars")),
    x509.NameAttribute(NameOID.SURNAME, u"{}".format("Liepins")),
    x509.NameAttribute(NameOID.USER_ID, u"{}".format("el11076")),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{}".format("citsedgars@gmail.com")),
])

subject = issuer
list_of_available_hashes = [
                #hashes.SHA512_224()        # Outright told me is not supported for signing signatures
                #hashes.SHA512_256()        # Outright told me is not supported for signing signatures
                hashes.SHA224()
                ,hashes.SHA256()
                ,hashes.SHA384()
                ,hashes.SHA512()
                ,hashes.SHA3_224()          # As can be seen by the test, below -> signing is OK, but during verification, fails due to unrecognized OID
                ,hashes.SHA3_256()          # As can be seen by the test, below -> signing is OK, but during verification, fails due to unrecognized OID
                ,hashes.SHA3_384()          # As can be seen by the test, below -> signing is OK, but during verification, fails due to unrecognized OID
                ,hashes.SHA3_512()          # As can be seen by the test, below -> signing is OK, but during verification, fails due to unrecognized OID
                #,hashes.SHAKE128()         # Failed due to lacking some additional parameters
                #,hashes.SHAKE256()         # Failed due to lacking some additional parameters
                ,hashes.MD5()
                #,hashes.BLAKE2b()          # Failed due to lacking some additional parameters
                #,hashes.BLAKE2s()          # Failed due to lacking some additional parameters
                #,hashes.SM3()              # Outright told me is not supported for signing signatures
                ]

for hash in list_of_available_hashes:
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        keys.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(hours=10)
    ).sign(keys, hash)

    while(True):
        try:
            keys.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                # Depends on the algorithm used to create the certificate
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            print(cert.signature_algorithm_oid, "Success!")
        except InvalidKey:
            print(cert.public_key(), "Invalid key!")
        except InvalidSignature:
            print(cert.signature, "Invalid signature!")
        except UnsupportedAlgorithm:
            print(cert.signature_algorithm_oid, "Unsupported algorithm!")  
        break

# Solution here is to add code to cryptography.hazmat._oid.py
# 1) _SIG_OIDS_TO_HASH needs:
# ----------------------------------------------------------
# SignatureAlgorithmOID.RSA_WITH_SHA3_224: hashes.SHA3_224(),
# SignatureAlgorithmOID.RSA_WITH_SHA3_256: hashes.SHA3_256(),
# SignatureAlgorithmOID.RSA_WITH_SHA3_384: hashes.SHA3_384(),
# SignatureAlgorithmOID.RSA_WITH_SHA3_512: hashes.SHA3_512(),
# ----------------------------------------------------------
#
# 2) _OID_NAMES needs:
# ----------------------------------------------------------
# SignatureAlgorithmOID.RSA_WITH_SHA3_224: "sha3_224WithRSAEncryption",
# SignatureAlgorithmOID.RSA_WITH_SHA3_256: "sha3_256WithRSAEncryption",
# SignatureAlgorithmOID.RSA_WITH_SHA3_384: "sha3_384WithRSAEncryption",
# SignatureAlgorithmOID.RSA_WITH_SHA3_512: "sha3_512WithRSAEncryption",
# ----------------------------------------------------------
#
# Then the test works and the signature verification with SHA3 as well