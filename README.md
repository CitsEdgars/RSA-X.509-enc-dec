# RSA-X.509-enc-dec
A small python program for generating RSA public/private keys and making self-signed X.509 certificates

Cryptography library lacks some data in cryptography.hazmat._oid.py, as a result, verification works only with non SHA3 hashes.
-Added a test to check if SHA3 is working with certificate verification with instructions on how to fix it.

Provided you have the necessary libs, compile-able to standalone (.exe) with: "pyinstaller.exe --onefile --windowed UI.py"

Layout files located in RSA_UI.ui
