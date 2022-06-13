from dataclasses import replace
from pydoc import plain
from PyQt5 import QtCore, QtGui, QtWidgets

# My imported libs
from PyQt5.QtWidgets import QMessageBox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from StateManager import StateManager
import pathlib
import sys
import re

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(996, 640)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(10, 10, 221, 151))
        self.groupBox.setObjectName("groupBox")
        self.RSA_generate_key = QtWidgets.QPushButton(self.groupBox)
        self.RSA_generate_key.setGeometry(QtCore.QRect(10, 20, 91, 31))
        self.RSA_generate_key.setObjectName("RSA_generate_key")
        self.RSA_save_key = QtWidgets.QPushButton(self.groupBox)
        self.RSA_save_key.setGeometry(QtCore.QRect(110, 20, 91, 31))
        self.RSA_save_key.setObjectName("RSA_save_key")
        self.RSA_saved_to_label = QtWidgets.QLabel(self.groupBox)
        self.RSA_saved_to_label.setGeometry(QtCore.QRect(10, 120, 191, 21))
        self.RSA_saved_to_label.setObjectName("RSA_saved_to_label")
        self.label_9 = QtWidgets.QLabel(self.groupBox)
        self.label_9.setGeometry(QtCore.QRect(10, 60, 31, 21))
        self.label_9.setObjectName("label_9")
        self.RSA_bit_count = QtWidgets.QLineEdit(self.groupBox)
        self.RSA_bit_count.setGeometry(QtCore.QRect(40, 60, 161, 20))
        self.RSA_bit_count.setObjectName("RSA_bit_count")
        self.label_10 = QtWidgets.QLabel(self.groupBox)
        self.label_10.setGeometry(QtCore.QRect(10, 90, 51, 21))
        self.label_10.setObjectName("label_10")
        self.RSA_public_exponent = QtWidgets.QLineEdit(self.groupBox)
        self.RSA_public_exponent.setGeometry(QtCore.QRect(70, 90, 131, 20))
        self.RSA_public_exponent.setObjectName("RSA_public_exponent")
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_2.setGeometry(QtCore.QRect(10, 170, 221, 381))
        self.groupBox_2.setObjectName("groupBox_2")
        self.X509_sign_certificate = QtWidgets.QPushButton(self.groupBox_2)
        self.X509_sign_certificate.setGeometry(QtCore.QRect(10, 20, 91, 31))
        self.X509_sign_certificate.setObjectName("X509_sign_certificate")
        self.X509_save_certificate = QtWidgets.QPushButton(self.groupBox_2)
        self.X509_save_certificate.setGeometry(QtCore.QRect(110, 20, 91, 31))
        self.X509_save_certificate.setObjectName("X509_save_certificate")
        self.X509_self_signed = QtWidgets.QRadioButton(self.groupBox_2)
        self.X509_self_signed.setGeometry(QtCore.QRect(10, 60, 82, 17))
        self.X509_self_signed.setObjectName("X509_self_signed")
        self.label_2 = QtWidgets.QLabel(self.groupBox_2)
        self.label_2.setGeometry(QtCore.QRect(10, 260, 61, 21))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.groupBox_2)
        self.label_3.setGeometry(QtCore.QRect(10, 80, 51, 21))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.groupBox_2)
        self.label_4.setGeometry(QtCore.QRect(10, 110, 71, 21))
        self.label_4.setObjectName("label_4")
        self.X509_full_name = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_full_name.setGeometry(QtCore.QRect(70, 80, 131, 20))
        self.X509_full_name.setObjectName("X509_full_name")
        self.X509_country_code = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_country_code.setGeometry(QtCore.QRect(90, 110, 111, 20))
        self.X509_country_code.setObjectName("X509_country_code")
        self.X509_expiry_value = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_expiry_value.setGeometry(QtCore.QRect(60, 260, 51, 20))
        self.X509_expiry_value.setObjectName("X509_expiry_value")
        self.X509_expiry_delta = QtWidgets.QComboBox(self.groupBox_2)
        self.X509_expiry_delta.setGeometry(QtCore.QRect(120, 260, 81, 22))
        self.X509_expiry_delta.setObjectName("X509_expiry_delta")
        self.X509_expiry_delta.addItem("")
        self.X509_expiry_delta.addItem("")
        self.X509_expiry_delta.addItem("")
        self.X509_expiry_delta.addItem("")
        self.X509_hash_function = QtWidgets.QComboBox(self.groupBox_2)
        self.X509_hash_function.setGeometry(QtCore.QRect(90, 290, 111, 22))
        self.X509_hash_function.setObjectName("X509_hash_function")
        self.X509_hash_function.addItem("")
        self.X509_hash_function.addItem("")
        self.X509_hash_function.addItem("")
        self.X509_hash_function.addItem("")
        self.X509_hash_function.addItem("")
        self.X509_hash_function.addItem("")
        self.label_5 = QtWidgets.QLabel(self.groupBox_2)
        self.label_5.setGeometry(QtCore.QRect(10, 290, 71, 21))
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.groupBox_2)
        self.label_6.setGeometry(QtCore.QRect(10, 320, 61, 31))
        self.label_6.setObjectName("label_6")
        self.X509_select_key = QtWidgets.QPushButton(self.groupBox_2)
        self.X509_select_key.setGeometry(QtCore.QRect(70, 320, 131, 31))
        self.X509_select_key.setObjectName("X509_select_key")
        self.X509_loaded_keys_label = QtWidgets.QLabel(self.groupBox_2)
        self.X509_loaded_keys_label.setGeometry(QtCore.QRect(10, 350, 191, 21))
        self.X509_loaded_keys_label.setObjectName("X509_loaded_keys_label")
        self.label_7 = QtWidgets.QLabel(self.groupBox_2)
        self.label_7.setGeometry(QtCore.QRect(10, 140, 91, 21))
        self.label_7.setObjectName("label_7")
        self.X509_state_province = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_state_province.setGeometry(QtCore.QRect(110, 140, 91, 20))
        self.X509_state_province.setObjectName("X509_state_province")
        self.X509_user_id = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_user_id.setGeometry(QtCore.QRect(60, 170, 141, 20))
        self.X509_user_id.setObjectName("X509_user_id")
        self.label_15 = QtWidgets.QLabel(self.groupBox_2)
        self.label_15.setGeometry(QtCore.QRect(10, 170, 47, 21))
        self.label_15.setObjectName("label_15")
        self.label_16 = QtWidgets.QLabel(self.groupBox_2)
        self.label_16.setGeometry(QtCore.QRect(10, 200, 71, 21))
        self.label_16.setObjectName("label_16")
        self.X509_organization = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_organization.setGeometry(QtCore.QRect(80, 200, 121, 20))
        self.X509_organization.setObjectName("X509_organization")
        self.label_17 = QtWidgets.QLabel(self.groupBox_2)
        self.label_17.setGeometry(QtCore.QRect(10, 230, 47, 21))
        self.label_17.setObjectName("label_17")
        self.X509_email = QtWidgets.QLineEdit(self.groupBox_2)
        self.X509_email.setGeometry(QtCore.QRect(50, 230, 151, 20))
        self.X509_email.setObjectName("X509_email")
        self.groupBox_3 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_3.setGeometry(QtCore.QRect(10, 560, 221, 61))
        self.groupBox_3.setObjectName("groupBox_3")
        self.X509_load_certificate = QtWidgets.QPushButton(self.groupBox_3)
        self.X509_load_certificate.setGeometry(QtCore.QRect(10, 20, 91, 31))
        self.X509_load_certificate.setObjectName("X509_load_certificate")
        self.X509_verify_certificate = QtWidgets.QPushButton(self.groupBox_3)
        self.X509_verify_certificate.setGeometry(QtCore.QRect(110, 20, 91, 31))
        self.X509_verify_certificate.setObjectName("X509_verify_certificate")
        self.groupBox_4 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_4.setGeometry(QtCore.QRect(240, 10, 741, 151))
        self.groupBox_4.setObjectName("groupBox_4")
        self.RSA_public_key = QtWidgets.QTextEdit(self.groupBox_4)
        self.RSA_public_key.setGeometry(QtCore.QRect(10, 40, 351, 91))
        self.RSA_public_key.setObjectName("RSA_public_key")
        self.label_11 = QtWidgets.QLabel(self.groupBox_4)
        self.label_11.setGeometry(QtCore.QRect(10, 20, 61, 21))
        self.label_11.setObjectName("label_11")
        self.label_12 = QtWidgets.QLabel(self.groupBox_4)
        self.label_12.setGeometry(QtCore.QRect(370, 20, 61, 21))
        self.label_12.setObjectName("label_12")
        self.RSA_private_key = QtWidgets.QTextEdit(self.groupBox_4)
        self.RSA_private_key.setGeometry(QtCore.QRect(370, 40, 351, 91))
        self.RSA_private_key.setObjectName("RSA_private_key")
        self.groupBox_5 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_5.setGeometry(QtCore.QRect(240, 170, 741, 451))
        self.groupBox_5.setObjectName("groupBox_5")
        self.RSA_encryption_input = QtWidgets.QTextEdit(self.groupBox_5)
        self.RSA_encryption_input.setGeometry(QtCore.QRect(10, 40, 291, 391))
        self.RSA_encryption_input.setObjectName("RSA_encryption_input")
        self.RSA_encrypton_output = QtWidgets.QTextEdit(self.groupBox_5)
        self.RSA_encrypton_output.setGeometry(QtCore.QRect(430, 40, 291, 391))
        self.RSA_encrypton_output.setObjectName("RSA_encrypton_output")
        self.label_13 = QtWidgets.QLabel(self.groupBox_5)
        self.label_13.setGeometry(QtCore.QRect(10, 20, 61, 21))
        self.label_13.setObjectName("label_13")
        self.label_14 = QtWidgets.QLabel(self.groupBox_5)
        self.label_14.setGeometry(QtCore.QRect(430, 20, 61, 21))
        self.label_14.setObjectName("label_14")
        self.RSA_Encrypt = QtWidgets.QPushButton(self.groupBox_5)
        self.RSA_Encrypt.setGeometry(QtCore.QRect(320, 170, 91, 31))
        self.RSA_Encrypt.setObjectName("RSA_Encrypt")
        self.RSA_decrypt = QtWidgets.QPushButton(self.groupBox_5)
        self.RSA_decrypt.setGeometry(QtCore.QRect(320, 210, 91, 31))
        self.RSA_decrypt.setObjectName("RSA_decrypt")
        self.RSA_load_key = QtWidgets.QPushButton(self.groupBox_5)
        self.RSA_load_key.setGeometry(QtCore.QRect(320, 130, 91, 31))
        self.RSA_load_key.setObjectName("RSA_load_key")
        self.RSA_clear_fields = QtWidgets.QPushButton(self.groupBox_5)
        self.RSA_clear_fields.setGeometry(QtCore.QRect(320, 290, 91, 31))
        self.RSA_clear_fields.setObjectName("RSA_clear_fields")
        self.RSA_switch_fields = QtWidgets.QPushButton(self.groupBox_5)
        self.RSA_switch_fields.setGeometry(QtCore.QRect(320, 250, 91, 31))
        self.RSA_switch_fields.setObjectName("RSA_switch_fields")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Cert&RSA"))
        self.groupBox.setTitle(_translate("MainWindow", "RSA"))
        self.RSA_generate_key.setText(_translate("MainWindow", "Generate"))
        self.RSA_save_key.setText(_translate("MainWindow", "Save"))
        self.RSA_saved_to_label.setText(_translate("MainWindow", "Keys saved to: -"))
        self.label_9.setText(_translate("MainWindow", "Bits:"))
        self.label_10.setText(_translate("MainWindow", "Exponent:"))
        self.groupBox_2.setTitle(_translate("MainWindow", "X.509 certificate"))
        self.X509_sign_certificate.setText(_translate("MainWindow", "Sign"))
        self.X509_save_certificate.setText(_translate("MainWindow", "Save"))
        self.X509_self_signed.setText(_translate("MainWindow", "Self signed"))
        self.label_2.setText(_translate("MainWindow", "Valid for:"))
        self.label_3.setText(_translate("MainWindow", "Full name:"))
        self.label_4.setText(_translate("MainWindow", "Country code:"))
        self.X509_expiry_delta.setItemText(0, _translate("MainWindow", "Minutes"))
        self.X509_expiry_delta.setItemText(1, _translate("MainWindow", "Hours"))
        self.X509_expiry_delta.setItemText(2, _translate("MainWindow", "Days"))
        self.X509_expiry_delta.setItemText(3, _translate("MainWindow", "Weeks"))
        self.X509_hash_function.setItemText(0, _translate("MainWindow", "SHA1"))
        self.X509_hash_function.setItemText(1, _translate("MainWindow", "SHA256"))
        self.X509_hash_function.setItemText(2, _translate("MainWindow", "SHA512"))
        self.X509_hash_function.setItemText(3, _translate("MainWindow", "SHA3-256"))
        self.X509_hash_function.setItemText(4, _translate("MainWindow", "SHA3-512"))
        self.X509_hash_function.setItemText(5, _translate("MainWindow", "MD5"))
        self.label_5.setText(_translate("MainWindow", "Hash function:"))
        self.label_6.setText(_translate("MainWindow", "Key used:"))
        self.X509_select_key.setText(_translate("MainWindow", "Select key file"))
        self.X509_loaded_keys_label.setText(_translate("MainWindow", "Certificate saved: -"))
        self.label_7.setText(_translate("MainWindow", "State or province:"))
        self.label_15.setText(_translate("MainWindow", "User ID:"))
        self.label_16.setText(_translate("MainWindow", "Organization:"))
        self.label_17.setText(_translate("MainWindow", "Email:"))
        self.groupBox_3.setTitle(_translate("MainWindow", "Certificate validation"))
        self.X509_load_certificate.setText(_translate("MainWindow", "Load certificate"))
        self.X509_verify_certificate.setText(_translate("MainWindow", "Verify"))
        self.groupBox_4.setTitle(_translate("MainWindow", "Keys:"))
        self.label_11.setText(_translate("MainWindow", "Public key:"))
        self.label_12.setText(_translate("MainWindow", "Private key:"))
        self.groupBox_5.setTitle(_translate("MainWindow", "Encrypt/Decrypt"))
        self.label_13.setText(_translate("MainWindow", "Input:"))
        self.label_14.setText(_translate("MainWindow", "Output:"))
        self.RSA_Encrypt.setText(_translate("MainWindow", "Encrypt"))
        self.RSA_decrypt.setText(_translate("MainWindow", "Decrypt"))
        self.RSA_load_key.setText(_translate("MainWindow", "Load key"))
        self.RSA_clear_fields.setText(_translate("MainWindow", "Clear"))
        self.RSA_switch_fields.setText(_translate("MainWindow", "<---->"))

    def setupFunctionality(self, MainWindow):
        self.sm = StateManager()
        self.disable_NA_functions()
        self.add_functions()
        self.populate_session_fields()
        self.center_app(MainWindow)

    def populate_session_fields(self):   
        self.X509_full_name.setText(self.sm.get("cert_details", "full_name"))
        self.X509_country_code.setText(self.sm.get("cert_details", "country_code"))
        self.X509_state_province.setText(self.sm.get("cert_details", "state_province"))
        self.X509_user_id.setText(self.sm.get("cert_details", "user_id"))
        self.X509_organization.setText(self.sm.get("cert_details", "organization"))
        self.X509_email.setText(self.sm.get("cert_details", "email"))
        self.X509_expiry_value.setText(self.sm.get("cert_details", "expiry_value"))
        self.X509_hash_function.setCurrentIndex(int(self.sm.get("cert_details", "hash_algorithm")))

        self.session_password = bytes(self.sm.get("config", "session_password"), 'UTF-8')
        self.RSA_public_exponent.setText(self.sm.get("config", "pub_exponent"))
        self.RSA_bit_count.setText(self.sm.get("config", "bit_count"))

        self.X509_self_signed.setChecked(True)        

    def add_functions(self):
        # Encryption/Decryption
        self.RSA_load_key.clicked.connect(self.load_RSA_keys)
        self.RSA_Encrypt.clicked.connect(self.encrypt)
        self.RSA_decrypt.clicked.connect(self.decrypt)
        self.RSA_clear_fields.clicked.connect(self.clear_enc_dec_fields)
        self.RSA_switch_fields.clicked.connect(self.switch_enc_dec_fields)

        # RSA keys
        self.RSA_save_key.clicked.connect(self.save_RSA_keys)
        self.RSA_generate_key.clicked.connect(self.generate_RSA_key_pair)
        
        # Certificate
        self.X509_select_key.clicked.connect(self.load_RSA_keys)
        self.X509_sign_certificate.clicked.connect(self.sign_cert)      
        self.X509_save_certificate.clicked.connect(self.save_cert)

        # Validation
        self.X509_load_certificate.clicked.connect(self.load_cert)
        self.X509_verify_certificate.clicked.connect(self.verify_cert)

    def update_config_values(self):
        self.sm.store("config", "bit_count", self.RSA_bit_count.text())
        self.sm.store("cert_details", "full_name", self.X509_full_name.text())
        self.sm.store("cert_details", "country_code", self.X509_country_code.text())
        self.sm.store("cert_details", "state_province", self.X509_state_province.text())
        self.sm.store("cert_details", "user_id", self.X509_user_id.text())
        self.sm.store("cert_details", "organization", self.X509_organization.text())
        self.sm.store("cert_details", "email", self.X509_email.text())
        self.sm.store("cert_details", "expiry_value", self.X509_expiry_value.text())
        self.sm.store("cert_details", "hash_index", str(self.X509_hash_function.currentIndex()))

    def load_RSA_keys(self):
        mypath = pathlib.Path().resolve()
        file_name = QtWidgets.QFileDialog.getOpenFileName(self.centralwidget, 'Open file', str(mypath), "PEM files (*.pem)")[0]
        if file_name == "": return
        with open(file_name, "rb") as key_file:
            keys = serialization.load_pem_private_key(
                key_file.read(),
                password=self.session_password,
            )
            self.keys = keys
            self.print_RSA_keys(self.keys.private_numbers().d, self.keys.public_key().public_numbers().n)

    def generate_RSA_key_pair(self):
        pub_exp = int(self.RSA_public_exponent.text())
        bit_count = int(self.RSA_bit_count.text())
        self.keys = rsa.generate_private_key(
            public_exponent=pub_exp,
            key_size=bit_count,
        )
        self.RSA_save_key.setDisabled(False)
        self.print_RSA_keys(self.keys.private_numbers().d, self.keys.public_key().public_numbers().n)
        self.update_config_values()

    def print_RSA_keys(self, private, public):
        self.RSA_private_key.setText(str(private))
        self.RSA_public_key.setText(str(public))
        self.RSA_Encrypt.setDisabled(False)
        self.RSA_decrypt.setDisabled(False)

    def save_RSA_keys(self, keys):
        key_file = "key-{}{}{}.pem".format(datetime.utcnow().hour, datetime.utcnow().minute, datetime.utcnow().second)
        with open(key_file, "wb") as f:
            f.write(self.keys.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(self.session_password), # Wanna change this??
            ))
            self.RSA_saved_to_label.setText("Keys saved to: {}".format(key_file))

    def clear_enc_dec_fields(self):
        self.RSA_encryption_input.setText(str(""))
        self.RSA_encrypton_output.setText(str(""))

    def switch_enc_dec_fields(self):
        temp_field = self.RSA_encryption_input.toPlainText()
        self.RSA_encryption_input.setText(self.RSA_encrypton_output.toPlainText())
        self.RSA_encrypton_output.setText(temp_field)

    def save_cert(self):
        cert_name = "cert-{}{}{}.pem".format(datetime.utcnow().hour, datetime.utcnow().minute, datetime.utcnow().second)
        with open(cert_name, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
            self.X509_loaded_keys_label.setText("Certificate saved: {}".format(cert_name))

    def load_cert(self):
        mypath = pathlib.Path().resolve()
        file_name = QtWidgets.QFileDialog.getOpenFileName(self.centralwidget, 'Open file', str(mypath), "PEM files (*.pem)")[0]
        if file_name == "": return
        with open(file_name, 'rb') as certfile:
            certbyes = certfile.read()
            cert = x509.load_pem_x509_certificate(certbyes)
            self.cert = cert
        self.X509_verify_certificate.setEnabled(True)
    
    def verify_filled_field(self, field):
        if type(field) == QtWidgets.QTextEdit:
            if field.toPlainText() == "":
                return False
            else: return True
        elif type(field) == QtWidgets.QLineEdit:
            if field.text() == "":
                return False
            else: return True

    def sign_cert(self):
        # Check empty fields
        if (not (self.verify_filled_field(self.X509_full_name) and
            self.verify_filled_field(self.X509_country_code) and
            self.verify_filled_field(self.X509_state_province) and
            self.verify_filled_field(self.X509_user_id) and
            self.verify_filled_field(self.X509_organization) and 
            self.verify_filled_field(self.X509_email) and
            self.verify_filled_field(self.X509_expiry_value) and
            self.verify_filled_field(self.RSA_public_key))):
            msg = QMessageBox()
            msg.setWindowTitle("Error")          
            msg.setText("Please fill out all empty/necessary fields!")
            msg.setStandardButtons(QMessageBox.Close)
            msg.exec_()
            return

        match int(self.X509_expiry_delta.currentIndex()):
            case 0:
                time_delta = datetime.utcnow() + timedelta(minutes=int(self.X509_expiry_value.text()))
            case 1:
                time_delta = datetime.utcnow() + timedelta(hours=int(self.X509_expiry_value.text()))
            case 2:
                time_delta = datetime.utcnow() + timedelta(days=int(self.X509_expiry_value.text()))
            case 3:
                time_delta = datetime.utcnow() + timedelta(weeks=int(self.X509_expiry_value.text()))

        hash_dict = {"SHA1": hashes.SHA1(),
                     "SHA256": hashes.SHA256(),
                     "SHA512": hashes.SHA512(),
                     "SHA3-256": hashes.SHA3_256(),
                     "SHA3-512": hashes.SHA3_512(),
                     "MD5": hashes.MD5()}

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"{}".format(self.X509_country_code.text())),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{}".format(self.X509_state_province.text())),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{}".format(self.X509_organization.text())),
            x509.NameAttribute(NameOID.GIVEN_NAME, u"{}".format(self.X509_full_name.text().split()[0])),
            x509.NameAttribute(NameOID.SURNAME, u"{}".format(self.X509_full_name.text().split()[-1])),
            x509.NameAttribute(NameOID.USER_ID, u"{}".format(self.X509_user_id.text())),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{}".format(self.X509_email.text())),
        ])
        if self.X509_self_signed.isChecked(): subject = issuer
        self.cert = x509.CertificateBuilder().subject_name(
            subject
            ).issuer_name(
                issuer
            ).public_key(
                self.keys.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                time_delta
            ).sign(self.keys, hash_dict[self.X509_hash_function.currentText()])
        self.X509_save_certificate.setDisabled(False)
        self.update_config_values()

    def verify_cert(self):
        msg = QMessageBox()
        msg.setWindowTitle("Certificate validation")
        resize_spaces = " "*55 # Hacky workaround for resizing MessageBox (trust me, it's hard)
        msg.setText("Certificate read successfully, see fields below:" + resize_spaces)
        msg.setStandardButtons(QMessageBox.Close)
        msg.setDefaultButton(QMessageBox.Close)
        def_str = "--------- Subject ---------\n{}\
                \n--------- Issuer ---------\n{}\
                \n--------- Other details ---------\
                \nSerial Number: {}\
                \nValid from: {}\
                \nValid to: {}\
                \nPublic key:\n{}".format(
                self.cert.subject.rfc4514_string().replace(",", "\n"),
                self.cert.issuer.rfc4514_string().replace(",", "\n"),
                self.cert.serial_number,
                self.cert.not_valid_before,
                self.cert.not_valid_after,
                re.sub("(.{64})", "\\1\n", str(self.cert.public_key().public_numbers().n), 0, re.DOTALL))
        if self.cert.subject == self.cert.issuer:
            def_str = def_str + "\nIMPORTANT! Issuer and Subject are the same!"
        if self.verify_filled_field(self.RSA_public_key):
            if self.cert.public_key().public_numbers().n == int(self.RSA_public_key.toPlainText()):
                def_str = def_str + "\nIMPORTANT! Loaded key and public key in certificate are the same!"

        msg.setInformativeText(def_str)
        msg.exec_()

    def encrypt(self):
        message = self.RSA_encryption_input.toPlainText().encode('UTF-8')
        ciphertext = self.keys.public_key().encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hex_list = []
        for i in list(ciphertext): hex_list.append(hex(i))
        self.RSA_encrypton_output.setText(''.join(map(str, hex_list)))

    def decrypt(self):
        input_text = self.RSA_encryption_input.toPlainText()
        cipher = input_text.split('0x')[1:]
        for idx, i in enumerate(cipher):
            cipher[idx] = int('0x' + i, base=16)
        plaintext = self.keys.decrypt(
            bytes(cipher),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.RSA_encrypton_output.setText(plaintext.decode(encoding='UTF-8'))

    def disable_NA_functions(self):
        self.X509_verify_certificate.setDisabled(True)
        self.RSA_Encrypt.setDisabled(True)
        self.RSA_decrypt.setDisabled(True)
        self.RSA_public_exponent.setDisabled(True)
        self.X509_self_signed.setDisabled(True)
        self.X509_save_certificate.setDisabled(True)
        self.RSA_save_key.setDisabled(True)

    def center_app(self, window):
        frameGm = window.frameGeometry()
        screen = QtWidgets.QApplication.desktop().screenNumber(QtWidgets.QApplication.desktop().cursor().pos())
        centerPoint = QtWidgets.QApplication.desktop().screenGeometry(screen).center()
        frameGm.moveCenter(centerPoint)
        window.move(frameGm.topLeft())

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    ui.setupFunctionality(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

