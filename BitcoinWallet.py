# Python 3.8.10 64, UTF-8 #

from os import remove, mkdir, path
from sys import exit, argv
from qrcode import make
from re import compile
from hashlib import sha3_256
from uuid import uuid4
from sqlite3 import connect, Error
from requests import get
from smtplib import SMTP
from email.mime.text import MIMEText
from gnupg import GPG
from datetime import datetime, timedelta
from ntplib import NTPClient
from bit import PrivateKeyTestnet as Key
from PIL import Image
from bs4 import BeautifulSoup
from random import sample
from decouple import config

from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow, QWidget, QComboBox
from PyQt5.QtWidgets import QMessageBox, QLabel, QTextEdit, QStatusBar, QMenuBar
from PyQt5.QtWidgets import QMenu, QAction, QPushButton, QLineEdit, QFrame, QCheckBox
from PyQt5.QtCore import QRect, Qt, QSettings
from PyQt5.QtGui import QIcon, QFont, QPixmap
from bit.exceptions import InsufficientFunds
from decimal import DecimalException

# класс отвечающий за вызов всплывающего окна отсутствия интернета


class PopUp(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Error'
        self.resize(250, 150)
        self.icon = 'error.png'
        self.center()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setWindowIcon(QIcon(self.icon))

        buttonReply = QMessageBox.information(
            self, 'Error', "No network connection.", QMessageBox.Ok)
        if buttonReply == QMessageBox.Ok:
            exit()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


# подключение к базе данных

conn = connect('database.db')
c = conn.cursor()

# парсинг средней цены и лучшей комиссии

url = 'https://bitaps.com/'
try:
    response = get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    best_fee = soup.find('span', class_="pl-1 pr-1 bold")
    average_price = soup.find('h2', class_="text-right pr-1 mb-0 pb-0")
except:
    app = QApplication(argv)
    ex = PopUp()
    exit(app.exec_())

# gpg шифрование

gpg = GPG()
gpg.encoding = 'utf-8'
encrypt_path = path.join('encrypted/')

# ntp сервер

ntp = NTPClient()

# ссылка на хеш транзакции

url_hash = 'https://www.blockchain.com/btc-testnet/tx/'

'''Класс Window отвечает за создание основного окна программы.'''

# класс создания основного приложения


class Window(QMainWindow):

    def __init__(self):  # стартовая страница программы

        super(Window, self).__init__()

        self.setWindowTitle("BitcoinWallet")
        self.setWindowIcon(QIcon("i.png"))
        self.setFixedSize(620, 500)
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

        self.background = QLabel(self)
        self.background.setGeometry(QRect(0, 0, 620, 500))
        self.background.setObjectName("background")
        self.background.show()

        self.widget = QWidget(self)
        self.widget.setGeometry(QRect(190, 190, 211, 301))
        self.widget.setObjectName("widget")

        self.statusbar = QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        self.menubar = QMenuBar(self)
        self.menubar.setGeometry(QRect(0, 0, 445, 21))
        self.menubar.setObjectName("menubar")
        font = QFont()
        font.setFamily("Trebuchet MS")

        self.menubar.setFont(font)

        self.menu = QMenu(self.menubar)
        self.menu.setObjectName("menu")
        self.menu.setTitle("Settings")
        font = QFont()
        font.setFamily("Trebuchet MS")
        self.menu.setFont(font)

        self.setMenuBar(self.menubar)

        self.action_dark = QAction(self)
        icon = QIcon()
        icon.addPixmap(QPixmap("m.png"),
                       QIcon.Normal, QIcon.Off)
        self.action_dark.setIcon(icon)
        self.action_dark.setObjectName("action_dark")
        self.action_dark.setCheckable(True)

        self.action_light = QAction(self)
        icon = QIcon()
        icon.addPixmap(QPixmap("s.png"),
                       QIcon.Normal, QIcon.Off)
        self.action_light.setIcon(icon)
        self.action_light.setObjectName("action_light")
        self.action_light.setCheckable(True)

        self.action_help = QAction(self)
        icon = QIcon()
        icon.addPixmap(QPixmap("help.png"),
                       QIcon.Normal, QIcon.Off)
        self.action_help.setIcon(icon)
        self.action_help.setObjectName("action_help")

        self.menu.addAction(self.action_dark)
        self.menu.addAction(self.action_light)
        self.menu.addSeparator()
        self.menu.addAction(self.action_help)
        self.menubar.addAction(self.menu.menuAction())

        self.action_dark.setText("Dark mode")
        self.action_light.setText("Light mode")
        self.action_help.setText("Help")

        self.CONFIG = 'config.ini'

        self.generate_btn = QPushButton(self.widget)
        self.generate_btn.setGeometry(QRect(20, 20, 181, 51))
        font = QFont()
        font.setPointSize(12)
        self.generate_btn.setFont(font)
        self.generate_btn.setObjectName("generate_btn")
        self.generate_btn.setText("Generate")
        font.setFamily("Roboto, Regular")
        self.generate_btn.setFont(font)

        self.balance_btn = QPushButton(self.widget)
        self.balance_btn.setGeometry(QRect(20, 70, 181, 51))
        font = QFont()
        font.setPointSize(12)
        self.balance_btn.setFont(font)
        self.balance_btn.setObjectName("balance_btn")
        self.balance_btn.setText("Balance")
        font.setFamily("Roboto, Regular")
        self.balance_btn.setFont(font)

        self.send_btn = QPushButton(self.widget)
        self.send_btn.setGeometry(QRect(20, 120, 181, 51))
        font = QFont()
        font.setPointSize(12)
        self.send_btn.setFont(font)
        self.send_btn.setObjectName("send_btn")
        self.send_btn.setText("Send")
        font.setFamily("Roboto, Regular")
        self.send_btn.setFont(font)

        self.hash_btn = QPushButton(self.widget)
        self.hash_btn.setGeometry(QRect(20, 170, 181, 51))
        font = QFont()
        font.setPointSize(12)
        self.hash_btn.setFont(font)
        self.hash_btn.setObjectName("hash_btn")
        self.hash_btn.setText("Hashes")
        font.setFamily("Roboto, Regular")
        self.hash_btn.setFont(font)

        self.exit_btn = QPushButton(self.widget)
        self.exit_btn.setGeometry(QRect(20, 220, 181, 51))
        font = QFont()
        font.setPointSize(12)
        self.exit_btn.setFont(font)
        self.exit_btn.setObjectName("exit_btn")
        self.exit_btn.setText("Exit")
        font.setFamily("Roboto, Regular")
        self.exit_btn.setFont(font)

        self.label = QLabel(self)
        self.label.setGeometry(QRect(65, 105, 481, 71))
        font = QFont()
        font.setPointSize(60)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label.setText("BitcoinWallet")
        font.setFamily("Berlin Sans FB Demi")
        font.setPointSize(60)
        font.setBold(False)
        font.setItalic(False)
        self.label.setFont(font)

        self.authorization = QPushButton(self)
        self.authorization.setGeometry(QRect(410, 45, 70, 34))
        font = QFont()
        font.setPointSize(11)
        self.authorization.setFont(font)
        self.authorization.setObjectName("authorization")
        self.authorization.setText("Login")
        font.setFamily("Roboto, Regular")
        self.authorization.setFont(font)

        self.registration = QPushButton(self)
        self.registration.setGeometry(QRect(480, 45, 110, 34))
        font = QFont()
        font.setPointSize(11)
        self.registration.setFont(font)
        self.registration.setObjectName("registration")
        self.registration.setText("Registration")
        font.setFamily("Roboto, Regular")
        self.registration.setFont(font)

        self.have_a_key = QPushButton(self)
        self.have_a_key.setGeometry(QRect(30, 45, 110, 34))
        font = QFont()
        font.setPointSize(11)
        self.have_a_key.setFont(font)
        self.have_a_key.setObjectName("have_a_key")
        self.have_a_key.setText("I have a key")
        font.setFamily("Roboto, Regular")
        self.have_a_key.setFont(font)

        self.log_out = QPushButton(self)
        self.log_out.setGeometry(QRect(480, 45, 110, 30))
        font = QFont()
        font.setPointSize(11)
        self.log_out.setFont(font)
        self.log_out.setObjectName("log_out")
        self.log_out.setText("Log out")
        font.setFamily("Roboto, Regular")
        self.log_out.setFont(font)
        self.log_out.hide()

        self.generate_btn.clicked.connect(self.generate_wallet_GUI)
        self.balance_btn.clicked.connect(self.check_balance_GUI)
        self.send_btn.clicked.connect(self.send_bitcoins_GUI)
        self.hash_btn.clicked.connect(self.hash_transactions_GUI)
        self.exit_btn.clicked.connect(self.close)

        self.action_dark.triggered.connect(self.dark_theme)
        self.action_light.triggered.connect(self.light_theme)

        self.authorization.clicked.connect(self.auth_GUI)
        self.registration.clicked.connect(self.registration_GUI)
        self.have_a_key.clicked.connect(self.registration_key_GUI)

        self.action_help.triggered.connect(self.openWin)

        self.load_settings()

    # окно создания учётной записи с имеющимся закрытым ключом

    def registration_key_GUI(self):
        self.registration_GUI()
        self.action_dark.triggered.connect(self.dark_theme_key_registration)
        self.action_light.triggered.connect(self.light_theme_key_registration)

        self.key_lbl_reg = QLabel(self)
        self.key_lbl_reg.setGeometry(QRect(162, 205, 71, 18))
        font = QFont()
        font.setFamily("Roboto, Black")
        font.setPointSize(11)
        self.key_lbl_reg.setFont(font)
        self.key_lbl_reg.setObjectName("key_lbl_reg")
        self.key_lbl_reg.setText('Key')
        self.key_lbl_reg.show()

        self.key_edit_reg = QLineEdit(self)
        self.key_edit_reg.setGeometry(QRect(210, 200, 291, 31))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.key_edit_reg.setFont(font)
        self.key_edit_reg.setObjectName("key_edit_reg")
        self.key_edit_reg.show()

        self.mail_lbl_reg.setGeometry(QRect(149, 245, 71, 18))
        self.password_lbl_reg.setGeometry(QRect(120, 285, 71, 20))

        self.mail_edit_reg.setGeometry(QRect(210, 240, 291, 31))
        self.password_edit_reg.setGeometry(QRect(210, 280, 291, 31))

        self.password_show_check.setGeometry(QRect(510, 293, 111, 17))
        self.warning_reg.setGeometry(QRect(90, 360, 411, 20))
        self.gen_btn_pass.setGeometry((QRect(260, 320, 161, 31)))
        self.reg_btn.setGeometry(QRect(290, 400, 161, 51))

        self.key_edit_reg.editingFinished.connect(self.key_reg)

        self.reg_back_btn.clicked.connect(self.reg_key_close)

    # создание окна виджетов авторизации пользователя

    def auth_GUI(self):
        self.action_dark.triggered.connect(self.dark_theme_authorization)
        self.action_light.triggered.connect(self.light_theme_authorization)

        self.widget.hide()
        self.authorization.close()
        self.registration.close()
        self.have_a_key.close()

        self.user_lbl = QLabel(self)
        self.user_lbl.setGeometry(QRect(164, 227, 71, 16))
        font = QFont()
        font.setFamily("Roboto, Black")
        font.setPointSize(11)
        self.user_lbl.setFont(font)
        self.user_lbl.setObjectName("user_lbl")
        self.user_lbl.setText("Email")
        self.user_lbl.show()

        self.user_input = QLineEdit(self)
        self.user_input.setGeometry(QRect(220, 220, 201, 31))
        self.user_input.setObjectName("user_input")
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.user_input.setFont(font)
        self.user_input.show()

        self.pass_lbl = QLabel(self)
        self.pass_lbl.setGeometry(QRect(135, 265, 71, 16))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.pass_lbl.setFont(font)
        self.pass_lbl.setObjectName("pass_lbl")
        self.pass_lbl.setText("Password")
        self.pass_lbl.show()

        self.pass_input = QLineEdit(self)
        self.pass_input.setGeometry(QRect(220, 260, 201, 31))
        self.pass_input.setObjectName("pass_input")
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.pass_input.setFont(font)
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.show()

        self.login_btn = QPushButton(self)
        self.login_btn.setGeometry(QRect(240, 340, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.login_btn.setFont(font)
        self.login_btn.setObjectName("login_btn")
        self.login_btn.setText("Login")
        self.login_btn.show()

        self.login_back_btn = QPushButton(self)
        self.login_back_btn.setGeometry(QRect(400, 45, 70, 34))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.login_back_btn.setFont(font)
        self.login_back_btn.setObjectName("login_back_btn")
        self.login_back_btn.setText("Back")
        self.login_back_btn.show()

        self.warning_log = QLabel(self)
        self.warning_log.setGeometry(QRect(150, 300, 301, 20))
        self.warning_log.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.warning_log.setFont(font)
        self.warning_log.setObjectName("warning_log")
        self.warning_log.show()

        self.user_input.editingFinished.connect(self.auth_user)
        self.pass_input.editingFinished.connect(self.auth_pass)

        self.login_btn.clicked.connect(self.check_login)
        self.login_back_btn.clicked.connect(self.close_authorization)

    # закрытие авторизации

    def close_authorization(self):
        self.user_lbl.close()
        self.user_input.close()
        self.pass_lbl.close()
        self.pass_input.close()
        self.login_btn.close()
        self.warning_log.close()
        self.login_back_btn.close()
        self.authorization.show()
        self.registration.show()
        self.have_a_key.show()

        self.widget.show()

    # проверка имени пользователя(строка не должна быть пустой)

    def auth_user(self):
        if self.action_dark.isChecked():
            self.user_input.textEdited.connect(
                lambda: self.user_input.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.user_input.textEdited.connect(
                lambda: self.user_input.setStyleSheet("background-color: white"))
        if self.user_input.text() == '':
            self.warning_log.clear()
            self.warning_log.setText('This field cannot be left blank')
            self.user_input.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        else:
            self.warning_log.clear()

    # проверка пароля пользователя(строка не должна быть пустой)

    def auth_pass(self):
        if self.action_dark.isChecked():
            self.pass_input.textEdited.connect(
                lambda: self.pass_input.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.pass_input.textEdited.connect(
                lambda: self.pass_input.setStyleSheet("background-color: white"))
        if self.pass_input.text() == '':
            self.warning_log.clear()
            self.warning_log.setText('This field cannot be left blank')
            self.pass_input.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        else:
            self.warning_log.clear()

    # проверка логина

    def check_login(self):
        global name
        global password_input
        global formatted_time

        login_count = 0
        format = '%Y-%m-%d %H:%M:%S'
        attempts = 0

        name = self.user_input.text()
        password_input = self.pass_input.text()
        statement = f"SELECT username from users"
        c.execute(statement)
        names = {name[0] for name in c.fetchall()}
        if name not in names:
            self.warning_log.clear()
            self.warning_log.setText("The username or password is incorrect")

        else:
            if password_input == '':
                self.warning_log.setText('This field cannot be left blank')
                self.pass_input.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                self.warning_log.clear()
                c.execute("SELECT salt, password FROM users WHERE username = ?;",
                          (name,))
                try:
                    for row in c:
                        salt = row[0]
                        actual_hash = row[1]
                        input_hash = sha3_256(
                            password_input.encode() + salt.encode()).hexdigest()
                        if input_hash == actual_hash:
                            c.execute("SELECT time_to_unblock FROM users WHERE username = ?;",
                                      (name, ))
                            for row in c:
                                time_to_unblock = row[0]
                                if time_to_unblock == None:

                                    self.user_interface_GUI()
                                    if self.action_dark.isChecked():
                                        self.dark_theme_log()
                                    elif self.action_light.isChecked():
                                        self.light_theme_log()
                                else:

                                    response = ntp.request('ntp2.time.in.ua')
                                    time = datetime.fromtimestamp(
                                        response.tx_time)
                                    time_now = time.strftime(format)
                                    c.execute("SELECT time_to_unblock FROM users WHERE username = ?;",
                                              (name, ))
                                    for row in c:
                                        time_to_unblock = row[0]

                                    d1 = datetime.strptime(time_now, format)
                                    d2 = datetime.strptime(
                                        time_to_unblock, format)
                                    difference = str(d2-d1)
                                    if difference.find("-"):
                                        self.warning_log.clear()
                                        self.warning_log.setText(
                                            'Locked out for ' + difference)
                                    else:
                                        self.warning_log.clear()
                                        c.execute("UPDATE users SET time_to_unblock = null, login_count = 0, block = 0 WHERE username = ?;",
                                                  (name, ))
                                        conn.commit()
                                        self.user_interface_GUI()
                                        if self.action_dark.isChecked():
                                            self.dark_theme_log()
                                        elif self.action_light.isChecked():
                                            self.light_theme_log()

                        else:
                            self.warning_log.setText(
                                "The username or password is incorrect")
                            c.execute("SELECT login_count FROM users WHERE username = ?;",
                                      (name, ))
                            try:
                                for row in c:
                                    login_count = row[0]
                                    if login_count == 0:
                                        self.count_commit()
                                    elif login_count == 1:
                                        self.count_commit()
                                    elif login_count == 2:
                                        self.count_commit()

                                        response = ntp.request(
                                            'ntp2.time.in.ua')
                                        time = datetime.fromtimestamp(
                                            response.tx_time) + timedelta(hours=2)
                                        formatted_time = time.strftime(format)

                                        c.execute("UPDATE users SET block = 1, time_to_unblock = ? WHERE username = ?;",
                                                  (formatted_time, name))
                                        conn.commit()

                                        self.warning_log.clear()
                                        self.warning_log.setText(
                                            "Locked out for 2 hours")
                                        statement = f"SELECT username from users"
                                        c.execute(statement)
                                        names = {name[0]
                                                 for name in c.fetchall()}
                                        if name in names:
                                            self.send_warning_mail()
                                        else:
                                            pass

                                    elif login_count == 3:

                                        response = ntp.request(
                                            'ntp2.time.in.ua')
                                        #attempts += 1

                                        time = datetime.fromtimestamp(
                                            response.tx_time)
                                        time_now = time.strftime(format)

                                        c.execute("SELECT time_to_unblock FROM users WHERE username = ?;",
                                                  (name, ))
                                        for row in c:
                                            time_to_unblock = row[0]

                                        d1 = datetime.strptime(
                                            time_now, format)
                                        d2 = datetime.strptime(
                                            time_to_unblock, format)
                                        difference = str(d2-d1)
                                        if difference.find("-"):
                                            self.warning_log.clear()
                                            self.warning_log.setText(
                                                'Locked out for ' + difference)
                                        else:
                                            self.warning_log.clear()
                                            c.execute("UPDATE users SET time_to_unblock = null, login_count = 1, block = 0 WHERE username = ?;",
                                                      (name, ))
                                            conn.commit()
                                            self.warning_log.setText(
                                                "The username or password is incorrect")
                                            self.pass_input.setStyleSheet(
                                                "background-color: rgb(255, 175, 175);")
                            except (Exception, Error):
                                pass
                except (Exception, Error):
                    pass

    # увеличение счётчика

    def count_commit(self):
        global name
        c.execute("UPDATE users SET login_count = login_count +1 WHERE username = ?;",
                  (name, ))
        conn.commit()

    # окно пользователя после входа в свой аккаунт

    def user_interface_GUI(self):
        global name
        global password_input
        global decrypted

        self.action_dark.triggered.connect(self.dark_theme_log)
        self.action_light.triggered.connect(self.light_theme_log)

        self.user_lbl.close()
        self.user_input.close()
        self.pass_lbl.close()
        self.pass_input.close()
        self.login_btn.close()
        self.warning_log.close()
        self.login_back_btn.close()
        self.authorization.close()
        self.registration.close()
        self.have_a_key.close()
        self.log_out.show()

        self.user_wallet_segwit = QLineEdit(self)
        self.user_wallet_segwit.setGeometry(QRect(30, 210, 470, 30))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.user_wallet_segwit.setFont(font)
        self.user_wallet_segwit.setFrame(False)
        self.user_wallet_segwit.setObjectName("user_wallet_segwit")
        self.user_wallet_segwit.setReadOnly(True)
        self.user_wallet_segwit.show()

        self.user_wallet_legacy = QLineEdit(self)
        self.user_wallet_legacy.setGeometry(QRect(30, 240, 470, 30))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.user_wallet_legacy.setFont(font)
        self.user_wallet_legacy.setFrame(False)
        self.user_wallet_legacy.setObjectName("user_wallet_legacy")
        self.user_wallet_legacy.setReadOnly(True)
        self.user_wallet_legacy.show()

        self.user_log_btn_send = QPushButton(self)
        self.user_log_btn_send.setGeometry(QRect(240, 285, 171, 51))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.user_log_btn_send.setFont(font)
        self.user_log_btn_send.setObjectName("user_log_btn_send")
        self.user_log_btn_send.show()

        self.user_log_btn_hash = QPushButton(self)
        self.user_log_btn_hash.setGeometry(QRect(240, 341, 171, 51))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.user_log_btn_hash.setFont(font)
        self.user_log_btn_hash.setObjectName("user_log_btn_hash")
        self.user_log_btn_hash.show()

        self.user_money = QTextEdit(self)
        self.user_money.setGeometry(QRect(70, 280, 180, 120))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(13)
        self.user_money.setFont(font)
        self.user_money.setFrameShape(QFrame.NoFrame)
        self.user_money.setObjectName("user_money")
        self.user_money.setReadOnly(True)
        self.user_money.show()

        self.user_lbl_btc = QLabel(self)
        self.user_lbl_btc.setGeometry(QRect(30, 284, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.user_lbl_btc.setFont(font)
        self.user_lbl_btc.setObjectName("user_lbl_btc")
        self.user_lbl_btc.setText('BTC')
        self.user_lbl_btc.show()

        self.user_lbl_satoshi = QLabel(self)
        self.user_lbl_satoshi.setGeometry(QRect(30, 304, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.user_lbl_satoshi.setFont(font)
        self.user_lbl_satoshi.setObjectName("user_lbl_satoshi")
        self.user_lbl_satoshi.setText('Sat')
        self.user_lbl_satoshi.show()

        self.user_lbl_usd = QLabel(self)
        self.user_lbl_usd.setGeometry(QRect(30, 326, 33, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.user_lbl_usd.setFont(font)
        self.user_lbl_usd.setObjectName("user_lbl_usd")
        self.user_lbl_usd.setText('USD')
        self.user_lbl_usd.show()

        self.user_lbl_eur = QLabel(self)
        self.user_lbl_eur.setGeometry(QRect(30, 347, 33, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.user_lbl_eur.setFont(font)
        self.user_lbl_eur.setObjectName("user_lbl_eur")
        self.user_lbl_eur.setText('EUR')
        self.user_lbl_eur.show()

        self.user_lbl_rub = QLabel(self)
        self.user_lbl_rub.setGeometry(QRect(30, 368, 33, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.user_lbl_rub.setFont(font)
        self.user_lbl_rub.setObjectName("user_lbl_rub")
        self.user_lbl_rub.setText('RUB')
        self.user_lbl_rub.show()

        self.user_average_price = QLabel(self)
        self.user_average_price.setGeometry(QRect(30, 400, 130, 30))
        font = QFont()
        font.setPointSize(16)
        font.setFamily("Roboto, Black")
        self.user_average_price.setFont(font)
        self.user_average_price.setObjectName("user_average_price")
        self.user_average_price.setText(
            '$ '+''.join(average_price.find('b').stripped_strings))
        self.user_average_price.show()

        self.user_QR_segwit = QLabel(self)
        self.user_QR_segwit.setGeometry(QRect(468, 280, 120, 120))
        self.user_QR_segwit.setObjectName("user_QR_segwit")

        self.user_QR_legacy = QLabel(self)
        self.user_QR_legacy.setGeometry(QRect(468, 280, 120, 120))
        self.user_QR_legacy.setObjectName("user_QR_legacy")

        self.user_segwit_QR_show = QPushButton(self)
        self.user_segwit_QR_show.setGeometry(QRect(490, 216, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.user_segwit_QR_show.setFont(font)
        self.user_segwit_QR_show.setObjectName("user_segwit_QR_show")
        self.user_segwit_QR_show.setText("SegWit QR")
        self.user_segwit_QR_show.show()

        self.user_legacy_QR_show = QPushButton(self)
        self.user_legacy_QR_show.setGeometry(QRect(490, 246, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.user_legacy_QR_show.setFont(font)
        self.user_legacy_QR_show.setObjectName("user_legacy_QR_show")
        self.user_legacy_QR_show.setText("Legacy QR")
        self.user_legacy_QR_show.show()

        self.user_refresh_price = QPushButton(self)
        self.user_refresh_price.setGeometry(QRect(30, 435, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.user_refresh_price.setFont(font)
        self.user_refresh_price.setObjectName("user_refresh_price")
        self.user_refresh_price.setText("Refresh")
        self.user_refresh_price.show()

        self.decrypt()
        decrypt_cipher = bytes.decode(decrypted.data, encoding='utf-8')

        my_wallet = Key(decrypt_cipher)

        self.user_wallet_segwit.setText("Segwit: " + my_wallet.segwit_address)
        self.user_wallet_legacy.setText("Legacy: " + my_wallet.address)

        data = my_wallet.segwit_address
        data2 = my_wallet.address

        img = make(data)
        img2 = make(data2)

        img.save("image.png")
        img2.save("image2.png")

        img = Image.open('image.png')
        img2 = Image.open('image2.png')

        width, height = 120, 120
        res_img = img.resize((width, height), Image.ANTIALIAS)
        res_img2 = img2.resize((width, height), Image.ANTIALIAS)

        res_img.save('image.png')
        res_img2.save('image2.png')

        self.user_QR_segwit.setPixmap(QPixmap("image.png"))
        self.user_QR_legacy.setPixmap(QPixmap("image2.png"))
        self.user_QR_segwit.show()

        self.user_log_btn_send.setText("Send")
        self.user_log_btn_hash.setText("Hashes")
        self.user_money.setAlignment(Qt.AlignCenter)

        self.user_money.setText(my_wallet.get_balance('btc') +
                                '\n'+my_wallet.get_balance(
            'satoshi') +
            '\n'+my_wallet.get_balance('usd') +
            '\n'+my_wallet.get_balance('eur') +
            '\n'+my_wallet.get_balance('rub'))

        self.log_out.clicked.connect(self.log_out_account)
        self.user_log_btn_send.clicked.connect(
            self.user_interface_send_bitcoins_GUI)
        self.user_log_btn_hash.clicked.connect(self.user_interface_hash)
        self.user_refresh_price.clicked.connect(self.user_price_refresh)
        self.user_segwit_QR_show.clicked.connect(self.user_show_segwit_QR)
        self.user_legacy_QR_show.clicked.connect(self.user_show_legacy_QR)

    # показать segwit qr

    def user_show_segwit_QR(self):
        self.user_QR_legacy.close()
        self.user_QR_segwit.show()

    # показать legacy qr

    def user_show_legacy_QR(self):
        self.user_QR_segwit.close()
        self.user_QR_legacy.show()

    # кнопка обновления цены биткоина

    def user_price_refresh(self):
        response = get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        average_price = soup.find('h2', class_="text-right pr-1 mb-0 pb-0")
        self.user_average_price.setText(
            '$ '+''.join(average_price.find('b').stripped_strings))

    # окно хеш транзакций юзера

    def user_interface_hash(self):
        global name
        global decrypted

        self.action_dark.triggered.connect(self.dark_theme_hash_user)
        self.action_light.triggered.connect(self.light_theme_hash_user)

        self.log_out.close()
        self.user_log_btn_send.close()
        self.user_log_btn_hash.close()
        self.user_money.close()
        self.user_QR_segwit.close()
        self.user_QR_legacy.close()
        self.user_lbl_btc.close()
        self.user_lbl_satoshi.close()
        self.user_lbl_usd.close()
        self.user_lbl_eur.close()
        self.user_lbl_rub.close()
        self.user_average_price.close()
        self.user_wallet_segwit.close()
        self.user_wallet_legacy.close()
        self.user_refresh_price.close()
        self.user_segwit_QR_show.close()
        self.user_legacy_QR_show.close()

        self.user_log_hash_txt = QTextEdit(self)
        self.user_log_hash_txt.setGeometry(QRect(23, 200, 581, 211))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.user_log_hash_txt.setFont(font)
        self.user_log_hash_txt.setObjectName("user_log_hash_txt")
        self.user_log_hash_txt.setReadOnly(True)
        self.user_log_hash_txt.setStyleSheet("background-color: white;")
        self.user_log_hash_txt.show()

        self.user_log_exit_hash = QPushButton(self)
        self.user_log_exit_hash.setGeometry(QRect(250, 430, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.user_log_exit_hash.setFont(font)
        self.user_log_exit_hash.setObjectName("user_log_exit_hash")
        self.user_log_exit_hash.setText("Exit")
        self.user_log_exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)};""")
        self.user_log_exit_hash.show()

        self.decrypt()
        decrypt_cipher = bytes.decode(decrypted.data, encoding='utf-8')

        my_wallet = Key(decrypt_cipher)

        transactions = str(my_wallet.get_transactions())
        unspents = str(my_wallet.get_unspents())
        self.user_log_hash_txt.setText(
            'Hashes:\n' + transactions[1:-1] +
            '\n\nUnspents: \n' + unspents[1:-1])

        self.user_log_exit_hash.clicked.connect(self.close_user_interface_hash)

    # закрытие окна хеш транзакций юзера

    def close_user_interface_hash(self):

        self.user_log_hash_txt.close()
        self.user_log_exit_hash.close()

        self.log_out.show()
        self.user_interface_GUI()

    # окно отправки биткоинов юзера

    def user_interface_send_bitcoins_GUI(self):

        self.action_dark.triggered.connect(self.dark_theme_send_user)
        self.action_light.triggered.connect(self.light_theme_send_user)

        self.log_out.close()
        self.user_log_btn_send.close()
        self.user_log_btn_hash.close()
        self.user_money.close()
        self.user_QR_segwit.close()
        self.user_QR_legacy.close()
        self.user_lbl_btc.close()
        self.user_lbl_satoshi.close()
        self.user_lbl_usd.close()
        self.user_lbl_eur.close()
        self.user_lbl_rub.close()
        self.user_average_price.close()
        self.user_wallet_segwit.close()
        self.user_wallet_legacy.close()
        self.user_refresh_price.close()
        self.user_segwit_QR_show.close()
        self.user_legacy_QR_show.close()

        self.user_send_btn_rej = QPushButton(self)
        self.user_send_btn_rej.setGeometry(QRect(160, 420, 121, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.user_send_btn_rej.setFont(font)
        self.user_send_btn_rej.setObjectName("user_send_btn_rej")
        self.user_send_btn_rej.setText("Cancel")
        self.user_send_btn_rej.show()

        self.send_bitcoins_GUI()
        self.recipient.setGeometry(32, 213, 101, 20)
        self.recipient_res.setGeometry(130, 210, 460, 31)
        self.currency.setGeometry(33, 253, 61, 20)
        self.currency_res.setGeometry(130, 253, 121, 22)
        self.fee.setGeometry(280, 253, 71, 20)
        self.fee_res.setGeometry(330, 250, 91, 31)
        self.sum.setGeometry(40, 293, 61, 20)
        self.sum_res.setGeometry(130, 290, 131, 31)

        self.QR_label_transaction.setGeometry(470, 260, 120, 120)
        self.clipboard.setGeometry(510, 390, 40, 25)
        self.warning_send.setGeometry(150, 350, 300, 20)
        self.send_btn_send.setGeometry(330, 400, 121, 41)
        self.user_send_btn_rej.setGeometry(160, 400, 121, 41)
        self.send_btn_rej.close()
        self.sender.close()
        self.user_sender()

        self.user_send_btn_rej.clicked.connect(self.user_close_send)

    # присваивание строке отправителя закрытый ключ юзера

    def user_sender(self):
        global name
        global decrypted

        self.decrypt()
        decrypt_cipher = bytes.decode(decrypted.data, encoding='utf-8')

        my_wallet = Key(decrypt_cipher)

        self.sender_res.setText(decrypt_cipher)
        self.sender_res.hide()

    # закрытие окна отправки биткоинов юзера

    def user_close_send(self):
        self.sender_res.close()
        self.recipient.close()
        self.recipient_res.close()
        self.currency.close()
        self.currency_res.close()
        self.sum.close()
        self.sum_res.close()
        self.fee.close()
        self.fee_res.close()
        self.send_btn_send.close()
        self.user_send_btn_rej.close()
        self.warning_send.close()
        self.QR_label_transaction.close()
        self.clipboard.close()

        self.log_out.show()
        self.user_interface_GUI()

    # закрытие окна отправки биткоинов юзера

    def close_user_interface_send_bitcoins_GUI(self):
        self.user_recipient.close()
        self.user_recipient_res.close()
        self.user_currency.close()
        self.user_currency_res.close()
        self.fee.close()
        self.fee_res.close()
        self.user_sum.close()
        self.user_sum_res.close()
        self.user_send_btn_send.close()
        self.user_send_btn_rej.close()
        self.user_warning_send.close()

        self.log_out.show()
        self.user_interface_GUI()

    # окно регистрации

    def registration_GUI(self):
        self.action_dark.triggered.connect(self.dark_theme_registration)
        self.action_light.triggered.connect(self.light_theme_registration)

        self.widget.hide()
        self.registration.close()
        self.authorization.close()
        self.have_a_key.close()

        self.success_reg = QLabel(self)
        self.success_reg.setGeometry(QRect(130, 220, 351, 31))
        font = QFont()
        font.setFamily("Microsoft YaHei UI")
        font.setPointSize(16)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.success_reg.setFont(font)
        self.success_reg.setObjectName("success_reg")
        self.success_reg.setText("You have successfully registered!")

        self.success_btn = QPushButton(self)
        self.success_btn.setGeometry(QRect(250, 330, 101, 31))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(15)
        self.success_btn.setFont(font)
        self.success_btn.setObjectName("success_btn")
        self.success_btn.setText("OK")

        self.mail_lbl_reg = QLabel(self)
        self.mail_lbl_reg.setGeometry(QRect(129, 205, 71, 18))
        font = QFont()
        font.setFamily("Roboto, Black")
        font.setPointSize(11)
        self.mail_lbl_reg.setFont(font)
        self.mail_lbl_reg.setObjectName("mail_lbl_reg")
        self.mail_lbl_reg.show()

        self.password_lbl_reg = QLabel(self)
        self.password_lbl_reg.setGeometry(QRect(100, 245, 71, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.password_lbl_reg.setFont(font)
        self.password_lbl_reg.setObjectName("password_lbl_reg")
        self.password_lbl_reg.show()

        self.mail_edit_reg = QLineEdit(self)
        self.mail_edit_reg.setGeometry(QRect(190, 200, 311, 31))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.mail_edit_reg.setFont(font)
        self.mail_edit_reg.setObjectName("mail_edit_reg")
        self.mail_edit_reg.show()

        self.password_edit_reg = QLineEdit(self)
        self.password_edit_reg.setGeometry(QRect(190, 240, 311, 31))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.password_edit_reg.setFont(font)
        self.password_edit_reg.setEchoMode(QLineEdit.Password)
        self.password_edit_reg.setReadOnly(True)
        self.password_edit_reg.setObjectName("password_edit_reg")
        self.password_edit_reg.show()

        self.password_show_check = QCheckBox(self)
        self.password_show_check.setGeometry(QRect(510, 247, 111, 17))
        self.password_show_check.setObjectName("password_show_check")
        self.password_show_check.setText("Show")
        font = QFont()
        font.setFamily("Roboto, Black")
        font.setPointSize(11)
        self.password_show_check.setFont(font)
        self.password_show_check.setStyleSheet('''
QCheckBox {
    spacing: 5px;
    font-size:15px;     
};''')

        self.password_show_check.show()

        self.gen_btn_pass = QPushButton(self)
        self.gen_btn_pass.setGeometry(QRect(260, 280, 161, 31))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.gen_btn_pass.setFont(font)
        self.gen_btn_pass.setObjectName("gen_btn_pass")
        self.gen_btn_pass.show()

        self.reg_btn = QPushButton(self)
        self.reg_btn.setGeometry(QRect(290, 360, 161, 51))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.reg_btn.setFont(font)
        self.reg_btn.setObjectName("reg_btn")
        self.reg_btn.show()

        self.warning_reg = QLabel(self)
        self.warning_reg.setGeometry(QRect(70, 320, 411, 20))
        font = QFont()
        font.setFamily("Roboto, Regular")
        font.setPointSize(11)
        self.warning_reg.setFont(font)
        self.warning_reg.setAlignment(Qt.AlignCenter)
        self.warning_reg.setObjectName("warning_reg")
        self.warning_reg.show()

        self.reg_back_btn = QPushButton(self)
        self.reg_back_btn.setGeometry(QRect(400, 45, 70, 34))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.reg_back_btn.setFont(font)
        self.reg_back_btn.setObjectName("reg_back_btn")
        self.reg_back_btn.setText("Back")
        self.reg_back_btn.show()

        self.mail_lbl_reg.setText("Email")
        self.password_lbl_reg.setText("Password")
        self.gen_btn_pass.setText("Generate")
        self.reg_btn.setText("Register now")

        self.mail_edit_reg.editingFinished.connect(self.mail_reg)
        self.password_edit_reg.editingFinished.connect(self.password_reg)
        self.gen_btn_pass.clicked.connect(self.generate_pass)

        self.reg_btn.clicked.connect(self.pass_registration)
        self.reg_back_btn.clicked.connect(self.reg_close)

        self.password_show_check.stateChanged.connect(self.show_pass)

    # генератор парольных фраз

    def generate_pass(self):
        self.password_edit_reg.clear()

        word_site = config('word_site')
        response = get(word_site)
        WORDS = response.content.splitlines()

        list_password = []

        for i in range(5):
            random_words_b = sample(WORDS, 1)
            list_password.append(random_words_b)
            if i == 0:
                one = list_password[0]
            elif i == 1:
                two = list_password[1]
            elif i == 2:
                three = list_password[2]
            elif i == 3:
                four = list_password[3]
            elif i == 4:
                five = list_password[4]

        list_password = one+two+three+four+five
        list_password = b' '.join(list_password)
        list_password = bytes.decode(list_password, encoding='utf-8')   
        list_password = list_password.title().replace(' ', '')
        self.password_edit_reg.setText(list_password)

    # чекбокс, отвечающий за переключения мода для пароля

    def show_pass(self):
        if self.password_show_check.isChecked():
            self.password_edit_reg.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit_reg.setEchoMode(QLineEdit.Password)

    # проверка на закрытый ключ в регистрации для I have a key

    def key_reg(self):
        global my_wallet
        if self.action_dark.isChecked():
            self.key_edit_reg.textEdited.connect(
                lambda: self.key_edit_reg.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.key_edit_reg.textEdited.connect(
                lambda: self.key_edit_reg.setStyleSheet("background-color: white"))
        try:
            key = self.key_edit_reg.text()
            if key == '':
                self.warning_reg.clear()
                self.warning_reg.setText('This field cannot be left blank')
                self.key_edit_reg.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                my_wallet = Key(key)
                self.warning_reg.clear()

        except ValueError:
            self.warning_reg.clear()
            self.warning_reg.setText("Invalid wallet address")
            self.key_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")

    # проверка на правильность почты в регистации

    def mail_reg(self):
        if self.action_dark.isChecked():
            self.mail_edit_reg.textEdited.connect(
                lambda: self.mail_edit_reg.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.mail_edit_reg.textEdited.connect(
                lambda: self.mail_edit_reg.setStyleSheet("background-color: white"))
        if self.mail_edit_reg.text() == '':
            self.warning_reg.clear()
            self.warning_reg.setText('This field cannot be left blank')
            self.mail_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        else:
            self.warning_reg.clear()
            mail = self.mail_edit_reg.text()
            symbols = r'^[a-zA-Z0-9_.+-]{1,100}[@][a-zA-Z0-9-]{2,8}\.[a-zA-Z0-9-]{2,4}$'
            symbols_find = compile(symbols)
            if symbols_find.findall(mail):
                self.warning_reg.clear()
                self.warning_reg.setText('Email is correct')
                c.execute("SELECT username FROM users;")
                names = {name[0] for name in c.fetchall()}
                if mail in names:
                    self.warning_reg.clear()
                    self.warning_reg.setText(
                        "An account with that email already exists")
                    self.mail_edit_reg.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")
            else:
                self.warning_reg.clear()
                self.warning_reg.setText(
                    'This value is not valid email address')
                self.mail_edit_reg.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")

    # проверка на правильность пароля в регистрации

    def password_reg(self):
        if self.action_dark.isChecked():
            self.password_edit_reg.textEdited.connect(
                lambda: self.password_edit_reg.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.password_edit_reg.textEdited.connect(
                lambda: self.password_edit_reg.setStyleSheet("background-color: white"))

        if self.password_edit_reg.text() == '':
            self.warning_reg.clear()
            self.warning_reg.setText('This field cannot be left blank')
            self.password_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        else:
            self.warning_reg.clear()
            passwordinput = self.password_edit_reg.text()
            self.warning_reg.clear()
            self.warning_reg.setText('Correct')


    # кнопка регистрации, повтор проверки условий

    def pass_registration(self):
        global key
        name = self.mail_edit_reg.text()

        symbols_mail = r'^[a-zA-Z0-9_.+-]{1,100}[@][a-zA-Z0-9-]{2,8}\.[a-zA-Z0-9-]{2,4}$'

        symbols_find_mail = compile(symbols_mail)

        statement = f"SELECT username from users WHERE username ='{name}'"
        c.execute(statement)
        names = {name[0] for name in c.fetchall()}

        accept_key = 0
        accept_mail = 0
        accept_pass = 0

        key = ''

        try:
            if self.key_edit_reg.text() == '':
                self.warning_reg.clear()
                self.warning_reg.setText('These fields cannot be left blank')
                self.key_edit_reg.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            try:
                key = self.key_edit_reg.text()
                if key == '':
                    self.warning_reg.clear()
                    self.warning_reg.setText('This field cannot be left blank')
                    self.key_edit_reg.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")
                else:
                    my_wallet = Key(key)
                    self.warning_reg.clear()
                    accept_key += 1
            except ValueError:
                self.warning_reg.clear()
                self.warning_reg.setText("Invalid wallet address")
                self.key_edit_reg.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
        except AttributeError:
            pass

        if self.mail_edit_reg.text() == '':
            self.warning_reg.clear()
            self.warning_reg.setText('These fields cannot be left blank')
            self.mail_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        elif not symbols_find_mail.findall(name):
            self.warning_reg.clear()
            self.warning_reg.setText('This value is not valid email address')
            self.mail_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        elif name in names:
            self.warning_reg.clear()
            self.warning_reg.setText(
                "An account with that email already exists")
            self.mail_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        else:
            accept_mail += 1

        if self.password_edit_reg.text() == '':
            self.warning_reg.clear()
            self.warning_reg.setText('These fields cannot be left blank')
            self.password_edit_reg.setStyleSheet(
                "background-color: rgb(255, 175, 175);")
        passwordinput = self.password_edit_reg.text()
        self.warning_reg.clear()
        accept_pass += 1


        if key == '':
            if accept_mail and accept_pass == 1:
                self.success_pass_reg()

        else:
            if accept_key and accept_mail and accept_pass == 1:
                self.success_pass_reg()

    # регистрация успешна

    def success_pass_reg(self):
        global name
        global password_input
        global private_key
        global key
        name = self.mail_edit_reg.text()
        password_input = self.password_edit_reg.text()

        format_date = '%Y-%m-%d'
        format_time = '%H:%M:%S'

        response = ntp.request('ntp2.time.in.ua')
        date = datetime.fromtimestamp(response.tx_time).strftime(format_date)
        time = datetime.fromtimestamp(response.tx_time).strftime(format_time)

        salt = uuid4().hex
        hash = sha3_256(password_input.encode() + salt.encode()).hexdigest()
        c.execute("INSERT INTO users(username,password,salt,date_of_reg,time_of_reg) VALUES(?,?,?,?,?);",
                  (name, hash, salt, date, time))
        conn.commit()
        if key == '':
            new_wallet = Key()
            private_key = new_wallet.to_wif()
        else:
            private_key = key

        folder = ''
        try:
            if folder != 'encrypted':
                mkdir('encrypted')

        except FileExistsError:
            pass

        self.crypt()
        with open(encrypt_path + name + '.dat', "w") as f:
            f.write(str(encrypted))
            f.close()


        self.pass_registration_close()
        self.success_reg.show()
        self.success_btn.show()

        self.success_btn.clicked.connect(self.pass_ok_close)

    # кнопка ок в успешной регистрации

    def pass_ok_close(self):
        self.success_reg.close()
        self.success_btn.close()

        self.authorization.show()
        self.registration.show()
        self.have_a_key.show()
        self.widget.show()

    # закрытие успешной регистрации

    def pass_registration_close(self):
        self.mail_lbl_reg.close()
        self.password_lbl_reg.close()
        self.mail_edit_reg.close()
        self.password_edit_reg.close()
        self.gen_btn_pass.close()
        self.reg_btn.close()
        self.warning_reg.close()
        self.reg_back_btn.close()
        self.password_show_check.close()
        try:
            self.key_lbl_reg.close()
            self.key_edit_reg.close()
        except AttributeError:
            pass

    # закрытие виджетов регистрции, открытие окна логина

    def reg_auth(self):
        self.mail_lbl_reg.close()
        self.password_lbl_reg.close()
        self.gen_btn_pass.close()
        self.reg_btn.close()
        self.mail_edit_reg.close()
        self.password_edit_reg.close()
        self.reg_auth_btn.close()
        self.reg_back_btn.close()
        self.warning_reg.close()
        self.password_show_check.close()
        self.registration.show()
        self.auth_GUI()

    # закрытие регистрации

    def reg_close(self):
        self.mail_lbl_reg.close()
        self.password_lbl_reg.close()
        self.gen_btn_pass.close()
        self.reg_btn.close()
        self.mail_edit_reg.close()
        self.password_edit_reg.close()
        self.reg_back_btn.close()
        self.warning_reg.close()
        self.password_show_check.close()
        self.authorization.show()
        self.registration.show()
        self.have_a_key.show()

        self.widget.show()

    # выйти из аккаунта

    def log_out_account(self):

        self.log_out.close()
        self.user_money.close()
        self.user_log_btn_send.close()
        self.user_log_btn_hash.close()
        self.user_QR_segwit.close()
        self.user_QR_legacy.close()
        self.user_lbl_btc.close()
        self.user_lbl_satoshi.close()
        self.user_lbl_usd.close()
        self.user_lbl_eur.close()
        self.user_lbl_rub.close()
        self.user_average_price.close()
        self.user_wallet_segwit.close()
        self.user_wallet_legacy.close()
        self.user_refresh_price.close()
        self.user_segwit_QR_show.close()
        self.user_legacy_QR_show.close()
        remove('image.png')
        remove('image2.png')

        self.authorization.show()
        self.registration.show()
        self.have_a_key.show()

        self.widget.show()

    # светлая тема логина

    def light_theme_log(self):
        self.user_wallet_segwit.setStyleSheet(
            "background-color: white; color: black; border: none;")
        self.user_wallet_legacy.setStyleSheet(
            "background-color: white; color: black; border: none;")
        self.user_money.setStyleSheet("background-color: white; color:black;")
        self.user_lbl_btc.setStyleSheet("color:black;")
        self.user_lbl_satoshi.setStyleSheet("color:black;")
        self.user_lbl_usd.setStyleSheet("color:black;")
        self.user_lbl_eur.setStyleSheet("color:black;")
        self.user_lbl_rub.setStyleSheet("color:black;")
        self.user_average_price.setStyleSheet("color:black;")
        self.user_refresh_price.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.user_segwit_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.user_legacy_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.user_log_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.user_log_btn_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.user_log_btn_send.clicked.connect(self.light_theme_send_user)
        self.user_log_btn_hash.clicked.connect(self.light_theme_hash_user)

    # светлая тема для главного меню

    def light_theme(self):
        self.action_light.setChecked(True)
        self.action_dark.setChecked(False)
        self.background.setStyleSheet('background: white;')

        self.label.setStyleSheet('color: black;')
        self.generate_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.balance_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.send_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.hash_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.exit_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.menu.setStyleSheet("""QMenu::item:selected{background-color:rgb(144,200,246)}
                                   QMenu::item{color: black}""")
        self.authorization.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.registration.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.have_a_key.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.log_out.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.generate_btn.clicked.connect(self.light_theme_gen)
        self.balance_btn.clicked.connect(self.light_theme_bal)
        self.send_btn.clicked.connect(self.light_theme_send)
        self.hash_btn.clicked.connect(self.light_theme_hash)

        self.authorization.clicked.connect(self.light_theme_authorization)
        self.registration.clicked.connect(self.light_theme_registration)
        self.have_a_key.clicked.connect(self.light_theme_key_registration)

    # светлая тема для окна I have a key

    def light_theme_key_registration(self):
        self.mail_lbl_reg.setStyleSheet("color: black;")
        self.key_lbl_reg.setStyleSheet("color: black;")
        self.password_lbl_reg.setStyleSheet("color: black;")
        self.mail_edit_reg.setStyleSheet("background-color: white;")
        self.password_edit_reg.setStyleSheet("background-color: white;")
        self.key_edit_reg.setStyleSheet("background-color: white;")
        self.warning_reg.setStyleSheet("color: black;")
        self.gen_btn_pass.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.reg_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.reg_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.success_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(142, 255, 146)}
                                           QPushButton:hover{background-color: rgb(56, 255, 72)}
                                           QPushButton{color: rgb(0, 0, 0) };""")
        self.success_reg.setStyleSheet("color: rgb(11, 170, 0);")
        self.password_show_check.setStyleSheet('color: black;')

    # светлая тема авторизации

    def light_theme_authorization(self):
        self.user_lbl.setStyleSheet("color: black;")
        self.user_input.setStyleSheet("background-color: white;")
        self.pass_lbl.setStyleSheet("color: black;")
        self.pass_input.setStyleSheet("background-color: white;")
        self.warning_log.setStyleSheet("color: black;")
        self.login_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.login_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

    # светлая тема регистрации

    def light_theme_registration(self):
        self.mail_lbl_reg.setStyleSheet("color: black;")
        self.password_lbl_reg.setStyleSheet("color: black;")
        self.mail_edit_reg.setStyleSheet("background-color: white;")
        self.password_edit_reg.setStyleSheet("background-color: white;")
        self.warning_reg.setStyleSheet("color: black;")
        self.gen_btn_pass.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.reg_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.reg_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.success_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(142, 255, 146)}
                                           QPushButton:hover{background-color: rgb(56, 255, 72)}
                                           QPushButton{color: rgb(0, 0, 0) };""")
        self.success_reg.setStyleSheet("color: rgb(11, 170, 0);")
        self.password_show_check.setStyleSheet('color: black;')

    # тёмная тема для логина

    def dark_theme_log(self):
        self.user_wallet_segwit.setStyleSheet(
            "background-color: rgb(40,44,52); color: rgb(222, 225, 231); border: none;")
        self.user_wallet_legacy.setStyleSheet(
            "background-color: rgb(40,44,52); color: rgb(222, 225, 231); border: none;")
        self.user_money.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.user_lbl_btc.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_lbl_satoshi.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_lbl_usd.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_lbl_eur.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_lbl_rub.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_average_price.setStyleSheet("color:rgb(222, 225, 231);")
        self.user_refresh_price.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_segwit_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_legacy_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_log_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_log_btn_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.user_log_btn_send.clicked.connect(self.dark_theme_send_user)
        self.user_log_btn_hash.clicked.connect(self.dark_theme_hash_user)

    # тёмная тема для главного меню

    def dark_theme(self):
        self.action_light.setChecked(False)
        self.action_dark.setChecked(True)

        self.background.setStyleSheet('background: rgb(40,44,52);')
        self.label.setStyleSheet('color: white')
        self.generate_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.balance_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.send_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.hash_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.exit_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.menu.setStyleSheet("""QMenu::item:selected{background-color:gray}
                                   QMenu::item{color: black}""")
        self.authorization.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.registration.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.have_a_key.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.log_out.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.generate_btn.clicked.connect(self.dark_theme_gen)
        self.balance_btn.clicked.connect(self.dark_theme_bal)
        self.send_btn.clicked.connect(self.dark_theme_send)
        self.hash_btn.clicked.connect(self.dark_theme_hash)

        self.authorization.clicked.connect(self.dark_theme_authorization)
        self.registration.clicked.connect(self.dark_theme_registration)
        self.have_a_key.clicked.connect(self.dark_theme_key_registration)

    # тёмная тема для I have a key

    def dark_theme_key_registration(self):
        self.mail_lbl_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.key_lbl_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.key_edit_reg.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.password_lbl_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.mail_edit_reg.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.password_edit_reg.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.warning_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.gen_btn_pass.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.reg_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.reg_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.success_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(0, 70, 0)}
                                           QPushButton:hover{background-color: rgb(0, 113, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")
        self.success_reg.setStyleSheet("color: rgb(11, 170, 0);")
        self.password_show_check.setStyleSheet('color: rgb(222, 225, 231);')

    # тёмная тема для авторизации

    def dark_theme_authorization(self):
        self.user_lbl.setStyleSheet("color: rgb(222, 225, 231);")
        self.user_input.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.pass_lbl.setStyleSheet("color: rgb(222, 225, 231);")
        self.pass_input.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.warning_log.setStyleSheet("color: rgb(222, 225, 231);")
        self.login_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.login_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

    # тёмная тема для регистрации

    def dark_theme_registration(self):
        self.mail_lbl_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.password_lbl_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.mail_edit_reg.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.password_edit_reg.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.warning_reg.setStyleSheet("color: rgb(222, 225, 231);")
        self.gen_btn_pass.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.reg_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.reg_back_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.success_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(0, 70, 0)}
                                           QPushButton:hover{background-color: rgb(0, 113, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")
        self.success_reg.setStyleSheet("color: rgb(11, 170, 0);")
        self.password_show_check.setStyleSheet('color: rgb(222, 225, 231);')

    # светлая тема для генерации кошельков

    def light_theme_gen(self):

        self.generate_btn_wallet.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.generate_btn_exit.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.generate_btn_lbl.setStyleSheet("color: black;")
        self.generate_btn_lbl1.setStyleSheet("color: black;")

    # тёмная тема для генерации кошельков

    def dark_theme_gen(self):
        self.generate_btn_wallet.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.generate_btn_exit.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.generate_btn_lbl.setStyleSheet("color: rgb(222, 225, 231);")
        self.generate_btn_lbl1.setStyleSheet("color: rgb(222, 225, 231);")

    # светлая тема для проверки баланса

    def light_theme_bal(self):
        self.balance_line.setStyleSheet("background-color: white;")
        self.label_text.setStyleSheet("background-color: white; color:black;")
        self.warning.setStyleSheet("background-color: white; color:black;")
        self.exit_balance1.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.refresh_price.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.segwit_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.legacy_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.you_wallet_segwit.setStyleSheet(
            "background-color: white; color: black; border: none;")
        self.you_wallet_legacy.setStyleSheet(
            "background-color: white; color: black; border: none;")
        self.money.setStyleSheet(
            "background-color: white; color:black; border: none;")
        self.lbl_btc.setStyleSheet("color:black;")
        self.lbl_satoshi.setStyleSheet("color:black;")
        self.lbl_usd.setStyleSheet("color:black;")
        self.lbl_eur.setStyleSheet("color:black;")
        self.lbl_rub.setStyleSheet("color:black;")
        self.average_price.setStyleSheet("color:black;")
        self.exit_balance.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

    # тёмная тема для проверки баланса

    def dark_theme_bal(self):
        self.balance_line.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.label_text.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.warning.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.exit_balance1.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.refresh_price.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.segwit_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.legacy_QR_show.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.you_wallet_segwit.setStyleSheet(
            "background-color: rgb(40,44,52); color: rgb(222, 225, 231); border: none;")
        self.you_wallet_legacy.setStyleSheet(
            "background-color: rgb(40,44,52); color: rgb(222, 225, 231); border: none;")
        self.money.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231); border: none;")
        self.lbl_btc.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.lbl_satoshi.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.lbl_usd.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.lbl_eur.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.lbl_rub.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.average_price.setStyleSheet(
            "color:rgb(222, 225, 231);")
        self.exit_balance.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

    # светлая тема для отправки биткоинов

    def light_theme_send(self):
        self.sender.setStyleSheet("background-color: white; color:black;")
        self.recipient.setStyleSheet("background-color: white; color:black;")
        self.currency.setStyleSheet("background-color: white; color:black;")
        self.sum.setStyleSheet("background-color: white; color:black;")
        self.fee.setStyleSheet("background-color: white; color:black;")
        self.sender_res.setStyleSheet("background-color: white;")
        self.recipient_res.setStyleSheet("background-color: white;")
        self.currency_res.setStyleSheet('''background-color: white; 
        selection-background-color: rgb(55,60,71);''')
        self.sum_res.setStyleSheet("background-color: white;")
        self.fee_res.setStyleSheet("background-color: white;")
        self.warning_send.setStyleSheet(
            "background-color: white; color: black;")
        self.send_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(142, 255, 146)}
                                           QPushButton:hover{background-color: rgb(56, 255, 72)}
                                           QPushButton{color: rgb(0, 0, 0) };""")
        self.send_btn_rej.setStyleSheet("""QPushButton:!hover{background-color: rgb(255,171,171)}
                                           QPushButton:hover{background-color: rgb(255, 112, 112)}
                                           QPushButton{color: rgb(0, 0, 0) };""")
        self.clipboard.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

    # светлая тема для отправки биткоинов

    def light_theme_send_user(self):
        self.recipient.setStyleSheet("background-color: white; color:black;")
        self.currency.setStyleSheet("background-color: white; color:black;")
        self.sum.setStyleSheet("background-color: white; color:black;")
        self.fee.setStyleSheet("background-color: white; color:black;")
        self.recipient_res.setStyleSheet("background-color: white;")
        self.currency_res.setStyleSheet('''background-color: white;
        selection-background-color: rgb(55,60,71);''')
        self.sum_res.setStyleSheet("background-color: white;")
        self.fee_res.setStyleSheet("background-color: white;")

        self.warning_send.setStyleSheet(
            "background-color: white; color: black;")
        self.send_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(142, 255, 146)}
                                           QPushButton:hover{background-color: rgb(56, 255, 72)}
                                           QPushButton{color: rgb(0, 0, 0) };""")

        self.user_send_btn_rej.setStyleSheet("""QPushButton:!hover{background-color: rgb(255,171,171)}
                                           QPushButton:hover{background-color: rgb(255, 112, 112)}
                                           QPushButton{color: rgb(0, 0, 0) };""")
        self.clipboard.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.user_send_btn_rej.clicked.connect(self.light_theme_log)

    # тёмная тема для отправки биткоинов

    def dark_theme_send(self):
        self.sender.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.recipient.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.currency.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.sum.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.fee.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.sender_res.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.recipient_res.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.currency_res.setStyleSheet(
            '''background-color: rgb(222, 225, 231);
            selection-background-color: rgb(55,60,71);''')
        self.sum_res.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.fee_res.setStyleSheet("background-color: rgb(222, 225, 231);")

        self.warning_send.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.send_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(0, 70, 0)}
                                           QPushButton:hover{background-color: rgb(0, 113, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")
        self.send_btn_rej.setStyleSheet("""QPushButton:!hover{background-color: rgb(100, 0, 0)}
                                           QPushButton:hover{background-color: rgb(140, 0, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")
        self.clipboard.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

    # тёмная тема для отправки биткоинов

    def dark_theme_send_user(self):
        self.recipient.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.currency.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.sum.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.fee.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.recipient_res.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.currency_res.setStyleSheet(
            '''background-color: rgb(222, 225, 231);
            selection-background-color: rgb(55,60,71);''')
        self.sum_res.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.fee_res.setStyleSheet("background-color: rgb(222, 225, 231);")
        self.warning_send.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.send_btn_send.setStyleSheet("""QPushButton:!hover{background-color: rgb(0, 70, 0)}
                                           QPushButton:hover{background-color: rgb(0, 113, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")

        self.user_send_btn_rej.setStyleSheet("""QPushButton:!hover{background-color: rgb(100, 0, 0)}
                                           QPushButton:hover{background-color: rgb(140, 0, 0)}
                                           QPushButton{color: rgb(187, 193, 206) };""")
        self.clipboard.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_send_btn_rej.clicked.connect(self.dark_theme_log)

    # светлая тема для проверки хешей транзакций

    def light_theme_hash(self):
        self.lineEdit_hash.setStyleSheet("background-color: white;")
        self.text_reminder.setStyleSheet(
            "background-color: white; color:black;")
        self.warning_hash.setStyleSheet(
            "background-color: white; color:black;")
        self.exit_hash_gen.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")

        self.exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.hash_txt.setStyleSheet("background-color: white;")

    # светлая тема для проверки хешей транзакций

    def light_theme_hash_user(self):
        self.user_log_exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)}
                                           QPushButton{color: black};""")
        self.user_log_hash_txt.setStyleSheet("background-color: white;")
        self.user_log_exit_hash.clicked.connect(self.light_theme_log)

    # тёмная тема для просмотра хеша

    def dark_theme_hash(self):
        self.lineEdit_hash.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.text_reminder.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.warning_hash.setStyleSheet(
            "background-color: rgb(40,44,52); color:rgb(222, 225, 231);")
        self.exit_hash_gen.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")

        self.exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.hash_txt.setStyleSheet("background-color: rgb(222, 225, 231);")

        self.exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.hash_txt.setStyleSheet("background-color: rgb(222, 225, 231);")

    # тёмная тема для проверки хешей транзакций

    def dark_theme_hash_user(self):
        self.user_log_exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(55,60,71)}
                                           QPushButton:hover{background-color: rgb(117, 125, 147)}
                                           QPushButton{color: rgb(222, 225, 231)};""")
        self.user_log_hash_txt.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.user_log_exit_hash.clicked.connect(self.dark_theme_log)

    # закрытие генерации кошельков

    def close_auth_reg_generate_wallet_GUI(self):
        self.generate_btn_wallet.close()
        self.generate_btn_exit.close()
        self.generate_btn_lbl.close()
        self.generate_btn_lbl1.close()

    # интерфейс генерации кошелька

    def generate_wallet_GUI(self):

        self.widget.hide()
        self.action_dark.triggered.connect(self.dark_theme_gen)
        self.action_light.triggered.connect(self.light_theme_gen)

        self.authorization.clicked.connect(
            self.close_auth_reg_generate_wallet_GUI)
        self.registration.clicked.connect(
            self.close_auth_reg_generate_wallet_GUI)
        self.have_a_key.clicked.connect(
            self.close_auth_reg_generate_wallet_GUI)

        self.generate_btn_wallet = QPushButton(self)
        self.generate_btn_wallet.setGeometry(QRect(210, 234, 181, 51))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Regular")
        self.generate_btn_wallet.setFont(font)
        self.generate_btn_wallet.setObjectName("generate_btn_wallet")
        self.generate_btn_wallet.setText("Generate")
        self.generate_btn_wallet.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)};""")
        self.generate_btn_wallet.show()

        self.generate_btn_exit = QPushButton(self)
        self.generate_btn_exit.setGeometry(QRect(210, 285, 181, 51))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Regular")
        self.generate_btn_exit.setFont(font)
        self.generate_btn_exit.setObjectName("generate_btn_exit")
        self.generate_btn_exit.setText("Back")
        self.generate_btn_exit.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)};""")
        self.generate_btn_exit.show()

        self.generate_btn_lbl = QLabel(self)
        self.generate_btn_lbl.setGeometry(QRect(50, 390, 500, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.generate_btn_lbl.setFont(font)
        self.generate_btn_lbl.setObjectName("generate_btn_lbl")
        self.generate_btn_lbl.show()

        self.generate_btn_lbl1 = QLabel(self)
        self.generate_btn_lbl1.setGeometry(QRect(50, 410, 500, 30))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.generate_btn_lbl1.setFont(font)
        self.generate_btn_lbl1.setObjectName("generate_btn_lbl1")
        self.generate_btn_lbl1.show()

        self.generate_btn_wallet.clicked.connect(self.generate_wallet)
        self.generate_btn_exit.clicked.connect(self.close_generate)

    # закрытие баланса

    def close_auth_reg_check_balance_GUI(self):
        self.balance_line.close()
        self.label_text.close()
        self.warning.close()
        self.you_wallet_segwit.close()
        self.you_wallet_legacy.close()
        self.money.close()
        self.lbl_btc.close()
        self.lbl_satoshi.close()
        self.lbl_usd.close()
        self.lbl_eur.close()
        self.lbl_rub.close()
        self.average_price.close()
        self.exit_balance.close()
        self.exit_balance1.close()
        self.refresh_price.close()
        self.segwit_QR_show.close()
        self.legacy_QR_show.close()
        self.QR_label_segwit.close()

    # интерфейс проверки баланса

    def check_balance_GUI(self):
        self.widget.hide()

        self.action_dark.triggered.connect(self.dark_theme_bal)
        self.action_light.triggered.connect(self.light_theme_bal)

        self.authorization.clicked.connect(
            self.close_auth_reg_check_balance_GUI)
        self.registration.clicked.connect(
            self.close_auth_reg_check_balance_GUI)
        self.have_a_key.clicked.connect(self.close_auth_reg_check_balance_GUI)

        self.balance_line = QLineEdit(self)
        self.balance_line.setGeometry(QRect(90, 240, 451, 41))
        self.balance_line.setObjectName("balance_line")
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.balance_line.setFont(font)
        self.balance_line.show()

        self.label_text = QLabel(self)
        self.label_text.setGeometry(QRect(90, 200, 461, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.label_text.setFont(font)
        self.label_text.setObjectName("label_text")
        self.label_text.setAlignment(Qt.AlignCenter)
        self.label_text.setText(
            "The secret key is used to check the balance")
        self.label_text.show()

        self.warning = QLabel(self)
        self.warning.setGeometry(QRect(200, 300, 240, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.warning.setFont(font)
        self.warning.setObjectName("warning")
        self.warning.show()

        self.you_wallet_segwit = QLineEdit(self)
        self.you_wallet_segwit.setGeometry(QRect(30, 210, 470, 30))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.you_wallet_segwit.setFont(font)
        self.you_wallet_segwit.setObjectName("you_wallet_segwit")
        self.you_wallet_segwit.setReadOnly(True)

        self.you_wallet_legacy = QLineEdit(self)
        self.you_wallet_legacy.setGeometry(QRect(30, 240, 470, 30))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.you_wallet_legacy.setFont(font)
        self.you_wallet_legacy.setObjectName("you_wallet_legacy")
        self.you_wallet_legacy.setReadOnly(True)

        self.money = QTextEdit(self)
        self.money.setGeometry(QRect(60, 280, 190, 120))
        font = QFont()
        font.setPointSize(13)
        font.setFamily("Roboto, Regular")
        self.money.setFont(font)
        self.money.setObjectName("money")
        self.money.setStyleSheet("border: none;")
        self.money.setReadOnly(True)

        self.lbl_btc = QLabel(self)
        self.lbl_btc.setGeometry(QRect(30, 283, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.lbl_btc.setFont(font)
        self.lbl_btc.setObjectName("lbl_btc")
        self.lbl_btc.setText('BTC')

        self.lbl_satoshi = QLabel(self)
        self.lbl_satoshi.setGeometry(QRect(30, 304, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.lbl_satoshi.setFont(font)
        self.lbl_satoshi.setObjectName("lbl_satoshi")
        self.lbl_satoshi.setText('Sat')

        self.lbl_usd = QLabel(self)
        self.lbl_usd.setGeometry(QRect(30, 326, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.lbl_usd.setFont(font)
        self.lbl_usd.setObjectName("lbl_usd")
        self.lbl_usd.setText('USD')

        self.lbl_eur = QLabel(self)
        self.lbl_eur.setGeometry(QRect(30, 347, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.lbl_eur.setFont(font)
        self.lbl_eur.setObjectName("lbl_eur")
        self.lbl_eur.setText('EUR')

        self.lbl_rub = QLabel(self)
        self.lbl_rub.setGeometry(QRect(30, 368, 30, 20))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Black")
        self.lbl_rub.setFont(font)
        self.lbl_rub.setObjectName("lbl_rub")
        self.lbl_rub.setText('RUB')

        self.average_price = QLabel(self)
        self.average_price.setGeometry(QRect(30, 400, 130, 30))
        font = QFont()
        font.setPointSize(16)
        font.setFamily("Roboto, Black")
        self.average_price.setFont(font)
        self.average_price.setObjectName("average_price")
        self.average_price.setText(
            '$ '+''.join(average_price.find('b').stripped_strings))

        self.exit_balance = QPushButton(self)
        self.exit_balance.setGeometry(QRect(250, 395, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.exit_balance.setFont(font)
        self.exit_balance.setObjectName("exit_balance")
        self.exit_balance.setText("Exit")

        self.exit_balance1 = QPushButton(self)
        self.exit_balance1.setGeometry(QRect(240, 340, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.exit_balance1.setFont(font)
        self.exit_balance1.setObjectName("exit_balance1")
        self.exit_balance1.setText("Back")
        self.exit_balance1.show()

        self.QR_label_segwit = QLabel(self)
        self.QR_label_segwit.setGeometry(QRect(476, 300, 100, 100))
        self.QR_label_segwit.setObjectName("QR_label_segwit")

        self.QR_label_legacy = QLabel(self)
        self.QR_label_legacy.setGeometry(QRect(476, 300, 100, 100))
        self.QR_label_legacy.setObjectName("QR_label_segwit")

        self.segwit_QR_show = QPushButton(self)
        self.segwit_QR_show.setGeometry(QRect(490, 216, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.segwit_QR_show.setFont(font)
        self.segwit_QR_show.setObjectName("segwit_QR_show")
        self.segwit_QR_show.setText("SegWit QR")

        self.legacy_QR_show = QPushButton(self)
        self.legacy_QR_show.setGeometry(QRect(490, 246, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.legacy_QR_show.setFont(font)
        self.legacy_QR_show.setObjectName("legacy_QR_show")
        self.legacy_QR_show.setText("Legacy QR")

        self.refresh_price = QPushButton(self)
        self.refresh_price.setGeometry(QRect(30, 435, 70, 20))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.refresh_price.setFont(font)
        self.refresh_price.setObjectName("refresh_price")
        self.refresh_price.setText("Refresh")

        self.exit_balance1.clicked.connect(self.close_balance_gen)
        self.refresh_price.clicked.connect(self.price_refresh)
        self.segwit_QR_show.clicked.connect(self.show_segwit_QR)
        self.legacy_QR_show.clicked.connect(self.show_legacy_QR)

        self.balance_line.editingFinished.connect(self.check_balance)

    # показать segwit QR

    def show_segwit_QR(self):
        self.QR_label_legacy.close()
        self.QR_label_segwit.show()

    # показать legacy QR

    def show_legacy_QR(self):
        self.QR_label_segwit.close()
        self.QR_label_legacy.show()

    # обновить среднюю цену на биткоин

    def price_refresh(self):
        response = get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        average_price = soup.find('h2', class_="text-right pr-1 mb-0 pb-0")
        self.average_price.setText(
            '$ '+''.join(average_price.find('b').stripped_strings))

    # закрытие отправки биткоинов

    def close_auth_reg_send_bitcoins_GUI(self):
        self.sender.close()
        self.sender_res.close()
        self.recipient.close()
        self.recipient_res.close()
        self.currency.close()
        self.currency_res.close()
        self.fee.close()
        self.fee_res.close()
        self.sum.close()
        self.sum_res.close()
        self.send_btn_send.close()
        self.send_btn_rej.close()
        self.warning_send.close()
        self.QR_label_transaction.close()
        self.clipboard.close()

    # интерфейс отправки биткоинов

    def send_bitcoins_GUI(self):
        self.widget.hide()

        self.action_dark.triggered.connect(self.dark_theme_send)
        self.action_light.triggered.connect(self.light_theme_send)

        self.authorization.clicked.connect(
            self.close_auth_reg_send_bitcoins_GUI)
        self.registration.clicked.connect(
            self.close_auth_reg_send_bitcoins_GUI)
        self.have_a_key.clicked.connect(self.close_auth_reg_send_bitcoins_GUI)

        self.sender = QLabel(self)
        self.sender.setGeometry(QRect(45, 213, 101, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.sender.setFont(font)
        self.sender.setObjectName("sender")
        self.sender.setText("Sender")
        self.sender.show()

        self.sender_res = QLineEdit(self)
        self.sender_res.setGeometry(QRect(130, 210, 460, 31))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.sender_res.setFont(font)
        self.sender_res.setObjectName("sender_res")
        self.sender_res.show()

        self.recipient = QLabel(self)
        self.recipient.setGeometry(QRect(30, 253, 91, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.recipient.setFont(font)
        self.recipient.setObjectName("recipient")
        self.recipient.setText("Recipient")
        self.recipient.show()

        self.recipient_res = QLineEdit(self)
        self.recipient_res.setGeometry(QRect(130, 250, 460, 31))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.recipient_res.setFont(font)
        self.recipient_res.setObjectName("recipient_res")
        self.recipient_res.show()

        self.currency = QLabel(self)
        self.currency.setGeometry(QRect(32, 293, 61, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.currency.setFont(font)
        self.currency.setObjectName("currency")
        self.currency.setText("Currency")
        self.currency.show()

        self.currency_res = QComboBox(self)
        self.currency_res.setGeometry(QRect(130, 293, 121, 22))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.currency_res.setFont(font)
        self.currency_res.setObjectName("currency_res")
        self.currency_res.addItem("")
        self.currency_res.addItem("")
        self.currency_res.addItem("")
        self.currency_res.addItem("")
        self.currency_res.addItem("")
        self.currency_res.setItemText(0, "btc")
        self.currency_res.setItemText(1, "satoshi")
        self.currency_res.setItemText(2, "usd")
        self.currency_res.setItemText(3, "eur")
        self.currency_res.setItemText(4, "rub")
        self.currency_res.show()

        self.fee = QLabel(self)
        self.fee.setGeometry(QRect(290, 293, 71, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.fee.setFont(font)
        self.fee.setObjectName("fee")
        self.fee.setText("Fee")
        self.fee.show()

        self.fee_res = QLineEdit(self)
        self.fee_res.setGeometry(QRect(330, 290, 91, 31))
        font = QFont()
        font.setPointSize(12)
        font.setFamily("Roboto, Regular")
        self.fee_res.setFont(font)
        self.fee_res.setObjectName("fee_res")
        num = round(float(best_fee.text))
        self.fee_res.setText((str(num)))
        self.fee_res.show()

        self.sum = QLabel(self)
        self.sum.setGeometry(QRect(35, 333, 61, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Black")
        self.sum.setFont(font)
        self.sum.setObjectName("sum")
        self.sum.setText("Amount")
        self.sum.show()

        self.sum_res = QLineEdit(self)
        self.sum_res.setGeometry(QRect(130, 330, 131, 31))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.sum_res.setFont(font)
        self.sum_res.setObjectName("sum_res")
        self.sum_res.show()

        self.QR_label_transaction = QLabel(self)
        self.QR_label_transaction.setGeometry(QRect(470, 310, 120, 120))
        self.QR_label_transaction.setObjectName("QR_label_transaction")

        self.clipboard = QPushButton(self)
        self.clipboard.setGeometry(QRect(510, 440, 40, 25))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.clipboard.setFont(font)
        self.clipboard.setObjectName("clipboard")
        self.clipboard.setText("Copy")

        self.send_btn_send = QPushButton(self)
        self.send_btn_send.setGeometry(QRect(330, 420, 121, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.send_btn_send.setFont(font)
        self.send_btn_send.setObjectName("send_btn_send")
        self.send_btn_send.setText("Send")
        self.send_btn_send.show()

        self.send_btn_rej = QPushButton(self)
        self.send_btn_rej.setGeometry(QRect(160, 420, 121, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.send_btn_rej.setFont(font)
        self.send_btn_rej.setObjectName("send_btn_rej")

        self.send_btn_rej.setText("Cancel")
        self.send_btn_rej.show()

        self.warning_send = QLabel(self)
        self.warning_send.setGeometry(QRect(130, 380, 330, 20))
        font = QFont()
        self.warning_send.setAlignment(Qt.AlignCenter)
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.warning_send.setFont(font)
        self.warning_send.setObjectName("warning_send")
        self.warning_send.show()

        self.sender_res.editingFinished.connect(self.transaction_sender)
        self.recipient_res.editingFinished.connect(self.transaction_recipient)
        self.currency_res.activated.connect(self.transaction_currency)
        self.fee_res.editingFinished.connect(self.transaction_fee)
        self.sum_res.editingFinished.connect(self.transaction_sum)

        self.send_btn_send.clicked.connect(self.send)

        self.send_btn_rej.clicked.connect(self.close_send)

    # закрытие хешей транзакций

    def close_auth_reg_hash_transactions_GUI(self):
        self.lineEdit_hash.close()
        self.text_reminder.close()
        self.warning_hash.close()
        self.exit_hash_gen.close()
        self.hash_txt.close()
        self.exit_hash.close()

    # интерфейс просмотра хешей транзакций

    def hash_transactions_GUI(self):
        self.widget.hide()

        self.action_dark.triggered.connect(self.dark_theme_hash)
        self.action_light.triggered.connect(self.light_theme_hash)

        self.authorization.clicked.connect(
            self.close_auth_reg_hash_transactions_GUI)
        self.registration.clicked.connect(
            self.close_auth_reg_hash_transactions_GUI)
        self.have_a_key.clicked.connect(
            self.close_auth_reg_hash_transactions_GUI)

        self.lineEdit_hash = QLineEdit(self)
        self.lineEdit_hash.setGeometry(QRect(90, 240, 451, 41))
        self.lineEdit_hash.setObjectName("lineEdit_hash")
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.lineEdit_hash.setFont(font)
        self.lineEdit_hash.show()

        self.text_reminder = QLabel(self)
        self.text_reminder.setGeometry(QRect(90, 200, 461, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.text_reminder.setFont(font)
        self.text_reminder.setObjectName("text_reminder")
        self.text_reminder.setAlignment(Qt.AlignCenter)
        self.text_reminder.setText(
            "The secret key is used to check the balance")
        self.text_reminder.show()

        self.exit_hash_gen = QPushButton(self)
        self.exit_hash_gen.setGeometry(QRect(240, 340, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.exit_hash_gen.setFont(font)
        self.exit_hash_gen.setObjectName("exit_hash_gen")
        self.exit_hash_gen.setText("Back")

        self.exit_hash_gen.show()

        self.hash_txt = QTextEdit(self)
        self.hash_txt.setGeometry(QRect(23, 210, 581, 211))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.hash_txt.setFont(font)
        self.hash_txt.setObjectName("hash_txt")
        self.hash_txt.setReadOnly(True)
        self.hash_txt.setStyleSheet("background-color: white;")

        self.exit_hash = QPushButton(self)
        self.exit_hash.setGeometry(QRect(250, 440, 131, 41))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.exit_hash.setFont(font)
        self.exit_hash.setObjectName("exit_hash")
        self.exit_hash.setText("Exit")
        self.exit_hash.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)};""")

        self.warning_hash = QLabel(self)
        self.warning_hash.setGeometry(QRect(200, 300, 240, 20))
        font = QFont()
        font.setPointSize(11)
        font.setFamily("Roboto, Regular")
        self.warning_hash.setFont(font)
        self.warning_hash.setObjectName("warning_hash")
        self.warning_hash.show()

        self.exit_hash_gen.clicked.connect(self.close_hash_gen)
        self.lineEdit_hash.editingFinished.connect(self.hash_transactions)

    # выход из генерации кошельков

    def close_generate(self):
        self.generate_btn_wallet.close()
        self.generate_btn_exit.close()
        self.generate_btn_lbl.close()
        self.generate_btn_lbl1.close()
        self.widget.show()

    # выход с первой стриницы проверки баланса

    def close_balance_gen(self):
        self.warning.close()
        self.balance_line.close()
        self.label_text.close()
        self.exit_balance1.close()
        self.widget.show()

    # выход из проверки баланса после ввода закрытого ключа

    def close_balance(self):
        self.you_wallet_segwit.close()
        self.you_wallet_legacy.close()
        self.money.close()
        self.lbl_btc.close()
        self.lbl_satoshi.close()
        self.lbl_usd.close()
        self.lbl_eur.close()
        self.lbl_rub.close()
        self.average_price.close()
        self.exit_balance.close()
        self.refresh_price.close()
        self.segwit_QR_show.close()
        self.legacy_QR_show.close()
        self.QR_label_legacy.close()
        self.QR_label_segwit.close()
        self.widget.show()

    # выход со страницы отправки биткоинов

    def close_send(self):
        self.sender.close()
        self.sender_res.close()
        self.recipient.close()
        self.recipient_res.close()
        self.currency.close()
        self.currency_res.close()
        self.sum.close()
        self.sum_res.close()
        self.fee.close()
        self.fee_res.close()
        self.send_btn_send.close()
        self.send_btn_rej.close()
        self.warning_send.close()
        self.QR_label_transaction.close()
        self.clipboard.close()

        self.widget.show()

    # выход с первой страницы просмотра хешей

    def close_hash_gen(self):
        self.warning_hash.close()
        self.lineEdit_hash.close()
        self.exit_hash_gen.close()
        self.text_reminder.close()
        self.widget.show()

    # выход со второй стриницы просмотра Хешей, после ввода ключа

    def close_hash(self):
        self.hash_txt.close()
        self.exit_hash.close()
        self.text_reminder.close()
        self.widget.show()

    # закрытие виджетов для I have a key

    def reg_key_close(self):
        self.key_lbl_reg.close()
        self.key_edit_reg.close()

    # генерация кошельков

    def generate_wallet(self):
        # сохранение img в файл
        def save_img(img, img2, public_key, filename_public, filename_segwit):
            mkdir('wallets/' + public_key)
            path_os = path.join('wallets/')

            img.save(path.join(path_os + public_key, filename_public))
            img2.save(path.join(path_os + public_key, filename_segwit))
        # запись сгенерированных кошельков в файл 'wallet.txt'

        def name_wallet():
            filename = "wallet.txt"
            with open(path.join("wallets/", public_key, filename), "w") as f:
                f.write("Private key:{0}\nPublic address:{1}\nSegWit address:{2}".format(
                    private_key, public_key, segwit_address))
            self.generate_btn_lbl.setText("Your new wallet is ")
            self.generate_btn_lbl1.setText(
                "wallets/{0}".format(public_key) + '/' + format(filename))
            f.close()
        new_wallet = Key()
        private_key = new_wallet.to_wif()
        public_key = new_wallet.address
        segwit_address = new_wallet.segwit_address

        data = public_key
        data2 = segwit_address

        filename_public = "Public.png"
        filename_segwit = "SegWit.png"

        img = make(data)
        img2 = make(data2)

        folder = ''
        try:
            if folder != 'wallets':
                mkdir('wallets')
                save_img(img, img2, public_key,
                         filename_public, filename_segwit)
                name_wallet()

        except FileExistsError:
            save_img(img, img2, public_key, filename_public, filename_segwit)
            name_wallet()

    # очистка предупреждения и установка цвета для тёмной темы баланса
    def setAndClear_balance_dark(self):
        self.balance_line.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.warning.clear()

    # очистка предупреждения и установка цвета для светлой темы баланса
    def setAndClear_balance_light(self):
        self.balance_line.setStyleSheet("background-color: white;")
        self.warning.clear()

    # проверка баланса

    def check_balance(self):
        if self.action_dark.isChecked():
            self.balance_line.textEdited.connect(self.setAndClear_balance_dark)
        elif self.action_light.isChecked():
            self.balance_line.textEdited.connect(
                self.setAndClear_balance_light)

        # вывод баланса на страницу

        def print_check_balance():

            self.warning.close()
            self.balance_line.close()
            self.label_text.close()
            self.exit_balance1.close()
            self.you_wallet_segwit.show()
            self.you_wallet_legacy.show()
            self.money.show()
            self.lbl_btc.show()
            self.lbl_satoshi.show()
            self.lbl_usd.show()
            self.lbl_eur.show()
            self.lbl_rub.show()
            self.average_price.show()
            self.refresh_price.show()
            self.segwit_QR_show.show()
            self.legacy_QR_show.show()

            self.you_wallet_segwit.setText(
                'SegWit: ' + my_wallet.segwit_address)
            self.you_wallet_legacy.setText('Legacy: ' + my_wallet.address)
            self.money.setText(my_wallet.get_balance('btc') +
                               '\n' +
                               my_wallet.get_balance(
                'satoshi') +
                '\n' + my_wallet.get_balance('usd') +
                '\n' +
                my_wallet.get_balance('eur') +
                '\n' + my_wallet.get_balance('rub'))

            data = my_wallet.segwit_address
            data2 = my_wallet.address

            img = make(data)
            img2 = make(data2)

            img.save("image.png")
            img2.save("image2.png")

            img = Image.open('image.png')
            img2 = Image.open('image2.png')

            width, height = 100, 100
            res_img = img.resize((width, height), Image.ANTIALIAS)
            res_img2 = img2.resize((width, height), Image.ANTIALIAS)

            res_img.save('image.png')
            res_img2.save('image2.png')

            self.QR_label_segwit.setPixmap(QPixmap("image.png"))
            self.QR_label_legacy.setPixmap(QPixmap("image2.png"))
            self.QR_label_segwit.show()
            self.exit_balance.show()
            self.exit_balance.clicked.connect(self.close_balance)

        try:
            key = self.balance_line.text()
            if key == '':
                self.warning.clear()
                self.warning.setText('This field cannot be left blank')
                self.balance_line.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                new_wallet = Key(key)
                my_wallet = new_wallet
                print_check_balance()
        except ValueError:
            self.warning.clear()
            self.warning.setText('Invalid wallet address')
            self.balance_line.setStyleSheet(
                "background-color: rgb(255, 175, 175);")

    # проверка правильности данных для отправителя

    def transaction_sender(self):
        if self.action_dark.isChecked():
            self.sender_res.textEdited.connect(
                lambda: self.sender_res.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.sender_res.textEdited.connect(
                lambda: self.sender_res.setStyleSheet("background-color: white"))
        try:
            key = self.sender_res.text()
            if key == '':
                self.warning_send.clear()
                self.warning_send.setText('This field cannot be left blank')
                self.sender_res.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                my_wallet = Key(key)
                self.warning_send.clear()
        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText("Invalid wallet address")
            self.sender_res.setStyleSheet(
                "background-color: rgb(255, 175, 175);")

    # проверка правильности данных для получателя

    def transaction_recipient(self):
        if self.action_dark.isChecked():
            self.recipient_res.textEdited.connect(
                lambda: self.recipient_res.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.recipient_res.textEdited.connect(
                lambda: self.recipient_res.setStyleSheet("background-color: white"))

        try:
            key2 = self.recipient_res.text()
            if key2 == '':
                self.warning_send.clear()
                self.warning_send.setText("This field cannot be left blank")
                self.recipient_res.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            elif len(key2) < 26:
                self.warning_send.clear()
                self.warning_send.setText("Invalid wallet address")
                self.recipient_res.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            elif len(key2) > 35:
                self.warning_send.clear()
                self.warning_send.setText("Invalid wallet address")
                self.recipient_res.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                self.warning_send.clear()
                return key2

        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText("Invalid wallet address")
            self.recipient_res.setStyleSheet(
                "background-color: rgb(255, 175, 175);")

    # выбор текущей валюты

    def transaction_currency(self):
        currency = self.currency_res.currentText()

    # выбор текущей комиссии

    def transaction_fee(self):
        if self.action_dark.isChecked():
            self.fee_res.textEdited.connect(
                lambda: self.fee_res.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.fee_res.textEdited.connect(
                lambda: self.fee_res.setStyleSheet("background-color: white"))
        try:
            fee = float(self.fee_res.text())

            if type(fee) == int or float:
                fee = float(
                    self.fee_res.text())

                if fee < 0:
                    self.warning_send.clear()
                    self.warning_send.setText(
                        'Fee cannot be less than zero')
                    self.fee_res.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")
                elif fee == 0:
                    self.fee_res.setText('1')
                    self.warning_send.clear()
                    self.warning_send.setText(
                        'Fee cannot be zero')
                    self.fee_res.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")

            else:
                self.warning_send.clear()

        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText('Fee contains number')
            self.fee_res.setText('1')
            self.fee_res.setStyleSheet("background-color: rgb(255, 175, 175);")

    # проверка правильности данных для суммы

    def transaction_sum(self):
        if self.action_dark.isChecked():
            self.sum_res.textEdited.connect(
                lambda: self.sum_res.setStyleSheet("background-color: rgb(222, 225, 231);"))
        elif self.action_light.isChecked():
            self.sum_res.textEdited.connect(
                lambda: self.sum_res.setStyleSheet("background-color: white"))
        try:
            amount = float(self.sum_res.text())
            if type(amount) == int or float:
                amount = float(
                    self.sum_res.text())
                if amount == 0:
                    self.warning_send.clear()
                    self.warning_send.setText("Amount cannot be zero")
                    self.sum_res.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")
                elif amount < 0:
                    self.warning_send.clear()
                    self.warning_send.setText(
                        'Amount cannot be less than zero')
                    self.sum_res.setStyleSheet(
                        "background-color: rgb(255, 175, 175);")
                else:
                    self.warning_send.clear()

        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText('Amount must contain a number')
            self.sum_res.setStyleSheet("background-color: rgb(255, 175, 175);")

    # отправка криптовалюты

    def send(self):
        try:
            key = self.sender_res.text()
            my_wallet = Key(key)
            wallet = self.recipient_res.text()
            amount = self.sum_res.text()
            currency = self.currency_res.currentText()
            fee = int(self.fee_res.text())

        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText(
                "Check the correctness of the entered data")
        except TypeError:
            self.warning_send.clear()
            self.warning_send.setText(
                "Check the correctness of the entered data")

        try:
            transaction = my_wallet.send([
                (wallet, amount, currency)], fee=fee)

            global data
            data = url_hash + transaction

            img = make(data)
            img.save("image.png")

            img = Image.open('image.png')
            width, height = 120, 120
            res_img = img.resize((width, height), Image.ANTIALIAS)
            res_img.save('image.png')
            self.QR_label_transaction.setPixmap(QPixmap("image.png"))
            remove('image.png')
            self.QR_label_transaction.show()
            self.clipboard.show()

        except DecimalException:
            self.warning_send.clear()
            self.warning_send.setText("Enter data in the fields")
        except ValueError:
            self.warning_send.clear()
            self.warning_send.setText(
                "Check the correctness of the entered data")
        except UnboundLocalError:
            self.warning_send.clear()
            self.warning_send.setText(
                "Check the correctness of the entered data")
        except InsufficientFunds:
            self.warning_send.clear()
            self.warning_send.setText("Insuffcient funds")
        except TypeError:
            self.warning_send.clear()
            self.warning_send.setText(
                "Check the correctness of the entered data")
        except OverflowError:
            self.warning_send.clear()
            self.warning_send.setText("Amount cannot be less than zero")
        except ConnectionError:
            self.warning_send.clear()
            self.warning_send.setText("Connection error")

        self.clipboard.clicked.connect(self.clipboard_def)

    def clipboard_def(self):
        global data
        c = QApplication.clipboard()
        if c != None:
            c.setText(data)

    # очистка предупреждения и установка цвета для тёмной темы хеша

    def setAndClear_hash_dark(self):
        self.lineEdit_hash.setStyleSheet(
            "background-color: rgb(222, 225, 231);")
        self.warning_hash.clear()

    # очистка предупреждения и установка цвета для светлой темы хеша
    def setAndClear_hash_light(self):
        self.lineEdit_hash.setStyleSheet("background-color: white;")
        self.warning_hash.clear()

    # просмотр хешей транзакций

    def hash_transactions(self):
        if self.action_dark.isChecked():
            self.lineEdit_hash.textEdited.connect(self.setAndClear_hash_dark)
        elif self.action_light.isChecked():
            self.lineEdit_hash.textEdited.connect(self.setAndClear_hash_light)

        # вывод хешей на страницу

        def print_hash_transactions():

            self.lineEdit_hash.close()
            self.warning_hash.close()
            self.exit_hash_gen.close()
            self.text_reminder.close()
            self.hash_txt.show()
            self.exit_hash.show()

            transactions = str(my_wallet.get_transactions())
            unspents = str(my_wallet.get_unspents())
            self.hash_txt.setText(my_wallet.segwit_address +
                                  '\nHashes: \n' + transactions[1:-1] +
                                  '\n\nUnspents: \n' + unspents[1:-1])
            self.exit_hash.clicked.connect(self.close_hash)

        try:
            key = self.lineEdit_hash.text()
            if key == '':
                self.warning_hash.clear()
                self.warning_hash.setText('This field cannot be left blank ')
                self.lineEdit_hash.setStyleSheet(
                    "background-color: rgb(255, 175, 175);")
            else:
                new_wallet = Key(key)
                my_wallet = new_wallet
                print_hash_transactions()
        except ValueError:
            self.warning_hash.clear()
            self.warning_hash.setText('Invalid wallet address')
            self.lineEdit_hash.setStyleSheet(
                "background-color: rgb(255, 175, 175);")

    # шифровка ключа

    def crypt(self):
        global name
        global password_input
        global private_key
        global encrypted


        encrypted = gpg.encrypt(str(private_key), recipients=None,
                symmetric='AES256',
                passphrase=password_input
                # armor=False
                )

    # расшифровка закрытого ключа

    def decrypt(self):
        global name
        global password_input
        global decrypted

        with open(encrypt_path + name + '.dat', 'r') as f:
            text = f.read()
            decrypted = gpg.decrypt(str(text), passphrase=password_input)
            f.close()

    # отправка предупреждающего письма

    def send_warning_mail(self):
        global name
        global formatted_time
        fromx = config('fromx')
        to = name
        message = MIMEText("""Someone tried to log into your BitcoinWallet account.
After three unsuccessful attempts, we were forced to block your account.
Your account will be unlocked in two hours. Unlock time """ + formatted_time)
        message['Subject'] = 'Your account has been blocked.'
        message['From'] = fromx
        message['To'] = to
        pass_bot = config('pass_bot')

        smtpObj = SMTP('smtp.gmail.com', 587)
        smtpObj.starttls()
        smtpObj.ehlo()
        smtpObj.login(fromx, pass_bot)
        smtpObj.sendmail(fromx, to, message.as_string())
        smtpObj.quit()

    # создание второго окна

    def openWin(self):
        self.secondWin = SecondWindow(self)
        self.secondWin.show()

    # сохранение настроек выбора тем в файл 'config.ini'

    def save_settings(self):
        settings = QSettings(self.CONFIG, QSettings.IniFormat)

        settings.setValue('DarkTheme', int(self.action_dark.isChecked()))
        settings.setValue('LightTheme', int(self.action_light.isChecked()))

    # загрузка настроек из файла 'config.ini'

    def load_settings(self):
        settings = QSettings(self.CONFIG, QSettings.IniFormat)

        self.action_dark.setChecked(bool(int(settings.value('DarkTheme', 0))))
        self.action_light.setChecked(
            bool(int(settings.value('LightTheme', 0))))

        if self.action_dark.isChecked():
            self.dark_theme()
        elif self.action_light.isChecked():
            self.light_theme()

    # сохранить настройки при закрытии программы

    def closeEvent(self, e):
        global name
        self.save_settings()
        c.close()
        conn.close()
        try:
            remove('image.png')
            remove('image2.png')
        except FileNotFoundError:
            pass
        super().closeEvent(e)

# класс, отвечающий за открытие окна помощи


class SecondWindow(QWidget):

    # открытие окна

    def __init__(self, parent=QMainWindow):
        super().__init__(parent, Qt.Window)
        self.build()

    # создание виджетов

    def build(self):

        self.setStyleSheet('background: white;')

        self.setWindowTitle('Help')
        self.setFixedSize(620, 500)
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

        self.OK_btn = QPushButton(self)
        self.OK_btn.setGeometry(QRect(250, 420, 111, 31))
        font = QFont()
        font.setPointSize(10)
        font.setFamily("Roboto, Regular")
        self.OK_btn.setFont(font)
        self.OK_btn.setObjectName("OK_btn")
        self.OK_btn.setText("OK")
        self.OK_btn.setStyleSheet("""QPushButton:!hover{background-color: rgb(238,255,251)}
                                           QPushButton:hover{background-color: rgb(74, 255, 237)};""")
        self.OK_btn.show()

        self.OK_btn.clicked.connect(self.close)

        self.text_help = QTextEdit(self)
        self.text_help.setGeometry(QRect(20, 20, 581, 400))
        self.text_help.setObjectName("text_help")
        self.text_help.setReadOnly(True)
        self.text_help.setStyleSheet('border: none')
        self.text_help.setHtml("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                               "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                               "p, li { white-space: pre-wrap; }\n"
                               "</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
                               "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:10pt; font-weight:600;\">What is a private key?</span></p>\n"
                               "<p align=\"justify\" style=\" margin-top:10px; margin-bottom:10px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:9pt;\">A private key is a secret alphanumeric number used to check balance or send bitcoins to another address. The private key resembles a password, no one should have access to it.</span></p>\n"
                               "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:10pt; font-weight:600;\">What is a public key?</span></p>\n"
                               "<p align=\"justify\" style=\" margin-top:10px; margin-bottom:10px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:9pt;\">The public key or the public address is generated from the private key using cryptographic functions, but it is impossible to obtain the private key knowing only the public one. Public addresses are used to receive bitcoins.</span></p>\n"
                               "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:10pt; font-weight:600;\">What is a transaction hash?</span></p>\n"
                               "<p align=\"justify\" style=\" margin-top:10px; margin-bottom:10px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:9pt;\">Also known as Transaction ID (TxID). Consists of alphanumeric characters and represents the unique identification number of the transaction.</span></p>\n"
                               "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:10pt; font-weight:600;\">What is a SegWit address?</span></p>\n"
                               "<p align=\"justify\" style=\" margin-top:10px; margin-bottom:10px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:9pt;\">SegWit address allows bitcoin to process more transactions at the same time. It does this by reducing the weight of a transaction on the blockchain. Higher transaction speed means lower transaction fees.</span></p>\n"
                               "<p align=\"justify\" style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:9pt;\"><br /></p></body></html>")

# запуск приложения

def application():
    app = QApplication(argv)
    app.setStyle('Fusion')
    window = Window()
    window.show()
    exit(app.exec_())


if __name__ == "__main__":
    application()
