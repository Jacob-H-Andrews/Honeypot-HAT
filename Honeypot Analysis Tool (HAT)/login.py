from PyQt4 import QtCore, QtGui
import honeypot_analysis_tool # Importing home_page UI
from sign_up import SignUpMain # Import sign_up ui
import sqlite3  # Database

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

# Login UI Class
class UiLogin(object):    
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(600, 300)
        Dialog.setStyleSheet(_fromUtf8(""))
        self.verticalLayoutWidget = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(160, 70, 101, 80))
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.user_label = QtGui.QLabel(self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.user_label.setFont(font)
        self.user_label.setObjectName(_fromUtf8("user_label"))
        self.verticalLayout.addWidget(self.user_label)
        self.pass_label = QtGui.QLabel(self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.pass_label.setFont(font)
        self.pass_label.setObjectName(_fromUtf8("pass_label"))
        self.verticalLayout.addWidget(self.pass_label)
        self.verticalLayoutWidget_2 = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(200, 180, 204, 89))
        self.verticalLayoutWidget_2.setObjectName(_fromUtf8("verticalLayoutWidget_2"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setMargin(0)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))       
        self.login_btn = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.login_btn.setStyleSheet(_fromUtf8(""))
        self.login_btn.setObjectName(_fromUtf8("login_btn"))
        self.verticalLayout_2.addWidget(self.login_btn)        
        self.signup_btn = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.signup_btn.setStyleSheet(_fromUtf8(""))
        self.signup_btn.setObjectName(_fromUtf8("signup_btn"))
        self.verticalLayout_2.addWidget(self.signup_btn)        
        self.forgot_btn = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.forgot_btn.setStyleSheet(_fromUtf8(""))
        self.forgot_btn.setObjectName(_fromUtf8("forgot_btn"))
        self.verticalLayout_2.addWidget(self.forgot_btn)
        self.verticalLayoutWidget_3 = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(290, 70, 151, 80))
        self.verticalLayoutWidget_3.setObjectName(_fromUtf8("verticalLayoutWidget_3"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setMargin(0)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.user_line = QtGui.QLineEdit(self.verticalLayoutWidget_3)
        self.user_line.setStyleSheet(_fromUtf8(""))
        self.user_line.setText(_fromUtf8(""))
        self.user_line.setObjectName(_fromUtf8("user_line"))
        self.verticalLayout_3.addWidget(self.user_line)
        self.pass_line = QtGui.QLineEdit(self.verticalLayoutWidget_3)
        self.pass_line.setStyleSheet(_fromUtf8(""))
        self.pass_line.setObjectName(_fromUtf8("pass_line"))
        self.verticalLayout_3.addWidget(self.pass_line)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Login Portal", None))
        self.user_label.setText(_translate("Dialog", "USERNAME", None))
        self.pass_label.setText(_translate("Dialog", "PASSWORD", None))
        self.login_btn.setText(_translate("Dialog", "Login", None))
        self.signup_btn.setText(_translate("Dialog", "Sign Up", None))
        self.forgot_btn.setText(_translate("Dialog", "Forgot username/password", None))

# Login UI Functionality Class
class LoginMain(QtGui.QDialog, UiLogin):
    def __init__(self):
        super(LoginMain, self).__init__()
        self.setupUi(self)
        self.login_btn.clicked.connect(self.loginCheck)
        self.signup_btn.clicked.connect(self.signUpShow)
        # Turn pass to asterisks
        self.pass_line.setEchoMode(QtGui.QLineEdit.Password)


    # Message box
    def showMessageBox(self,title,message):
        msgBox = QtGui.QMessageBox()
        msgBox.setIcon(QtGui.QMessageBox.Warning)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setStandardButtons(QtGui.QMessageBox.Ok)
        msgBox.exec_()

    
    # Login Authentication
    def loginCheck(self):
        username = self.user_line.text()
        password = self.pass_line.text()

        # Connect to database
        connection = sqlite3.connect("login.db")
        result = connection.execute("SELECT * FROM USERS WHERE USERNAME = ? AND PASSWORD = ?", (username,password))
        if(len(result.fetchall()) > 0):
            print("Username Recognised")
            # Calls function to show .py ui
            self.homePageShow()
            # Close connection
            connection.close()
            self.close()
            
        else:
            print("Username or password not recognised")
            self.showMessageBox('Warning', 'Invalid username or password.')

            
    # show sign_up.py file window
    def signUpShow(self):
        self.signUpWindow = SignUpMain()
        self.signUpWindow.show()


    # Show home_page.py file window
    def homePageShow(self):
        # This prevents circular importing
        from honeypot_analysis_tool import MainWindow
        self.homePageWindow = MainWindow()
        self.homePageWindow.show()



# Main Trigger
if __name__ == "__main__":
    import sys
    application = QtGui.QApplication(sys.argv)
    login = LoginMain()
    login.show()
    sys.exit(application.exec_())

