from PyQt4 import QtCore, QtGui
import sqlite3

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

# Sign Up UI Class
class UiSignUp(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(600, 300)
        self.verticalLayoutWidget_3 = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(290, 90, 151, 89))
        self.verticalLayoutWidget_3.setObjectName(_fromUtf8("verticalLayoutWidget_3"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setMargin(0)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.user_line = QtGui.QLineEdit(self.verticalLayoutWidget_3)
        self.user_line.setText(_fromUtf8(""))
        self.user_line.setObjectName(_fromUtf8("user_line"))
        self.verticalLayout_3.addWidget(self.user_line)
        self.email_line = QtGui.QLineEdit(self.verticalLayoutWidget_3)
        self.email_line.setObjectName(_fromUtf8("email_line"))
        self.verticalLayout_3.addWidget(self.email_line)
        self.pass_line = QtGui.QLineEdit(self.verticalLayoutWidget_3)
        self.pass_line.setObjectName(_fromUtf8("pass_line"))
        self.verticalLayout_3.addWidget(self.pass_line)
        self.verticalLayoutWidget_4 = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(160, 90, 101, 91))
        self.verticalLayoutWidget_4.setObjectName(_fromUtf8("verticalLayoutWidget_4"))
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.verticalLayoutWidget_4)
        self.verticalLayout_4.setMargin(0)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.user_label = QtGui.QLabel(self.verticalLayoutWidget_4)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.user_label.setFont(font)
        self.user_label.setObjectName(_fromUtf8("user_label"))
        self.verticalLayout_4.addWidget(self.user_label)
        self.email_label = QtGui.QLabel(self.verticalLayoutWidget_4)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.email_label.setFont(font)
        self.email_label.setObjectName(_fromUtf8("email_label"))
        self.verticalLayout_4.addWidget(self.email_label)
        self.pass_label = QtGui.QLabel(self.verticalLayoutWidget_4)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.pass_label.setFont(font)
        self.pass_label.setObjectName(_fromUtf8("pass_label"))
        self.verticalLayout_4.addWidget(self.pass_label)
        self.verticalLayoutWidget = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(220, 200, 160, 58))
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.signup_btn = QtGui.QPushButton(self.verticalLayoutWidget)
        self.signup_btn.setObjectName(_fromUtf8("signup_btn"))
        self.verticalLayout.addWidget(self.signup_btn)    
        self.cancel_btn = QtGui.QPushButton(self.verticalLayoutWidget)
        self.cancel_btn.setObjectName(_fromUtf8("cancel_btn"))
        self.verticalLayout.addWidget(self.cancel_btn)  
        self.verticalLayoutWidget_2 = QtGui.QWidget(Dialog)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(240, 30, 131, 41))
        self.verticalLayoutWidget_2.setObjectName(_fromUtf8("verticalLayoutWidget_2"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setMargin(0)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.create_acc_label = QtGui.QLabel(self.verticalLayoutWidget_2)
        self.create_acc_label.setObjectName(_fromUtf8("create_acc_label"))
        self.verticalLayout_2.addWidget(self.create_acc_label)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Sign Up", None))
        self.user_label.setText(_translate("Dialog", "USERNAME", None))
        self.email_label.setText(_translate("Dialog", "EMAIL", None))
        self.pass_label.setText(_translate("Dialog", "PASSWORD", None))
        self.signup_btn.setText(_translate("Dialog", "Sign Up", None))
        self.cancel_btn.setText(_translate("Dialog", "Cancel", None))
        self.create_acc_label.setText(_translate("Dialog", "CREATE ACCOUNT", None))


# Sign Up UI Functionality
class SignUpMain(QtGui.QDialog, UiSignUp):
    def __init__(self):
        super(SignUpMain, self).__init__()
        self.setupUi(self)
        self.signup_btn.clicked.connect(self.insertData)
        self.cancel_btn.clicked.connect(self.cancel)
        # Turn text to asterisks*
        self.pass_line.setEchoMode(QtGui.QLineEdit.Password)


    # Message box
    def showMessageBox(self,title,message):
        msgBox = QtGui.QMessageBox()
        msgBox.setIcon(QtGui.QMessageBox.Information)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setStandardButtons(QtGui.QMessageBox.Ok)
        msgBox.exec_()

    
    # Inserting data into login.db
    def insertData(self):
        username = self.user_line.text()
        email = self.email_line.text()
        password = self.pass_line.text()

        if((len(username) == 0) | (len(email) == 0) | (len(password) == 0)):
            self.showMessageBox('Error','Please fill out all the entries.')
        elif(((len(username) >0) & (len(email)>0) & (len(password)> 0)) & ('@' not in email)):
            self.showMessageBox('Error','Please correct your email.')
        else:
            connection = sqlite3.connect("login.db")
            connection.execute("INSERT INTO USERS VALUES (?,?,?)", (username,email,password))
            connection.commit()
            self.showMessageBox('Success', 'Succesful sign up.')
            connection.close()
            self.close()

    # Pressing cancel closes Sign Up window
    def cancel(self):
        self.close()



# Main Trigger
if __name__ == "__main__":
    import sys
    application = QtGui.QApplication(sys.argv)
    sign_up = SignUpMain()
    sign_up.show()
    sys.exit(application.exec_())

