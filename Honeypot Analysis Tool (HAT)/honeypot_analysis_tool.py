####################################
### HONEYPOT ANALYSIS TOOL (HAT) ###
####################################

from PyQt4 import QtCore, QtGui
from functools import partial
import login
import server_log_analysis
import os
import sys
import datetime as dt
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.collections import PolyCollection
from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt4agg import NavigationToolbar2QT as NavigationToolbar
import networkx as nx
import statistics
import pandas as pd
import numpy as np
import seaborn as sb

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
    
# HAT UI Class
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(1129, 514)
        MainWindow.setTabShape(QtGui.QTabWidget.Rounded)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(30, 340, 161, 89))
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.start_server_btn = QtGui.QPushButton(self.verticalLayoutWidget)
        self.start_server_btn.setObjectName(_fromUtf8("start_server_btn"))
        self.verticalLayout.addWidget(self.start_server_btn)
        self.stop_server_btn = QtGui.QPushButton(self.verticalLayoutWidget)
        self.stop_server_btn.setObjectName(_fromUtf8("stop_server_btn"))
        self.verticalLayout.addWidget(self.stop_server_btn)
        self.server_status_btn = QtGui.QPushButton(self.verticalLayoutWidget)
        self.server_status_btn.setObjectName(_fromUtf8("server_status_btn"))
        self.verticalLayout.addWidget(self.server_status_btn)
        self.horizontalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(30, 430, 161, 31))
        self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.log_out_btn = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.log_out_btn.setObjectName(_fromUtf8("log_out_btn"))
        self.horizontalLayout.addWidget(self.log_out_btn)
        self.quit_btn = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.quit_btn.setObjectName(_fromUtf8("quit_btn"))
        self.horizontalLayout.addWidget(self.quit_btn)
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setEnabled(True)
        self.tabWidget.setGeometry(QtCore.QRect(220, 10, 901, 451))
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.tabWidget.setFont(font)
        self.tabWidget.setTabShape(QtGui.QTabWidget.Rounded)
        self.tabWidget.setMovable(True)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.network_analysis_tab = QtGui.QWidget()
        self.network_analysis_tab.setObjectName(_fromUtf8("network_analysis_tab"))
        self.tabWidget_3 = QtGui.QTabWidget(self.network_analysis_tab)
        self.tabWidget_3.setGeometry(QtCore.QRect(-4, 0, 901, 431))
        self.tabWidget_3.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.tabWidget_3.setMouseTracking(False)
        self.tabWidget_3.setMovable(True)
        self.tabWidget_3.setObjectName(_fromUtf8("tabWidget_3"))
        self.network_node_info_tab = QtGui.QWidget()
        self.network_node_info_tab.setObjectName(_fromUtf8("network_node_info_tab"))
        self.network_info_textEdit = QtGui.QTextEdit(self.network_node_info_tab)
        self.network_info_textEdit.setGeometry(QtCore.QRect(10, 10, 691, 371))
        self.network_info_textEdit.setReadOnly(True)
        self.network_info_textEdit.setObjectName(_fromUtf8("network_info_textEdit"))
        self.formLayoutWidget_2 = QtGui.QWidget(self.network_node_info_tab)
        self.formLayoutWidget_2.setGeometry(QtCore.QRect(720, 10, 161, 116))
        self.formLayoutWidget_2.setObjectName(_fromUtf8("formLayoutWidget_2"))
        self.gridLayout = QtGui.QGridLayout(self.formLayoutWidget_2)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.new_connections_label = QtGui.QLabel(self.formLayoutWidget_2)
        self.new_connections_label.setAlignment(QtCore.Qt.AlignCenter)
        self.new_connections_label.setWordWrap(True)
        self.new_connections_label.setObjectName(_fromUtf8("new_connections_label"))
        self.gridLayout.addWidget(self.new_connections_label, 3, 0, 1, 1)
        self.total_connections = QtGui.QLabel(self.formLayoutWidget_2)
        self.total_connections.setAlignment(QtCore.Qt.AlignCenter)
        self.total_connections.setWordWrap(True)
        self.total_connections.setObjectName(_fromUtf8("total_connections"))
        self.gridLayout.addWidget(self.total_connections, 2, 0, 1, 1)
        self.total_connection_num = QtGui.QLCDNumber(self.formLayoutWidget_2)
        self.total_connection_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.total_connection_num.setObjectName(_fromUtf8("total_connection_num"))
        self.gridLayout.addWidget(self.total_connection_num, 2, 1, 1, 1)
        self.new_connections_num = QtGui.QLCDNumber(self.formLayoutWidget_2)
        self.new_connections_num.setEnabled(True)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.new_connections_num.setFont(font)
        self.new_connections_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.new_connections_num.setObjectName(_fromUtf8("new_connections_num"))
        self.gridLayout.addWidget(self.new_connections_num, 3, 1, 1, 1)
        self.verticalLayoutWidget_5 = QtGui.QWidget(self.network_node_info_tab)
        self.verticalLayoutWidget_5.setGeometry(QtCore.QRect(720, 320, 161, 61))
        self.verticalLayoutWidget_5.setObjectName(_fromUtf8("verticalLayoutWidget_5"))
        self.verticalLayout_5 = QtGui.QVBoxLayout(self.verticalLayoutWidget_5)
        self.verticalLayout_5.setMargin(0)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.clear_page_network_btn = QtGui.QPushButton(self.verticalLayoutWidget_5)
        self.clear_page_network_btn.setObjectName(_fromUtf8("clear_page_network_btn"))
        self.verticalLayout_5.addWidget(self.clear_page_network_btn)
        self.save_log_btn = QtGui.QPushButton(self.verticalLayoutWidget_5)
        self.save_log_btn.setObjectName(_fromUtf8("save_log_btn"))
        self.verticalLayout_5.addWidget(self.save_log_btn)
        self.verticalLayoutWidget_3 = QtGui.QWidget(self.network_node_info_tab)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(720, 150, 161, 31))
        self.verticalLayoutWidget_3.setObjectName(_fromUtf8("verticalLayoutWidget_3"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setMargin(0)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.analyse_network_btn = QtGui.QPushButton(self.verticalLayoutWidget_3)
        self.analyse_network_btn.setObjectName(_fromUtf8("analyse_network_btn"))
        self.verticalLayout_3.addWidget(self.analyse_network_btn)
        self.tabWidget_3.addTab(self.network_node_info_tab, _fromUtf8(""))
        self.tab_6 = QtGui.QWidget()
        self.tab_6.setObjectName(_fromUtf8("tab_6"))
        self.formLayoutWidget_5 = QtGui.QWidget(self.tab_6)
        self.formLayoutWidget_5.setGeometry(QtCore.QRect(720, 10, 161, 116))
        self.formLayoutWidget_5.setObjectName(_fromUtf8("formLayoutWidget_5"))
        self.gridLayout_4 = QtGui.QGridLayout(self.formLayoutWidget_5)
        self.gridLayout_4.setMargin(0)
        self.gridLayout_4.setObjectName(_fromUtf8("gridLayout_4"))
        self.new_connections_label_4 = QtGui.QLabel(self.formLayoutWidget_5)
        self.new_connections_label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.new_connections_label_4.setWordWrap(True)
        self.new_connections_label_4.setObjectName(_fromUtf8("new_connections_label_4"))
        self.gridLayout_4.addWidget(self.new_connections_label_4, 3, 0, 1, 1)
        self.total_connections_4 = QtGui.QLabel(self.formLayoutWidget_5)
        self.total_connections_4.setAlignment(QtCore.Qt.AlignCenter)
        self.total_connections_4.setWordWrap(True)
        self.total_connections_4.setObjectName(_fromUtf8("total_connections_4"))
        self.gridLayout_4.addWidget(self.total_connections_4, 2, 0, 1, 1)
        self.grouped_total_connection_num = QtGui.QLCDNumber(self.formLayoutWidget_5)
        self.grouped_total_connection_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.grouped_total_connection_num.setObjectName(_fromUtf8("grouped_total_connection_num"))
        self.gridLayout_4.addWidget(self.grouped_total_connection_num, 2, 1, 1, 1)
        self.grouped_new_connections_num = QtGui.QLCDNumber(self.formLayoutWidget_5)
        self.grouped_new_connections_num.setEnabled(True)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.grouped_new_connections_num.setFont(font)
        self.grouped_new_connections_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.grouped_new_connections_num.setObjectName(_fromUtf8("grouped_new_connections_num"))
        self.gridLayout_4.addWidget(self.grouped_new_connections_num, 3, 1, 1, 1)
        self.verticalLayoutWidget_11 = QtGui.QWidget(self.tab_6)
        self.verticalLayoutWidget_11.setGeometry(QtCore.QRect(720, 150, 161, 31))
        self.verticalLayoutWidget_11.setObjectName(_fromUtf8("verticalLayoutWidget_11"))
        self.verticalLayout_11 = QtGui.QVBoxLayout(self.verticalLayoutWidget_11)
        self.verticalLayout_11.setMargin(0)
        self.verticalLayout_11.setObjectName(_fromUtf8("verticalLayout_11"))
        self.grouped_analyse_network_btn = QtGui.QPushButton(self.verticalLayoutWidget_11)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.grouped_analyse_network_btn.setFont(font)
        self.grouped_analyse_network_btn.setObjectName(_fromUtf8("grouped_analyse_network_btn"))
        self.verticalLayout_11.addWidget(self.grouped_analyse_network_btn)
        self.label_3 = QtGui.QLabel(self.tab_6)
        self.label_3.setGeometry(QtCore.QRect(720, 200, 161, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.grouped_potential_threats_textEdit = QtGui.QTextEdit(self.tab_6)
        self.grouped_potential_threats_textEdit.setGeometry(QtCore.QRect(720, 220, 161, 151))
        self.grouped_potential_threats_textEdit.setReadOnly(True)
        self.grouped_potential_threats_textEdit.setObjectName(_fromUtf8("grouped_potential_threats_textEdit"))
        self.cyber_textEdit = QtGui.QTextEdit(self.tab_6)
        self.cyber_textEdit.setGeometry(QtCore.QRect(30, 30, 151, 151))
        self.cyber_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.cyber_textEdit.setReadOnly(True)
        self.cyber_textEdit.setObjectName(_fromUtf8("cyber_textEdit"))
        self.label_10 = QtGui.QLabel(self.tab_6)
        self.label_10.setGeometry(QtCore.QRect(30, 10, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_10.setFont(font)
        self.label_10.setAlignment(QtCore.Qt.AlignCenter)
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.label_11 = QtGui.QLabel(self.tab_6)
        self.label_11.setGeometry(QtCore.QRect(540, 10, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_11.setFont(font)
        self.label_11.setAlignment(QtCore.Qt.AlignCenter)
        self.label_11.setObjectName(_fromUtf8("label_11"))
        self.label_14 = QtGui.QLabel(self.tab_6)
        self.label_14.setGeometry(QtCore.QRect(370, 10, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_14.setFont(font)
        self.label_14.setAlignment(QtCore.Qt.AlignCenter)
        self.label_14.setObjectName(_fromUtf8("label_14"))
        self.label_15 = QtGui.QLabel(self.tab_6)
        self.label_15.setGeometry(QtCore.QRect(30, 200, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_15.setFont(font)
        self.label_15.setAlignment(QtCore.Qt.AlignCenter)
        self.label_15.setObjectName(_fromUtf8("label_15"))
        self.label_16 = QtGui.QLabel(self.tab_6)
        self.label_16.setGeometry(QtCore.QRect(200, 200, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_16.setFont(font)
        self.label_16.setAlignment(QtCore.Qt.AlignCenter)
        self.label_16.setObjectName(_fromUtf8("label_16"))
        self.label_17 = QtGui.QLabel(self.tab_6)
        self.label_17.setGeometry(QtCore.QRect(370, 200, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_17.setFont(font)
        self.label_17.setAlignment(QtCore.Qt.AlignCenter)
        self.label_17.setObjectName(_fromUtf8("label_17"))
        self.label_18 = QtGui.QLabel(self.tab_6)
        self.label_18.setGeometry(QtCore.QRect(540, 200, 151, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_18.setFont(font)
        self.label_18.setAlignment(QtCore.Qt.AlignCenter)
        self.label_18.setObjectName(_fromUtf8("label_18"))
        self.label_19 = QtGui.QLabel(self.tab_6)
        self.label_19.setGeometry(QtCore.QRect(190, 10, 171, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_19.setFont(font)
        self.label_19.setAlignment(QtCore.Qt.AlignCenter)
        self.label_19.setObjectName(_fromUtf8("label_19"))
        self.carding_textEdit = QtGui.QTextEdit(self.tab_6)
        self.carding_textEdit.setGeometry(QtCore.QRect(30, 220, 151, 151))
        self.carding_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.carding_textEdit.setReadOnly(True)
        self.carding_textEdit.setObjectName(_fromUtf8("carding_textEdit"))
        self.fake_id_textEdit = QtGui.QTextEdit(self.tab_6)
        self.fake_id_textEdit.setGeometry(QtCore.QRect(200, 220, 151, 151))
        self.fake_id_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.fake_id_textEdit.setReadOnly(True)
        self.fake_id_textEdit.setObjectName(_fromUtf8("fake_id_textEdit"))
        self.groups_textEdit = QtGui.QTextEdit(self.tab_6)
        self.groups_textEdit.setGeometry(QtCore.QRect(200, 30, 151, 151))
        self.groups_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.groups_textEdit.setReadOnly(True)
        self.groups_textEdit.setObjectName(_fromUtf8("groups_textEdit"))
        self.weapons_textEdit = QtGui.QTextEdit(self.tab_6)
        self.weapons_textEdit.setGeometry(QtCore.QRect(370, 30, 151, 151))
        self.weapons_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.weapons_textEdit.setReadOnly(True)
        self.weapons_textEdit.setObjectName(_fromUtf8("weapons_textEdit"))
        self.drugs_textEdit = QtGui.QTextEdit(self.tab_6)
        self.drugs_textEdit.setGeometry(QtCore.QRect(540, 30, 151, 151))
        self.drugs_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.drugs_textEdit.setReadOnly(True)
        self.drugs_textEdit.setObjectName(_fromUtf8("drugs_textEdit"))
        self.info_seeker_textEdit = QtGui.QTextEdit(self.tab_6)
        self.info_seeker_textEdit.setGeometry(QtCore.QRect(370, 220, 151, 151))
        self.info_seeker_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.info_seeker_textEdit.setReadOnly(True)
        self.info_seeker_textEdit.setObjectName(_fromUtf8("info_seeker_textEdit"))
        self.curious_textEdit = QtGui.QTextEdit(self.tab_6)
        self.curious_textEdit.setGeometry(QtCore.QRect(540, 220, 151, 151))
        self.curious_textEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.curious_textEdit.setReadOnly(True)
        self.curious_textEdit.setObjectName(_fromUtf8("curious_textEdit"))
        self.tabWidget_3.addTab(self.tab_6, _fromUtf8(""))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.formLayoutWidget_4 = QtGui.QWidget(self.tab)
        self.formLayoutWidget_4.setGeometry(QtCore.QRect(720, 10, 161, 116))
        self.formLayoutWidget_4.setObjectName(_fromUtf8("formLayoutWidget_4"))
        self.gridLayout_3 = QtGui.QGridLayout(self.formLayoutWidget_4)
        self.gridLayout_3.setMargin(0)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.new_connections_label_3 = QtGui.QLabel(self.formLayoutWidget_4)
        self.new_connections_label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.new_connections_label_3.setWordWrap(True)
        self.new_connections_label_3.setObjectName(_fromUtf8("new_connections_label_3"))
        self.gridLayout_3.addWidget(self.new_connections_label_3, 3, 0, 1, 1)
        self.total_connections_3 = QtGui.QLabel(self.formLayoutWidget_4)
        self.total_connections_3.setAlignment(QtCore.Qt.AlignCenter)
        self.total_connections_3.setWordWrap(True)
        self.total_connections_3.setObjectName(_fromUtf8("total_connections_3"))
        self.gridLayout_3.addWidget(self.total_connections_3, 2, 0, 1, 1)
        self.threat_total_connection_num = QtGui.QLCDNumber(self.formLayoutWidget_4)
        self.threat_total_connection_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.threat_total_connection_num.setObjectName(_fromUtf8("threat_total_connection_num"))
        self.gridLayout_3.addWidget(self.threat_total_connection_num, 2, 1, 1, 1)
        self.threat_new_connections_num = QtGui.QLCDNumber(self.formLayoutWidget_4)
        self.threat_new_connections_num.setEnabled(True)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.threat_new_connections_num.setFont(font)
        self.threat_new_connections_num.setFrameShape(QtGui.QFrame.NoFrame)
        self.threat_new_connections_num.setObjectName(_fromUtf8("threat_new_connections_num"))
        self.gridLayout_3.addWidget(self.threat_new_connections_num, 3, 1, 1, 1)
        self.verticalLayoutWidget_10 = QtGui.QWidget(self.tab)
        self.verticalLayoutWidget_10.setGeometry(QtCore.QRect(720, 150, 161, 31))
        self.verticalLayoutWidget_10.setObjectName(_fromUtf8("verticalLayoutWidget_10"))
        self.verticalLayout_10 = QtGui.QVBoxLayout(self.verticalLayoutWidget_10)
        self.verticalLayout_10.setMargin(0)
        self.verticalLayout_10.setObjectName(_fromUtf8("verticalLayout_10"))
        self.threat_analyse_network_btn = QtGui.QPushButton(self.verticalLayoutWidget_10)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.threat_analyse_network_btn.setFont(font)
        self.threat_analyse_network_btn.setObjectName(_fromUtf8("threat_analyse_network_btn"))
        self.verticalLayout_10.addWidget(self.threat_analyse_network_btn)
        self.potential_threats_textEdit = QtGui.QTextEdit(self.tab)
        self.potential_threats_textEdit.setGeometry(QtCore.QRect(720, 220, 161, 151))
        self.potential_threats_textEdit.setReadOnly(True)
        self.potential_threats_textEdit.setObjectName(_fromUtf8("potential_threats_textEdit"))
        self.label_2 = QtGui.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(720, 200, 161, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayoutWidget_7 = QtGui.QWidget(self.tab)
        self.gridLayoutWidget_7.setGeometry(QtCore.QRect(10, 10, 691, 371))
        self.gridLayoutWidget_7.setObjectName(_fromUtf8("gridLayoutWidget_7"))
        self.flagged_nodes_grid = QtGui.QGridLayout(self.gridLayoutWidget_7)
        self.flagged_nodes_grid.setMargin(0)
        self.flagged_nodes_grid.setObjectName(_fromUtf8("flagged_nodes_grid"))
        self.tabWidget_3.addTab(self.tab, _fromUtf8(""))
        self.node_network_tab = QtGui.QWidget()
        self.node_network_tab.setObjectName(_fromUtf8("node_network_tab"))
        self.gridLayoutWidget_2 = QtGui.QWidget(self.node_network_tab)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(-120, -60, 1111, 501))
        self.gridLayoutWidget_2.setObjectName(_fromUtf8("gridLayoutWidget_2"))
        self.node_network_grid = QtGui.QGridLayout(self.gridLayoutWidget_2)
        self.node_network_grid.setMargin(0)
        self.node_network_grid.setObjectName(_fromUtf8("node_network_grid"))
        self.tabWidget_3.addTab(self.node_network_tab, _fromUtf8(""))
        self.page_interest_tab = QtGui.QWidget()
        self.page_interest_tab.setObjectName(_fromUtf8("page_interest_tab"))
        self.gridLayoutWidget_4 = QtGui.QWidget(self.page_interest_tab)
        self.gridLayoutWidget_4.setGeometry(QtCore.QRect(0, 0, 681, 391))
        self.gridLayoutWidget_4.setObjectName(_fromUtf8("gridLayoutWidget_4"))
        self.page_interest_grid = QtGui.QGridLayout(self.gridLayoutWidget_4)
        self.page_interest_grid.setMargin(0)
        self.page_interest_grid.setObjectName(_fromUtf8("page_interest_grid"))
        self.page_interest_textEdit = QtGui.QTextEdit(self.page_interest_tab)
        self.page_interest_textEdit.setGeometry(QtCore.QRect(690, 30, 201, 351))
        self.page_interest_textEdit.setReadOnly(True)
        self.page_interest_textEdit.setObjectName(_fromUtf8("page_interest_textEdit"))
        self.label = QtGui.QLabel(self.page_interest_tab)
        self.label.setGeometry(QtCore.QRect(690, 6, 201, 21))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName(_fromUtf8("label"))
        self.tabWidget_3.addTab(self.page_interest_tab, _fromUtf8(""))
        self.tabWidget.addTab(self.network_analysis_tab, _fromUtf8(""))
        self.node_profiling_tab = QtGui.QWidget()
        self.node_profiling_tab.setObjectName(_fromUtf8("node_profiling_tab"))
        self.tabWidget_2 = QtGui.QTabWidget(self.node_profiling_tab)
        self.tabWidget_2.setGeometry(QtCore.QRect(-4, 0, 711, 431))
        self.tabWidget_2.setMovable(True)
        self.tabWidget_2.setObjectName(_fromUtf8("tabWidget_2"))
        self.node_analysis_tab = QtGui.QWidget()
        self.node_analysis_tab.setObjectName(_fromUtf8("node_analysis_tab"))
        self.node_analysis_textEdit = QtGui.QTextEdit(self.node_analysis_tab)
        self.node_analysis_textEdit.setGeometry(QtCore.QRect(10, 10, 691, 371))
        self.node_analysis_textEdit.setReadOnly(True)
        self.node_analysis_textEdit.setObjectName(_fromUtf8("node_analysis_textEdit"))
        self.tabWidget_2.addTab(self.node_analysis_tab, _fromUtf8(""))
        self.node_threat_analysis_tab = QtGui.QWidget()
        self.node_threat_analysis_tab.setObjectName(_fromUtf8("node_threat_analysis_tab"))
        self.node_movement_textEdit = QtGui.QTextEdit(self.node_threat_analysis_tab)
        self.node_movement_textEdit.setGeometry(QtCore.QRect(20, 30, 471, 91))
        self.node_movement_textEdit.setReadOnly(True)
        self.node_movement_textEdit.setObjectName(_fromUtf8("node_movement_textEdit"))
        self.label_5 = QtGui.QLabel(self.node_threat_analysis_tab)
        self.label_5.setGeometry(QtCore.QRect(20, 10, 471, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignCenter)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.threat_movement_textEdit = QtGui.QTextEdit(self.node_threat_analysis_tab)
        self.threat_movement_textEdit.setGeometry(QtCore.QRect(20, 150, 471, 231))
        self.threat_movement_textEdit.setReadOnly(True)
        self.threat_movement_textEdit.setObjectName(_fromUtf8("threat_movement_textEdit"))
        self.label_7 = QtGui.QLabel(self.node_threat_analysis_tab)
        self.label_7.setGeometry(QtCore.QRect(20, 130, 471, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_7.setFont(font)
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName(_fromUtf8("label_7"))
        self.threat_comparison_textEdit = QtGui.QTextEdit(self.node_threat_analysis_tab)
        self.threat_comparison_textEdit.setGeometry(QtCore.QRect(510, 150, 181, 231))
        self.threat_comparison_textEdit.setReadOnly(True)
        self.threat_comparison_textEdit.setObjectName(_fromUtf8("threat_comparison_textEdit"))
        self.label_6 = QtGui.QLabel(self.node_threat_analysis_tab)
        self.label_6.setGeometry(QtCore.QRect(510, 130, 181, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setAlignment(QtCore.Qt.AlignCenter)
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.label_4 = QtGui.QLabel(self.node_threat_analysis_tab)
        self.label_4.setGeometry(QtCore.QRect(510, 20, 181, 41))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setWordWrap(True)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.potential_threats_comboBox = QtGui.QComboBox(self.node_threat_analysis_tab)
        self.potential_threats_comboBox.setGeometry(QtCore.QRect(510, 60, 181, 31))
        self.potential_threats_comboBox.setObjectName(_fromUtf8("potential_threats_comboBox"))
        self.tabWidget_2.addTab(self.node_threat_analysis_tab, _fromUtf8(""))
        self.node_travel_path_tab = QtGui.QWidget()
        self.node_travel_path_tab.setObjectName(_fromUtf8("node_travel_path_tab"))
        self.gridLayoutWidget = QtGui.QWidget(self.node_travel_path_tab)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(0, -10, 711, 411))
        self.gridLayoutWidget.setObjectName(_fromUtf8("gridLayoutWidget"))
        self.node_travel_path_grid = QtGui.QGridLayout(self.gridLayoutWidget)
        self.node_travel_path_grid.setMargin(0)
        self.node_travel_path_grid.setObjectName(_fromUtf8("node_travel_path_grid"))
        self.tabWidget_2.addTab(self.node_travel_path_tab, _fromUtf8(""))
        self.node_timeline_tab = QtGui.QWidget()
        self.node_timeline_tab.setObjectName(_fromUtf8("node_timeline_tab"))
        self.gridLayoutWidget_3 = QtGui.QWidget(self.node_timeline_tab)
        self.gridLayoutWidget_3.setGeometry(QtCore.QRect(0, -10, 761, 411))
        self.gridLayoutWidget_3.setObjectName(_fromUtf8("gridLayoutWidget_3"))
        self.node_timeline_grid = QtGui.QGridLayout(self.gridLayoutWidget_3)
        self.node_timeline_grid.setMargin(0)
        self.node_timeline_grid.setObjectName(_fromUtf8("node_timeline_grid"))
        self.tabWidget_2.addTab(self.node_timeline_tab, _fromUtf8(""))
        self.verticalLayoutWidget_4 = QtGui.QWidget(self.node_profiling_tab)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(720, 20, 161, 111))
        self.verticalLayoutWidget_4.setObjectName(_fromUtf8("verticalLayoutWidget_4"))
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.verticalLayoutWidget_4)
        self.verticalLayout_4.setMargin(0)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.total_nodes_label = QtGui.QLabel(self.verticalLayoutWidget_4)
        self.total_nodes_label.setAutoFillBackground(False)
        self.total_nodes_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.total_nodes_label.setWordWrap(True)
        self.total_nodes_label.setObjectName(_fromUtf8("total_nodes_label"))
        self.horizontalLayout_5.addWidget(self.total_nodes_label)
        self.total_nodes_lcd = QtGui.QLCDNumber(self.verticalLayoutWidget_4)
        self.total_nodes_lcd.setFrameShape(QtGui.QFrame.NoFrame)
        self.total_nodes_lcd.setLineWidth(3)
        self.total_nodes_lcd.setObjectName(_fromUtf8("total_nodes_lcd"))
        self.horizontalLayout_5.addWidget(self.total_nodes_lcd)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.node_to_analys_label = QtGui.QLabel(self.verticalLayoutWidget_4)
        self.node_to_analys_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.node_to_analys_label.setWordWrap(True)
        self.node_to_analys_label.setObjectName(_fromUtf8("node_to_analys_label"))
        self.horizontalLayout_3.addWidget(self.node_to_analys_label)
        self.node_spinBox = QtGui.QSpinBox(self.verticalLayoutWidget_4)
        font = QtGui.QFont()
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.node_spinBox.setFont(font)
        self.node_spinBox.setObjectName(_fromUtf8("node_spinBox"))
        self.horizontalLayout_3.addWidget(self.node_spinBox)
        self.verticalLayout_4.addLayout(self.horizontalLayout_3)
        self.verticalLayoutWidget_2 = QtGui.QWidget(self.node_profiling_tab)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(720, 350, 160, 61))
        self.verticalLayoutWidget_2.setObjectName(_fromUtf8("verticalLayoutWidget_2"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setMargin(0)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.clear_page_node_analysis_btn = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.clear_page_node_analysis_btn.setObjectName(_fromUtf8("clear_page_node_analysis_btn"))
        self.verticalLayout_2.addWidget(self.clear_page_node_analysis_btn)
        self.save_log_node_analysis_btn = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.save_log_node_analysis_btn.setObjectName(_fromUtf8("save_log_node_analysis_btn"))
        self.verticalLayout_2.addWidget(self.save_log_node_analysis_btn)
        self.verticalLayoutWidget_7 = QtGui.QWidget(self.node_profiling_tab)
        self.verticalLayoutWidget_7.setGeometry(QtCore.QRect(720, 160, 161, 91))
        self.verticalLayoutWidget_7.setObjectName(_fromUtf8("verticalLayoutWidget_7"))
        self.verticalLayout_7 = QtGui.QVBoxLayout(self.verticalLayoutWidget_7)
        self.verticalLayout_7.setMargin(0)
        self.verticalLayout_7.setObjectName(_fromUtf8("verticalLayout_7"))
        self.analyse_node_btn = QtGui.QPushButton(self.verticalLayoutWidget_7)
        self.analyse_node_btn.setObjectName(_fromUtf8("analyse_node_btn"))
        self.verticalLayout_7.addWidget(self.analyse_node_btn)
        self.evaluate_threat_btn = QtGui.QPushButton(self.verticalLayoutWidget_7)
        self.evaluate_threat_btn.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.evaluate_threat_btn.setObjectName(_fromUtf8("evaluate_threat_btn"))
        self.verticalLayout_7.addWidget(self.evaluate_threat_btn)
        self.tabWidget.addTab(self.node_profiling_tab, _fromUtf8(""))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.tabWidget_4 = QtGui.QTabWidget(self.tab_2)
        self.tabWidget_4.setGeometry(QtCore.QRect(-10, 0, 911, 431))
        self.tabWidget_4.setMovable(True)
        self.tabWidget_4.setObjectName(_fromUtf8("tabWidget_4"))
        self.overview_tab = QtGui.QWidget()
        self.overview_tab.setObjectName(_fromUtf8("overview_tab"))
        self.experiment_data_table = QtGui.QTableView(self.overview_tab)
        self.experiment_data_table.setGeometry(QtCore.QRect(310, 30, 581, 351))
        self.experiment_data_table.setObjectName(_fromUtf8("experiment_data_table"))
        self.label_12 = QtGui.QLabel(self.overview_tab)
        self.label_12.setGeometry(QtCore.QRect(20, 10, 271, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_12.setFont(font)
        self.label_12.setAlignment(QtCore.Qt.AlignCenter)
        self.label_12.setObjectName(_fromUtf8("label_12"))
        self.site_locations_table = QtGui.QTableView(self.overview_tab)
        self.site_locations_table.setGeometry(QtCore.QRect(20, 30, 271, 351))
        self.site_locations_table.setObjectName(_fromUtf8("site_locations_table"))
        self.label_13 = QtGui.QLabel(self.overview_tab)
        self.label_13.setGeometry(QtCore.QRect(310, 10, 581, 20))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_13.setFont(font)
        self.label_13.setAlignment(QtCore.Qt.AlignCenter)
        self.label_13.setObjectName(_fromUtf8("label_13"))
        self.tabWidget_4.addTab(self.overview_tab, _fromUtf8(""))
        self.model_type_graph = QtGui.QWidget()
        self.model_type_graph.setObjectName(_fromUtf8("model_type_graph"))
        self.gridLayoutWidget_8 = QtGui.QWidget(self.model_type_graph)
        self.gridLayoutWidget_8.setGeometry(QtCore.QRect(-10, -10, 931, 401))
        self.gridLayoutWidget_8.setObjectName(_fromUtf8("gridLayoutWidget_8"))
        self.pos_prob_gridLayout = QtGui.QGridLayout(self.gridLayoutWidget_8)
        self.pos_prob_gridLayout.setMargin(0)
        self.pos_prob_gridLayout.setObjectName(_fromUtf8("pos_prob_gridLayout"))
        self.tabWidget_4.addTab(self.model_type_graph, _fromUtf8(""))
        self.tab_3 = QtGui.QWidget()
        self.tab_3.setObjectName(_fromUtf8("tab_3"))
        self.gridLayoutWidget_5 = QtGui.QWidget(self.tab_3)
        self.gridLayoutWidget_5.setGeometry(QtCore.QRect(0, -10, 911, 401))
        self.gridLayoutWidget_5.setObjectName(_fromUtf8("gridLayoutWidget_5"))
        self.avg_time_gridLayout = QtGui.QGridLayout(self.gridLayoutWidget_5)
        self.avg_time_gridLayout.setMargin(0)
        self.avg_time_gridLayout.setObjectName(_fromUtf8("avg_time_gridLayout"))
        self.tabWidget_4.addTab(self.tab_3, _fromUtf8(""))
        self.tab_5 = QtGui.QWidget()
        self.tab_5.setObjectName(_fromUtf8("tab_5"))
        self.pos_prob_table = QtGui.QTableView(self.tab_5)
        self.pos_prob_table.setGeometry(QtCore.QRect(20, 10, 871, 371))
        self.pos_prob_table.setObjectName(_fromUtf8("pos_prob_table"))
        self.tabWidget_4.addTab(self.tab_5, _fromUtf8(""))
        self.tab_4 = QtGui.QWidget()
        self.tab_4.setObjectName(_fromUtf8("tab_4"))
        self.transition_matrx_table = QtGui.QTableView(self.tab_4)
        self.transition_matrx_table.setGeometry(QtCore.QRect(20, 10, 871, 371))
        self.transition_matrx_table.setObjectName(_fromUtf8("transition_matrx_table"))
        self.tabWidget_4.addTab(self.tab_4, _fromUtf8(""))
        self.tabWidget.addTab(self.tab_2, _fromUtf8(""))
        self.verticalLayoutWidget_6 = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget_6.setGeometry(QtCore.QRect(30, 10, 161, 120))
        self.verticalLayoutWidget_6.setObjectName(_fromUtf8("verticalLayoutWidget_6"))
        self.verticalLayout_6 = QtGui.QVBoxLayout(self.verticalLayoutWidget_6)
        self.verticalLayout_6.setMargin(0)
        self.verticalLayout_6.setObjectName(_fromUtf8("verticalLayout_6"))
        self.onion_btn = QtGui.QPushButton(self.verticalLayoutWidget_6)
        self.onion_btn.setObjectName(_fromUtf8("onion_btn"))
        self.verticalLayout_6.addWidget(self.onion_btn)
        self.onion_line = QtGui.QLineEdit(self.verticalLayoutWidget_6)
        self.onion_line.setReadOnly(True)
        self.onion_line.setObjectName(_fromUtf8("onion_line"))
        self.verticalLayout_6.addWidget(self.onion_line)
        self.start_tor_btn = QtGui.QPushButton(self.verticalLayoutWidget_6)
        self.start_tor_btn.setObjectName(_fromUtf8("start_tor_btn"))
        self.verticalLayout_6.addWidget(self.start_tor_btn)
        self.close_tor_btn = QtGui.QPushButton(self.verticalLayoutWidget_6)
        self.close_tor_btn.setDefault(False)
        self.close_tor_btn.setObjectName(_fromUtf8("close_tor_btn"))
        self.verticalLayout_6.addWidget(self.close_tor_btn)
        self.console_textEdit = QtGui.QTextEdit(self.centralwidget)
        self.console_textEdit.setGeometry(QtCore.QRect(10, 140, 201, 191))
        self.console_textEdit.setReadOnly(True)
        self.console_textEdit.setObjectName(_fromUtf8("console_textEdit"))
        self.tabWidget.raise_()
        self.verticalLayoutWidget.raise_()
        self.horizontalLayoutWidget.raise_()
        self.verticalLayoutWidget_6.raise_()
        self.console_textEdit.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1129, 22))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuFile = QtGui.QMenu(self.menubar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        self.menuRun = QtGui.QMenu(self.menubar)
        self.menuRun.setObjectName(_fromUtf8("menuRun"))
        self.menuOptions = QtGui.QMenu(self.menubar)
        self.menuOptions.setObjectName(_fromUtf8("menuOptions"))
        self.menuHelp = QtGui.QMenu(self.menubar)
        self.menuHelp.setObjectName(_fromUtf8("menuHelp"))
        self.menuStop = QtGui.QMenu(self.menubar)
        self.menuStop.setObjectName(_fromUtf8("menuStop"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.menu_quit_action = QtGui.QAction(MainWindow)
        self.menu_quit_action.setObjectName(_fromUtf8("menu_quit_action"))
        self.menu_start_server = QtGui.QAction(MainWindow)
        self.menu_start_server.setObjectName(_fromUtf8("menu_start_server"))
        self.actionShutdown_Server = QtGui.QAction(MainWindow)
        self.actionShutdown_Server.setObjectName(_fromUtf8("actionShutdown_Server"))
        self.menu_stop_server = QtGui.QAction(MainWindow)
        self.menu_stop_server.setObjectName(_fromUtf8("menu_stop_server"))
        self.menu_stop_tor = QtGui.QAction(MainWindow)
        self.menu_stop_tor.setObjectName(_fromUtf8("menu_stop_tor"))
        self.actionLog_Out = QtGui.QAction(MainWindow)
        self.actionLog_Out.setObjectName(_fromUtf8("actionLog_Out"))
        self.menu_log_out_action = QtGui.QAction(MainWindow)
        self.menu_log_out_action.setObjectName(_fromUtf8("menu_log_out_action"))
        self.menu_start_tor = QtGui.QAction(MainWindow)
        self.menu_start_tor.setObjectName(_fromUtf8("menu_start_tor"))
        self.actionAnalyse_Network = QtGui.QAction(MainWindow)
        self.actionAnalyse_Network.setObjectName(_fromUtf8("actionAnalyse_Network"))
        self.actionRefresh = QtGui.QAction(MainWindow)
        self.actionRefresh.setObjectName(_fromUtf8("actionRefresh"))
        self.actionGuide = QtGui.QAction(MainWindow)
        self.actionGuide.setObjectName(_fromUtf8("actionGuide"))
        self.menuFile.addAction(self.menu_log_out_action)
        self.menuFile.addAction(self.menu_quit_action)
        self.menuRun.addAction(self.menu_start_server)
        self.menuRun.addAction(self.menu_start_tor)
        self.menuRun.addAction(self.actionAnalyse_Network)
        self.menuOptions.addAction(self.actionRefresh)
        self.menuHelp.addAction(self.actionGuide)
        self.menuStop.addAction(self.menu_stop_tor)
        self.menuStop.addAction(self.menu_stop_server)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuRun.menuAction())
        self.menubar.addAction(self.menuStop.menuAction())
        self.menubar.addAction(self.menuOptions.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget_3.setCurrentIndex(0)
        self.tabWidget_2.setCurrentIndex(0)
        self.tabWidget_4.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


    # Add text to the HAT's UI
    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "Honeypot Analysis Tool (HAT)", None))
        self.start_server_btn.setText(_translate("MainWindow", "Start Server", None))
        self.stop_server_btn.setText(_translate("MainWindow", "Stop Server", None))
        self.server_status_btn.setText(_translate("MainWindow", "Server Status", None))
        self.log_out_btn.setText(_translate("MainWindow", "Log Out", None))
        self.quit_btn.setText(_translate("MainWindow", "Quit", None))
        self.network_info_textEdit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
"<p align=\"center\" style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>", None))
        self.new_connections_label.setText(_translate("MainWindow", "New Connections", None))
        self.total_connections.setText(_translate("MainWindow", "Total Connections", None))
        self.clear_page_network_btn.setText(_translate("MainWindow", "Clear Page", None))
        self.save_log_btn.setText(_translate("MainWindow", "Save Log", None))
        self.analyse_network_btn.setText(_translate("MainWindow", "Analyse Network", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.network_node_info_tab), _translate("MainWindow", "Network Node Information", None))
        self.new_connections_label_4.setText(_translate("MainWindow", "New Connections", None))
        self.total_connections_4.setText(_translate("MainWindow", "Total Connections", None))
        self.grouped_analyse_network_btn.setText(_translate("MainWindow", "Analyse Network", None))
        self.label_3.setText(_translate("MainWindow", "Profiles", None))
        self.label_10.setText(_translate("MainWindow", "Cyber", None))
        self.label_11.setText(_translate("MainWindow", "Drugs", None))
        self.label_14.setText(_translate("MainWindow", "Weapons", None))
        self.label_15.setText(_translate("MainWindow", "Carding", None))
        self.label_16.setText(_translate("MainWindow", "Fake ID", None))
        self.label_17.setText(_translate("MainWindow", "Information Seeker", None))
        self.label_18.setText(_translate("MainWindow", "Curious", None))
        self.label_19.setText(_translate("MainWindow", "Self-Identified Groups", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.tab_6), _translate("MainWindow", "Nodes Grouped by Profile", None))
        self.new_connections_label_3.setText(_translate("MainWindow", "New Connections", None))
        self.total_connections_3.setText(_translate("MainWindow", "Total Connections", None))
        self.threat_analyse_network_btn.setText(_translate("MainWindow", "Analyse Network", None))
        self.label_2.setText(_translate("MainWindow", "Profiles", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.tab), _translate("MainWindow", "Flagged Nodes", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.node_network_tab), _translate("MainWindow", "Node Network Graph", None))
        self.label.setText(_translate("MainWindow", "Page Key", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.page_interest_tab), _translate("MainWindow", "Page Interest", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.network_analysis_tab), _translate("MainWindow", "Network Analysis", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.node_analysis_tab), _translate("MainWindow", "Node Analysis", None))
        self.label_5.setText(_translate("MainWindow", "Node Movement", None))
        self.label_7.setText(_translate("MainWindow", "Real Profile Movement", None))
        self.label_6.setText(_translate("MainWindow", "Profile Evaluation", None))
        self.label_4.setText(_translate("MainWindow", "Select a Profile to Evaluate Node Against", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.node_threat_analysis_tab), _translate("MainWindow", "Profile Analysis", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.node_travel_path_tab), _translate("MainWindow", "Node Travel Path", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.node_timeline_tab), _translate("MainWindow", "Node Travel Timeline", None))
        self.total_nodes_label.setText(_translate("MainWindow", "Total Nodes Found", None))
        self.node_to_analys_label.setText(_translate("MainWindow", "Node To Analyse", None))
        self.clear_page_node_analysis_btn.setText(_translate("MainWindow", "Clear Pages", None))
        self.save_log_node_analysis_btn.setText(_translate("MainWindow", "Save Log", None))
        self.analyse_node_btn.setText(_translate("MainWindow", "Analyse Node", None))
        self.evaluate_threat_btn.setText(_translate("MainWindow", "Evaluate Profile", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.node_profiling_tab), _translate("MainWindow", "Node Analysis", None))
        self.label_12.setText(_translate("MainWindow", "Defined Site Locations", None))
        self.label_13.setText(_translate("MainWindow", "Categorised Experiment Data", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.overview_tab), _translate("MainWindow", "  Overview", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.model_type_graph), _translate("MainWindow", "Positional Prob. Graph", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.tab_3), _translate("MainWindow", "Avg. Time at Each Site Location", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.tab_5), _translate("MainWindow", "Position Probability Matrix", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.tab_4), _translate("MainWindow", "Transition Prob. Matrix", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Node Position Markov Model", None))
        self.onion_btn.setText(_translate("MainWindow", "Retrieve .onion", None))
        self.start_tor_btn.setText(_translate("MainWindow", "Create Tor Session", None))
        self.close_tor_btn.setText(_translate("MainWindow", "Terminate Tor Session", None))
        self.menuFile.setTitle(_translate("MainWindow", "Fi&le", None))
        self.menuRun.setTitle(_translate("MainWindow", "R&un", None))
        self.menuOptions.setTitle(_translate("MainWindow", "Optio&ns", None))
        self.menuHelp.setTitle(_translate("MainWindow", "Help", None))
        self.menuStop.setTitle(_translate("MainWindow", "Stop", None))
        self.menu_quit_action.setText(_translate("MainWindow", "&Quit", None))
        self.menu_start_server.setText(_translate("MainWindow", "&Start Server", None))
        self.actionShutdown_Server.setText(_translate("MainWindow", "Shutdown Server", None))
        self.menu_stop_server.setText(_translate("MainWindow", "&Shutdown Server", None))
        self.menu_stop_tor.setText(_translate("MainWindow", "&Terminate Tor Session", None))
        self.actionLog_Out.setText(_translate("MainWindow", "Log Out", None))
        self.menu_log_out_action.setText(_translate("MainWindow", "&Log Out", None))
        self.menu_start_tor.setText(_translate("MainWindow", "Sta&rt Tor Session", None))
        self.actionAnalyse_Network.setText(_translate("MainWindow", "&Analyse Network", None))
        self.actionRefresh.setText(_translate("MainWindow", "&Refresh", None))
        self.actionGuide.setText(_translate("MainWindow", "&Guide", None))




# HAT Functionality Class
class MainWindow(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        
        # Main Window UI Connections
        self.quit_btn.clicked.connect(self.closeApplication)
        self.start_server_btn.clicked.connect(self.startServer)
        self.stop_server_btn.clicked.connect(self.stopServer)
        self.server_status_btn.clicked.connect(self.serverStatus)
        self.start_tor_btn.clicked.connect(self.openTor)
        self.close_tor_btn.clicked.connect(self.closeTor)
        self.onion_btn.clicked.connect(self.fetchOnionLink)
        self.log_out_btn.clicked.connect(self.logOut)

        # Network Analysis Tab UI Connections
        total_node_list = []
        self.potential_threats = ['Cyber','Groups','Weapons','Drugs','Carding','Fake ID',
                                  'Information Seeker','Curious']
        self.total_nodes = 0
        self.network_info_textEdit.setText("Analysing the network can take a while so please wait...")
        self.analyse_network_btn.clicked.connect(partial(self.analyseNetwork, total_node_list))
        self.threat_analyse_network_btn.clicked.connect(partial(self.analyseNetwork, total_node_list))
        self.grouped_analyse_network_btn.clicked.connect(partial(self.analyseNetwork, total_node_list))
        self.clear_page_network_btn.clicked.connect(self.clearNetworkPage)
        for threat in self.potential_threats:
            self.potential_threats_textEdit.append(threat)
            self.grouped_potential_threats_textEdit.append(threat)

        # Node Analysis Tab UI Conncetions
        self.analyse_node_btn.setEnabled(False)
        self.node_spinBox.setMinimum(1)
        self.analyse_node_btn.clicked.connect(self.analyseNode)
        self.clear_page_node_analysis_btn.clicked.connect(self.clearNodePages)
        self.potential_threats_comboBox.addItems(self.potential_threats)
        self.potential_threats_comboBox.setEnabled(False)
        self.potential_threats_comboBox.currentIndexChanged.connect(self.evalThreatTrigger)
        self.evaluate_threat_btn.setEnabled(False)
        self.evaluate_threat_btn.clicked.connect(self.evalThreatTrigger)

        # Node Pos. Markov Model Tab UI Connections
        self.model()
        
        # Write to console
        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)

        # Figure Warning Exception
        plt.rcParams.update({'figure.max_open_warning': 0})
        
        
    # Analyse Network
    def analyseNetwork(self,total_node_list):
        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)
        self.all_node_means = []
        self.grouped_nodes = {}
        print("Analysing Network...")
        total_node_list.append(self.analyseAccessLog())
        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)
        print("Network Analysis Complete")
        
        #totals connections & new connections
        if len(total_node_list) == 1:
            print(">",total_node_list[0],"Node connections found\n")
        else:
            i = len(total_node_list) - 1
            new_nodes = total_node_list[i]-total_node_list[i-1]
            self.new_connections_num.display(new_nodes)
            self.threat_new_connections_num.display(new_nodes)
            self.grouped_new_connections_num.display(new_nodes)
            if new_nodes == 1:
                print(">",new_nodes,"New connection\n")
            else:
                print(">",new_nodes,"New connections\n")
                
        self.analyse_node_btn.setEnabled(True)
        self.evaluate_threat_btn.setEnabled(False)


    def analyseAccessLog(self):
        # Network Graph
        self.network_figure = plt.figure()
        self.network_canvas = FigureCanvas(self.network_figure)
        self.node_network_grid.addWidget(self.network_canvas, 0, 1, 9, 9)
        self.network_figure.clf()

        self.network_info_textEdit.clear()
        sys.stdout = EmittingStream(text_written=self.netAnalysisOutputWritten)
        global node_pos
        self.total_nodes, graph, label_dict, node_pos, self.all_page_interests = server_log_analysis.networkAnalysisProtocol()
        self.total_connection_num.display(self.total_nodes)
        self.total_nodes_lcd.display(self.total_nodes)
        self.threat_total_connection_num.display(self.total_nodes)
        self.grouped_total_connection_num.display(self.total_nodes)
        self.node_spinBox.setMaximum(self.total_nodes)
        
        global all_nodes
        all_nodes = list(range(0,self.total_nodes))
        
        # Network Graph
        nx.draw_networkx(graph, pos=node_pos, labels = label_dict, node_color='yellow', with_labels=True)
        self.network_canvas.mpl_connect('button_press_event', self.onNodeClick)
        self.network_canvas.draw_idle()

        # Page Interest
        if len(self.all_page_interests) != 0:
            self.pageInterest()
        else:
            pass

        # Flagged Nodes
        self.flaggedNodes()

        # Grouping Nodes via their highest matched profile
        self.groupedNodes()
        
        return self.total_nodes


    # Generates Flagged Nodes Network Graph in Network Analysis Tab
    def flaggedNodes(self):
        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)
        for node in range(self.total_nodes):
            self.node_spinBox.setValue(node+1)
            self.analyseNode()
        self.node_spinBox.setValue(1)
        self.clearNodePages()
        self.node_figure.clf()
        self.timeline_figure.clf()

        # Flagged Nodes Graph
        self.flagged_figure = plt.figure()
        self.flagged_canvas = FigureCanvas(self.flagged_figure)
        self.flagged_nodes_grid.addWidget(self.flagged_canvas, 0, 1, 9, 9)
        self.flagged_figure.clf()
        sb.set_style('ticks')
        G = nx.Graph()
        
        flagged = {}
        label_dict = {}
        for i in range(len(self.all_node_means)):
            if self.all_node_means[i] >= 50:
                flagged[i+1] = self.all_node_means[i]
                label_dict.update({i:i+1})
                G.add_node(i)
            else:
                pass
        node_sizes = list(flagged.values())
        for i in range(len(node_sizes)):
            if node_sizes[i] > 80:
                node_sizes[i] = node_sizes[i]*20
            elif node_sizes[i] > 70:
               node_sizes[i] = node_sizes[i]*10
            elif node_sizes[i] > 60:
               node_sizes[i] = node_sizes[i]*5
            else:
                node_sizes[i] = node_sizes[i]*2.5
            
        self.flagged_nodes = list(flagged.keys())
        self.flagged_node_pos = nx.circular_layout(G)
        nx.draw_networkx(G, node_size = node_sizes, pos = self.flagged_node_pos, labels = label_dict, node_color='yellow', with_labels=True)
        self.flagged_canvas.mpl_connect('button_press_event', self.onFlaggedNodeClick)
        self.flagged_canvas.draw_idle()


    # Groups nodes via their highest matched profile
    def groupedNodes(self):
        self.cyber_textEdit.clear()
        self.groups_textEdit.clear()
        self.weapons_textEdit.clear()
        self.drugs_textEdit.clear()
        self.carding_textEdit.clear()
        self.fake_id_textEdit.clear()
        self.info_seeker_textEdit.clear()
        self.curious_textEdit.clear()
        
        for i in range(self.total_nodes):
            t_profile = self.grouped_nodes[i]
            if t_profile == 'cyber':
                self.cyber_textEdit.append("Node "+str(i+1))
            elif t_profile == 'groups':
                self.groups_textEdit.append("Node "+str(i+1))
            elif t_profile == 'weapons':
                self.weapons_textEdit.append("Node "+str(i+1))
            elif t_profile == 'drugs':
                self.drugs_textEdit.append("Node "+str(i+1))
            elif t_profile == 'carding':
                self.carding_textEdit.append("Node "+str(i+1))
            elif t_profile == 'fake id':
                self.fake_id_textEdit.append("Node "+str(i+1))
            elif t_profile == 'information seeker':
                self.info_seeker_textEdit.append("Node "+str(i+1))
            elif t_profile == 'curious':
                self.curious_textEdit.append("Node "+str(i+1))
            else:
                pass

                    
    # Allows for clicking interactivity with Flagged Nodes network graph
    def onFlaggedNodeClick(self, event):
        (x,y) = (event.xdata, event.ydata)
        for i in self.flagged_nodes:
            node = self.flagged_node_pos[i-1]
            try:
                distance = pow(x-node[0],2)+pow(y-node[1],2)
                if distance < 0.01:
                    print("Node",i,"Clicked")
                    self.node_spinBox.setValue(i)
                    self.tabWidget.setCurrentWidget(self.node_profiling_tab)
                    self.analyseNode()
            except:
                break


    # Generates Bar Chart for individual page interests
    def pageInterest(self):
        self.page_interest_figure = plt.figure()
        self.page_interest_canvas = FigureCanvas(self.page_interest_figure)
        self.page_interest_grid.addWidget(self.page_interest_canvas, 0, 1, 9, 9)
        self.page_interest_figure.clf()
        n_pages = len(self.all_page_interests)
        plt.bar(range(n_pages), list(self.all_page_interests.values()), edgecolor = "black", color = 'blue', align='center')
        plt.xlabel("Page")
        plt.ylabel("Interest")
        self.page_interest_canvas.draw_idle()

        pages = list(self.all_page_interests.keys())
        for i in range(n_pages):
            self.page_interest_textEdit.append(str(i)+": "+pages[i])
            

    def onNodeClick(self, event):
        (x,y) = (event.xdata, event.ydata)
        for i in all_nodes:
            node = node_pos[i]
            try:
                distance = pow(x-node[0],2)+pow(y-node[1],2)
                if distance < 0.01:
                    print("Node",i+1,"Clicked")
                    self.node_spinBox.setValue(i+1)
                    self.tabWidget.setCurrentWidget(self.node_profiling_tab)
                    self.analyseNode()
            except:
                break
            

    # Analyses Single Nodes
    def analyseNode(self):
        # Node Travel Graph
        self.node_figure = plt.figure()
        self.node_canvas = FigureCanvas(self.node_figure)
        self.node_travel_path_grid.addWidget(self.node_canvas, 0, 1, 9, 9)
        self.node_figure.clf()
        
        self.node_analysis_textEdit.clear()
        self.node_movement_textEdit.clear()
        self.threat_movement_textEdit.clear()
        self.node = self.node_spinBox.value() - 1
        print("Analysing Node",self.node+1,"...")
        
        sys.stdout = EmittingStream(text_written=self.nodeAnalysisOutputWritten)
        self.total_nodes, G, label_dict, self.all_pages_visited, self.timeline_data= server_log_analysis.nodeAnalysisProtocol(self.node)
        self.total_connection_num.display(self.total_nodes)
        self.total_nodes_lcd.display(self.total_nodes)
        self.node_spinBox.setMaximum(self.total_nodes)

        travel_path = self.travelPath(self.all_pages_visited)
        self.node_movement_textEdit.append(travel_path)
        
        self.potential_threats_comboBox.setEnabled(True)
        self.evaluate_threat_btn.setEnabled(True)
        sys.stdout = EmittingStream(text_written=self.threatMovementOutputWritten)
        self.nodeThreatComparison()
        sys.stdout = EmittingStream(text_written=self.threatMovementOutputWritten)
        self.highestMatch()
        
        # Node Travel Graph
        nx.draw_circular(G, labels=label_dict, node_color='yellow', with_labels=True)
        self.node_canvas.draw_idle()

        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)
        self.time_data = False
        
        # Node timeline
        if self.timeline_data != []:
            self.time_data = True
            self.nodeTimeline()
            print("Node Analysis Complete\n")
        else:
            self.nodeTimeline()
            print("Node Analysis Complete")
            print("> No timeline data available\n")
            

    # Threat Analysis
    def highestMatch(self):        
        self.profile_list = ['cyber', 'groups', 'weapons', 'drugs', 'carding', 'fake id',
                    'information seeker', 'curious']
        all_percentages = {}
        mean_matches = {}
        highest_mean_match = []
        highest_percent_match = []

        for profile in self.profile_list:
            profile_pages_visited = server_log_analysis.getThreatMovement(profile)
            percentages = []
            for i in range(len(profile_pages_visited)):
                travel_path = self.travelPath(profile_pages_visited[i])
                res = len(set(self.all_pages_visited) & set(profile_pages_visited[i])) / float(len(set(self.all_pages_visited) | set(profile_pages_visited[i]))) * 100
                percentages.append(round(res,2))
            all_percentages[profile] = max(percentages)
            mean_matches[profile]=(round(statistics.mean(percentages),2))

        # Finds profile with highest mean match
        highest_mean_key = max(mean_matches, key=mean_matches.get)
        # Attaches node to its highest mean profile for grouping nodes by their profile
        self.grouped_nodes[self.node] = highest_mean_key
        # This puts all node means in a list for threat overview
        self.all_node_means.append(mean_matches[highest_mean_key])
        highest_mean_match.append(highest_mean_key.title())
        highest_mean_match.append(mean_matches[highest_mean_key])
        self.threat_comparison_textEdit.append("Highest Average Match:")
        self.threat_comparison_textEdit.append("<b><i>"+str(highest_mean_match[0])+" "+str(highest_mean_match[1])+"%</b></i>")
        self.threat_comparison_textEdit.append("")
        
        highest_percent_key = max(all_percentages, key=all_percentages.get)
        highest_percent_match.append(highest_percent_key.title())
        highest_percent_match.append(all_percentages[highest_percent_key])
        self.threat_comparison_textEdit.append("Highest Percentage Match:")
        self.threat_comparison_textEdit.append("<b><i>"+str(highest_percent_match[0])+" "+str(highest_percent_match[1])+"%</b></i>")
        
        self.threat_movement_textEdit.clear()
        for text in self.stream:
            self.threat_movement_textEdit.append(text)

        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)

            
    def evalThreatTrigger(self):
        sys.stdout = EmittingStream(text_written=self.threatMovementOutputWritten)
        self.nodeThreatComparison()
        sys.stdout = EmittingStream(text_written=self.threatMovementOutputWritten)
        self.highestMatch()


    # Compares selected node to profile data collected in
    # Experiment 4
    def nodeThreatComparison(self):
        self.threat_movement_textEdit.clear()
        self.threat_comparison_textEdit.clear()
        percentages = []
        profile_picked = self.potential_threats_comboBox.currentText()
        profile = profile_picked.lower()

        self.threat_movement_textEdit.clear()
        profile_pages_visited = server_log_analysis.getThreatMovement(profile)
        profile = profile.upper()
        self.stream = []
        movement_group = ['Interested','Engaged','Invested']
        
        for i in range(len(profile_pages_visited)):
            travel_path = self.travelPath(profile_pages_visited[i])
            self.threat_movement_textEdit.clear()
            self.stream.append(profile+" NODE "+str(i+1)+"\n"+"MOVEMENT GROUP - "+movement_group[i].upper()+"\n"+travel_path+"\n")
            res = len(set(self.all_pages_visited) & set(profile_pages_visited[i])) / float(len(set(self.all_pages_visited) | set(profile_pages_visited[i]))) * 100
            percentages.append(round(res,2))
            self.threat_comparison_textEdit.append(profile+" NODE "+str(i+1)+" % MATCH:\n"+str(round(res,2))+"%\n")
            
        self.threat_comparison_textEdit.append("Average "+profile_picked+" Percentage Match:")
        self.threat_comparison_textEdit.append("<b><i>"+str(round(statistics.mean(percentages),2))+"%</b></i>")
        self.threat_comparison_textEdit.append("")
        sys.stdout = EmittingStream(text_written=self.consoleOutputWritten)
        print("Node",self.node+1,"evaluated against",profile_picked)
        

    # Generates Node Travel Timeline Graph for selected node
    def nodeTimeline(self):
        if self.time_data == True:
            self.timeline_figure = plt.figure()
            self.timeline_canvas = FigureCanvas(self.timeline_figure)
            self.node_timeline_grid.addWidget(self.timeline_canvas, 0, 1, 9, 9)
            self.timeline_figure.clf()
            
            cats = {}
            colormapping = {}
            data = self.timeline_data
            pages_visited = list(dict.fromkeys(self.all_pages_visited))
            
            for i in range(len(pages_visited)):
                cats[pages_visited[i]] = i+1
                colormapping[pages_visited[i]] = "C"+str(i)

            verts = []
            colors = []
            for d in data:
                v =  [(mdates.date2num(d[0]), cats[d[2]]-.4),
                      (mdates.date2num(d[0]), cats[d[2]]+.4),
                      (mdates.date2num(d[1]), cats[d[2]]+.4),
                      (mdates.date2num(d[1]), cats[d[2]]-.4),
                      (mdates.date2num(d[0]), cats[d[2]]-.4)]
                verts.append(v)
                colors.append(colormapping[d[2]])

            bars = PolyCollection(verts, facecolors=colors, edgecolors="black")

            self.timeline_ax = self.timeline_figure.add_subplot(111)
            
            self.timeline_ax.add_collection(bars)
            self.timeline_ax.autoscale()
            loc = mdates.MinuteLocator(byminute=[0,15,30,45])
            self.timeline_ax.xaxis.set_major_locator(loc)
            self.timeline_ax.xaxis.set_major_formatter(mdates.AutoDateFormatter(loc))
            
            yticks = list(range(1,len(pages_visited)+1))
            self.timeline_ax.set_yticks(yticks)
            self.timeline_ax.set_yticklabels(pages_visited)

            self.timeline_canvas.draw_idle()
        else:
            self.timeline_figure = plt.figure()
            self.timeline_canvas = FigureCanvas(self.timeline_figure)
            self.node_timeline_grid.addWidget(self.timeline_canvas, 0, 1, 9, 9)


    # Node Pos. Markov Model
    def model(self):
        self.xls = pd.ExcelFile('experiment_data/Experiment Data Analysis.xlsx')
        
        user_types = pd.read_excel(self.xls, 'User Type',usecols="A:C",skiprows=range(0),nrows=7)
        user_types.rename(columns={'Unnamed: 3':''}, inplace = True)
        view = self.site_locations_table
        model = PandasModel(user_types)
        view.setModel(model)
        
        cat_nodes = pd.read_excel(self.xls, 'Analysis',usecols="BX:CF",skiprows=range(89),nrows=34)
        view = self.experiment_data_table
        model = PandasModel(cat_nodes)
        view.setModel(model)
        
        prob_pos_matrix = pd.read_excel(self.xls, 'Analysis',usecols="BU:CB",skiprows=range(68),nrows=7)
        prob_pos_matrix.rename(columns={'Unnamed: 0':''}, inplace = True)
        view = self.pos_prob_table
        model = PandasModel(prob_pos_matrix)
        view.setModel(model)

        # Prob. Site Graph
        self.pos_prob_figure = plt.figure()
        self.pos_prob_ax = self.pos_prob_figure.add_subplot(111)
        self.pos_prob_canvas = FigureCanvas(self.pos_prob_figure)
        self.pos_prob_gridLayout.addWidget(self.pos_prob_canvas, 0, 1, 9, 9)
        self.pos_prob_figure.clf()

        types = ["A","B","C","D","F","G"]
        x = ['0','P1','P2','P3','P4','P5','P6']
        for i in range(len(prob_pos_matrix.columns)-3):
            y = prob_pos_matrix[types[i]]
            plt.plot(x, y, label = types[i])
            
        self.pos_prob_ax = self.pos_prob_figure.gca()
        self.pos_prob_ax.set_ylim([0,0.1])

        plt.ylabel('Probability')
        plt.xlabel('Position')
        plt.title('Probability of user at Stage X after each transition')
        plt.legend()
        
        self.pos_prob_canvas.draw_idle()
        #

        transition_matrix = pd.read_excel(self.xls, 'Analysis',usecols="BN:BU",skiprows=range(56),nrows=7)
        transition_matrix.rename(columns={'Unnamed: 0':''}, inplace = True)
        view = self.transition_matrx_table
        model = PandasModel(transition_matrix)
        view.setModel(model)

        avg_time_at_stage = pd.read_excel(self.xls, 'Analysis',usecols="CK:CO",skiprows=range(88),nrows=1)
        avg_time_at_stage.rename(columns={'Unnamed: 0':'', 'User Type':'Node'}, inplace = True)

        # Avg. Time Bar Graph
        avg_times = []
        self.avg_time_figure = plt.figure()
        self.avg_time_canvas = FigureCanvas(self.avg_time_figure)
        self.avg_time_gridLayout.addWidget(self.avg_time_canvas, 0, 1, 9, 9)
        self.avg_time_figure.clf()
        self.avg_time_ax = self.avg_time_figure.add_subplot(111)
        types = ['A','B','C','D','F']
        for data in range(len(avg_time_at_stage.columns)):
            avg_times.append(avg_time_at_stage.iloc[0][types[data]])

        self.avg_time_ax.bar(types,avg_times, edgecolor = "black", color = 'orange', align='center')
        plt.ylabel('Average Time At Site Location (s)')
        plt.xlabel('Site Location')
        self.avg_time_canvas.draw_idle()
        #

    # Node Travel Path (string)
    def travelPath(self, pages_visited):
        travel_path = ""
        first_page = True
        for page in range(len(pages_visited)):
            if first_page:
                travel_path = travel_path + str(pages_visited[page])
                first_page = False
            else:
                travel_path = travel_path + " -> "+ str(pages_visited[page])
        return travel_path


    def saveLog(self):
        log = self.network_info_textEdit.toPlainText()


    def clearNetworkPage(self):
        self.network_info_textEdit.clear()
        print("Network analysis page cleared\n")


    def clearNodePages(self):
        self.node_analysis_textEdit.clear()
        self.node_movement_textEdit.clear()
        self.threat_movement_textEdit.clear()
        self.threat_comparison_textEdit.clear()
        print("Node analysis pages cleared\n")

    
    def startServer(self):
        os.system("gnome-terminal -x  sudo service nginx start")
        print("Server Started\n")

        
    def stopServer(self):
        os.system("gnome-terminal -x  sudo service nginx stop")
        print("Server Terminated\n")


    def serverStatus(self):
        os.system("gnome-terminal -x  sudo service nginx status")
        print("Server Status Printed\n")


    def fetchOnionLink(self):
        f = open("hat_txt_files/honeypot_onion.txt", "r")
        link = f.read().replace('\n', '')
        self.onion_line.setText(link)
        print(".onion Fetched\n")


    def openTor(self):
        os.chdir('//home//john//Desktop//tor-browser_en-US')
        os.system(' "//home/john//Desktop//tor-browser_en-US//start-tor-browser.desktop" ')
        print("Tor Session Created\n")


    def closeTor(self):
        os.system("gnome-terminal -x  killall firefox.real")
        print("Tor Session Closed\n")


    def logOut(self):
        msg = QtGui.QMessageBox()
        msg.setIcon(msg.Information)
        msg.setText("Are you sure you want to log out?")
        msg.setWindowTitle("Log Out")
        msg.setStandardButtons(msg.Yes | msg.No | msg.Cancel)
        answer = msg.exec_()
        if answer == msg.Yes:
            print("Logged Out\n")
            # This prevents circular importing
            from login import LoginMain
            self.loginWindow = LoginMain()
            self.loginWindow.show()
            self.close()
        else:
            pass


    def closeApplication(self):
        msg = QtGui.QMessageBox()
        msg.setIcon(msg.Information)
        msg.setText("Are you sure you want to quit?")
        msg.setWindowTitle("Close Application")
        msg.setStandardButtons(msg.Yes | msg.No | msg.Cancel)
        answer = msg.exec_()
        if answer == msg.Yes:
            print("Application Closed\n")
            self.close()
        else:
            pass

    # Selected textEdit boxes to write HAT output 
    def consoleOutputWritten(self, text):
        """Append text to the QTextEdit."""
        # Maybe QTextEdit.append() works as well:
        cursor = self.console_textEdit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.console_textEdit.setTextCursor(cursor)
        self.console_textEdit.ensureCursorVisible()
        

    # Selected textEdit boxes to write HAT output 
    def netAnalysisOutputWritten(self, text):
        """Append text to the QTextEdit."""
        # Maybe QTextEdit.append() works as well:
        cursor = self.network_info_textEdit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.network_info_textEdit.setTextCursor(cursor)
        self.network_info_textEdit.ensureCursorVisible()
        

    # Selected textEdit boxes to write HAT output    
    def nodeAnalysisOutputWritten(self, text):
        """Append text to the QTextEdit."""
        # Maybe QTextEdit.append() works as well:
        cursor = self.node_analysis_textEdit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.node_analysis_textEdit.setTextCursor(cursor)
        self.node_analysis_textEdit.ensureCursorVisible()


    # Selected textEdit boxes to write HAT output 
    def threatMovementOutputWritten(self, text):
        """Append text to the QTextEdit."""
        # Maybe QTextEdit.append() works as well:
        cursor = self.threat_movement_textEdit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.threat_movement_textEdit.setTextCursor(cursor)
        self.threat_movement_textEdit.ensureCursorVisible()

        

# Node Pos. Markov Model Tab Pandas Class for generating tables
class PandasModel(QtCore.QAbstractTableModel):
    def __init__(self, data, parent=None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self._data = data

    def rowCount(self, parent=None):
        return len(self._data.values)

    def columnCount(self, parent=None):
        return self._data.columns.size

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if index.isValid():
            if role == QtCore.Qt.DisplayRole:
                return str(self._data.values[index.row()][index.column()])
        return None

    def headerData(self, col, orientation, role):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self._data.columns[col]
        return None


    
#Shell output to PyQt Window
class EmittingStream(QtCore.QObject):
    text_written = QtCore.pyqtSignal(str)

    
    def write(self, text):
        self.text_written.emit(str(text))


        
# Main Trigger
if __name__ == "__main__":
    import sys
    application = QtGui.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(application.exec_())
