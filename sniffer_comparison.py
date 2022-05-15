from PyQt5 import QtCore, QtGui, QtWidgets
from QT_designs import main_ui

import sys
import os
from threading import Thread

sys.path.append(os.path.join(os.getcwd(), "socket_sniff"))

from socket_sniff import socket_sniffer


class Comparator():
    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)

        self.Form_comparator_ui = QtWidgets.QWidget()
        self.comparator_ui = main_ui.Ui_Form()
        self.comparator_ui.setupUi(self.Form_comparator_ui)
        self.Form_comparator_ui.show()

        self.comparator_ui.sniff_but.clicked.connect(self.sniff)
        self.comparator_ui.socket_table.cellClicked.connect(self.socket_row_selected)

        self.app.exec_()

    def socket_row_selected(self):
        self.comparator_ui.socket_detail_box.setText(self.socket_packet_list[self.comparator_ui.socket_table.currentRow()]["Details"])

    def sniff(self):
        self.socket_packet_list = socket_sniffer.start_sniff(self.comparator_ui.packet_count_box.value(), self.comparator_ui.create_pcap_box.isChecked())

        for packet in self.socket_packet_list:
            row_position = self.comparator_ui.socket_table.rowCount()

            self.comparator_ui.socket_table.insertRow(row_position)
            self.comparator_ui.socket_table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(packet["Time(ms)"]))
            self.comparator_ui.socket_table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(packet["Source IP"]))
            self.comparator_ui.socket_table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(packet["Destination IP"]))
            self.comparator_ui.socket_table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(packet["Protocol"]))
            self.comparator_ui.socket_table.setItem(row_position, 4, QtWidgets.QTableWidgetItem(packet["Packet Length"]))


c = Comparator()