from PyQt5 import QtCore, QtGui, QtWidgets
from QT_designs import main_ui

from pathlib import Path
from fpdf import FPDF
import matplotlib.pyplot as plt
import numpy as np

import sys
import os
from threading import Thread

sys.path.append(os.path.join(os.getcwd(), "socket_sniff"))

from socket_sniff import socket_sniffer
import scapy_sniffer
import pyshark_sniffer

class Comparator():
    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)

        self.Form_comparator_ui = QtWidgets.QWidget()
        self.comparator_ui = main_ui.Ui_Form()
        self.comparator_ui.setupUi(self.Form_comparator_ui)
        self.Form_comparator_ui.show()

        self.comparator_ui.sniff_but.clicked.connect(self.sniff)
        self.comparator_ui.socket_table.cellClicked.connect(self.socket_row_selected)
        self.comparator_ui.scapy_table.cellClicked.connect(self.scapy_row_selected)
        self.comparator_ui.pyshark_table.cellClicked.connect(self.pyshark_row_selected)

        self.app.exec_()

    def socket_row_selected(self):
        self.comparator_ui.socket_detail_box.setText(self.socket_packet_list[self.comparator_ui.socket_table.currentRow()]["Details"])

    def scapy_row_selected(self):
        self.comparator_ui.scapy_detail_box.setText(self.scapy_packet_list[self.comparator_ui.scapy_table.currentRow()]["Details"])
    
    def pyshark_row_selected(self):
        self.comparator_ui.pyshark_detail_box.setText(self.pyshark_packet_list[self.comparator_ui.pyshark_table.currentRow()]["Details"])

    def sniff(self):
        self.comparator_ui.create_pcap_box.setEnabled(True)
        self.comparator_ui.sniff_but.setEnabled(True)
        self.comparator_ui.packet_count_box.setEnabled(True)
        self.comparator_ui.sniff_table.setEnabled(True)

        self.comparator_ui.socket_table.setRowCount(0)
        self.comparator_ui.scapy_table.setRowCount(0)
        self.comparator_ui.pyshark_table.setRowCount(0)

        threads_list = []
        results = [None] * 3

        threads_list.append(Thread(target=socket_sniffer.start_sniff, args=(self.comparator_ui.packet_count_box.value(), self.comparator_ui.create_pcap_box.isChecked(), results, 0)))
        threads_list.append(Thread(target=scapy_sniffer.start_sniff, args=(self.comparator_ui.packet_count_box.value(), self.comparator_ui.create_pcap_box.isChecked(), self.comparator_ui.interface_name_label.text(), results, 1)))
        threads_list.append(Thread(target=pyshark_sniffer.start_sniff, args=(self.comparator_ui.packet_count_box.value(), self.comparator_ui.create_pcap_box.isChecked(), self.comparator_ui.interface_name_label.text(), results, 2)))

        for i in threads_list:
            i.start()

        for i in threads_list:
            i.join()

        self.socket_packet_list = results[0][0]
        self.scapy_packet_list = results[1][0]
        self.pyshark_packet_list = results[2][0]

        self.socket_total_time = results[0][1]
        self.scapy_total_time = results[1][1]
        self.pyshark_total_time = results[2][1]

        for packet in self.socket_packet_list:
            row_position = self.comparator_ui.socket_table.rowCount()

            self.comparator_ui.socket_table.insertRow(row_position)
            self.comparator_ui.socket_table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(packet["Time(ms)"]))
            self.comparator_ui.socket_table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(packet["Source IP"]))
            self.comparator_ui.socket_table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(packet["Destination IP"]))
            self.comparator_ui.socket_table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(packet["Protocol"]))
            self.comparator_ui.socket_table.setItem(row_position, 4, QtWidgets.QTableWidgetItem(packet["Packet Length"]))

        for packet in self.scapy_packet_list:
            row_position = self.comparator_ui.scapy_table.rowCount()

            self.comparator_ui.scapy_table.insertRow(row_position)
            self.comparator_ui.scapy_table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(packet["Time(ms)"]))
            self.comparator_ui.scapy_table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(packet["Source IP"]))
            self.comparator_ui.scapy_table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(packet["Destination IP"]))
            self.comparator_ui.scapy_table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(packet["Protocol"]))
            self.comparator_ui.scapy_table.setItem(row_position, 4, QtWidgets.QTableWidgetItem(packet["Packet Length"]))

        for packet in self.pyshark_packet_list:
            row_position = self.comparator_ui.pyshark_table.rowCount()

            self.comparator_ui.pyshark_table.insertRow(row_position)
            self.comparator_ui.pyshark_table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(packet["Time(ms)"]))
            self.comparator_ui.pyshark_table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(packet["Source IP"]))
            self.comparator_ui.pyshark_table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(packet["Destination IP"]))
            self.comparator_ui.pyshark_table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(packet["Protocol"]))
            self.comparator_ui.pyshark_table.setItem(row_position, 4, QtWidgets.QTableWidgetItem(packet["Packet Length"]))

        self.create_report()

    def create_report(self):
        Path("./images").mkdir(parents=True, exist_ok=True)

        #sniffinf time comparison
        labels = ["Socket", "Scapy", "Pyshark"]
        sniffing_speeds = [self.socket_total_time, self.scapy_total_time, self.pyshark_total_time]
        y_pos = np.arange(len(labels))  # the label locations
        plt.bar(y_pos, sniffing_speeds, align='center', alpha=0.5, width=0.25)
        plt.xticks(y_pos, labels)
        plt.legend()
        plt.ylabel('Sniffing Time (ms)')
        plt.title('Sniffing Time Comparison')
        plt.savefig("./images/sniffing_time_comparison.png")

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", size = 20)
        pdf.cell(75, 10, "Comparison results of the Socket, Pyshark and Scapy")
        pdf.cell(-75, 40)
        pdf.image('./images/sniffing_time_comparison.png', x = None, y = None, w = 0, h = 0, type = '', link = '')
        pdf.output("Report.pdf", "F")

c = Comparator()