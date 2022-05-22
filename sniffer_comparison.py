from PyQt5 import QtCore, QtGui, QtWidgets
from QT_designs import main_ui

from pathlib import Path
from fpdf import FPDF
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import sys
import os
from datetime import datetime
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

        self.sniffing_times = [results[0][1], results[1][1], results[2][1]]
        self.log_sizes = [results[0][2], results[1][2], results[2][2]]
        self.protocol_types = [results[0][3], results[1][3], results[2][3]]

        print(self.protocol_types)

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

        module_list = ["Socket", "Scapy", "Pyshark"]

        #sniffing time comparison
        labels = module_list
        y_pos = np.arange(len(labels))  # the label locations
        plt.bar(y_pos, self.sniffing_times, align='center', alpha=0.5, width=0.25)
        plt.xticks(y_pos, labels)
        plt.ylabel('Sniffing Time (ms)')
        plt.title('Sniffing Time Comparison')
        plt.savefig("./images/sniffing_time_comparison.png")
        plt.clf()

        #log size
        labels = module_list
        y_pos = np.arange(len(labels))  # the label locations
        plt.bar(y_pos, self.log_sizes, align='center', alpha=0.5, width=0.25)
        plt.xticks(y_pos, labels)
        plt.ylabel('Size (Bytes)')
        plt.title('Log Size Comparison')
        plt.savefig("./images/log_size_comparison.png")
        plt.clf()

        #protocol types
        for module in range(len(module_list)):
            labels = list(self.protocol_types[module].keys())
            y_pos = np.arange(len(labels))
            plt.bar(y_pos, [self.protocol_types[module][i] for i in labels], align='center', alpha=0.5, width=0.25)
            plt.xticks(y_pos, labels)
            plt.ylabel('Number of Packets')
            plt.title('Sniffed Protocol Counts - ' + module_list[module])
            plt.savefig("./images/protocol_types_" + module_list[module] + ".png")
            plt.clf()
            print(module_list[module])
            print(labels)
            print(list(self.protocol_types[module].values()))

        pdf = FPDF()
        pdf.add_page()

        df = pd.DataFrame()
        df['Module Name'] = module_list
        packet_count = self.comparator_ui.packet_count_box.value()
        df['Packet Count'] = [packet_count]*3
        df['Thread ID'] = [0, 1, 2]
        pdf.set_xy(0, 0)
        pdf.set_font('arial', 'B', 12)
        pdf.cell(60)
        pdf.cell(75, 10, "Comparison Report -" + datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 0, 2, 'C')
        pdf.cell(50, 10, " ", 0, 2, 'C')
        interface_name = self.comparator_ui.interface_name_label.text()
        pdf.cell(75, 10, "Interface Name: " + interface_name , 0, 2, 'C')
        pdf.cell(90, 10, " ", 0, 2, 'C')
        pdf.cell(-40)
        pdf.cell(50, 10, 'Module Name', 1, 0, 'C')
        pdf.cell(40, 10, 'Thread ID', 1, 0, 'C')
        pdf.cell(40, 10, 'Packet Count', 1, 2, 'C')
        pdf.cell(-90)
        pdf.set_font('arial', '', 12)
        for i in range(0, len(df)):
            pdf.cell(50, 10, '%s' % (df['Module Name'].iloc[i]), 1, 0, 'C')
            pdf.cell(40, 10, '%s' % (str(df["Thread ID"].iloc[i])), 1, 0, 'C')
            pdf.cell(40, 10, '%s' % (str(df["Packet Count"].iloc[i])), 1, 2, 'C')
            pdf.cell(-90)
        pdf.cell(90, 10, " ", 0, 2, 'C')
        pdf.cell(-30)

        pdf.image('./images/sniffing_time_comparison.png', x = 30, y = None, w = 120, h = 90, type = '', link = '')
        pdf.image('./images/log_size_comparison.png', x = 30, y = None, w = 120, h = 90, type = '', link = '')
        pdf.cell(40)
        pdf.image('./images/protocol_types_Socket.png', x = 30, y = None, w = 100, h = 75, type = '', link = '')
        pdf.image('./images/protocol_types_Scapy.png', x = 30, y = None, w = 100, h = 75, type = '', link = '')
        pdf.image('./images/protocol_types_Pyshark.png', x = 30, y = None, w = 100, h = 75, type = '', link = '')
        pdf.output("Report.pdf", "F")

c = Comparator()