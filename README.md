# Network_Packet_Analyzer
This project is a simple Network Packet Analyzer built using Java and several libraries, including JFreeChart for data visualization and jNetPcap for capturing and handling network packets. The purpose of this project is to allow users to analyze network packet data stored in a packet capture (PCAP) file, visualize the packet count over time using a time series chart, and display some basic packet statistics.
Here's a breakdown of the main components and functionalities of the project:

GUI Components:

The GUI includes a JFrame (window) titled "Network Packet Analyzer" with a layout of 3 rows and 1 column.
The first row contains a JButton "Choose File" and a JLabel "No file selected" to indicate the selected PCAP file.
The second row contains a single JButton "Analyze" to start the packet analysis process.

File Selection:

When the "Choose File" button is clicked, a file chooser dialog opens, allowing the user to select a PCAP file.
The selected file path is displayed in the "No file selected" label.

Packet Analysis and Visualization:

When the "Analyze" button is clicked, the selected PCAP file is opened for packet analysis using the jNetPcap library.
The program then iterates through each packet in the PCAP file and processes them.
It keeps track of the total number of packets, the total size of packets in bytes, and the count of packets for each protocol encountered in the file.
It also creates a time series chart using JFreeChart to visualize the packet count over time.
The chart is displayed in a separate window with the title "Packet Count Over Time."

Packet Statistics:

After analyzing all the packets, the program displays the total number of packets and the total size of packets in bytes.
It also displays a breakdown of the packet count for each protocol encountered in the file.

Chart Saving:

The time series chart is saved as a PNG image named "packet-count-over-time.png" in the project directory.
