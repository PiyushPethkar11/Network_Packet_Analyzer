import org.jfree.chart.*;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

     class NetworkPacketAnalyzerGUI {
    private static String filename = null;
    private static StringBuilder errbuf = new StringBuilder();
    private static Pcap pcap = null;

    public static void main(String[] args) {
        JFrame frame = new JFrame("Network Packet Analyzer");

        // Create UI components
        JButton chooseFileBtn = new JButton("Choose File");
        JLabel fileNameLbl = new JLabel("No file selected");
        JButton analyzeBtn = new JButton("Analyze");

        // Set layout
        frame.setLayout(new GridLayout(3, 1));

        // Add components to the frame
        JPanel panel1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel1.add(chooseFileBtn);
        panel1.add(fileNameLbl);
        frame.add(panel1);

        JPanel panel2 = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel2.add(analyzeBtn);
        frame.add(panel2);

        // Add action listeners
        chooseFileBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(frame);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    filename = selectedFile.getAbsolutePath();
                    fileNameLbl.setText(filename);
                }
            }
        });

        analyzeBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (filename == null) {
                    JOptionPane.showMessageDialog(frame, "Please choose a file.");
                    return;
                }

                pcap = Pcap.openOffline(filename, errbuf);

                // If there is an error in opening the file, Program will terminate.
                if (pcap == null) {
                    System.err.println("Error: " + errbuf);
                    return;
                }

                // Packet Statistics
                final int[] packetCount = {0};
                final int[] totalSize = {0};
                Map<String, Integer> protocolCounts = new HashMap<>();

                // Time Series Data
                TimeSeries timeSeries = new TimeSeries("Packet Count Over Time");
                TimeSeriesCollection timeSeriesCollection = new TimeSeriesCollection();
                timeSeriesCollection.addSeries(timeSeries);

                JFreeChart chart = ChartFactory.createTimeSeriesChart(
                        "Packet Count Over Time",
                        "Time",
                        "Packet Count",
                        timeSeriesCollection
                );

                ChartFrame chartFrame = new ChartFrame("Packet Count Over Time", chart);
                chartFrame.setVisible(true);
                chartFrame.setSize(800, 600);

                XYPlot plot = chart.getXYPlot();
                plot.setRangeGridlinePaint(Color.BLACK);
                plot.setBackgroundPaint(Color.WHITE);

                PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
                    private long lastUpdate = 0;

                    public void nextPacket(PcapPacket packet, String user) {
                        //Printing Packets
                        packetCount[0]++;
                        totalSize[0] += packet.size();
                        String protocol = packet.getClass().getSimpleName();
                        protocolCounts.put(protocol, protocolCounts.getOrDefault(protocol, 0) + 1);

                        long currentTime = packet.getCaptureHeader().timestampInMillis();
                        if (currentTime - lastUpdate > 1000) {
                            timeSeries.add(new Millisecond(new Date(currentTime)), packetCount[0]);
                            lastUpdate = currentTime;
                        }

                        System.out.println(packet);
                    }
                };

                // Loop through all packets in the file
                pcap.loop(Pcap.LOOP_INFINITE, handler, "jNetPcap rocks!");

                // Close the pcap handle
                pcap.close();

                // Display packet statistics
                System.out.println("Packet Count: " + packetCount[0]);
                System.out.println("Total Size: " + totalSize[0] + " bytes");

                System.out.println("Protocol Counts:");
                for (Map.Entry<String, Integer> entry : protocolCounts.entrySet()) {
                    System.out.println(entry.getKey() + ": " + entry.getValue());
                }

                // Save time series chart as PNG
                try {
                    ChartUtilities.saveChartAsPNG(new File("packet-count-over-time.png"), chart, 800, 600);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });

        // Set frame properties
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 150);
        frame.setVisible(true);
    }
}
