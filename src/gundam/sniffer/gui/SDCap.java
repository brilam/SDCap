/**
 *  This file is a part of SDCap: Gundam Packet Sniffer
    Copyright (C) 2019  Brian Lam (brian_lam@live.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package gundam.sniffer.gui;

import gundam.sniffer.GundamSniffer;
import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.packets.GundamPacket;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

public class SDCap {

  private JFrame frame;
  private JTable table;
  private JTextArea packetDataTextArea;
  private JComboBox opcodesDropDown;
  private GundamPacketTableModel model;
  
  /**
   * Create the application.
   * @param sc the sniffing configuration
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException if the look and feel class isn't accessible
   * @throws InstantiationException if a new instance of the look and feel class couldn't be created
   * @throws ClassNotFoundException if the look and feel class couldn't be found
   */
  public SDCap(SniffingConfiguration sc) throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    try {
      placeUIComponents(sc);
    } catch (Exception e) {
      // TODO: Log this out later!
      e.printStackTrace();
    }
    
    // Spawn a thread used for capturing packets
    Thread snifferThread = new Thread() {
      public void run() {
        GundamSniffer gs = new GundamSniffer(sc);
        try {
          gs.startSniffing(table, model);
        } catch (Exception e) {
          // TODO: Log this out later!
          e.printStackTrace();
        }
      }
    };
    snifferThread.start();
  }

  private void createFrame() {
    frame = new JFrame("SDCap - Gundam Sniffer");
    frame.setResizable(false);
    frame.setVisible(true);
    frame.setBounds(100, 100, 599, 475);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
  }

  private JMenuBar createMenu() {
    JMenuBar menuBar = new JMenuBar();
    JMenu menu = new JMenu("File");
    JMenuItem openMenuItem = new JMenuItem("Open");
    JMenuItem saveMenuitem = new JMenuItem("Save");
    menu.add(openMenuItem);
    menu.add(saveMenuitem);
    menuBar.add(menu);
    return menuBar;
  }

  /**
   * Places the UI components on the frame.
   * @param sc the sniffing configuration
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException if the look and feel class isn't accessible
   * @throws InstantiationException if a new instance of the look and feel class couldn't be created
   * @throws ClassNotFoundException if the look and feel class couldn't be found
   */
  private void placeUIComponents(SniffingConfiguration sc) throws ClassNotFoundException,
      InstantiationException, IllegalAccessException, UnsupportedLookAndFeelException {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    createFrame();
    JMenuBar menuBar = createMenu();
    frame.setJMenuBar(menuBar);
    frame.getContentPane().setLayout(null);

    JScrollPane scrollPane = new JScrollPane();
    scrollPane.setBounds(0, 22, 573, 221);
    frame.getContentPane().add(scrollPane);
    
    packetDataTextArea = new JTextArea();
    packetDataTextArea.setEditable(false);
    packetDataTextArea.setBounds(10, 276, 563, 129);
    packetDataTextArea.setLineWrap(true);
    frame.getContentPane().add(packetDataTextArea);
    
    model = new GundamPacketTableModel();
    table = new JTable(model);
    table.setShowGrid(false);
    scrollPane.setViewportView(table);
    table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
      @Override
      public void valueChanged(ListSelectionEvent arg0) {
        int selectedRowIndex = table.getSelectedRow();
        // If there is a row selected, show the packet data
        if (selectedRowIndex >= -1) {
          GundamPacket selectedPacket = model.getPacketLog().get(selectedRowIndex);
          String[] packetInfo = selectedPacket.getPacketInformation();
          // Remove the "Packet Data: " before the actual packet data and set the packetDataTextArea
          String packetData = packetInfo[GundamPacket.PACKET_DATA_START_INDEX];
          packetData = selectedPacket.removeColumnNameFromCell(packetData);
          packetDataTextArea.setText(packetData);
        }
      }
    });

    opcodesDropDown = new JComboBox();
    opcodesDropDown.setBounds(0, 0, 573, 20);
    frame.getContentPane().add(opcodesDropDown);

    JLabel lblPacketData = new JLabel("Packet Data");
    lblPacketData.setBounds(10, 251, 58, 20);
    frame.getContentPane().add(lblPacketData);
    frame.addWindowListener(new WindowAdapter() {
      @Override
      public void windowClosing(WindowEvent arg0) {
        // Save packet definitions on closing
        try {
          OpcodeDefinitions.exportPacketDefinitions();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    });
  }
}
