package gundam.sniffer.gui;

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
import gundam.sniffer.config.SniffingConfiguration;

public class SDCap {

  private JFrame frame;
  private JTable table;
  
  /**
   * Create the application.
   * @param sc the sniffing configuration
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException if the look and feel class isn't accessible
   * @throws InstantiationException if a new instance of the look and feel class couldn't be created
   * @throws ClassNotFoundException if the look and feel class couldn't be found
   */
  public SDCap(SniffingConfiguration sc) throws ClassNotFoundException, InstantiationException, IllegalAccessException,
      UnsupportedLookAndFeelException {
    placeUIComponents(sc);
  }

  private void createFrame() {
    frame = new JFrame("SDCap - Gundam Sniffer");
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
  private void placeUIComponents(SniffingConfiguration sc) throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    createFrame();
    JMenuBar menuBar = createMenu();
    frame.setJMenuBar(menuBar);
    frame.getContentPane().setLayout(null);

    JScrollPane scrollPane = new JScrollPane();
    scrollPane.setBounds(0, 22, 573, 221);
    frame.getContentPane().add(scrollPane);


    Object[][] data = {{"2019-04-27", "Inbound", "75", "F0 03", "0x2329", "REQ_LOGIN"}};

    String[] columnNames =
        {"Timestamp", "Direction", "Packet Length", "Unknown Data", "Opcode", "Opcode Name"};

    table = new JTable(data, columnNames);
    table.setShowGrid(false);
    scrollPane.setViewportView(table);

    JComboBox comboBox = new JComboBox();
    comboBox.setBounds(0, 0, 573, 20);
    frame.getContentPane().add(comboBox);

    JLabel lblPacketData = new JLabel("Packet Data");
    lblPacketData.setBounds(10, 251, 58, 20);
    frame.getContentPane().add(lblPacketData);

    JTextArea textArea = new JTextArea();
    textArea.setBounds(10, 276, 563, 129);
    textArea.setLineWrap(true);
    frame.getContentPane().add(textArea);
    textArea.setText("00 00 00 00 31 39 39 39 39 39 39 30 32 36 33 00 00 "
        + "32 30 32 63 62 39 36 32 61 63 35 39 30 37 35 62 39 36 34 62 30 "
        + "37 31 35 32 64 32 33 34 62 37 30 00 00 00 00 00 FE FF FF FF 02 "
        + "00 00 00 68 FB 19 00 40 00 00 00 58 00 00");
  }
}
