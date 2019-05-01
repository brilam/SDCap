package gundam.sniffer.gui;

import java.awt.EventQueue;
import java.awt.TextArea;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

public class SDCap {

  private JFrame frame;
  private JTable table;

  /**
   * Launch the application.
   */
  public static void main(String[] args) {
    EventQueue.invokeLater(new Runnable() {
      public void run() {
        try {
          SDCap window = new SDCap();
          window.frame.setVisible(true);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    });
  }

  /**
   * Create the application.
   * 
   * @throws UnsupportedLookAndFeelException
   * @throws IllegalAccessException
   * @throws InstantiationException
   * @throws ClassNotFoundException
   */
  public SDCap() throws ClassNotFoundException, InstantiationException, IllegalAccessException,
      UnsupportedLookAndFeelException {
    initialize();
  }

  private void createFrame() {
    frame = new JFrame("SDCap - Gundam Sniffer");
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
   * Initialize the contents of the frame.
   * 
   * @throws UnsupportedLookAndFeelException
   * @throws IllegalAccessException
   * @throws InstantiationException
   * @throws ClassNotFoundException
   */
  private void initialize() throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    createFrame();
    JMenuBar menuBar = createMenu();
    frame.setJMenuBar(menuBar);
    frame.getContentPane().setLayout(null);

    JScrollPane scrollPane = new JScrollPane();
    scrollPane.setBounds(0, 22, 573, 221);
    frame.getContentPane().add(scrollPane);


    Object[][] data = {{"2019-04-27", "Inbound", "12", "0x0A", "KEEP_ALIVE"},
        {"2019-04-27", "Inbound", "12", "0x0A", "KEEP_ALIVE"}};

    String[] columnNames = {"Timestamp", "Direction", "Packet Length", "Opcode", "Opcode Name"};

    table = new JTable(data, columnNames);
    table.setShowGrid(false);
    scrollPane.setViewportView(table);

    JComboBox comboBox = new JComboBox();
    comboBox.setBounds(0, 0, 573, 20);
    frame.getContentPane().add(comboBox);

    JLabel lblPacketData = new JLabel("Packet Data");
    lblPacketData.setBounds(10, 251, 58, 20);
    frame.getContentPane().add(lblPacketData);

    TextArea textArea = new TextArea();
    textArea.setBounds(10, 276, 563, 129);
    frame.getContentPane().add(textArea);
  }
}
