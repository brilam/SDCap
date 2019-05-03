package gundam.sniffer.gui;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import pcap4j.Pcap4jWrapper;

public class SDCapDeviceSetting {
  private JFrame frame;

  /**
   * Launch the application.
   */
  public static void main(String[] args) {
    EventQueue.invokeLater(new Runnable() {
      public void run() {
        try {
          Pcap4jWrapper.loadAllDevices();
          SDCapDeviceSetting window = new SDCapDeviceSetting();
          window.frame.setVisible(true);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    });
  }

  /**
   * Create the application.
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException if the look and feel class isn't accessible
   * @throws InstantiationException if a new instance of the look and feel class couldn't be created
   * @throws ClassNotFoundException if the look and feel class couldn't be found
   */
  public SDCapDeviceSetting() throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    placeUIComponents();
  }

  /**
   * Places the UI components on the frame.
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException if the look and feel class isn't accessible
   * @throws InstantiationException if a new instance of the look and feel class couldn't be created
   * @throws ClassNotFoundException if the look and feel class couldn't be found
   */
  private void placeUIComponents() throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

    // Sets the frame
    frame = new JFrame("SDCap Settings");
    frame.setBounds(100, 100, 430, 181);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.getContentPane().setLayout(null);

    // Adds network device labels and tool tips
    JLabel networkDeviceLabel = new JLabel("Network Device");
    networkDeviceLabel.setToolTipText("Select the network device you wish to sniff from. "
        + "Typically, this would be the device for Ethernet or Wifi.");
    networkDeviceLabel.setBounds(11, 11, 80, 14);
    frame.getContentPane().add(networkDeviceLabel);

    // Add the network devices to the JComboBox
    JComboBox<String> devices = new JComboBox<>(Pcap4jWrapper.getDeviceNames());
    devices.setBounds(11, 34, 394, 20);
    frame.getContentPane().add(devices);

    // Adds the port label
    JLabel portLabel = new JLabel("Port");
    portLabel.setBounds(11, 62, 46, 14);
    frame.getContentPane().add(portLabel);

    // Adds the port text field
    JTextField portTextField = new JTextField();
    portTextField.setBounds(11, 77, 86, 20);
    frame.getContentPane().add(portTextField);
    portTextField.setColumns(10);

    // Adds OK button to confirm the sniffing configuration
    JButton okButton = new JButton("OK");
    okButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent arg0) {}
    });
    okButton.setBounds(325, 96, 80, 23);
    frame.getContentPane().add(okButton);
  }
}
