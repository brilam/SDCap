package gundam.sniffer.gui;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import org.pcap4j.core.PcapNetworkInterface;
import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.packets.OpcodeDefinitions;
import pcap4j.Pcap4jWrapper;

public class SDCapDeviceSetting {
  private JFrame frame;
  private JComboBox<String> devices;
  private JTextField portTextField;
  private static final String DEFAULT_PORT = "5001"; 
  private static final int UNSET_PORT_VAL = -1;
  private static final int MIN_PORT_VAL = 0;
  private static final int MAX_PORT_VAL = 65535;
  private static final String PORT_ERROR_MESSAGE =
      String.format("Port must be a number between %d and %d!", MIN_PORT_VAL, MAX_PORT_VAL);
  private SniffingConfiguration sc;


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
    frame.setResizable(false);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.getContentPane().setLayout(null);

    // Adds network device labels and tool tips
    JLabel networkDeviceLabel = new JLabel("Network Device");
    networkDeviceLabel.setToolTipText("Select the network device you wish to sniff from. "
        + "Typically, this would be the device for Ethernet or Wifi.");
    networkDeviceLabel.setBounds(11, 11, 80, 14);
    frame.getContentPane().add(networkDeviceLabel);

    // Add the network devices to the JComboBox
    devices = new JComboBox<>(Pcap4jWrapper.getDeviceNames());
    devices.setBounds(11, 34, 394, 20);
    frame.getContentPane().add(devices);

    // Adds the port label
    JLabel portLabel = new JLabel("Port");
    portLabel.setBounds(11, 62, 46, 14);
    frame.getContentPane().add(portLabel);

    // Adds the port text field
    portTextField = new JTextField();
    portTextField.setBounds(11, 77, 86, 20);
    portTextField.setText(DEFAULT_PORT);
    frame.getContentPane().add(portTextField);
    portTextField.setColumns(10);

    // Adds OK button to confirm the sniffing configuration
    JButton okButton = new JButton("OK");
    okButton.addActionListener(new DeviceSettingListener());
    okButton.setBounds(325, 96, 80, 23);
    frame.getContentPane().add(okButton);
  }
  
  private class DeviceSettingListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent event) {
      int deviceIndex = devices.getSelectedIndex();
      int portNumber = UNSET_PORT_VAL;
      
      try {
        portNumber = Integer.parseInt(portTextField.getText());
      } catch (NumberFormatException e) {
        JOptionPane.showMessageDialog(frame, PORT_ERROR_MESSAGE, "Invalid port value!", 
            JOptionPane.ERROR_MESSAGE);
        return;
      }
      
      // If the port isn't within the valid port range
      if (!(portNumber >= MIN_PORT_VAL && portNumber <= MAX_PORT_VAL)) {
        JOptionPane.showMessageDialog(frame, PORT_ERROR_MESSAGE, "Invalid port value!", 
            JOptionPane.ERROR_MESSAGE);
        return;
      }
      
      PcapNetworkInterface device = Pcap4jWrapper.getAllDevices().get(deviceIndex);
      sc = new SniffingConfiguration.SniffingConfigurationBuilder().setSniffingDevice(device)
          .setPort(portNumber).build();
      frame.dispose();
      try {
        OpcodeDefinitions.loadPacketDefinitions();
        new SDCap(sc);
      } catch (Exception e) {
        // Should never reach here since the look and feel will always be correct
        e.printStackTrace();
      }
    }
  }
}
