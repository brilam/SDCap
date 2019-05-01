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

public class SDCapDeviceSetting {

  private JFrame frame;
  private JTextField portTextField;

  /**
   * Launch the application.
   */
  public static void main(String[] args) {
    EventQueue.invokeLater(new Runnable() {
      public void run() {
        try {
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
   * 
   * @throws UnsupportedLookAndFeelException
   * @throws IllegalAccessException
   * @throws InstantiationException
   * @throws ClassNotFoundException
   */
  public SDCapDeviceSetting() throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    initialize();
  }

  /**
   * Initialize the contents of the frame.
   * 
   * @throws UnsupportedLookAndFeelException if the look and feel doesn't exist
   * @throws IllegalAccessException
   * @throws InstantiationException
   * @throws ClassNotFoundException
   */
  private void initialize() throws ClassNotFoundException, InstantiationException,
      IllegalAccessException, UnsupportedLookAndFeelException {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

    frame = new JFrame("SDCap Settings");
    frame.setBounds(100, 100, 430, 181);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.getContentPane().setLayout(null);

    JLabel networkDeviceLabel = new JLabel("Network Device");
    networkDeviceLabel.setToolTipText(
        "Select the network device you wish to sniff from. "
        + "Typically, this would be the device for Ethernet or Wifi.");
    networkDeviceLabel.setBounds(11, 11, 80, 14);
    frame.getContentPane().add(networkDeviceLabel);

    JComboBox<String> packetsDropdown = new JComboBox<>();
    packetsDropdown.setBounds(11, 34, 394, 20);
    frame.getContentPane().add(packetsDropdown);

    JButton okButton = new JButton("OK");
    okButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent arg0) {}
    });
    okButton.setBounds(325, 96, 80, 23);
    frame.getContentPane().add(okButton);

    JLabel portLabel = new JLabel("Port");
    portLabel.setBounds(11, 62, 46, 14);
    frame.getContentPane().add(portLabel);

    portTextField = new JTextField();
    portTextField.setBounds(11, 77, 86, 20);
    frame.getContentPane().add(portTextField);
    portTextField.setColumns(10);
  }
}
