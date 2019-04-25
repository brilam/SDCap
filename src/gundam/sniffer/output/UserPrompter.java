package gundam.sniffer.output;

import java.util.Scanner;
import pcap4j.Pcap4jWrapper;

public class UserPrompter {
  // A Scanner object used to read keyboard input
  private static Scanner input = new Scanner(System.in);
  private static final int MAX_PORT_VALUE = 65535;
  
  /**
   * Returns the device number of the selected device after prompting the 
   * user for a device number.
   * @return the device number of the device
   */
  public static int askDeviceNumber() {
    System.out.println("Enter the device number: ");
    int deviceNumber = input.nextInt();
    int numOfDevices = Pcap4jWrapper.getNumOfDevices();
    
    while (deviceNumber < 1 || deviceNumber > numOfDevices) {
      System.out.println("Invalid device number! Try again");
      askDeviceNumber();
      break;
    }
    return deviceNumber;
  }
  
  /**
   * Returns the port number of the selected device after prompting the
   * user for a port number.
   * @return the port number to sniff from
   */
  public static int askPortNumber() {
    System.out.println("Enter a port number: ");
    int portNumber = input.nextInt();
    
    while (portNumber < 0 || portNumber > MAX_PORT_VALUE) {
      System.out.println("Invalid port number! Try again");
      askPortNumber();
      break;
    }
    return portNumber;
  }
}
