package pcap4j;

import java.io.IOException;
import java.util.List;
import org.pcap4j.core.PcapNetworkInterface;

/**
 * This class is used to output Pcap4j relevant information for CLI mode. 
 * @author Brian
 */
public class Pcap4jOutputter {
  private static final int NO_DEVICES_ERROR_CODE = 1;
  
  /**
   * Prints out all the device names (they are technically descriptions according to pcap4j), but it
   * is easier to identify these then the actual device numbers.
   * @throws IOException if an error occurs in the pcaps native library
   */
  public static void displayDeviceNames() throws IOException {
    List<PcapNetworkInterface> allDevices = Pcap4jWrapper.getAllDevices();
    
    if (allDevices == null || allDevices.isEmpty()) {
      System.out.println("No devices available");
      System.exit(NO_DEVICES_ERROR_CODE);
    }
  
    for (int index = 0; index < allDevices.size(); index++) {
      String deviceName = allDevices.get(index).getDescription();
      String deviceInfo = String.format("Device #%d: %s", index + 1, deviceName);
      System.out.println(deviceInfo);
    }
  }
}
