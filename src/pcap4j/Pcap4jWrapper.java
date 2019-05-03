package pcap4j;

import java.io.IOException;
import java.util.List;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 * This class wraps around pcap4j to make things easier to
 * work with or more readable for the end-user.
 * @author Brian
 *
 */
public class Pcap4jWrapper {
  private static List<PcapNetworkInterface> allDevices;
  private static String[] deviceNames;

  /**
   * Loads all the network devices to sniff packets from.
   * @throws IOException if an error occurs in the pcaps native library
   */
  public static void loadAllDevices() throws IOException {
    try {
      allDevices = Pcaps.findAllDevs();
      populateDeviceNames();
    } catch (PcapNativeException e) {
      throw new IOException(e.getMessage());
    }
  }
  
  /**
   * Returns all the network devices to sniff from.
   * @return all the network devices to sniff from.
   */
  public static List<PcapNetworkInterface> getAllDevices() {
    return allDevices;
  }
  
  public static String[] getDeviceNames() {
    return deviceNames;
  }
  
  /**
   * Returns the number of devices there are to sniff from.
   * @return the number of devices there are to sniff from
   */
  public static int getNumOfDevices() {
    return getAllDevices().size();
  }
  
  /**
   * Populates the deviceNames arrays with the device names (they
   * are technically device descriptions). 
   */
  private static void populateDeviceNames() {
    deviceNames = new String[getNumOfDevices()];
    for (int index = 0; index < getNumOfDevices(); index++) {
      String deviceName = allDevices.get(index).getDescription();
      deviceNames[index] = deviceName;
    }
  }
}
