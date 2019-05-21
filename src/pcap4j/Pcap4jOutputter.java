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
