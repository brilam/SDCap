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

package gundam.sniffer;

import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.output.UserPrompter;
import gundam.sniffer.packets.OpcodeDefinitions;
import gundam.sniffer.packets.io.OpcodeDefinitionReader;
import java.io.IOException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import pcap4j.Pcap4jOutputter;
import pcap4j.Pcap4jWrapper;

/**
 * This class is used to run the GundamSniffer in command line interface (CLI) mode.
 * @author Brian
 */
public class Driver {
  /**
   * Used to run the command line interface version of GundamSniffer.
   * @param args no arguments required
   */
  public static void main(String[] args) {
    try {
      Pcap4jWrapper.loadAllDevices();
      Pcap4jOutputter.displayDeviceNames();
      int deviceNumber = UserPrompter.askDeviceNumber();
      int portNumber = UserPrompter.askPortNumber();
      PcapNetworkInterface device = Pcap4jWrapper.getAllDevices().get(deviceNumber - 1);
      SniffingConfiguration sc = new SniffingConfiguration.SniffingConfigurationBuilder()
          .setSniffingDevice(device)
          .setPort(portNumber).build();
      GundamSniffer gundamSniffer = new GundamSniffer(sc);
      if (OpcodeDefinitionReader.isDefinitionFileExists()) {
        OpcodeDefinitions.loadPacketDefinitions();
      }
      gundamSniffer.startSniffing();
    } catch (IOException | PcapNativeException | NotOpenException | InterruptedException e) {
      e.printStackTrace();
    }
  }
}
