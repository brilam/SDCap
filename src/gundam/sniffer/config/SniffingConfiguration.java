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

package gundam.sniffer.config;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;

/**
 * This class is used to represent the sniffing configuration determined
 * by the user's choices.
 *
 */
public class SniffingConfiguration {
  private PcapNetworkInterface device = null;
  private int port;
  private List<InetAddress> localAddrs = new ArrayList<>();

  /**
   * Creates a SniffingConfiguration with the given device and port.
   * @param device the device for which packets will be sniffed
   * @param port the port that packets are sniffed from
   */
  private SniffingConfiguration(PcapNetworkInterface device, int port) {
    this.device = device;
    setLocalAddrs(device);
    this.port = port;
  }
  
  /**
   * Sets the local addresses of the network device.
   * @param device the network device
   */
  public void setLocalAddrs(PcapNetworkInterface device) {
    for (PcapAddress pcapAddr : device.getAddresses()) {
      localAddrs.add(pcapAddr.getAddress());
    }
  }
  
  /**
   * Returns the list of local addresses for the network device.
   * @return the list of local addresses for the network device
   */
  public List<InetAddress> getLocalAddrs() {
    return localAddrs;
  }

  /**
   * Returns the networking device that we would like to sniff from.
   * @return the networking device that we would like to sniff from
   */
  public PcapNetworkInterface getDevice() {
    return device;
  }

  /**
   * Returns the port that we'll be sniffing from.
   * @return the port that we'll sniff from
   */
  public int getPort() {
    return port;
  }

  /**
   * This class is used to build a SniffingConfiguration object.
   */
  public static class SniffingConfigurationBuilder {
    private PcapNetworkInterface device = null;
    private int port;

    /**
     * Sets the sniffing device.
     * @param device the device to set
     * @return SniffingConfigurationBuilder object with the set sniffing device
     */
    public SniffingConfigurationBuilder setSniffingDevice(PcapNetworkInterface device) {
      this.device = device;
      return this;
    }

    
    /**
     * Sets the port.
     * @param port the port to sniff
     * @return SniffingConfigurationBuilder object with the set sniffing device
     */
    public SniffingConfigurationBuilder setPort(int port) {
      this.port = port;
      return this;
    }

    /**
     * Returns a SniffingConfiguration object with the given device and port.
     * @return a SniffingConfiguration object with the given device and port
     */
    public SniffingConfiguration build() {
      return new SniffingConfiguration(device, port);
    }
  }
}
