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
   * 
   * @param device
   * @param port
   */
  private SniffingConfiguration(PcapNetworkInterface device, int port) {
    this.device = device;
    setLocalAddrs(device);
    this.port = port;
  }
  
  public void setLocalAddrs(PcapNetworkInterface device) {
    for (PcapAddress pcapAddr : device.getAddresses()) {
      localAddrs.add(pcapAddr.getAddress());
    }
  }
  
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
     * @param device the device to set
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
