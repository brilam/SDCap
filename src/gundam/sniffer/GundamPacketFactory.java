package gundam.sniffer;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;

/**
 * This class is used to create an appropriate Gundam packet depending on if the packet
 * is an outbound or inbound packet.
 * @author Brian
 */
public class GundamPacketFactory {
  /**
   * Returns a particular GundamPacket (@see OutboundGundamPacket or @see InboundGundamPacket).
   * @param handle the PcapHandle object used for capturing packets
   * @param tcpPacket the TcpPacket object representing the TcpPacket that was sniffed
   * @param isOutbound whether or not the packet is an outbound packet
   * @return a particular GundamPacket (@see OutboundGundamPacket or @see InboundGundamPacket)
   */
  public GundamPacket createPacket(PcapHandle handle, TcpPacket tcpPacket, boolean isOutbound) {
    if (isOutbound) {
      return new OutboundGundamPacket(handle, tcpPacket);
    } else {
      return new InboundGundamPacket(handle, tcpPacket);
    }
  }
}
