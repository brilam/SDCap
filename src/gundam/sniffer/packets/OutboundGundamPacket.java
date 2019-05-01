package gundam.sniffer.packets;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;

/**
 * This immutable class is used to create an outbound Gundam packet.
 * @author Brian
 */
public final class OutboundGundamPacket extends GundamPacket {
  /**
   * Creates an outbound Gundam packet.
   * @param handle the PcapHandle object used for sniffing the packet
   * @param tcpPacket the TcpPacket that was sniffed
   */
  OutboundGundamPacket(PcapHandle handle, TcpPacket tcpPacket) {
    super(handle, tcpPacket, "Outbound");
  }
}