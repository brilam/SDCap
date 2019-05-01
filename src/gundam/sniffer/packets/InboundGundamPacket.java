package gundam.sniffer.packets;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;

/**
 * This immutable class is used to create an inbound Gundam packet.
 * @author Brian
 */
public final class InboundGundamPacket extends GundamPacket {
  /**
   * Creates an inbound Gundam packet.
   * @param handle the PcapHandle used for sniffing the packet
   * @param tcpPacket the TcpPacket that was sniffed
   */
  InboundGundamPacket(PcapHandle handle, TcpPacket tcpPacket) {
    super(handle, tcpPacket, "Inbound");
  }
}