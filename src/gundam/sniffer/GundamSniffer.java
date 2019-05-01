package gundam.sniffer;

import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.packets.GundamPacket;
import gundam.sniffer.packets.GundamPacketFactory;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 * This class represents the Gundam packet sniffing functionality (ie.
 * logging the packets).
 */
public class GundamSniffer {
  private SniffingConfiguration sc;
  private static final int SNAPSHOT_LENGTH = 65536;
  private static final int READ_TIMEOUT = 50;
  private static final int LOOP_INFINITY = -1;
  private static final GundamPacketFactory GUNDAM_PACKET_FACTORY = new GundamPacketFactory();

  /**
   * Create a GundamSniffer object which allows us to start sniffing for packets.
   * @param sc the SniffingConfiguration for this sniffer
   */
  public GundamSniffer(SniffingConfiguration sc) {
    this.sc = sc;
  }

  /**
   * Starts sniffing for Gundam packets.
   * @throws PcapNativeException if an error occurs in the pcap native library
   * @throws NotOpenException if the PcapHandle is not open
   * @throws InterruptedException if the PcapHandle loop is terminated due to a call to breakLoop()
   * @throws UnknownHostException if the address of localhost cannot be resolved
   */
  public void startSniffing()
      throws PcapNativeException, NotOpenException, InterruptedException, UnknownHostException {
    final PcapHandle handle;
    PcapNetworkInterface device = sc.getDevice();
    int port = sc.getPort();
    handle = device.openLive(SNAPSHOT_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    String filter = "tcp port " + port;
    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    
    PacketListener listener = new PacketListener() {

      @Override
      public void gotPacket(Packet packet) {
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
          if (tcpPacket.getPayload() != null) {
            Inet4Address srcAddr = ipv4.getHeader().getSrcAddr();
            boolean isOutbound = sc.getLocalAddrs().contains(srcAddr);
            GundamPacket gundamPacket =
                GUNDAM_PACKET_FACTORY.createPacket(handle, tcpPacket, isOutbound);
            System.out.println(gundamPacket);
          }
        }
      }
    };
    handle.loop(LOOP_INFINITY, listener);
  }
}
