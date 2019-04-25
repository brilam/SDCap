package gundam.sniffer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import gundam.sniffer.config.SniffingConfiguration;

/**
 * This class represents the Gundam sniffer.
 */
public class GundamSniffer {
  private SniffingConfiguration sc;
  private static final int SNAPSHOT_LENGTH = 65536;
  private static final int READ_TIMEOUT = 50;
  private static final int LOOP_INFINITY = -1;

  /**
   * Create a GundamSniffer object which allows us to start sniffing for packets.
   * @param sc
   */
  public GundamSniffer(SniffingConfiguration sc) {
    this.sc = sc;
  }

  /**
   * Starts sniffing for Gundam packets.
   * @throws PcapNativeException if an error occurs in the pcap native library
   * @throws NotOpenException if the PcapHandle is not open
   * @throws InterruptedException if the PcapHandle loop is terminated due to a call to breakLoop()
   */
  public void startSniffing() throws PcapNativeException, NotOpenException, InterruptedException {
    final PcapHandle handle;
    PcapNetworkInterface device = sc.getDevice();
    int port = sc.getPort();
    handle = device.openLive(SNAPSHOT_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    String filter = "tcp port " + port;
    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    PacketListener listener = new PacketListener() {

      @Override
      public void gotPacket(PcapPacket packet) {
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket == null) {
          System.out.println("Packet is null");
        } else {
          if (tcpPacket.getPayload() != null) {
            System.out.println("Source Address: " + ipv4.getHeader().getSrcAddr());
            System.out.println("Destination Address: " + ipv4.getHeader().getDstAddr());
            System.out.println("Length: " + tcpPacket.length());
            System.out.println("Data: " + tcpPacket.getPayload().getRawData());
          }
        }
      }
    };
    handle.loop(LOOP_INFINITY, listener);
  }
}
