package gundam.sniffer;

import java.sql.Timestamp;
import java.util.Arrays;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.ByteArrays;

/**
 * This class represents a Gundam packet. A Gundam packet is not encrypted (at
 * least as seen in the Chinese locale of the game). The packet is a TCP packet
 * sent over IPv4 Protocol. The first short (two bytes) of the packet is known as 
 * the "opcode", and the bytes after the opcode are the packet data.
 * @author Brian
 */
public abstract class GundamPacket {
  private PcapHandle handle;
  private TcpPacket tcpPacket;
  private String packetDirection;
  
  /**
   * Creates a Gundam packet.
   * @param handle the PcapHandle object for sniffing for packet
   * @param tcpPacket the TcpPacket sniffed
   * @param packetDirection the direction of the packet (Inbound or Outbound?)
   */
  public GundamPacket(PcapHandle handle, TcpPacket tcpPacket, String packetDirection) {
    this.handle = handle;
    this.tcpPacket = tcpPacket;
    this.packetDirection = packetDirection;
  }
  
  /**
   * Returns the timestamp for when the packet was sent or received.
   * @return the timestamp for when the packet was sent or received
   */
  public final Timestamp getTimestamp() {
    return handle.getTimestamp();
  }
  
  /**
   * Returns the direction of the packet (inbound or outbound).
   * @return the direction of the packet (inbound or outbound)
   */
  public final String getDirection() {
    return packetDirection;
  }
  
  /**
   * Returns the length of the packet.
   * @return the length of the packet
   */
  public final int getLength() {
    return tcpPacket.getPayload().getRawData().length;
  }
  
  /**
   * Returns the opcode of the packet. Opcodes are a short (two bytes)
   * in SD Gundam Online.
   * @return the opcode of the packet
   */
  public final String getOpcode() {
    byte[] packetData = tcpPacket.getPayload().getRawData();
    byte[] opcode = Arrays.copyOfRange(packetData, 0, 2); 
    return ByteArrays.toHexString(opcode, " ").toUpperCase();
  }
  
  /**
   * Returns the packet data of the packet. The packet data is the bytes
   * after the opcode.
   * @return the packet data of the packet
   */
  public final String getData() {
    byte[] originalData = tcpPacket.getPayload().getRawData();
    if (originalData.length > 2) {
      byte[] packetData = Arrays.copyOfRange(originalData, 2, originalData.length); 
      return ByteArrays.toHexString(packetData, " ").toUpperCase();
    }
    return "";
  }
  
  /**
   * Returns a String representation of a Gundam packet.
   */
  @Override
  public final String toString() {
    String message = "Timestamp: " + getTimestamp();
    message += "\nPacket Direction: " + getDirection();
    message += "\nLength: " + getLength();
    message += "\nOpcode: " + getOpcode();
    message += "\nData: " + getData();
    message += "\n";
    return message;
  }
}
