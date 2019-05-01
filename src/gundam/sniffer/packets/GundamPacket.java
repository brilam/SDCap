package gundam.sniffer.packets;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Map;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;

/**
 * This class represents a Gundam packet. A Gundam packet is not encrypted (at
 * least as seen in the Chinese locale of the game). The packet is a TCP packet
 * sent over IPv4 Protocol. The first short (two bytes) of the packet is known as 
 * the "opcode", and the bytes after the opcode are the packet data. The byte ordering
 * is Little Endian.
 * @author Brian
 */
public abstract class GundamPacket {
  private PcapHandle handle;
  private TcpPacket tcpPacket;
  private String packetDirection;
  private static final int UNKNOWN_DATA_START_INDEX = 2;
  private static final int OPCODE_START_INDEX = 4;
  private static final int PACKET_DATA_START_INDEX = 6;
  
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
    byte[] packetData = tcpPacket.getPayload().getRawData();
    /* First two bytes of the packet represent the length of the packet
       excluding the two bytes after the length */
    byte[] packetLengthInHex = Arrays.copyOfRange(packetData, 0, UNKNOWN_DATA_START_INDEX);
    packetLengthInHex = HexTool.reverseTwoByteArray(packetLengthInHex);
    String hexString = HexTool.byteArrayToHexString(packetLengthInHex, false);
    return Integer.parseInt(hexString, 16);
  }
  
  /**
   * Returns the opcode of the packet. Opcodes are a short (two bytes)
   * in SD Gundam Online.
   * @return the opcode of the packet
   */
  public final byte[] getOpcode() {
    byte[] packetData = tcpPacket.getPayload().getRawData();
    byte[] opcode = Arrays.copyOfRange(packetData, OPCODE_START_INDEX, PACKET_DATA_START_INDEX);
    return opcode;
  }
  
  /**
   * Returns the bytes in the packet representing the unknown data. The unknown data is
   * the two bytes after the packet length.
   * @return the bytes representing the unknown data
   */
  public final byte[] getUnknownData() {
    byte[] originalData = tcpPacket.getPayload().getRawData();
    byte[] unknownData =
        Arrays.copyOfRange(originalData, UNKNOWN_DATA_START_INDEX, OPCODE_START_INDEX);
    return unknownData;
  }
  
  /**
   * Returns the packet data of the packet. The packet data is the bytes
   * after the opcode.
   * @return the packet data of the packet
   */
  public final byte[] getData() {
    byte[] originalData = tcpPacket.getPayload().getRawData();
    // If there is more than two bytes, it is everything after the first two bytes
    if (originalData.length > PACKET_DATA_START_INDEX) {
      byte[] packetData =
          Arrays.copyOfRange(originalData, PACKET_DATA_START_INDEX, originalData.length);
      return packetData;
    }
    // Empty byte array if there is no data
    return new byte[0];
  }
  
  /**
   * Returns a String representation of a Gundam packet.
   */
  @Override
  public final String toString() {
    String message = "Timestamp: " + getTimestamp();
    message += "\nPacket Direction: " + getDirection();
    message += "\nLength: " + getLength();
    String unknownData = HexTool.byteArrayToHexString(getUnknownData(), true);
    message += "\nUnknown Data: " + unknownData;
    Map<String, String> opcodes;
    byte[] opcode = getOpcode();
    opcode = HexTool.reverseTwoByteArray(opcode);
    String opcodeHexString = HexTool.byteArrayToHexString(opcode, false);
    message += "\nOpcode: 0x" + opcodeHexString;
    if (packetDirection.equalsIgnoreCase("Inbound")) {
      opcodes = OpcodeDefinitions.getInboundOpcodes();
    } else {
      opcodes = OpcodeDefinitions.getOutboundOpcodes();
    }
    String opcodeName = OpcodeDefinitions.lookupOpcodeName("0x" + opcodeHexString, opcodes);
    message += "\nOpcode name: " + opcodeName;
    byte[] packetData = getData();
    String packetDataHexString = HexTool.byteArrayToHexString(packetData, true);
    message += "\nData: " + packetDataHexString;
    message += "\n";
    return message;
  }
}
