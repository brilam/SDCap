package gundam.sniffer.packets;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the opcode definitions (a mapping of the opcode to
 * an opcode name).
 * @author Brian
 *
 */
public final class OpcodeDefinitions {
  public static Map<String, String> inboundOpcodes = new HashMap<>();
  public static Map<String, String> outboundOpcodes = new HashMap<>();
  
  private OpcodeDefinitions() {
    // Doesn't need to be instantiated
  }
  
  /**
   * Adds the inbound opcode with the given opcode name.
   * @param opcode the inbound opcode as a Little Endian hex string
   * @param opcodeName the opcode name
   */
  public static void addInboundOpcode(String opcode, String opcodeName) {
    inboundOpcodes.put(opcode, opcodeName);
  }
  
  /**
   * Adds the outbound opcode with the given opcode name.
   * @param opcode the outbound opcode as a Little Endian hex string
   * @param opcodeName the opcode name
   */
  public static void addOutboundOpcode(String opcode, String opcodeName) {
    outboundOpcodes.put(opcode, opcodeName);
  }
  
  /**
   * Returns all the inbound opcode definitions.
   * @return all the inbound opcode definitions
   */
  public static Map<String, String> getInboundOpcodes() {
    return inboundOpcodes;
  }
  
  /**
   * Returns all the outbound opcode definitions.
   * @return all the outbound opcode definitions
   */
  public static Map<String, String> getOutboundOpcodes() {
    return outboundOpcodes;
  }
  
  public static void loadPacketDefinitions() throws IOException {
    OpcodeDefinitionIO.loadFromFile();
  }
  
  public static void exportPacketDefinitions() throws IOException {
    OpcodeDefinitionIO.writeToFile();
  }
  
  /**
   * Returns the name of the opcode given an opcode.
   * @param opcode the opcode as a Little Endian HEX string
   * @param opcodes the opcode definitions
   * @return the name of the opcode given an opcode
   */
  public static String lookupOpcodeName(String opcode, Map<String, String> opcodes) {
    String name = "";
    if (opcodes.get(opcode) != null) {
      name += opcodes.get(opcode);
    }
    return name;
  }
}
