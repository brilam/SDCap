package gundam.sniffer.packets;

import java.util.HashMap;
import java.util.Map;

public final class OpcodeDefinitions {
  public static Map<String, String> inboundOpcodes = new HashMap<>();
  public static Map<String, String> outboundOpcodes = new HashMap<>();
  
  private OpcodeDefinitions() {
    // Doesn't need to be instantiated
  }
  
  public static void addInboundOpcode(String opcode, String opcodeName) {
    inboundOpcodes.put(opcode, opcodeName);
  }
  
  public static void addOutboundOpcode(String opcode, String opcodeName) {
    outboundOpcodes.put(opcode, opcodeName);
  }
  
  public static Map<String, String> getInboundOpcodes() {
    return inboundOpcodes;
  }
  
  public static Map<String, String> getOutboundOpcodes() {
    return outboundOpcodes;
  }
  
  public static void loadPacketDefinitions() {
    // TODO: Actually load the packet definitions from a JSON file if it exists
    inboundOpcodes.put("0x000A", "KEEP_ALIVE");
    outboundOpcodes.put("0x000A", "KEEP_ALIVE");
    outboundOpcodes.put("0x004B", "LOGIN_RESULT");
    outboundOpcodes.put("0x000E", "HANDSHAKE");
  }
  
  public static void exportPacketDefinitions() {
    // TODO: Write the packet definitions to the JSON file if it exists
  }
  
  public static String lookupOpcodeName(String opcode, Map<String, String> opcodes) {
    String name = "";
    if (opcodes.get(opcode) != null) {
      name += opcodes.get(opcode);
    }
    return name;
  }
}
