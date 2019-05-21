/**
 *  This file is a part of SDCap: Gundam Packet Sniffer
    Copyright (C) 2019  Brian Lam (brian_lam@live.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package gundam.sniffer.packets;

import gundam.sniffer.packets.io.OpcodeDefinitionReader;
import gundam.sniffer.packets.io.OpcodeDefinitionsWriter;

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
    OpcodeDefinitionReader.loadFromFile();
  }
  
  public static void exportPacketDefinitions() throws IOException {
    OpcodeDefinitionsWriter.writeToFile();
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
