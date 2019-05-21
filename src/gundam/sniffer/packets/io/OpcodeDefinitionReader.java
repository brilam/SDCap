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

package gundam.sniffer.packets.io;

import com.google.gson.stream.JsonReader;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * This class represents reading the opcode definition file.
 * @author Brian
 *
 */
public class OpcodeDefinitionReader {
  private OpcodeDefinitionReader() {
    // Doesn't need to be instantiated
  }
  
  /**
   * Returns whether or not the opcode definitions file exists.
   * @return whether or not the opcode definitions file exists
   */
  public static boolean isDefinitionFileExists() {
    File file = new File(OpcodeDefinitionConstants.DEFINITIONS_FILE_NAME);
    return file.exists();
  }
  
  /**
   * Loads the opcode definitions file.
   * @throws IOException if there is any issue reading the file
   */
  public static void loadFromFile() throws IOException {
    File file = new File(OpcodeDefinitionConstants.DEFINITIONS_FILE_NAME);
    FileInputStream fileInputStream = new FileInputStream(file);
    JsonReader reader = new JsonReader(
        new InputStreamReader(fileInputStream, OpcodeDefinitionConstants.UTF_8_ENCODING));
    reader.beginArray();
    reader.beginObject();
    addOpcodesFromFile(reader, true);
    reader.endObject();
    reader.beginObject();
    addOpcodesFromFile(reader, false);
    reader.endObject();
    reader.endArray();
    reader.close();
  }
  
  /**
   * Adds the opcodes from file.
   * @param reader the JsonReader that is reading the file
   * @param isInbound the packet direction of the opcodes
   * @throws IOException if there is any issues reading the files
   */
  private static void addOpcodesFromFile(JsonReader reader, boolean isInbound)
      throws IOException {
    while (reader.hasNext()) {
      String opcodeValue = reader.nextName();
      String opcodeName = reader.nextString();
      if (isInbound) {
        OpcodeDefinitions.addInboundOpcode(opcodeValue, opcodeName);
      } else {
        OpcodeDefinitions.addOutboundOpcode(opcodeValue, opcodeName);
      }
    }
  }
}
