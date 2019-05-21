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

import com.google.gson.stream.JsonWriter;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

/**
 * This class represents writing the opcode definition file.
 * @author Brian
 *
 */
public class OpcodeDefinitionsWriter {
  private OpcodeDefinitionsWriter() {
    // Doesn't need to be instantiated
  }

  /**
   * Writes the opcode definitions file.
   * @throws IOException if there is any issue writing the file
   */
  public static void writeToFile() throws IOException {
    File file = new File(OpcodeDefinitionConstants.DEFINITIONS_FILE_NAME);
    FileOutputStream fileOutputStream = new FileOutputStream(file);
    JsonWriter writer =
        new JsonWriter(
            new OutputStreamWriter(fileOutputStream, OpcodeDefinitionConstants.UTF_8_ENCODING));
    writer.setIndent("    ");
    writer.beginArray();
    writer.beginObject();
    OpcodeDefinitionsWriter.writeOpcodesToFile(writer, true);
    writer.endObject();
    writer.beginObject();
    OpcodeDefinitionsWriter.writeOpcodesToFile(writer, false);
    writer.endObject();
    writer.endArray();
    writer.close();
  }

  /**
   * Writes the opcodes to the file.
   * @param writer the JsonWriter that is currently writing to file
   * @param isInbound the packet direction of the opcodes
   * @throws IOException if there is any issues writing the file
   */
  private static void writeOpcodesToFile(JsonWriter writer, boolean isInbound) throws IOException {
    if (isInbound) {
      for (String opcodeVal : OpcodeDefinitions.getInboundOpcodes().keySet()) {
        writer.name(opcodeVal).value(OpcodeDefinitions.getInboundOpcodes().get(opcodeVal));
      }
    } else {
      for (String opcodeVal : OpcodeDefinitions.getOutboundOpcodes().keySet()) {
        writer.name(opcodeVal).value(OpcodeDefinitions.getOutboundOpcodes().get(opcodeVal));
      }
    }
  }

}
