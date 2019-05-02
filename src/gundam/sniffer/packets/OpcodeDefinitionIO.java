package gundam.sniffer.packets;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

/**
 * This class represents IO operations related to opcode definition.
 * @author brian
 *
 */
public class OpcodeDefinitionIO {
  private static final String DEFINITIONS_FILE_NAME = "definitions.json";
  private static final String UTF_8_ENCODING = "UTF-8";

  private OpcodeDefinitionIO() {
    // Doesn't need to be instantiated
  }

  /**
   * Writes the opcode definitions file.
   * @throws IOException if there is any issue writing the file
   */
  public static void writeToFile() throws IOException {
    File file = new File(DEFINITIONS_FILE_NAME);
    FileOutputStream fileOutputStream = new FileOutputStream(file);
    JsonWriter writer = new JsonWriter(new OutputStreamWriter(fileOutputStream, UTF_8_ENCODING));
    writer.setIndent("    ");
    writer.beginArray();
    writer.beginObject();
    writeOpcodesToFile(writer, true);
    writer.endObject();
    writer.beginObject();
    writeOpcodesToFile(writer, false);
    writer.endObject();
    writer.endArray();
    writer.close();
  }

  /**
   * Loads the opcode definitions file.
   * @throws IOException if there is any issue reading the file
   */
  public static void loadFromFile() throws IOException {
    File file = new File(DEFINITIONS_FILE_NAME);
    FileInputStream fileInputStream = new FileInputStream(file);
    JsonReader reader = new JsonReader(new InputStreamReader(fileInputStream, UTF_8_ENCODING));
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
      for (String opcodeVal : OpcodeDefinitions.getInboundOpcodes().keySet()) {
        writer.name(opcodeVal).value(OpcodeDefinitions.getOutboundOpcodes().get(opcodeVal));
      }
    }
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
