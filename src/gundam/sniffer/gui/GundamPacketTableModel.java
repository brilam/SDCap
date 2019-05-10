package gundam.sniffer.gui;

import gundam.sniffer.packets.GundamPacket;
import gundam.sniffer.packets.HexTool;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.table.DefaultTableModel;

public class GundamPacketTableModel extends DefaultTableModel {
  private static final long serialVersionUID = -7010214871843797001L;
  private static final String[] COLUMN_NAMES =
      {"Timestamp", "Direction", "Packet Length", "Unknown Data", "Opcode", "Opcode Name"};
  private List<GundamPacket> packetLog;
  private static final int TIMESTAMP_COL_INDEX = 0;
  private static final int DIRECTION_COL_INDEX = 1;
  private static final int LENGTH_COL_INDEX  = 2;
  private static final int UNKNOWN_DATA_COL_INDEX = 3;
  private static final int OPCODE_COL_INDEX = 4;
  private static final int OPCODE_NAME_COL_INDEX = 5;
  
  /**
   * Creates a GundamPacketTableModel to specify how the table model
   * for the JTable should look like.
   */
  public GundamPacketTableModel() {
    this.packetLog = new ArrayList<>();
    // Sets the column names
    for (int index = 0; index < COLUMN_NAMES.length; index++) {
      addColumn(COLUMN_NAMES[index]);
    }
  }
  
  @Override
  public int getColumnCount() {
    return COLUMN_NAMES.length;
  }

  @Override
  public int getRowCount() {
    if (packetLog == null) {
      return 0;
    }
    return packetLog.size();
  }

  @Override
  public Object getValueAt(int row, int col) {
    GundamPacket gundamPacket = packetLog.get(row);
    if (col == TIMESTAMP_COL_INDEX) {
      return gundamPacket.getTimestamp();
    } else if (col == DIRECTION_COL_INDEX) {
      return gundamPacket.getDirection();
    } else if (col == LENGTH_COL_INDEX) {
      return gundamPacket.getLength();
    } else if (col == UNKNOWN_DATA_COL_INDEX) {
      String unknownData = HexTool.byteArrayToHexString(gundamPacket.getUnknownData(), true);
      return unknownData;
    } else if (col == OPCODE_COL_INDEX || col == OPCODE_NAME_COL_INDEX) {
      byte[] opcode = gundamPacket.getOpcode();
      opcode = HexTool.reverseTwoByteArray(opcode);
      String opcodeHexString = HexTool.byteArrayToHexString(opcode, false);
      if (col == OPCODE_COL_INDEX) {
        return opcodeHexString;
      }
      Map<String, String> opcodes;
      if (gundamPacket.getDirection().equalsIgnoreCase("Inbound")) {
        opcodes = OpcodeDefinitions.getInboundOpcodes();
      } else {
        opcodes = OpcodeDefinitions.getOutboundOpcodes();
      }
      String opcodeName = OpcodeDefinitions.lookupOpcodeName("0x" + opcodeHexString, opcodes);
      return opcodeName;
    }
    // Should never occur since we assume the index passed in is one of the above
    return null; 
  }
  
  @Override
  public boolean isCellEditable(int row, int col) {
    if (col < OPCODE_NAME_COL_INDEX) {
      return false;
    }
    // Only opcode name should be editable
    return true;
  }
  
  public void addRow(GundamPacket gundamPacket) {
    String[] rowData = gundamPacket.toString().split("\n");
    super.addRow(rowData);
  }
}
