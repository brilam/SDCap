package gundam.sniffer.gui;

import gundam.sniffer.packets.GundamPacket;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.swing.table.DefaultTableModel;

public class GundamPacketTableModel extends DefaultTableModel {
  public static final int OPCODE_NAME_COL_INDEX = 5;
  private static final long serialVersionUID = -7010214871843797001L;
  private static final String[] COLUMN_NAMES =
      {"Timestamp", "Direction", "Packet Length", "Unknown Data", "Opcode", "Opcode Name"};
  private List<GundamPacket> packetLog;
  
  /**
   * Creates a GundamPacketTableModel to specify how the table model
   * for the JTable should look like.
   */
  public GundamPacketTableModel() {
    this.packetLog = new ArrayList<>();
    // Sets the column names
    for (int index = 0; index < COLUMN_NAMES.length; index++) {
      super.addColumn(COLUMN_NAMES[index]);
    }
  }
  
  @Override
  public int getColumnCount() {
    return COLUMN_NAMES.length;
  }
  
  @Override
  public boolean isCellEditable(int row, int col) {
    if (col < OPCODE_NAME_COL_INDEX) {
      return false;
    }
    // Only opcode name should be editable
    return true;
  }
  
  /**
   * Sets the opcode name for the given opcode.
   * @param value the opcode name
   * @param opcode the opcode
   */
  private void setOpcodeNameAt(byte[] opcode, Object value) {
    for (int index = 0; index < getPacketLog().size(); index++) {
      GundamPacket packet = getPacketLog().get(index);
      if (Arrays.equals(opcode, packet.getOpcode())) {
        super.setValueAt(value, index, OPCODE_NAME_COL_INDEX);
      }
    }
  }
  
  @Override
  public void setValueAt(Object value, int row, int column) {
    if (isCellEditable(row, column)) {
      String opcodeName = (String) value;
      GundamPacket editedPacket = getPacketLog().get(row);
      String opcodeHexString =  editedPacket.getOpcodeAsString();

      if (editedPacket.getDirection().equalsIgnoreCase("Inbound")) {
        OpcodeDefinitions.addInboundOpcode(opcodeHexString, opcodeName);
      } else {
        OpcodeDefinitions.addOutboundOpcode(opcodeHexString, opcodeName);
      }
      setOpcodeNameAt(editedPacket.getOpcode(), value);
    }
  }
    
  /**
   * Adding the Gundam packet to the GundamPacketTableModel.
   * @param gundamPacket the Gundam packet to add
   */
  public void addRow(GundamPacket gundamPacket) {
    packetLog.add(gundamPacket);
    String[] packetInfo = gundamPacket.getPacketInformation();
    String[] rowData = Arrays.copyOfRange(packetInfo, 0, packetInfo.length - 1);
    rowData = gundamPacket.cleanRowData(rowData);
    super.addRow(rowData);
  }
  
  /**
   * Returns the packet log.
   * @return the packet log
   */
  public List<GundamPacket> getPacketLog() {
    return packetLog;
  }
}
