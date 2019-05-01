package gundam.sniffer.packets;

import org.pcap4j.util.ByteArrays;

public class HexTool {
  /**
   * Returns the HEX String as An ASCII String.
   * @param hexString the hex string representing packet data
   * @return the HEX String as An ASCII String
   */
  public static String convertHexToString(String hexString) {

    StringBuilder sb = new StringBuilder();
    StringBuilder temp = new StringBuilder();

    // 49204c6f7665204a617661 split into two characters 49, 20, 4c...
    for (int i = 0; i < hexString.length() - 1; i += 2) {

      // grab the hex in pairs
      String output = hexString.substring(i, (i + 2));
      // convert hex to decimal
      int decimal = Integer.parseInt(output, 16);
      // convert the decimal to character
      sb.append((char) decimal);

      temp.append(decimal);
    }
    return sb.toString();
  }
  
  /**
   * Returns the hex string given a byte array representing the packet data.
   * 
   * @param packetData the packet data as a byte array
   * @param isBeautified whether or not the hex string should be "beautified". Beautified contains
   *        spaces.
   * @return the hex string given a byte array representing the packet data
   */
  public static String byteArrayToHexString(byte[] packetData, boolean isBeautified) {
    if (packetData.length == 0) {
      return "";
    }
    if (!isBeautified) {
      return ByteArrays.toHexString(packetData, "").toUpperCase();
    }
    return ByteArrays.toHexString(packetData, " ").toUpperCase();
  }
  
  /**
   * Returns the reversed array of a two byte.
   * @param twoByteArray a two byte array
   * @return the reversed two byte array
   */
  public static byte[] reverseTwoByteArray(byte[] twoByteArray) {
    byte originalByte = twoByteArray[0];
    twoByteArray[0] = twoByteArray[1];
    twoByteArray[1] = originalByte;
    return twoByteArray;
  }
}
