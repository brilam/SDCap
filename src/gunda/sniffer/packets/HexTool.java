package gunda.sniffer.packets;

public class HexTool {
  public static String convertHexToString(String hex) {

    StringBuilder sb = new StringBuilder();
    StringBuilder temp = new StringBuilder();

    // 49204c6f7665204a617661 split into two characters 49, 20, 4c...
    for (int i = 0; i < hex.length() - 1; i += 2) {

      // grab the hex in pairs
      String output = hex.substring(i, (i + 2));
      // convert hex to decimal
      int decimal = Integer.parseInt(output, 16);
      // convert the decimal to character
      sb.append((char) decimal);

      temp.append(decimal);
    }
    System.out.println("ASCII DATA : " + temp.toString());

    return sb.toString();
  }
  
  public static void main(String[] args) {
   System.out.println(convertHexToString("4847128"));
  }
}
