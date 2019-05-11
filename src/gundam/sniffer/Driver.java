package gundam.sniffer;

import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.output.UserPrompter;
import gundam.sniffer.packets.OpcodeDefinitions;
import java.io.IOException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import pcap4j.Pcap4jOutputter;
import pcap4j.Pcap4jWrapper;

/**
 * This class is used to run the GundamSniffer in command line interface (CLI) mode.
 * @author Brian
 */
public class Driver {
  /**
   * Used to run the command line interface version of GundamSniffer.
   * @param args no arguments required
   */
  public static void main(String[] args) {
    try {
      Pcap4jWrapper.loadAllDevices();
      Pcap4jOutputter.displayDeviceNames();
      int deviceNumber = UserPrompter.askDeviceNumber();
      int portNumber = UserPrompter.askPortNumber();
      PcapNetworkInterface device = Pcap4jWrapper.getAllDevices().get(deviceNumber - 1);
      SniffingConfiguration sc = new SniffingConfiguration.SniffingConfigurationBuilder()
          .setSniffingDevice(device)
          .setPort(portNumber).build();
      GundamSniffer gundamSniffer = new GundamSniffer(sc);
      OpcodeDefinitions.loadPacketDefinitions();
      gundamSniffer.startSniffing();
    } catch (IOException | PcapNativeException | NotOpenException | InterruptedException e) {
      e.printStackTrace();
    }
  }
}
