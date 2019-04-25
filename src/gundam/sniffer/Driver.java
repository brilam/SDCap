package gundam.sniffer;

import java.io.IOException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import gundam.sniffer.config.SniffingConfiguration;
import gundam.sniffer.output.UserPrompter;
import pcap4j.Pcap4jOutputter;
import pcap4j.Pcap4jWrapper;

public class Driver {
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
      gundamSniffer.startSniffing();
    } catch (IOException | PcapNativeException | NotOpenException | InterruptedException e) {
      e.printStackTrace();
    }
  }
}
