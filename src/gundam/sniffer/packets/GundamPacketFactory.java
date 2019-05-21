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

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.TcpPacket;

/**
 * This class is used to create an appropriate Gundam packet depending on if the packet
 * is an outbound or inbound packet.
 * @author Brian
 */
public class GundamPacketFactory {
  /**
   * Returns a particular GundamPacket (@see OutboundGundamPacket or @see InboundGundamPacket).
   * @param handle the PcapHandle object used for capturing packets
   * @param tcpPacket the TcpPacket object representing the TcpPacket that was sniffed
   * @param isOutbound whether or not the packet is an outbound packet
   * @return a particular GundamPacket (@see OutboundGundamPacket or @see InboundGundamPacket)
   */
  public GundamPacket createPacket(PcapHandle handle, TcpPacket tcpPacket, boolean isOutbound) {
    if (isOutbound) {
      return new OutboundGundamPacket(handle, tcpPacket);
    } else {
      return new InboundGundamPacket(handle, tcpPacket);
    }
  }
}
