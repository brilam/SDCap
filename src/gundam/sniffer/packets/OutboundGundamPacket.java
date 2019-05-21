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
 * This immutable class is used to create an outbound Gundam packet.
 * @author Brian
 */
public final class OutboundGundamPacket extends GundamPacket {
  /**
   * Creates an outbound Gundam packet.
   * @param handle the PcapHandle object used for sniffing the packet
   * @param tcpPacket the TcpPacket that was sniffed
   */
  OutboundGundamPacket(PcapHandle handle, TcpPacket tcpPacket) {
    super(handle, tcpPacket, "Outbound");
  }
}