import system
import std/strformat
import std/strutils
import ../src/libpcap


proc `$`(bytes: seq[byte]): string =
  ## Create an ASCII string of the raw bytes
  result = newString(bytes.len())
  for idx in 0..<bytes.len():
    let b = bytes[idx]

    if 32 <= b and b <= 126:
      result.add(char(bytes[idx]))
    else:
      result.add(".")


proc copyBytes(packet: ptr byte, pkt_header: PcapPacketHeader): seq[byte] =
  ## Copy the bytes of the packet into a sequence we own
  result = newSeq[byte](pkt_header.capLen)
  if packet != nil and pkt_header.capLen > 0:
    copyMem(addr result[0], packet, pkt_header.capLen)


proc main() =
  ## Print out 10 incoming packets
  const snapLen = 65536
  const promisc = 1
  const timeoutms = 1_000

  var errBuf: array[PcapErrbufSize, char]
  var devices = newSeq[string]()
  var iface: PcapIf
  let error = pcapFindAllDevs(addr(iface), addr(errBuf[0]))

  if error != 0:
    echo("Error: ", $cast[cstring](addr(errBuf[0])))

  var device = addr(iface)

  var idx = 1
  while device != nil:
    if $device.name != "":
      echo(idx, " ", device.name, " ", device.description)
      devices.add($device.name)
      idx += 1

    device = device.next

  echo("Choose device ID")
  let deviceId = parseInt(readLine(stdin))
  let deviceName = devices[deviceId - 1]

  let handle = pcapOpenLive(deviceName.cstring, snapLen, promisc, timeoutms,
      addr(errBuf[0]))

  if handle == nil:
    echo("Error opening device: ", $cast[cstring](addr(errBuf[0])))
    quit(1)

  var packetHeader: PcapPacketHeader = PcapPacketHeader()

  echo("Waiting on packets...")
  for i in 0..<10:
    let packet = pcapNext(handle, addr(packetHeader))
    var bytes: seq[byte] = copyBytes(packet, packetHeader)
    echo(fmt("{i} "), packetHeader, " ", $bytes)

  pcapClose(handle)


when isMainModule:
  main()
