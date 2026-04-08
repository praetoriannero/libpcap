import system
import ../src/libpcap


proc main() =
  var iface: PcapIf
  var errBuf: array[PcapErrbufSize, char]

  let error = pcapFindAllDevs(addr(iface), addr(errBuf[0]))

  if error != 0:
    echo("Error: ", $cast[cstring](addr(errBuf[0])))

  var device = addr(iface)

  while device != nil:
    echo("Device: ", device.name)
    echo("\taddresses: ", device.addresses[])
    echo("\tflags: ", device.flags)
    echo("\tdescription: ", device.description)
    echo()
    device = device.next


when isMainModule:
  main()
