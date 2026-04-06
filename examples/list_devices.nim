import system
import ../src/libpcap

proc main() =
    var iface: ptr PcapIf
    var errBuf: array[PcapErrbufSize, char]

    let error = pcapFindAllDevs(iface, addr(errBuf[0]))
    echo("Error: ", $cast[cstring](addr(errBuf[0])))

    var device = iface

    while device != nil:
        echo("Device: ", device.name)
        echo("\taddresses: ", device.addresses[])
        echo("\tflags: ", device.flags)
        echo("\tdescription: ", device.description)
        echo()
        device = device.next


when isMainModule:
    main()
