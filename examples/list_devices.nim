import system
import ../src/libpcap

var iface: ptr PcapIf
var errStr: cstring

let _ = pcapFindAllDevs(iface, errStr)

var device = iface

while device != nil:
    echo("Device: ", device.name)
    echo("\taddresses: ", device.addresses[])
    echo("\tflags: ", device.flags)
    echo("\tdescription: ", device.description)
    echo()
    device = device.next
