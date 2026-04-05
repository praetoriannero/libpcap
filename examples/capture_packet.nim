import system
import std/strformat
import ../src/libpcap

const snapLen = 2048
const promisc = 1
const timeoutms = 1000
var errBuf: cstring


proc `$`(iface: PcapIf): string =
    fmt("PcapIf(name: {iface.name}, addr: {iface.addresses[]})")

# Open device (nil = default device)
let handle = pcapOpenLive("eth0", snapLen, promisc, timeoutms, errBuf)

if handle == nil:
    echo "Error opening device: ", $(cast[cstring](addr errBuf[0]))
    quit(1)

var header: PcapPacketHeader = PcapPacketHeader()
var dataBuffer: array[snapLen, byte]
var iface: PcapIf
var errStr: cstring

var devices = pcapFindAllDevs(addr(iface), errStr)

if iface != nil:
    echo(iface.name)
    while iface.next != nil:
        iface = iface.next
        echo(iface.name)

var pcapHeader: PcapPacketHeader = PcapPacketHeader()

let packet = pcapNext(handle, addr(pcapHeader))
echo(typeof(packet))
# for idx in 0..pcapHeader.capLen:
#     echo(packet[idx])


pcapClose(handle)
