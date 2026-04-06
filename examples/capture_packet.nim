import system
import ../src/libpcap

proc `$`(bytes: seq[byte]): string =
    result = newString(bytes.len())
    for idx in 0..<bytes.len():
        let b = bytes[idx]

        if 32 <= b and b <= 126:
            result.add(char(bytes[idx]))
        else:
            result.add(".")

const snapLen = 2048
const promisc = 1
const timeoutms = 1000
var errBuf: array[PcapErrbufSize, char]

let handle = pcapOpenLive("b", snapLen, promisc, timeoutms, addr(errBuf[0]))

if handle == nil:
    echo($errBuf)
    echo("Error opening device: ", $errBuf)
    quit(1)

var pcapHeader: PcapPacketHeader

let packet: ptr byte = pcapNext(handle, addr(pcapHeader))

echo(pcapHeader)

var bytes: seq[byte] = newSeq[byte](pcapHeader.capLen)

if packet != nil and pcapHeader.capLen > 0:
    copyMem(addr bytes[0], packet, pcapHeader.capLen)

echo($bytes)

pcapClose(handle)
