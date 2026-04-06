import system
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
    const snapLen = 2048
    const promisc = 1
    const timeoutms = 1000

    var errBuf: array[PcapErrbufSize, char]

    let handle = pcapOpenLive(nil, snapLen, promisc, timeoutms, addr(errBuf[0]))

    if handle == nil:
        echo("Error opening device: ", $cast[cstring](addr(errBuf[0])))
        quit(1)

    var pcapHeader: PcapPacketHeader
    let packet: ptr byte = pcapNext(handle, addr(pcapHeader))

    echo(pcapHeader)

    var bytes: seq[byte] = copyBytes(packet, pcapHeader)

    echo($bytes)

    pcapClose(handle)


when isMainModule:
    main()
