# import system
# import ../src/libpcap

# proc main() =
#     const snapLen = 65536
#     const promisc = 1
#     const timeoutms = 1000
#     var errBuf: array[PcapErrbufSize, char]

#     # Use correct device string
#     let deviceName = "\\Device\\NPF_{F33A56C0-C405-447D-8062-88DB028EA630}"
#     # let deviceName = "\\Device\\NPF_Loopback"
#     let handle = pcapOpenLive(deviceName.cstring, snapLen, promisc, timeoutms, addr(errBuf[0]))

#     if handle == nil:
#         echo "Error opening device: ", $cast[cstring](addr(errBuf[0]))
#         quit(1)

#     echo "Capture started..."

#     # simple loop
#     for i in 0..<1000:
#       var pktHdr: PcapPacketHeader
#       let packetPtr = pcapNext(handle, addr(pktHdr))
#       if packetPtr != nil and pktHdr.capLen > 0:
#         var bytes: seq[byte] = newSeq[byte](pktHdr.capLen)
#         copyMem(addr bytes[0], packetPtr, pktHdr.capLen)
#         echo "Packet ", i, ": ", $(bytes)
#       else:
#         echo "No packet captured or zero-length packet"
#     # for i in 0..<10:
#     #     var pktHdr: PcapPacketHeader
#     #     let packetPtr = pcapNext(handle, addr(pktHdr))
#     #     if packetPtr != nil:
#     #         echo(packetPtr[])
#     #         # copy bytes into seq[byte]
#     #         var bytes: seq[byte] = newSeq[byte](pktHdr.capLen)
#     #         copyMem(addr bytes[0], packetPtr, pktHdr.capLen)
#     #         echo "Packet ", i, ": ", $(bytes) # uses your `$` proc
#     #     else:
#     #         echo "No packet captured"

#     pcapClose(handle)

# when isMainModule:
#     main()


import system
import std/strformat
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
    const snapLen = 65536
    const promisc = 1
    const timeoutms = 1_000

    var errBuf: array[PcapErrbufSize, char]
    # var packetBuf: array[snapLen, byte]
    # var pktHeaders: array[64, PcapPacketHeader]
    # 
    let deviceName = "\\Device\\NPF_{F33A56C0-C405-447D-8062-88DB028EA630}"
    # let deviceName = "\\Device\\NPF_Loopback"
    let handle = pcapOpenLive(deviceName.cstring, snapLen, promisc, timeoutms, addr(errBuf[0]))

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
