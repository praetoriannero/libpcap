import system
import std/net

# RESOURCES
# https://www.tcpdump.org/pcap.html
# https://livebook.manning.com/book/nim-in-action/chapter-8/79

when defined(windows):
    echo("Windows OS detected")
    const libName* = "wpcap.dll"
else:
    echo("Unknown OS detected")

const
    PcapBuffSize* = 65535
    PcapVersionMajor* = 2
    PcapVersionMinor* = 4
    PcapErrbufSize* = 256
    PcapError*: cint = -1
    PcapErrorBreak*: cint = -2
    PcapErrorNotActivated*: cint = -3
    PcapErrorActivated*: cint = -4
    PcapErrorNoSuchDevice*: cint = -5
    PcapErrorRfmonNotsup*: cint = -6
    PcapErrorNotRfmon*: cint = -7
    PcapErrorPermDenied*: cint = -8
    PcapErrorIfaceNotUp*: cint = -9
    PcapErrorCantsetTstampType*: cint = -10
    PcapErrorPromiscPermDenied*: cint = -11
    PcapErrorTstampPrecisionNotsup*: cint = -12
    PcapWarning*: cint = 1
    PcapWarningPromiscNotsup*: cint = 2
    PcapWarningTstampTypeNotsup*: cint = 3
    PcapNetmaskUnknown*: int64 = 0xffffffff
    PcapCharEncLocal*: cuint = 0x00000000
    PcapCharEncUtf8*: cuint = 0x00000001
    PcapBufSize* = 1024
    PcapSrcFile* = 2
    PcapSrcIfLocal* = 3
    PcapSrcIfRemote* = 4
    PcapSrcFileString*: cstring = "file://"
    PcapSrcIfString*: cstring = "rpcap://"
    PcapOpenFlagPromiscous* = 0x00000001
    PcapOpenFlagDataTxUdp* = 0x00000002
    PcapOpenFlagNoCaptureRpcap* = 0x00000004
    PcapOpenFlagNoCaptureLocal* = 0x00000008
    PcapOpenFlagMaxResponsiveness* = 0x00000010
    RpcapRmtAuthNull* = 0
    RpcapRmtAuthPwd* = 1
    ModeCapt* = 0
    ModeStat* = 1
    ModeMon* = 2
    PcapSampNoSamp* = 0
    PcapSamp1EveryN* = 1
    PcapSampFirstAfterNMs* = 2
    RpcapHostlistSize* = 1024

type
    Pcap* = pointer

    PcapDumper* = pointer

    SockAddr* = object
        saFamily: uint16
        saData: array[14, byte]

    PcapAddr* = object
        next: ptr PcapAddr
        address: ptr SockAddr
        netmask: ptr SockAddr
        broadaddr: ptr SockAddr
        dstaddr: ptr SockAddr

    PcapIf* = ptr object
        next: PcapIf
        name: cstring
        description: cstring
        addresses: ptr PcapAddr
        flags: cuint

    TimeVal* = object
        tvSec: int32
        tvUsec: int32

    PcapPacketHeader* = object
        ts: TimeVal
        capLen: cuint
        len: cuint

    PcapFileHeader* = object
        magic: cuint
        versionMajor: cushort
        versionMinor: cushort
        thisZone: cint
        sigFigs: cuint
        snapLen: cuint
        linkType: cuint

    PcapDirection* = enum
        PCAP_D_INOUT = 0
        PCAP_D_IN
        PCAP_D_OUT

    BpfInsn* = object
        code*: cushort
        jf*: uint8
        jt*: uint8
        k*: cint

    BpfProgram* = object
        bfInsns*: ptr BpfInsn
        bfLen*: cuint

    PcapRmtAuth* = object
        authType*: cint
        username*: cstring
        password*: cstring

    PcapSamp* = object
        sampMethod*: cint
        sampValue*: cint

    PcapHandler* = proc(user: ptr char, header: PcapPacketHeader, bytes: ptr byte)

when defined(Windows):
    type PcapStat = object
        psRecv: cuint
        psDrop: cuint
        psIfDrop: cuint
        psCapt: cuint
        psSent: cuint
        psNetDrop: cuint
else:
    type PcapStat = object
        psRecv: cuint
        psDrop: cuint
        psIfDrop: cuint

{.push dynlib: libName.}

proc pcapInit*(opts: cuint, errorStr: cstring): cint
    {.importc: "pcap_init".}

proc pcapLookupDev*(buffer: var cstring): cstring
    {.importc: "pcap_lookupdev".}

proc pcapLookupNet*(device: cstring, net: var cuint, mask: var cuint, errorBuf: var cstring): cint
    {.importc: "pcap_lookupnet".}

proc pcapCreate*(source: cstring, errorBuf: var cstring): Pcap
    {.importc: "pcap_create".}

proc pcapSetSnapLen*(handle: Pcap, length: cint): cint
    {.importc: "pcap_set_snaplen".}

proc pcapSetPromisc*(handle: Pcap, flag: cint): cint
    {.importc: "pcap_set_promisc".}

proc pcapCanSetRfmon*(handle: Pcap): cint
    {.importc: "pcap_can_set_rfmon".}

proc pcapSetRfmon*(handle: Pcap, flag: cint): cint
    {.importc: "pcap_set_rfmon".}

proc pcapSetTimeout*(handle: Pcap, ms: cint): cint
    {.importc: "pcap_set_timeout".}

proc pcapSetTstampType*(handle: Pcap, tsType: cint): cint
    {.importc: "pcap_set_tstamp_type".}

proc pcapSetImmediateMode*(handle: Pcap, immediateMode: cint): cint
    {.importc: "pcap_set_immediate_mode".}

proc pcapSetBufferSize*(handle: Pcap, size: cint): cint
    {.importc: "pcap_set_buffer_size".}

proc pcapSetTstampPrecision*(handle: Pcap, prec: cint): cint
    {.importc: "pcap_set_tstamp_precision".}

proc pcapGetTstampPrecision*(handle: Pcap): cint
    {.importc: "pcap_get_tstamp_precision".}

proc pcapActivate*(handle: Pcap): cint
    {.importc: "pcap_activate".}

proc pcapListTstampTypes*(handle: Pcap, tstampTypes: ptr int): cint
    {.importc: "pcap_list_tstamp_types".}

proc pcapFreeTstampTypes*(handle: Pcap): cint
    {.importc: "pcap_free_tstamp_types".}

proc pcapTstampTypeNameToVal*(typeName: cstring): cint
    {.importc: "pcap_tstamp_type_name_to_val".}

proc pcapTstampTypeValToName*(typeVal: cint): cstring
    {.importc: "pcap_tstamp_type_val_to_name".}

proc pcapTstampTypeValToDescription*(typeVal: cint): cstring
    {.importc: "pcap_tstamp_type_val_to_description".}

when defined(Linux):
    proc pcapSetProtocolLinux*(handle: Pcap, protocol: cint): cint
        {.importc: "pcap_set_protocol_linux".}

proc pcapOpenLive*(device: cstring, snapLen: cint, promisc: cint, toMs: cint, errorBuf: var cstring): Pcap
    {.importc: "pcap_open_live".}

proc pcapOpenDead*(linkType: cint, snapLen: cint): Pcap
    {.importc: "pcap_open_dead".}

proc pcapOpenDeadWithTstampPrecision*(linkType: cint, snapLen: cint, precision: cuint): Pcap
    {.importc: "pcap_open_dead_with_tstamp_precision".}

proc pcapOpenOfflineWithTstampPrecision*(fname: cstring, errorBuf: var cstring): Pcap
    {.importc: "pcap_open_offline_with_tstamp_precision".}

proc pcapOpenOffline*(fname: cstring, errorBuf: var cstring): Pcap
    {.importc: "pcap_open_offline".}

proc pcapFopenOffline*(filePointer: File, errorBuf: var cstring): Pcap
    {.importc: "pcap_fopen_offline".}

proc pcapFopenOfflineWithTstampPrecision*(filePointer: File, precision: cuint, errorBuf: var cstring): Pcap
    {.importc: "pcap_fopen_offline_with_timestamp_precision".}

proc pcapClose*(handle: Pcap)
    {.importc: "pcap_close".}

proc pcapLoop*(handle: Pcap, count: cint, callback: PcapHandler, user: ptr char)
    {.importc: "pcap_loop".}

proc pcapDispatch*(handle: Pcap, count: cint, callback: PcapHandler, user: ptr char)
    {.importc: "pcap_dispatch".}

proc pcapNext*(handle: Pcap, packetHeader: ptr PcapPacketHeader): ptr byte
    {.importc: "pcap_next".}

proc pcapNextEx*(handle: Pcap, header: var PcapPacketHeader, packetBuff: ptr byte): cint
    {.importc: "pcap_next_ex".}

proc pcapBreakLoop*(handle: Pcap)
    {.importc: "pcap_breakloop".}

proc pcapStats*(handle: Pcap, pcapStats: PcapStat): cint
    {.importc: "pcap_stats".}

proc pcapSetFilter*(handle: Pcap, bpfProgram: BpfProgram): cint
    {.importc: "pcap_setfilter".}

proc pcapSetDirection*(handle: Pcap, direction: PcapDirection): cint
    {.importc: "pcap_setdirection".}

proc pcapGetNonblock*(handle: Pcap, errorBuf: var cstring): cint
    {.importc: "pcap_getnonblock".}

proc pcapSetNonblock*(handle: Pcap, nonblock: cint, errorBuf: var cstring): cint
    {.importc: "pcap_setnonblock".}

proc pcapInject*(handle: Pcap, buffer: pointer, size: csize_t): cint
    {.importc: "pcap_inject".}

proc pcapSendPacket*(handle: Pcap, buffer: ptr uint8, size: cint): cint
    {.importc: "pcap_sendpacket".}

proc pcapStatusToStr*(status: cint): cstring
    {.importc: "pcap_statustostr".}

proc pcapStrError*(status: cint): cstring
    {.importc: "pcap_strerror".}

proc pcapGetErr*(handle: Pcap): cstring
    {.importc: "pcap_geterr".}

proc pcapPerror*(handle: Pcap, prefix: cstring)
    {.importc: "pcap_perror".}

proc pcapCompile*(handle: Pcap, bpfProgram: BpfProgram, str: cstring, optimize: cint, netmask: uint32): cint
    {.importc: "pcap_compile".}

proc pcapCompileNoPcap*(snaplen: cint, linktype: cint, bpfProgram: BpfProgram, str: cstring, optimize, cint, netmask: uint32): cint
    {.importc: "pcap_compile_nopcap".}

proc pcapFreeCode*(bpfProgram: BpfProgram)
    {.importc: "pcap_freecode".}

proc pcapOfflineFilter*(bpfProgram: BpfProgram, packetHeader: PcapPacketHeader, pkt: ptr uint8): cint
    {.importc: "pcap_offline_filter".}

proc pcapDatalink*(handle: Pcap): cint
    {.importc: "pcap_datalink".}

proc pcapDatalinkExt*(handle: Pcap): cint
    {.importc: "pcap_datalink_ext".}

proc pcapListDatalinks*(handle: Pcap, dltBuf: ptr cint): cint
    {.importc: "pcap_list_datalinks".}

proc pcapSetDatalink*(handle: Pcap, datalink: cint): cint
    {.importc: "pcap_set_datalink".}

proc pcapFreeDatalinks*(dltList: ptr cint)
    {.importc: "pcap_free_datalinks".}

proc pcapDatalinkNameToVal*(name: cstring): cint
    {.importc: "pcap_datalink_name_to_val".}

proc pcapDatalinkValToName*(val: cint): cstring
    {.importc: "pcap_datalink_val_to_name".}

proc pcapDatalinkValToDescription*(val: cint): cstring
    {.importc: "pcap_datalink_val_to_description".}

proc pcapDatalinkValToDescriptionOrDlt*(val: cint): cstring
    {.importc: "pcap_datalink_val_to_description_or_dlt".}

proc pcapSnapshot*(handle: Pcap): cint
    {.importc: "pcap_snapshot".}

proc pcapIsSwapped*(handle: Pcap): cint
    {.importc: "pcap_is_swapped".}

proc pcapMajorVersion*(handle: Pcap): cint
    {.importc: "pcap_major_version".}

proc pcapMinorVersion*(handle: Pcap): cint
    {.importc: "pcap_minor_version".}

proc pcapBufsize*(handle: Pcap): cint
    {.importc: "pcap_bufsize".}

proc pcapFile*(handle: Pcap): File
    {.importc: "pcap_file".}

proc pcapFileNo*(handle: Pcap): cint
    {.importc: "pcap_fileno".}

proc pcapWsockinit*(): cint
    {.importc: "pcap_wsockinit".}

proc pcapDumpOpen*(handle: Pcap, fname: cstring): PcapDumper
    {.importc: "pcap_dump_open".}

proc pcapDumpFopen*(handle: Pcap, filePointer: File): PcapDumper
    {.importc: "pcap_dump_fopen".}

proc pcapDumpOpenAppend*(handle: Pcap, fname: cstring): PcapDumper
    {.importc: "pcap_dump_open_append".}

proc pcapDumpFile*(pd: PcapDumper): File
    {.importc: "pcap_dump_file".}

proc pcapDumpFtell*(pd: PcapDumper): clong
    {.importc: "pcap_dump_ftell".}

proc pcapDumpFtell64*(pd: PcapDumper): int64
    {.importc: "pcap_dump_ftell64".}

proc pcapDumpFlush*(pd: PcapDumper): cint
    {.importc: "pcap_dump_flush".}

proc pcapDumpClose*(pd: PcapDumper)
    {.importc: "pcap_dump_close".}

proc pcapDump*(dumpFile: PcapDumper, packetHeader: PcapPacketHeader, pkt: ptr uint8)
    {.importc: "pcap_dump".}

proc pcapFindAllDevs*(iface: var PcapIf, errorStr: cstring): cint
    {.importc: "pcap_findalldevs".}

proc pcapFreeAllDevs*(iface: var PcapIf)
    {.importc: "pcap_freealldevs".}

proc pcapLibVersion*(): cstring
    {.importc: "pcap_lib_version".}

when defined(Windows):
    type
        PcapSendQueue* = object
            maxLen*: cuint
            len*: cuint
            buffer*: ptr uint8

        PAirPcapHandle* = pointer

    proc pcapSetBuff*(handle: Pcap, dim: cint): cint
        {.importc: "pcap_setbuff".}

    proc pcapSetMode*(handle: Pcap, mode: cint): cint
        {.importc: "pcap_setmode".}

    proc pcapSetMinToCopy*(handle: Pcap, size: cint): cint
        {.importc: "pcap_setmintocopy".}

    proc pcapGetEvent*(handle: Pcap): pointer
        {.importc: "pcap_getevent".}

    proc pcapOidGetRequest*(handle: Pcap, val: uint32, voidPtr: pointer, sizePtr: openarray[byte]): cint
        {.importc: "pcap_oid_get_request".}

    proc pcapOidSetRequest*(handle: Pcap, val: uint32, voidPtr: pointer, sizePtr: openarray[byte]): cint
        {.importc: "pcap_oid_set_request".}

    proc pcapSendQueueAlloc*(memSize: cuint): PcapSendQueue
        {.importc: "pcap_sendqueue_alloc".}

    proc pcapSendQueueDestroy*(queue: PcapSendQueue)
        {.importc: "pcap_sendqueue_destroy".}

    proc pcapSendQueueTransmit*(handle: Pcap, queue: PcapSendQueue, sync: cint): cuint
        {.importc: "pcap_sendqueue_transmit".}

    proc pcapStatsEx*(handle: Pcap, pcapStatSize: cint): PcapStat
        {.importc: "pcap_stats_ex".}

    proc pcapSetUserBuffer*(handle: Pcap, size: cint): cint
        {.importc: "pcap_setuserbuffer".}

    proc pcapLiveDump*(handle: Pcap, fileName: cstring, maxSize: cint, maxPacks: cint): cint
        {.importc: "pcap_live_dump".}

    proc pcapLiveDumpEnded*(handle: Pcap, sync: cint): cint
        {.importc: "pcap_live_dump_ended".}
    
    proc pcapStartOem*(errorBuf: var cstring, flags: cint): cint
        {.importc: "pcap_start_oem".}

    proc pcapGetAircapHandle*(handle: Pcap): PAirPcapHandle
        {.importc: "pcap_get_airpcap".}
  
when defined(Linux):
    proc pcapGetSelectableFd*(handle: Pcap): cint
        {.importc: "pcap_get_selectable_fd".}

    proc pcapGetRequiredSelectTimeout*(handle: Pcap): TimeVal
        {.importc: "pcap_get_required_select_timeout".}

proc pcapOpen*(source: cstring, snapLen: cint, flags: cint, readTimeout: cint, auth: PcapRmtAuth, errorBuf: var cstring): Pcap
    {.importc: "pcap_open".}

proc pcapCreateSrcStr*(source: cstring, srcType: cint, host: cstring, port: cstring, name: cstring, errorBuf: var cstring): cint
    {.importc: "pcap_createsrcstr".}

proc pcapParseSrcStr*(source: cstring, srcType: cint, host: var cstring, port: cstring, name: cstring, errorBuf: var cstring): cint
    {.importc: "pcap_parsesrcstr".}

proc pcapFindAllDevsEx*(source: cstring, auth: PcapRmtAuth, alldevs: var PcapIf, errorBuf: var cstring): cint
    {.importc: "pcap_findalldevs_ex".}

proc pcapSetSampling*(handle: Pcap): PcapSamp
    {.importc: "pcap_setsampling".}

proc pcapRemoteActAccept*(address: cstring, port: cstring, hostlist: cstring, connectingHost: var cstring, auth: var PcapRmtAuth, errorBuf: var cstring): Socket
    {.importc: "pcap_remoteact_accept".}

proc pcapRemoteActAcceptEx*(address: cstring, port: cstring, hostlist: cstring, connectingHost: var cstring, auth: var PcapRmtAuth, usesSSL: cint, errorBuf: var cstring): Socket
    {.importc: "pcap_remoteact_accept".}

proc pcapRemoteActList*(hostList: var cstring, sep: char, size: cint, errorBuf: var cstring): cint
    {.importc: "pcap_remoteact_list".}

proc pcapRemoteActClose*(host: cstring, errorBuf: var cstring): cint
    {.importc: "pcap_remoteact_close".}

proc pcapRemoteActCleanup*(voidPtr: pointer)
    {.importc: "pcap_remoteact_cleanup".}

{.pop.}
