local tcpPortLs = {7555}

local SIZE_LEN = 4
local pErlangExt = Proto("ErlangExt", "erlang term")
local fLen = ProtoField.uint32("ErlangExt.len", "PackageLength", base.DEC)
local fCompressFlag = ProtoField.string("ErlangExt.compressFlag", "compressFlag", base.ASCII)
local fBytes = ProtoField.bytes("ErlangExt.data", "PackageData", base.COLON)

pErlangExt.fields = {
    fLen,
    fBytes,
    fCompressFlag,
}

local function msg_pdu_length(buf, pkt, offset)
    local size_tvbr = buf:range(offset, SIZE_LEN)
    local size = size_tvbr:uint()
    return size + SIZE_LEN
end

local function _headBytes(n, dataBuf)
    local head = dataBuf(0, n)
    if dataBuf:len() == n then
        return head, nil
    end
    local tailDataBuf = dataBuf(n, dataBuf:len() - n)
    return head, tailDataBuf
end

local function _addToGroup()
    -- ...
end

local function _calcMainTree()
    -- ...
end

local function msg_proto_dissector(buf, pkt, root)
    local dataLenBuf, metaAndDataBytes = _headBytes(SIZE_LEN, buf)
    local detail = root:add(pErlangExt, buf)
    local dataLen = dataLenBuf:uint()
    detail:add(fLen, dataLenBuf, dataLen)
    local zlibFlagBuf, tupleDataBuf = _headBytes(1, metaAndDataBytes)
    local zlibFlag = zlibFlagBuf:uint()
    detail:add(fCompressFlag, zlibFlagBuf, zlibFlag)
    local dataRoot = detail:add(fBytes, tupleDataBuf)
    pkt.cols.protocol = "ErlangExt"
    local tree = _calcMainTree(tupleDataBuf, zlibFlag)
    _addToGroup(dataRoot, tree)
end

function pErlangExt.dissector(buf, pkt, root)
    local pktLen = buf:len()
    if pktLen ~= buf:reported_len() then
        return 0
    end
    dissect_tcp_pdus(buf, root, 4, msg_pdu_length, msg_proto_dissector)
    return pktLen
end

local tcp_encap_table = DissectorTable.get("tcp.port")
-- --只需要处理TCP端口就可以了
for _, port in pairs(tcpPortLs) do
    tcp_encap_table:add(port, pErlangExt)
end
