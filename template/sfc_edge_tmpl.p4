/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 4

const bit<16> TYPE_SFC = 0x1234;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

const bit<2> STATUS_INIT = 0;
const bit<2> STATUS_RUNNING = 1;
const bit<2> STATUS_FAILED = 2;
const bit<2> STATUS_DONE = 3;

const bit<2> QOS_TOP = 0;
const bit<2> QOS_HIGH = 1;
const bit<2> QOS_MEDIUM = 2;
const bit<2> QOS_LOW = 3;

const bit<4> APP_TYPE_GENERAL = 0;
const bit<4> APP_TYPE_WEB = 1;

const bit<6> SVC_TYPE_PROXY = 0;
const bit<6> SVC_TYPE_FIRWALL = 1;
const bit<6> SVC_TYPE_QOS = 2;
const bit<6> SVC_TYPE_LOAD_BALANCE = 3;

const bit<15> CONTEXT_PROXY= 1000;
const bit<15> CONTEXT_FIREWALL = 1024;
const bit<15> CONTEXT_QOS = 1336;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header sfc_header_t {
    bit<2> version; 
    bit<4> max_size;
    bit<4> app_type;
    bit<2> qos;
    bit<4> dst_id;
}

header sfc_service_t {
    bit<6> svc_type;
    bit<2> status;
    bit<4> act;
    bit<4> params;
}

header sfc_context_t {
    bit<1>  bos;
    bit<15> content;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    sfc_header_t            sfc_header;
    sfc_service_t           sfc_service;
    sfc_context_t[MAX_HOPS] sfc_context;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SFC: parse_sfc_header;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_sfc_header {
        packet.extract(hdr.sfc_header);
        transition parse_sfc_service;
    }

    state parse_sfc_service {
        packet.extract(hdr.sfc_service);
        transition parse_sfc_context;
    }

    state parse_sfc_context {
        packet.extract(hdr.sfc_context.next);
        transition select(hdr.sfc_context.last.bos) {
            1: parse_ipv4;
            default: parse_sfc_context;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action enable_sfc(bit<4> max_size, bit<2> qos, bit<4> dst_id, bit<4> app_type) {
        hdr.sfc_header.setValid();
        hdr.sfc_header.version = (bit<2>) 1;
        hdr.sfc_header.max_size = max_size;
        hdr.sfc_header.app_type = app_type;
        hdr.sfc_header.qos = qos;
        hdr.sfc_header.dst_id = dst_id;

        hdr.sfc_service.setValid();
        hdr.sfc_service.status = STATUS_INIT;
        hdr.sfc_service.svc_type = SVC_TYPE_PROXY;
        
        hdr.ethernet.etherType = TYPE_SFC;
    }

    action update_sfc_service(bit<6> svc_type, 
                              bit<2> status,
                              bit<4> act,
                              bit<4> params) {
        hdr.sfc_service.svc_type = svc_type;
        hdr.sfc_service.status = status;
        hdr.sfc_service.act = act;
        hdr.sfc_service.params = params;
    }

    action add_sfc_context(bit<15> content) {
        hdr.sfc_context.push_front(1);
        hdr.sfc_context[0].setValid();
        hdr.sfc_context[0].content = content;

        // Set the last context to be 1
        hdr.sfc_context[hdr.sfc_context.size - 1].bos = 1;
    }

    action forward_sfc(egressSpec_t port, bit<6> svc_type) {
        standard_metadata.egress_spec = port;
        update_sfc_service(svc_type, STATUS_RUNNING, 0, 0);
    }

    action disable_sfc(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action check_sfc_service() {
        // Simply used in check, so no-ops
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            enable_sfc;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table sfc_forward_exact {
        key = {
            hdr.sfc_header.app_type: exact;
            hdr.sfc_header.dst_id: exact;
            hdr.sfc_service.act: exact;
        }
        actions = {
            forward_sfc;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table sfc_disable_exact {
        key = {
            hdr.sfc_header.dst_id: exact;
        }
        actions = {
            disable_sfc;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table sfc_service_exact {
        key = {
            hdr.sfc_header.app_type: exact;
            hdr.sfc_service.svc_type: exact;
        }
        actions = {
            check_sfc_service;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.sfc_header.isValid()) {
            // Process only non-served IPv4 packets.
            ipv4_lpm.apply();
        }

        if (hdr.sfc_header.isValid() && sfc_service_exact.apply().hit) {
            add_sfc_context(CONTEXT_PROXY);
            hdr.sfc_context[0].bos = 1;

            if (sfc_forward_exact.apply().miss) {
                if (sfc_disable_exact.apply().hit) {
                    // Disable header and service
                    hdr.sfc_header.setInvalid();
                    hdr.sfc_service.setInvalid();

                    // Disable all context
                    bit<4> tmp = 0;
                    bit<4> size = (bit<4>)hdr.sfc_context.size;
                    
                    // Disable sfc context header
                    // We assume max size = 4
                    if (tmp < size) {
                        hdr.sfc_context[tmp].setInvalid();
                        tmp = tmp + 1;
                    }
                    if (tmp < size) {
                        hdr.sfc_context[tmp].setInvalid();
                        tmp = tmp + 1;
                    }
                    if (tmp < size) {
                        hdr.sfc_context[tmp].setInvalid();
                        tmp = tmp + 1;
                    }
                    if (tmp < size) {
                        hdr.sfc_context[tmp].setInvalid();
                        tmp = tmp + 1;
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.sfc_header);
        packet.emit(hdr.sfc_service);
        packet.emit(hdr.sfc_context);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
