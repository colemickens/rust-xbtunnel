#[crate_id="tunnelrs"];
#[crate_type="bin"];
#[desc = "Xbox Tunnel"];
#[license = "MIT"];

#[feature(globs)];

extern mod native;
extern mod extra;
extern mod pcapfe;
extern mod pktutil;

use std::comm::*;

use std::hashmap::*;
use std::io::net::ip;
use std::io::net::udp;
use std::io::net::udp::{UdpSocket};
use std::os;
use std::sync::arc::UnsafeArc;

use extra::getopts::*;

use pktutil::*;
use pcapfe::*;

#[start]
fn start(argc: int, argv: **u8) -> int {
    do native::start(argc, argv) {
        main();
    }
}

static BROADCAST: &'static[u8] = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

struct Packet { src_mac: ~[u8], dst_mac: ~[u8], payload: ~[u8] }
impl Packet {
    fn as_raw_packet(&self) -> ~[u8] {
        let eth_hdr = EthernetHeader{
            dst_mac:   self.dst_mac.to_owned(),
            src_mac:   self.src_mac.to_owned(),
            ethertype: Ethertype_IP,
        };

        let ip_hdr = Ipv4Header{
            version:       4,
            total_len:     0,
            diff_services: 0x00,
            ecn:           0x00,
            id:            0x0000, // set this dynamically -- is this transparently copied or what?
            flags:         0x02,
            frag_offset:   0,
            ttl:           64,
            checksum:      0x0000, // will have to write the functions to calculate it
            src_ip:        ip::Ipv4Addr(0, 0, 0, 1),
            dst_ip:        ip::Ipv4Addr(0, 0, 0, 1),
            ihl:           5, // none?
            protocol:      UserDatagram,
            options:       ~[],
        };

        let udp_hdr = UdpHeader{
            src_port:  3074,
            dst_port:  3074,
            length:    2, // set this
            checksum:  0x0000,
        };
        
        let mut res_bytes = eth_hdr.as_bytes();
        res_bytes.push_all(ip_hdr.as_bytes());
        res_bytes.push_all(udp_hdr.as_bytes());
        res_bytes.push_all(self.payload);

        // make new fns that go from eth_hdr -> eth_hdr with proper len and checksum
        // (or take params and then generate a complete one or both?)

        // TODO: make this into an api-able thing better what yeah.....


        res_bytes
    }

    fn as_udp_payload(&self) -> ~[u8] {
        let mut byts = self.payload.to_owned();
        byts.push_all(self.src_mac.to_owned());
        byts.push_all(self.dst_mac.to_owned());
        byts
    }
}

fn from_pcap(payload: ~[u8]) -> Option<Packet> {
    match decode_packet(payload) {
        UdpPacket(ehdr, _ihdr, _uhdr, pld) => {
            Some(Packet{
                src_mac: ehdr.src_mac.to_owned(),
                dst_mac: ehdr.dst_mac.to_owned(),
                payload: pld.to_owned(),
            })
        },
        _ => { None },
    }
}

fn from_udp_payload(payload: &[u8]) -> Option<Packet> {
    if payload.len() < 50 {
        None
    } else {
        Some(Packet{
            payload: payload.slice(0,                payload.len()-12).to_owned(),
            src_mac: payload.slice(payload.len()-12, payload.len()-6).to_owned(),
            dst_mac: payload.slice(payload.len()-6,  payload.len()).to_owned(),
        })
    }
}

fn packet_capture_inject_loop(dev: &str, capture_chan: Chan<Packet>, inject_port: Port<Packet>, pcap_update_port: Port<~[u8]>) {
    let dev1: ~str = dev.to_str();
    let dev2: ~str = dev.to_str();

    println!("prespawn1");
    spawn(proc(){
        let cap_dev = pcap_open_dev(dev1).unwrap();
        let mut filter_str = ~"host 0.0.0.1 && udp";

        if cap_dev.set_filter(dev1, filter_str).is_err() {
            fail!("couldn't set filter");
        }

        loop {
            match cap_dev.next_packet_ex() {
                Ok(pcap_pkt) => match from_pcap(pcap_pkt.payload) {
                    Some(pkt) => {
                        println!("got pcap packet");
                        capture_chan.send(pkt);
                    },
                    None => {
                        println!("bad pkt");
                    },
                },
                Err(NextEx_Timeout) => {
                    println!("timeout");
                },
                Err(t) => {
                    fail!(format!("{:?}", t));
                }
            }
            match pcap_update_port.try_recv() {
                Data(addr) => {
                    filter_str = filter_str.append(format!(" && !(ether src {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X})",
                        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]));

                    if cap_dev.set_filter(dev1, filter_str).is_err() {
                        fail!("couldn't set filter");
                    } else {
                        println!("set filter {}", filter_str);
                    }
                }
                Empty => {}
                Disconnected => { return; }
            }
        }
    });
    println!("postspawn1");

    println!("prespawn2");
    spawn(proc(){
        let cap_dev = pcap_open_dev(dev2).unwrap();
        loop {
            let pkt = inject_port.recv();
            let res = cap_dev.inject(pkt.as_raw_packet());
            println!("inject res {}", res);
        }
    });
    println!("postspawn2");
}

fn main() {
    let args = os::args();
    let opts = ~[
        optflag("host"),
        optopt("join"),
        reqopt("dev")
    ];
    
    let args = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()); }
    };

    if !args.opt_present("host") && !args.opt_present("join") {
        fail!("Must host or join.")
    }

    if args.opt_present("host") && args.opt_present("join") {
        fail!("Can't host and join.")
    }

    let dev = args.opt_str("dev").expect("device is required");

    let (capture_port, capture_chan): (Port<Packet>, Chan<Packet>) = Chan::new();
    let (inject_port, inject_chan): (Port<Packet>, Chan<Packet>) = Chan::new();

    let (pcap_update_port, pcap_update_chan): (Port<~[u8]>, Chan<~[u8]>) = Chan::new();
    
    println!("inject_loop starting");
    packet_capture_inject_loop(dev, capture_chan, inject_port, pcap_update_port);
    println!("inject_loop started");

    if args.opt_present("host") {
        let (xbox_update_port, xbox_update_chan): (Port<(~[u8], ip::SocketAddr)>, Chan<(~[u8], ip::SocketAddr)>) = Chan::new();

        let udp_sock = udp::UdpSocket::bind(
            ip::SocketAddr{ ip: ip::Ipv4Addr(0,0,0,0),
                port: 8602 as ip::Port
            }
        ).expect("can't bind to 8602");

        let (udp_send_arc, udp_recv_arc) = UnsafeArc::new2(udp_sock);

        spawn(proc() {   // This is the udp_send loop (read from capture_port)
            let mut xbox_to_socketaddr_a: HashMap<~[u8], ip::SocketAddr> = HashMap::new();
            let udp_sock = udp_send_arc.get();
            loop {
                match capture_port.try_recv() {
                    Data(pkt) => {
                        // check if broadcast
                        if BROADCAST == pkt.dst_mac {
                            for sa in xbox_to_socketaddr_a.values() {
                                unsafe {
                                    (*udp_sock).sendto(pkt.as_udp_payload(), *sa);    
                                }
                            }
                        } else {
                            match xbox_to_socketaddr_a.find(&pkt.dst_mac) {
                                Some(sa) => {
                                    unsafe {
                                        println!("about to send packet");
                                        (*udp_sock).sendto(pkt.as_udp_payload(), *sa);
                                    }
                                }
                                None => { println!("dunna where this goes"); }
                            }
                        }
                    },
                    Disconnected => { return; },
                    Empty => { /* skip over, keep going */ }
                }
                match xbox_update_port.try_recv() {
                    Data((src_mac, sockaddr)) => {
                        xbox_to_socketaddr_a.insert(src_mac, sockaddr);
                    },
                    Disconnected => { return; },
                    Empty => {},
                }
                //println!(".");
            }
        });

        {   // This is the udp_recv loop (writes to inject_chan)
            let udp_sock = udp_recv_arc.get();

            let mut xbox_to_socketaddr = HashMap::new();
            let mut byts = [0u8,..65536];
            loop {
                let (sz, sockaddr) = unsafe { (*udp_sock).recvfrom(byts).unwrap() };
                let pkt = match from_udp_payload(byts.slice_to(sz)) { Some(pkt) => {pkt}, None => {println!("skipping bad packet"); continue;}};

                let new_entry = xbox_to_socketaddr.insert(pkt.src_mac.to_owned(), sockaddr);
                if new_entry {
                    xbox_update_chan.send((pkt.src_mac.to_owned(), sockaddr));
                    pcap_update_chan.send(pkt.src_mac.to_owned());
                }
                inject_chan.send(pkt);
            }
        }
    } else if args.opt_present("join") {
        let remote_host = args.opt_str("join").expect("join requires an argument");
        let saddr: ip::SocketAddr = from_str(remote_host).expect("failed to parse the remote host");
        let bind_addr: ip::SocketAddr = from_str("0.0.0.0:0").unwrap();

        let udp_sock: UdpSocket = UdpSocket::bind(bind_addr).expect("couldn't bind to outgoing udp");

        let (udp_send_arc, udp_recv_arc) = UnsafeArc::new2(udp_sock);
        println!("senxxxxxxxxxxxxxxxxxxx");

        spawn(proc() { // the udp recv loop (writes to inject chan)
            let udp_sock = udp_recv_arc.get();
            let mut byts = [0u8,..65536];
            loop {
                let (sz, _sa) = unsafe{ (*udp_sock).recvfrom(byts).unwrap() };
                match from_udp_payload(byts.slice_to(sz)) {
                    Some(pkt) => {
                        inject_chan.send(pkt);
                    },
                    None => { println!("skipping bad udp payload"); }
                }
            }
        });

        { // the udp send loop (read from capture_chan)
            let udp_sock = udp_send_arc.get();
            loop {
                // TODO: Remove this silliness
                unsafe { (*udp_sock).sendto([0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,], saddr); }
                println!("sent something as a test");
                //

                let pkt = capture_port.recv();
                let pkt_udp = pkt.as_udp_payload();
                unsafe {
                    (*udp_sock).sendto(pkt_udp, saddr);
                }
            }
        }
    }
}