//! Flow reconstruction and per-connection parser dispatch.
//!
//! One event on the wire rarely corresponds to one L7 message. A single
//! HTTP response might arrive over several `tcp_recvmsg` calls; a single
//! `tcp_sendmsg` might carry two small requests (pipelining). We keep a
//! bounded byte buffer per `(connection, direction)` and feed it to the
//! protocol parser we've selected for that connection.
//!
//! Connection identity:
//! - TCP events: `(pid, sock_id)`
//! - TLS events: `(pid, conn_id)` (library-specific pointer; SSL* for OpenSSL)
//!
//! Protocol detection uses two signals:
//! 1. **Destination port** — well-known port picks a parser immediately.
//! 2. **First bytes** — signature match on the head of the stream.
//!
//! Once a protocol is locked in we stay with that parser for the life of
//! the connection; a parser can still decide on its own to `Bypass` and
//! start returning `Skip(buf.len())` if the stream goes sideways.

use std::collections::HashMap;

use crate::events::Direction;
use crate::parsers::{
    amqp::{AmqpParser, AmqpParserOutput, AmqpRecord},
    bacnet::{BacnetParser, BacnetParserOutput, BacnetRecord},
    cassandra::{CassandraParser, CqlParserOutput, CqlRecord},
    dhcp::{DhcpParser, DhcpParserOutput, DhcpRecord},
    dnp3::{Dnp3Parser, Dnp3ParserOutput, Dnp3Record},
    dns::{DnsParser, DnsParserOutput, DnsRecord},
    enip::{EnipParser, EnipParserOutput, EnipRecord},
    ftp::{FtpParser, FtpParserOutput, FtpRecord},
    http1::{Http1Parser, ParsedRecord as Http1Record, ParserOutput as Http1Output},
    http2::{Http2Parser, Http2ParserOutput, Http2Record},
    iec104::{Iec104Parser, Iec104ParserOutput, Iec104Record},
    imap::{ImapParser, ImapParserOutput, ImapRecord},
    irc::{IrcParser, IrcParserOutput, IrcRecord},
    kafka::{KafkaParser, KafkaParserOutput, KafkaRecord},
    kerberos::{KerberosParser, KerberosParserOutput, KerberosRecord},
    ldap::{LdapParser, LdapParserOutput, LdapRecord},
    memcached::{McParserOutput, McRecord, MemcachedParser},
    modbus::{ModbusParser, ModbusParserOutput, ModbusRecord},
    mongodb::{MongoParser, MongoParserOutput, MongoRecord},
    mqtt::{MqttParser, MqttParserOutput, MqttRecord},
    mssql::{MssqlParser, MssqlParserOutput, MssqlRecord},
    mysql::{MysqlParser, MysqlParserOutput, MysqlRecord},
    nats::{NatsParser, NatsParserOutput, NatsRecord},
    nfs::{NfsParser, NfsParserOutput, NfsRecord},
    ntp::{NtpParser, NtpParserOutput, NtpRecord},
    opcua::{OpcuaParser, OpcuaParserOutput, OpcuaRecord},
    oracle::{OracleParser, OracleParserOutput, OracleRecord},
    pop3::{Pop3Parser, Pop3ParserOutput, Pop3Record},
    postgres::{PgParserOutput, PgRecord, PostgresParser},
    quic::{QuicParser, QuicParserOutput, QuicRecord},
    radius::{RadiusParser, RadiusParserOutput, RadiusRecord},
    rdp::{RdpParser, RdpParserOutput, RdpRecord},
    redis::{RedisParser, RedisParserOutput, RedisRecord},
    rtsp::{RtspParser, RtspParserOutput, RtspRecord},
    s7comm::{S7Parser, S7ParserOutput, S7Record},
    sip::{SipParser, SipParserOutput, SipRecord},
    smb::{SmbParser, SmbParserOutput, SmbRecord},
    smpp::{SmppParser, SmppParserOutput, SmppRecord},
    smtp::{SmtpParser, SmtpParserOutput, SmtpRecord},
    snmp::{SnmpParser, SnmpParserOutput, SnmpRecord},
    socks::{SocksParser, SocksParserOutput, SocksRecord},
    ssh::{SshParser, SshParserOutput, SshRecord},
    stun::{StunParser, StunParserOutput, StunRecord},
    syslog::{SyslogParser, SyslogParserOutput, SyslogRecord},
    tacacs::{TacacsParser, TacacsParserOutput, TacacsRecord},
    telnet::{TelnetParser, TelnetParserOutput, TelnetRecord},
    tftp::{TftpParser, TftpParserOutput, TftpRecord},
    tls::{TlsParser, TlsParserOutput, TlsRecord},
    websocket::{WebSocketParser, WsParserOutput, WsRecord},
    wireguard::{WireguardParser, WireguardParserOutput, WireguardRecord},
};

const BUF_CAP: usize = 64 * 1024;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub enum FlowKey {
    Tcp { pid: u32, sock_id: u64 },
    Tls { pid: u32, conn_id: u64 },
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    #[default]
    Unknown,
    Http1,
    Http2,
    Postgres,
    Mysql,
    Redis,
    Mongodb,
    Kafka,
    Cassandra,
    Memcached,
    Mqtt,
    Nats,
    WebSocket,
    Pop3,
    Smtp,
    Imap,
    Modbus,
    Ldap,
    OpcUa,
    Iec104,
    Ssh,
    Dnp3,
    S7,
    Enip,
    Bacnet,
    Stun,
    Ftp,
    Sip,
    Tls,
    Rdp,
    Socks,
    Telnet,
    Ntp,
    Radius,
    Syslog,
    Amqp,
    Kerberos,
    Oracle,
    Mssql,
    Dhcp,
    Tftp,
    Tacacs,
    Snmp,
    Smb,
    WireGuard,
    Irc,
    Nfs,
    Rtsp,
    Smpp,
    Dns,
    Mdns,
    Quic,
    Bypass,
}

impl Protocol {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "?",
            Self::Http1 => "http",
            Self::Http2 => "h2",
            Self::Postgres => "pg",
            Self::Mysql => "mysql",
            Self::Redis => "redis",
            Self::Mongodb => "mongo",
            Self::Kafka => "kafka",
            Self::Cassandra => "cql",
            Self::Memcached => "mc",
            Self::Mqtt => "mqtt",
            Self::Nats => "nats",
            Self::WebSocket => "ws",
            Self::Pop3 => "pop3",
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Modbus => "modbus",
            Self::Ldap => "ldap",
            Self::OpcUa => "opcua",
            Self::Iec104 => "iec104",
            Self::Ssh => "ssh",
            Self::Dnp3 => "dnp3",
            Self::S7 => "s7",
            Self::Enip => "enip",
            Self::Bacnet => "bacnet",
            Self::Stun => "stun",
            Self::Ftp => "ftp",
            Self::Sip => "sip",
            Self::Tls => "tls",
            Self::Rdp => "rdp",
            Self::Socks => "socks",
            Self::Telnet => "telnet",
            Self::Ntp => "ntp",
            Self::Radius => "radius",
            Self::Syslog => "syslog",
            Self::Amqp => "amqp",
            Self::Kerberos => "krb5",
            Self::Oracle => "oracle",
            Self::Mssql => "mssql",
            Self::Dhcp => "dhcp",
            Self::Tftp => "tftp",
            Self::Tacacs => "tacacs+",
            Self::Snmp => "snmp",
            Self::Smb => "smb",
            Self::WireGuard => "wg",
            Self::Irc => "irc",
            Self::Nfs => "nfs",
            Self::Rtsp => "rtsp",
            Self::Smpp => "smpp",
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Quic => "quic",
            Self::Bypass => "-",
        }
    }
}

pub enum AnyRecord {
    Http1(Box<Http1Record>),
    Http2(Box<Http2Record>),
    Postgres(Box<PgRecord>),
    Mysql(Box<MysqlRecord>),
    Redis(Box<RedisRecord>),
    Mongodb(Box<MongoRecord>),
    Kafka(Box<KafkaRecord>),
    Cassandra(Box<CqlRecord>),
    Memcached(Box<McRecord>),
    Mqtt(Box<MqttRecord>),
    Nats(Box<NatsRecord>),
    WebSocket(Box<WsRecord>),
    Pop3(Box<Pop3Record>),
    Smtp(Box<SmtpRecord>),
    Imap(Box<ImapRecord>),
    Modbus(Box<ModbusRecord>),
    Ldap(Box<LdapRecord>),
    OpcUa(Box<OpcuaRecord>),
    Iec104(Box<Iec104Record>),
    Ssh(Box<SshRecord>),
    Dnp3(Box<Dnp3Record>),
    S7(Box<S7Record>),
    Enip(Box<EnipRecord>),
    Bacnet(Box<BacnetRecord>),
    Stun(Box<StunRecord>),
    Ftp(Box<FtpRecord>),
    Sip(Box<SipRecord>),
    Tls(Box<TlsRecord>),
    Rdp(Box<RdpRecord>),
    Socks(Box<SocksRecord>),
    Telnet(Box<TelnetRecord>),
    Ntp(Box<NtpRecord>),
    Radius(Box<RadiusRecord>),
    Syslog(Box<SyslogRecord>),
    Amqp(Box<AmqpRecord>),
    Kerberos(Box<KerberosRecord>),
    Oracle(Box<OracleRecord>),
    Mssql(Box<MssqlRecord>),
    Dhcp(Box<DhcpRecord>),
    Tftp(Box<TftpRecord>),
    Tacacs(Box<TacacsRecord>),
    Snmp(Box<SnmpRecord>),
    Smb(Box<SmbRecord>),
    WireGuard(Box<WireguardRecord>),
    Irc(Box<IrcRecord>),
    Nfs(Box<NfsRecord>),
    Rtsp(Box<RtspRecord>),
    Smpp(Box<SmppRecord>),
    Dns(Box<DnsRecord>),
    Quic(Box<QuicRecord>),
}

impl AnyRecord {
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Http1(_) => "http",
            Self::Http2(_) => "h2",
            Self::Postgres(_) => "pg",
            Self::Mysql(_) => "mysql",
            Self::Redis(_) => "redis",
            Self::Mongodb(_) => "mongo",
            Self::Kafka(_) => "kafka",
            Self::Cassandra(_) => "cql",
            Self::Memcached(_) => "mc",
            Self::Mqtt(_) => "mqtt",
            Self::Nats(_) => "nats",
            Self::WebSocket(_) => "ws",
            Self::Pop3(_) => "pop3",
            Self::Smtp(_) => "smtp",
            Self::Imap(_) => "imap",
            Self::Modbus(_) => "modbus",
            Self::Ldap(_) => "ldap",
            Self::OpcUa(_) => "opcua",
            Self::Iec104(_) => "iec104",
            Self::Ssh(_) => "ssh",
            Self::Dnp3(_) => "dnp3",
            Self::S7(_) => "s7",
            Self::Enip(_) => "enip",
            Self::Bacnet(_) => "bacnet",
            Self::Stun(_) => "stun",
            Self::Ftp(_) => "ftp",
            Self::Sip(_) => "sip",
            Self::Tls(_) => "tls",
            Self::Rdp(_) => "rdp",
            Self::Socks(_) => "socks",
            Self::Telnet(_) => "telnet",
            Self::Ntp(_) => "ntp",
            Self::Radius(_) => "radius",
            Self::Syslog(_) => "syslog",
            Self::Amqp(_) => "amqp",
            Self::Kerberos(_) => "krb5",
            Self::Oracle(_) => "oracle",
            Self::Mssql(_) => "mssql",
            Self::Dhcp(_) => "dhcp",
            Self::Tftp(_) => "tftp",
            Self::Tacacs(_) => "tacacs+",
            Self::Snmp(_) => "snmp",
            Self::Smb(_) => "smb",
            Self::WireGuard(_) => "wg",
            Self::Irc(_) => "irc",
            Self::Nfs(_) => "nfs",
            Self::Rtsp(_) => "rtsp",
            Self::Smpp(_) => "smpp",
            Self::Dns(r) => {
                if r.multicast {
                    "mdns"
                } else {
                    "dns"
                }
            }
            Self::Quic(_) => "quic",
        }
    }

    pub fn display_line(&self) -> String {
        match self {
            Self::Http1(r) => render_http1(r),
            Self::Http2(r) => render_http2(r),
            Self::Postgres(r) => r.display_line(),
            Self::Mysql(r) => r.display_line(),
            Self::Redis(r) => r.display_line(),
            Self::Mongodb(r) => r.display_line(),
            Self::Kafka(r) => r.display_line(),
            Self::Cassandra(r) => r.display_line(),
            Self::Memcached(r) => r.display_line(),
            Self::Mqtt(r) => r.display_line(),
            Self::Nats(r) => r.display_line(),
            Self::WebSocket(r) => r.display_line(),
            Self::Pop3(r) => r.display_line(),
            Self::Smtp(r) => r.display_line(),
            Self::Imap(r) => r.display_line(),
            Self::Modbus(r) => r.display_line(),
            Self::Ldap(r) => r.display_line(),
            Self::OpcUa(r) => r.display_line(),
            Self::Iec104(r) => r.display_line(),
            Self::Ssh(r) => r.display_line(),
            Self::Dnp3(r) => r.display_line(),
            Self::S7(r) => r.display_line(),
            Self::Enip(r) => r.display_line(),
            Self::Bacnet(r) => r.display_line(),
            Self::Stun(r) => r.display_line(),
            Self::Ftp(r) => r.display_line(),
            Self::Sip(r) => r.display_line(),
            Self::Tls(r) => r.display_line(),
            Self::Rdp(r) => r.display_line(),
            Self::Socks(r) => r.display_line(),
            Self::Telnet(r) => r.display_line(),
            Self::Ntp(r) => r.display_line(),
            Self::Radius(r) => r.display_line(),
            Self::Syslog(r) => r.display_line(),
            Self::Amqp(r) => r.display_line(),
            Self::Kerberos(r) => r.display_line(),
            Self::Oracle(r) => r.display_line(),
            Self::Mssql(r) => r.display_line(),
            Self::Dhcp(r) => r.display_line(),
            Self::Tftp(r) => r.display_line(),
            Self::Tacacs(r) => r.display_line(),
            Self::Snmp(r) => r.display_line(),
            Self::Smb(r) => r.display_line(),
            Self::WireGuard(r) => r.display_line(),
            Self::Irc(r) => r.display_line(),
            Self::Nfs(r) => r.display_line(),
            Self::Rtsp(r) => r.display_line(),
            Self::Smpp(r) => r.display_line(),
            Self::Dns(r) => r.display_line(),
            Self::Quic(r) => r.display_line(),
        }
    }
}

fn render_http1(r: &Http1Record) -> String {
    use crate::parsers::http1::RecordKind;
    match r.kind {
        RecordKind::Request => format!(
            "{} {}  {} B",
            r.method.as_deref().unwrap_or("?"),
            r.path.as_deref().unwrap_or("/"),
            r.total_body_bytes
        ),
        RecordKind::Response => format!(
            "{} {}  {} B",
            r.status.unwrap_or(0),
            r.reason.as_deref().unwrap_or(""),
            r.total_body_bytes
        ),
    }
}

fn render_http2(r: &Http2Record) -> String {
    if let Some(g) = &r.grpc {
        format!("gRPC {}/{} ({}B)", g.service, g.method, g.message_length)
    } else if let Some(st) = r.status {
        format!("h2 stream={} {}", r.stream_id, st)
    } else {
        format!(
            "h2 stream={} {} {}",
            r.stream_id,
            r.method.as_deref().unwrap_or(""),
            r.path.as_deref().unwrap_or("")
        )
    }
}

#[derive(Default)]
struct HalfFlow {
    buf: Vec<u8>,
    seen: u64,
}

impl HalfFlow {
    fn push(&mut self, bytes: &[u8]) {
        if self.buf.len() + bytes.len() > BUF_CAP {
            let drop = (self.buf.len() + bytes.len()) - BUF_CAP;
            self.buf.drain(..drop.min(self.buf.len()));
        }
        self.buf.extend_from_slice(bytes);
        self.seen += bytes.len() as u64;
    }

    fn consume(&mut self, n: usize) {
        self.buf.drain(..n.min(self.buf.len()));
    }
}

#[derive(Default)]
struct ParserSlot {
    http1: Option<Http1Parser>,
    http2: Option<Http2Parser>,
    postgres: Option<PostgresParser>,
    mysql: Option<MysqlParser>,
    redis: Option<RedisParser>,
    mongodb: Option<MongoParser>,
    kafka: Option<KafkaParser>,
    cassandra: Option<CassandraParser>,
    memcached: Option<MemcachedParser>,
    mqtt: Option<MqttParser>,
    nats: Option<NatsParser>,
    websocket: Option<WebSocketParser>,
    pop3: Option<Pop3Parser>,
    smtp: Option<SmtpParser>,
    imap: Option<ImapParser>,
    modbus: Option<ModbusParser>,
    ldap: Option<LdapParser>,
    opcua: Option<OpcuaParser>,
    iec104: Option<Iec104Parser>,
    ssh: Option<SshParser>,
    dnp3: Option<Dnp3Parser>,
    s7: Option<S7Parser>,
    enip: Option<EnipParser>,
    bacnet: Option<BacnetParser>,
    stun: Option<StunParser>,
    ftp: Option<FtpParser>,
    sip: Option<SipParser>,
    tls: Option<TlsParser>,
    rdp: Option<RdpParser>,
    socks: Option<SocksParser>,
    telnet: Option<TelnetParser>,
    ntp: Option<NtpParser>,
    radius: Option<RadiusParser>,
    syslog: Option<SyslogParser>,
    amqp: Option<AmqpParser>,
    kerberos: Option<KerberosParser>,
    oracle: Option<OracleParser>,
    mssql: Option<MssqlParser>,
    dhcp: Option<DhcpParser>,
    tftp: Option<TftpParser>,
    tacacs: Option<TacacsParser>,
    snmp: Option<SnmpParser>,
    smb: Option<SmbParser>,
    wireguard: Option<WireguardParser>,
    irc: Option<IrcParser>,
    nfs: Option<NfsParser>,
    rtsp: Option<RtspParser>,
    smpp: Option<SmppParser>,
    dns: Option<DnsParser>,
    quic: Option<QuicParser>,
}

#[derive(Default)]
struct FlowState {
    tx: HalfFlow,
    rx: HalfFlow,
    proto: Protocol,
    parser_tx: ParserSlot,
    parser_rx: ParserSlot,
    dst_port: u16,
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn hint_port(&mut self, key: FlowKey, dst_port: u16) {
        let state = self.flows.entry(key).or_default();
        if state.dst_port == 0 {
            state.dst_port = dst_port;
        }
    }

    pub fn feed(&mut self, key: FlowKey, dir: Direction, bytes: &[u8]) -> Vec<AnyRecord> {
        if bytes.is_empty() {
            return Vec::new();
        }
        let state = self.flows.entry(key).or_default();
        let half = match dir {
            Direction::Tx => &mut state.tx,
            Direction::Rx => &mut state.rx,
        };
        half.push(bytes);

        if matches!(state.proto, Protocol::Unknown) {
            state.proto = detect(&state.tx.buf, &state.rx.buf, state.dst_port);
        }

        match state.proto {
            Protocol::Http1 => drive_http1(state, dir),
            Protocol::Http2 => drive_http2(state, dir),
            Protocol::Postgres => drive_postgres(state, dir),
            Protocol::Mysql => drive_mysql(state, dir),
            Protocol::Redis => drive_redis(state, dir),
            Protocol::Mongodb => drive_mongodb(state, dir),
            Protocol::Kafka => drive_kafka(state, dir),
            Protocol::Cassandra => drive_cassandra(state, dir),
            Protocol::Memcached => drive_memcached(state, dir),
            Protocol::Mqtt => drive_mqtt(state, dir),
            Protocol::Nats => drive_nats(state, dir),
            Protocol::WebSocket => drive_websocket(state, dir),
            Protocol::Pop3 => drive_pop3(state, dir),
            Protocol::Smtp => drive_smtp(state, dir),
            Protocol::Imap => drive_imap(state, dir),
            Protocol::Modbus => drive_modbus(state, dir),
            Protocol::Ldap => drive_ldap(state, dir),
            Protocol::OpcUa => drive_opcua(state, dir),
            Protocol::Iec104 => drive_iec104(state, dir),
            Protocol::Ssh => drive_ssh(state, dir),
            Protocol::Dnp3 => drive_dnp3(state, dir),
            Protocol::S7 => drive_s7(state, dir),
            Protocol::Enip => drive_enip(state, dir),
            Protocol::Bacnet => drive_bacnet(state, dir),
            Protocol::Stun => drive_stun(state, dir),
            Protocol::Ftp => drive_ftp(state, dir),
            Protocol::Sip => drive_sip(state, dir),
            Protocol::Tls => drive_tls(state, dir),
            Protocol::Rdp => drive_rdp(state, dir),
            Protocol::Socks => drive_socks(state, dir),
            Protocol::Telnet => drive_telnet(state, dir),
            Protocol::Ntp => drive_ntp(state, dir),
            Protocol::Radius => drive_radius(state, dir),
            Protocol::Syslog => drive_syslog(state, dir),
            Protocol::Amqp => drive_amqp(state, dir),
            Protocol::Kerberos => drive_kerberos(state, dir),
            Protocol::Oracle => drive_oracle(state, dir),
            Protocol::Mssql => drive_mssql(state, dir),
            Protocol::Dhcp => drive_dhcp(state, dir),
            Protocol::Tftp => drive_tftp(state, dir),
            Protocol::Tacacs => drive_tacacs(state, dir),
            Protocol::Snmp => drive_snmp(state, dir),
            Protocol::Smb => drive_smb(state, dir),
            Protocol::WireGuard => drive_wireguard(state, dir),
            Protocol::Irc => drive_irc(state, dir),
            Protocol::Nfs => drive_nfs(state, dir),
            Protocol::Rtsp => drive_rtsp(state, dir),
            Protocol::Smpp => drive_smpp(state, dir),
            Protocol::Dns => drive_dns(state, dir, false),
            Protocol::Mdns => drive_dns(state, dir, true),
            Protocol::Quic => drive_quic(state, dir),
            Protocol::Unknown | Protocol::Bypass => Vec::new(),
        }
    }

    pub fn forget(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }
}

fn detect(tx: &[u8], rx: &[u8], port: u16) -> Protocol {
    match port {
        80 | 8080 | 8000 | 3000 | 5000 | 8888 => return Protocol::Http1,
        5432 => return Protocol::Postgres,
        3306 | 33060 => return Protocol::Mysql,
        6379 => return Protocol::Redis,
        27017 | 27018 | 27019 => return Protocol::Mongodb,
        9092 | 29092 => return Protocol::Kafka,
        9042 | 9142 => return Protocol::Cassandra,
        11211 => return Protocol::Memcached,
        1883 | 8883 => return Protocol::Mqtt,
        4222 | 6222 => return Protocol::Nats,
        110 | 995 => return Protocol::Pop3,
        25 | 465 | 587 | 2525 => return Protocol::Smtp,
        143 | 993 => return Protocol::Imap,
        502 => return Protocol::Modbus,
        389 | 636 | 3268 | 3269 => return Protocol::Ldap,
        4840 | 4843 => return Protocol::OpcUa,
        2404 => return Protocol::Iec104,
        22 => return Protocol::Ssh,
        20000 => return Protocol::Dnp3,
        102 => return Protocol::S7,
        44818 | 2222 => return Protocol::Enip,
        47808 | 47809 => return Protocol::Bacnet,
        3478 | 5349 => return Protocol::Stun,
        21 => return Protocol::Ftp,
        5060 | 5061 => return Protocol::Sip,
        443 | 8443 => return Protocol::Tls,
        3389 => return Protocol::Rdp,
        1080 => return Protocol::Socks,
        23 => return Protocol::Telnet,
        123 => return Protocol::Ntp,
        1812 | 1813 => return Protocol::Radius,
        514 | 601 | 6514 => return Protocol::Syslog,
        5672 | 5671 => return Protocol::Amqp,
        88 => return Protocol::Kerberos,
        1521 | 1526 => return Protocol::Oracle,
        1433 | 1434 => return Protocol::Mssql,
        67 | 68 => return Protocol::Dhcp,
        69 => return Protocol::Tftp,
        49 => return Protocol::Tacacs,
        161 | 162 => return Protocol::Snmp,
        139 | 445 => return Protocol::Smb,
        51820 => return Protocol::WireGuard,
        6667 | 6697 | 7000 => return Protocol::Irc,
        2049 => return Protocol::Nfs,
        554 | 8554 => return Protocol::Rtsp,
        2775 => return Protocol::Smpp,
        53 => return Protocol::Dns,
        5353 => return Protocol::Mdns,
        _ => {}
    }
    for buf in [tx, rx] {
        if let Some(p) = signature(buf) {
            return p;
        }
    }
    Protocol::Unknown
}

fn signature(buf: &[u8]) -> Option<Protocol> {
    if buf.len() < 4 {
        return None;
    }
    // QUIC v1 long-header: first byte has the form+fixed bits set
    // (0xc0 mask) and the next 4 bytes are the version, which for v1
    // is 0x00000001. We check the version before TLS because a QUIC
    // Initial *could* theoretically begin with bytes that are also
    // valid TLS — but version=1 is unique.
    if buf.len() >= 5
        && (buf[0] & 0xc0) == 0xc0
        && buf[1] == 0x00
        && buf[2] == 0x00
        && buf[3] == 0x00
        && buf[4] == 0x01
    {
        return Some(Protocol::Quic);
    }
    // TLS handshake record: 0x16 (type=Handshake) + 0x03 0x0[0..=4] version.
    if buf.len() >= 5
        && buf[0] == 0x16
        && buf[1] == 0x03
        && buf[2] <= 0x04
        && (buf[3] != 0 || buf[4] != 0)
    {
        return Some(Protocol::Tls);
    }
    if buf.len() >= 24 && buf.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return Some(Protocol::Http2);
    }
    if buf.starts_with(b"HTTP/") {
        return Some(Protocol::Http1);
    }
    if let Some(space) = buf.iter().take(8).position(|&b| b == b' ') {
        if buf[..space].iter().all(|b| b.is_ascii_uppercase()) {
            const METHODS: &[&[u8]] = &[
                b"GET", b"PUT", b"POST", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT",
                b"TRACE",
            ];
            if METHODS.iter().any(|m| m == &&buf[..space]) {
                return Some(Protocol::Http1);
            }
        }
    }
    for verb in [
        &b"PING"[..],
        b"PONG",
        b"INFO ",
        b"CONNECT ",
        b"PUB ",
        b"SUB ",
        b"MSG ",
        b"HPUB ",
        b"HMSG ",
        b"UNSUB ",
        b"+OK",
        b"-ERR",
    ] {
        if buf.starts_with(verb) {
            return Some(Protocol::Nats);
        }
    }
    if matches!(
        buf[0],
        b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b'#' | b',' | b'(' | b'=' | b'%' | b'~' | b'>'
    ) && buf.contains(&b'\r')
    {
        return Some(Protocol::Redis);
    }
    if buf[0] == 0x80 || buf[0] == 0x81 {
        return Some(Protocol::Memcached);
    }
    if buf.len() >= 12 {
        let nibble = buf[0] >> 4;
        if nibble == 1 {
            let cursor = &buf[2..];
            if cursor.len() >= 6 && cursor[0] == 0 && (cursor[1] == 4 || cursor[1] == 6) {
                let name_len = cursor[1] as usize;
                if cursor.len() >= 2 + name_len {
                    let name = &cursor[2..2 + name_len];
                    if name == b"MQTT" || name == b"MQIsdp" {
                        return Some(Protocol::Mqtt);
                    }
                }
            }
        }
    }
    if matches!(buf[0], 0x04 | 0x84 | 0x05 | 0x85) && buf.len() >= 9 {
        let body_len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if body_len <= 256 * 1024 * 1024 {
            return Some(Protocol::Cassandra);
        }
    }
    if buf.len() >= 16 {
        let msg_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let op = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if (16..=48 * 1024 * 1024).contains(&msg_len) && matches!(op, 1 | 2001..=2007 | 2010..=2013)
        {
            return Some(Protocol::Mongodb);
        }
    }
    if buf.len() >= 8 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let ver = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if len >= 8 && len < 1024 && (0x0003_0000..=0x0003_FFFF).contains(&ver) {
            return Some(Protocol::Postgres);
        }
        if len == 8 && ver == 0x04d2_162f {
            return Some(Protocol::Postgres);
        }
    }
    if buf.len() >= 12 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let api_key = i16::from_be_bytes([buf[4], buf[5]]);
        if (8..=100 * 1024 * 1024).contains(&len) && (-1..=1000).contains(&api_key) {
            return Some(Protocol::Kafka);
        }
    }
    None
}

fn drive_http1(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.http1),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.http1),
    };
    let parser = slot.get_or_insert_with(Http1Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            Http1Output::Need => break,
            Http1Output::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Http1(Box::new(record)));
            }
            Http1Output::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_http2(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.http2),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.http2),
    };
    let parser = slot.get_or_insert_with(Http2Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            Http2ParserOutput::Need => break,
            Http2ParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Http2(Box::new(record)));
            }
            Http2ParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_postgres(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.postgres),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.postgres),
    };
    let parser = slot.get_or_insert_with(PostgresParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            PgParserOutput::Need => break,
            PgParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Postgres(Box::new(record)));
            }
            PgParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_mysql(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.mysql),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.mysql),
    };
    let parser = slot.get_or_insert_with(MysqlParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            MysqlParserOutput::Need => break,
            MysqlParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Mysql(Box::new(record)));
            }
            MysqlParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_redis(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.redis),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.redis),
    };
    let parser = slot.get_or_insert_with(RedisParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            RedisParserOutput::Need => break,
            RedisParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Redis(Box::new(record)));
            }
            RedisParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_mongodb(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.mongodb),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.mongodb),
    };
    let parser = slot.get_or_insert_with(MongoParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            MongoParserOutput::Need => break,
            MongoParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Mongodb(Box::new(record)));
            }
            MongoParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_kafka(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.kafka),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.kafka),
    };
    let parser = slot.get_or_insert_with(KafkaParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            KafkaParserOutput::Need => break,
            KafkaParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Kafka(Box::new(record)));
            }
            KafkaParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_cassandra(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.cassandra),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.cassandra),
    };
    let parser = slot.get_or_insert_with(CassandraParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            CqlParserOutput::Need => break,
            // Cassandra's parser already returns a Box<CqlRecord> — it was
            // bigger than the rest and avoids a second heap allocation.
            CqlParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Cassandra(record));
            }
            CqlParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_memcached(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.memcached),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.memcached),
    };
    let parser = slot.get_or_insert_with(MemcachedParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            McParserOutput::Need => break,
            McParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Memcached(Box::new(record)));
            }
            McParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_mqtt(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.mqtt),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.mqtt),
    };
    let parser = slot.get_or_insert_with(MqttParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            MqttParserOutput::Need => break,
            MqttParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Mqtt(Box::new(record)));
            }
            MqttParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_nats(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.nats),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.nats),
    };
    let parser = slot.get_or_insert_with(NatsParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            NatsParserOutput::Need => break,
            NatsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Nats(Box::new(record)));
            }
            NatsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_websocket(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.websocket),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.websocket),
    };
    let parser = slot.get_or_insert_with(WebSocketParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            WsParserOutput::Need => break,
            WsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::WebSocket(Box::new(record)));
            }
            WsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_pop3(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.pop3),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.pop3),
    };
    let parser = slot.get_or_insert_with(Pop3Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            Pop3ParserOutput::Need => break,
            Pop3ParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Pop3(Box::new(record)));
            }
            Pop3ParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_smtp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.smtp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.smtp),
    };
    let parser = slot.get_or_insert_with(SmtpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SmtpParserOutput::Need => break,
            SmtpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Smtp(Box::new(record)));
            }
            SmtpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_imap(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.imap),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.imap),
    };
    let parser = slot.get_or_insert_with(ImapParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            ImapParserOutput::Need => break,
            ImapParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Imap(Box::new(record)));
            }
            ImapParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_modbus(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.modbus),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.modbus),
    };
    let parser = slot.get_or_insert_with(ModbusParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            ModbusParserOutput::Need => break,
            ModbusParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Modbus(Box::new(record)));
            }
            ModbusParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_ldap(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.ldap),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.ldap),
    };
    let parser = slot.get_or_insert_with(LdapParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            LdapParserOutput::Need => break,
            LdapParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Ldap(Box::new(record)));
            }
            LdapParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_opcua(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.opcua),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.opcua),
    };
    let parser = slot.get_or_insert_with(OpcuaParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            OpcuaParserOutput::Need => break,
            OpcuaParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::OpcUa(Box::new(record)));
            }
            OpcuaParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_iec104(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.iec104),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.iec104),
    };
    let parser = slot.get_or_insert_with(Iec104Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            Iec104ParserOutput::Need => break,
            Iec104ParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Iec104(Box::new(record)));
            }
            Iec104ParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_ssh(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.ssh),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.ssh),
    };
    let parser = slot.get_or_insert_with(SshParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SshParserOutput::Need => break,
            SshParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Ssh(Box::new(record)));
            }
            SshParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_dnp3(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.dnp3),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.dnp3),
    };
    let parser = slot.get_or_insert_with(Dnp3Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            Dnp3ParserOutput::Need => break,
            Dnp3ParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Dnp3(Box::new(record)));
            }
            Dnp3ParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_s7(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.s7),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.s7),
    };
    let parser = slot.get_or_insert_with(S7Parser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            S7ParserOutput::Need => break,
            S7ParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::S7(Box::new(record)));
            }
            S7ParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_enip(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.enip),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.enip),
    };
    let parser = slot.get_or_insert_with(EnipParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            EnipParserOutput::Need => break,
            EnipParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Enip(Box::new(record)));
            }
            EnipParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_bacnet(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.bacnet),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.bacnet),
    };
    let parser = slot.get_or_insert_with(BacnetParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            BacnetParserOutput::Need => break,
            BacnetParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Bacnet(Box::new(record)));
            }
            BacnetParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_stun(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.stun),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.stun),
    };
    let parser = slot.get_or_insert_with(StunParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            StunParserOutput::Need => break,
            StunParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Stun(Box::new(record)));
            }
            StunParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_ftp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.ftp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.ftp),
    };
    let parser = slot.get_or_insert_with(FtpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            FtpParserOutput::Need => break,
            FtpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Ftp(Box::new(record)));
            }
            FtpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_sip(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.sip),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.sip),
    };
    let parser = slot.get_or_insert_with(SipParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SipParserOutput::Need => break,
            SipParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Sip(Box::new(record)));
            }
            SipParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_tls(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.tls),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.tls),
    };
    let parser = slot.get_or_insert_with(TlsParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            TlsParserOutput::Need => break,
            TlsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Tls(Box::new(record)));
            }
            TlsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_rdp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.rdp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.rdp),
    };
    let parser = slot.get_or_insert_with(RdpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            RdpParserOutput::Need => break,
            RdpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Rdp(Box::new(record)));
            }
            RdpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_socks(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.socks),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.socks),
    };
    let parser = slot.get_or_insert_with(SocksParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SocksParserOutput::Need => break,
            SocksParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Socks(Box::new(record)));
            }
            SocksParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_telnet(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.telnet),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.telnet),
    };
    let parser = slot.get_or_insert_with(TelnetParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            TelnetParserOutput::Need => break,
            TelnetParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Telnet(Box::new(record)));
            }
            TelnetParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_ntp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.ntp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.ntp),
    };
    let parser = slot.get_or_insert_with(NtpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            NtpParserOutput::Need => break,
            NtpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Ntp(Box::new(record)));
            }
            NtpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_radius(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.radius),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.radius),
    };
    let parser = slot.get_or_insert_with(RadiusParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            RadiusParserOutput::Need => break,
            RadiusParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Radius(Box::new(record)));
            }
            RadiusParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_syslog(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.syslog),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.syslog),
    };
    let parser = slot.get_or_insert_with(SyslogParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SyslogParserOutput::Need => break,
            SyslogParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Syslog(Box::new(record)));
            }
            SyslogParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_amqp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.amqp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.amqp),
    };
    let parser = slot.get_or_insert_with(AmqpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            AmqpParserOutput::Need => break,
            AmqpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Amqp(Box::new(record)));
            }
            AmqpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_kerberos(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.kerberos),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.kerberos),
    };
    let parser = slot.get_or_insert_with(KerberosParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            KerberosParserOutput::Need => break,
            KerberosParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Kerberos(Box::new(record)));
            }
            KerberosParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_oracle(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.oracle),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.oracle),
    };
    let parser = slot.get_or_insert_with(OracleParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            OracleParserOutput::Need => break,
            OracleParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Oracle(Box::new(record)));
            }
            OracleParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_mssql(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.mssql),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.mssql),
    };
    let parser = slot.get_or_insert_with(MssqlParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            MssqlParserOutput::Need => break,
            MssqlParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Mssql(Box::new(record)));
            }
            MssqlParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_dhcp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.dhcp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.dhcp),
    };
    let parser = slot.get_or_insert_with(DhcpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            DhcpParserOutput::Need => break,
            DhcpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Dhcp(Box::new(record)));
            }
            DhcpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_tftp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.tftp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.tftp),
    };
    let parser = slot.get_or_insert_with(TftpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            TftpParserOutput::Need => break,
            TftpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Tftp(Box::new(record)));
            }
            TftpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_tacacs(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.tacacs),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.tacacs),
    };
    let parser = slot.get_or_insert_with(TacacsParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            TacacsParserOutput::Need => break,
            TacacsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Tacacs(Box::new(record)));
            }
            TacacsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_snmp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.snmp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.snmp),
    };
    let parser = slot.get_or_insert_with(SnmpParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SnmpParserOutput::Need => break,
            SnmpParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Snmp(Box::new(record)));
            }
            SnmpParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_smb(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.smb),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.smb),
    };
    let parser = slot.get_or_insert_with(SmbParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SmbParserOutput::Need => break,
            SmbParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Smb(Box::new(record)));
            }
            SmbParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_wireguard(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.wireguard),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.wireguard),
    };
    let parser = slot.get_or_insert_with(WireguardParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            WireguardParserOutput::Need => break,
            WireguardParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::WireGuard(Box::new(record)));
            }
            WireguardParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_irc(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.irc),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.irc),
    };
    let parser = slot.get_or_insert_with(IrcParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            IrcParserOutput::Need => break,
            IrcParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Irc(Box::new(record)));
            }
            IrcParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_nfs(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.nfs),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.nfs),
    };
    let parser = slot.get_or_insert_with(NfsParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            NfsParserOutput::Need => break,
            NfsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Nfs(Box::new(record)));
            }
            NfsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_rtsp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.rtsp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.rtsp),
    };
    let parser = slot.get_or_insert_with(RtspParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            RtspParserOutput::Need => break,
            RtspParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Rtsp(Box::new(record)));
            }
            RtspParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_smpp(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.smpp),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.smpp),
    };
    let parser = slot.get_or_insert_with(SmppParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            SmppParserOutput::Need => break,
            SmppParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Smpp(Box::new(record)));
            }
            SmppParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_dns(state: &mut FlowState, dir: Direction, mdns: bool) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.dns),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.dns),
    };
    let parser = slot.get_or_insert_with(|| {
        if mdns {
            DnsParser::new_mdns()
        } else {
            DnsParser::default()
        }
    });
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            DnsParserOutput::Need => break,
            DnsParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Dns(Box::new(record)));
            }
            DnsParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

fn drive_quic(state: &mut FlowState, dir: Direction) -> Vec<AnyRecord> {
    let (half, slot) = match dir {
        Direction::Tx => (&mut state.tx, &mut state.parser_tx.quic),
        Direction::Rx => (&mut state.rx, &mut state.parser_rx.quic),
    };
    let parser = slot.get_or_insert_with(QuicParser::default);
    let mut out = Vec::new();
    loop {
        match parser.parse(&half.buf, dir) {
            QuicParserOutput::Need => break,
            QuicParserOutput::Record { record, consumed } => {
                half.consume(consumed);
                out.push(AnyRecord::Quic(Box::new(record)));
            }
            QuicParserOutput::Skip(n) => {
                if n == 0 {
                    break;
                }
                half.consume(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http1_by_method() {
        assert_eq!(signature(b"GET / HTTP/1.1\r\n"), Some(Protocol::Http1));
        assert_eq!(signature(b"HTTP/1.1 200 OK\r\n"), Some(Protocol::Http1));
    }

    #[test]
    fn detects_http2_preface() {
        assert_eq!(
            signature(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Some(Protocol::Http2)
        );
    }

    #[test]
    fn port_hint_wins() {
        assert_eq!(detect(b"", b"", 5432), Protocol::Postgres);
        assert_eq!(detect(b"", b"", 11211), Protocol::Memcached);
        assert_eq!(detect(b"", b"", 1883), Protocol::Mqtt);
        assert_eq!(detect(b"", b"", 4222), Protocol::Nats);
    }
}
