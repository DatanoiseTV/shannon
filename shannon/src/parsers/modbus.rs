//! Modbus TCP (MBAP + Modbus function codes).
//!
//! Compact binary protocol, `tcp/502`. Each ADU is:
//! ```text
//!   [Transaction id 2B BE] [Protocol id 2B BE, always 0] [Length 2B BE]
//!   [Unit id 1B] [Function code 1B] [data...]
//! ```
//! We surface the common read / write function codes by name plus the
//! unit id and the register/coil range when available.

use crate::events::Direction;

const MBAP_HEADER_LEN: usize = 7;
const MAX_PDU: usize = 253; // per spec

pub struct ModbusParser {
    bypass: bool,
}

impl Default for ModbusParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum ModbusParserOutput {
    Need,
    Record { record: ModbusRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct ModbusRecord {
    pub direction: Direction,
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function: FunctionCode,
    pub kind: MessageKind,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionCode {
    ReadCoils,                 // 0x01
    ReadDiscreteInputs,        // 0x02
    ReadHoldingRegisters,      // 0x03
    ReadInputRegisters,        // 0x04
    WriteSingleCoil,           // 0x05
    WriteSingleRegister,       // 0x06
    ReadExceptionStatus,       // 0x07
    Diagnostics,               // 0x08
    GetCommEventCounter,       // 0x0B
    GetCommEventLog,           // 0x0C
    WriteMultipleCoils,        // 0x0F
    WriteMultipleRegisters,    // 0x10
    ReportSlaveId,             // 0x11
    ReadFileRecord,            // 0x14
    WriteFileRecord,           // 0x15
    MaskWriteRegister,         // 0x16
    ReadWriteMultipleRegisters,// 0x17
    ReadFifoQueue,             // 0x18
    EncapsulatedTransport,     // 0x2B
    Exception(u8),             // 0x80 | original code
    Other(u8),
}

impl FunctionCode {
    const fn name(&self) -> &'static str {
        use FunctionCode::*;
        match self {
            ReadCoils => "ReadCoils",
            ReadDiscreteInputs => "ReadDiscreteInputs",
            ReadHoldingRegisters => "ReadHoldingRegisters",
            ReadInputRegisters => "ReadInputRegisters",
            WriteSingleCoil => "WriteSingleCoil",
            WriteSingleRegister => "WriteSingleRegister",
            ReadExceptionStatus => "ReadExceptionStatus",
            Diagnostics => "Diagnostics",
            GetCommEventCounter => "GetCommEventCounter",
            GetCommEventLog => "GetCommEventLog",
            WriteMultipleCoils => "WriteMultipleCoils",
            WriteMultipleRegisters => "WriteMultipleRegisters",
            ReportSlaveId => "ReportSlaveId",
            ReadFileRecord => "ReadFileRecord",
            WriteFileRecord => "WriteFileRecord",
            MaskWriteRegister => "MaskWriteRegister",
            ReadWriteMultipleRegisters => "ReadWriteMultipleRegisters",
            ReadFifoQueue => "ReadFifoQueue",
            EncapsulatedTransport => "EncapsulatedTransport",
            Exception(_) => "Exception",
            Other(_) => "Other",
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessageKind {
    Request,
    Response,
    ExceptionResponse { code: u8 },
}

impl ModbusRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            MessageKind::Request => format!(
                "tid={} unit={} {} req {}",
                self.transaction_id,
                self.unit_id,
                self.function.name(),
                self.summary
            ),
            MessageKind::Response => format!(
                "tid={} unit={} {} resp {}",
                self.transaction_id,
                self.unit_id,
                self.function.name(),
                self.summary
            ),
            MessageKind::ExceptionResponse { code } => format!(
                "tid={} unit={} {} EXCEPTION code={} ({})",
                self.transaction_id,
                self.unit_id,
                self.function.name(),
                code,
                exception_name(*code),
            ),
        }
    }
}

fn exception_name(c: u8) -> &'static str {
    match c {
        1 => "IllegalFunction",
        2 => "IllegalDataAddress",
        3 => "IllegalDataValue",
        4 => "SlaveDeviceFailure",
        5 => "Acknowledge",
        6 => "SlaveDeviceBusy",
        8 => "MemoryParityError",
        10 => "GatewayPathUnavailable",
        11 => "GatewayTargetDeviceFailedToRespond",
        _ => "?",
    }
}

impl ModbusParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> ModbusParserOutput {
        if self.bypass {
            return ModbusParserOutput::Skip(buf.len());
        }
        if buf.len() < MBAP_HEADER_LEN {
            return ModbusParserOutput::Need;
        }
        let tid = u16::from_be_bytes([buf[0], buf[1]]);
        let pid = u16::from_be_bytes([buf[2], buf[3]]);
        let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let unit = buf[6];
        // Protocol id MUST be 0 for Modbus TCP.
        if pid != 0 || len == 0 || len > MAX_PDU + 1 {
            self.bypass = true;
            return ModbusParserOutput::Skip(buf.len());
        }
        let adu_total = 6 + len; // MBAP header (excluding length field's own 2 bytes counted in len)
        if buf.len() < adu_total {
            return ModbusParserOutput::Need;
        }
        if buf.len() < MBAP_HEADER_LEN {
            return ModbusParserOutput::Need;
        }
        let pdu = &buf[MBAP_HEADER_LEN..adu_total];
        if pdu.is_empty() {
            return ModbusParserOutput::Skip(adu_total);
        }
        let raw_fc = pdu[0];
        let payload = &pdu[1..];

        let (function, kind, summary) = classify(raw_fc, payload, dir);
        let rec = ModbusRecord {
            direction: dir,
            transaction_id: tid,
            unit_id: unit,
            function,
            kind,
            summary,
        };
        ModbusParserOutput::Record { record: rec, consumed: adu_total }
    }
}

fn classify(raw_fc: u8, payload: &[u8], dir: Direction) -> (FunctionCode, MessageKind, String) {
    // Exception response: MSB set.
    if raw_fc & 0x80 != 0 {
        let fc = base_function(raw_fc & 0x7f);
        let code = payload.first().copied().unwrap_or(0);
        return (fc, MessageKind::ExceptionResponse { code }, String::new());
    }
    let fc = base_function(raw_fc);
    let (kind, summary) = match dir {
        Direction::Tx => (MessageKind::Request, request_summary(&fc, payload)),
        Direction::Rx => (MessageKind::Response, response_summary(&fc, payload)),
    };
    (fc, kind, summary)
}

const fn base_function(code: u8) -> FunctionCode {
    use FunctionCode::*;
    match code {
        0x01 => ReadCoils,
        0x02 => ReadDiscreteInputs,
        0x03 => ReadHoldingRegisters,
        0x04 => ReadInputRegisters,
        0x05 => WriteSingleCoil,
        0x06 => WriteSingleRegister,
        0x07 => ReadExceptionStatus,
        0x08 => Diagnostics,
        0x0b => GetCommEventCounter,
        0x0c => GetCommEventLog,
        0x0f => WriteMultipleCoils,
        0x10 => WriteMultipleRegisters,
        0x11 => ReportSlaveId,
        0x14 => ReadFileRecord,
        0x15 => WriteFileRecord,
        0x16 => MaskWriteRegister,
        0x17 => ReadWriteMultipleRegisters,
        0x18 => ReadFifoQueue,
        0x2b => EncapsulatedTransport,
        c => Other(c),
    }
}

fn request_summary(fc: &FunctionCode, p: &[u8]) -> String {
    use FunctionCode::*;
    match fc {
        ReadCoils | ReadDiscreteInputs | ReadHoldingRegisters | ReadInputRegisters => {
            if p.len() >= 4 {
                let addr = u16::from_be_bytes([p[0], p[1]]);
                let qty = u16::from_be_bytes([p[2], p[3]]);
                format!("addr={addr} qty={qty}")
            } else {
                String::new()
            }
        }
        WriteSingleCoil | WriteSingleRegister => {
            if p.len() >= 4 {
                let addr = u16::from_be_bytes([p[0], p[1]]);
                let val = u16::from_be_bytes([p[2], p[3]]);
                format!("addr={addr} value=0x{val:04x}")
            } else {
                String::new()
            }
        }
        WriteMultipleCoils | WriteMultipleRegisters => {
            if p.len() >= 5 {
                let addr = u16::from_be_bytes([p[0], p[1]]);
                let qty = u16::from_be_bytes([p[2], p[3]]);
                let bc = p[4];
                format!("addr={addr} qty={qty} bytecount={bc}")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

fn response_summary(fc: &FunctionCode, p: &[u8]) -> String {
    use FunctionCode::*;
    match fc {
        ReadCoils | ReadDiscreteInputs | ReadHoldingRegisters | ReadInputRegisters => {
            if !p.is_empty() {
                let bc = p[0];
                format!("bytecount={bc}")
            } else {
                String::new()
            }
        }
        WriteSingleCoil | WriteSingleRegister => request_summary(fc, p), // echoes request
        WriteMultipleCoils | WriteMultipleRegisters => {
            if p.len() >= 4 {
                let addr = u16::from_be_bytes([p[0], p[1]]);
                let qty = u16::from_be_bytes([p[2], p[3]]);
                format!("addr={addr} qty={qty}")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_holding_registers_request() {
        // tid=1, pid=0, len=6, unit=1, fc=3, addr=0x006B, qty=3.
        let buf = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x6b, 0x00, 0x03];
        let mut p = ModbusParser::default();
        match p.parse(&buf, Direction::Tx) {
            ModbusParserOutput::Record { record, consumed } => {
                assert_eq!(record.function, FunctionCode::ReadHoldingRegisters);
                assert!(record.summary.contains("addr=107"));
                assert!(record.summary.contains("qty=3"));
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn exception_response() {
        // Exception to fc=3: raw_fc 0x83, code 0x02 (IllegalDataAddress).
        let buf = [0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02];
        let mut p = ModbusParser::default();
        match p.parse(&buf, Direction::Rx) {
            ModbusParserOutput::Record { record, .. } => {
                assert!(matches!(record.kind, MessageKind::ExceptionResponse { code: 2 }));
                assert_eq!(record.function, FunctionCode::ReadHoldingRegisters);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_zero_protocol_id_bypasses() {
        // pid = 1 (not modbus).
        let buf = [0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01];
        let mut p = ModbusParser::default();
        assert!(matches!(p.parse(&buf, Direction::Tx), ModbusParserOutput::Skip(_)));
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = ModbusParser::default();
        assert!(matches!(p.parse(&[0u8; 5], Direction::Tx), ModbusParserOutput::Need));
    }
}
