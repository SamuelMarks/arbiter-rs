//! Fixed-point integer resource units and checked arithmetic for Arbiter.
//!
//! All resource accounting in Arbiter strictly uses 64-bit fixed-point integer newtypes
//! with 128-bit intermediate ratio math (`u128`), eliminating floating-point (`f32`/`f64`)
//! precision drift across DRF scheduling, quota accounting, and telemetry aggregation.

use core::fmt;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};

/// One billion (`1_000_000_000`), the denominator for [`SharePartsPerBillion`].
pub const ONE_BILLION: u64 = 1_000_000_000;

/// One hundred thousand (`100_000`), the maximum permitted basis point weight (`10x` standard).
pub const MAX_BASIS_POINTS: u64 = 100_000;

/// Macro defining a fixed-point `u64` unit newtype with checked and saturating arithmetic.
macro_rules! define_u64_unit {
    ($(#[$meta:meta])* $name:ident, $unit_suffix:literal, $op_prefix:literal) => {
        $(#[$meta])*
        #[must_use]
        #[derive(
            Debug,
            Default,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
            Archive,
            RkyvSerialize,
            RkyvDeserialize,
        )]
        pub struct $name(u64);

        impl $name {
            /// Zero quantity constant.
            pub const ZERO: Self = Self(0);

            /// Maximum representable quantity constant (`u64::MAX`).
            pub const MAX: Self = Self(u64::MAX);

            /// Constructs a new instance from a raw `u64` value.
            ///
            /// # Arguments
            ///
            /// * `value` - Raw 64-bit unsigned integer quantity.
            ///
            /// # Returns
            ///
            /// New instance of `Self`.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the inner `u64` value.
            ///
            /// # Returns
            ///
            /// The underlying `u64` integer.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Returns `true` if the quantity is zero.
            ///
            /// # Returns
            ///
            /// `true` when inner value is `0`.
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }

            /// Checked addition of two quantities.
            ///
            /// # Arguments
            ///
            /// * `rhs` - Quantity to add.
            ///
            /// # Returns
            ///
            /// Sum wrapped in `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::ArithmeticOverflow`] if `self + rhs > u64::MAX`.
            pub fn checked_add(self, rhs: Self) -> ArbiterResult<Self> {
                self.0.checked_add(rhs.0).map(Self).ok_or_else(|| {
                    ArbiterError::ArithmeticOverflow {
                        operation: concat!($op_prefix, "::checked_add").to_owned(),
                    }
                })
            }

            /// Checked subtraction of two quantities.
            ///
            /// # Arguments
            ///
            /// * `rhs` - Quantity to subtract.
            ///
            /// # Returns
            ///
            /// Difference wrapped in `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::ArithmeticUnderflow`] if `self < rhs`.
            pub fn checked_sub(self, rhs: Self) -> ArbiterResult<Self> {
                self.0.checked_sub(rhs.0).map(Self).ok_or_else(|| {
                    ArbiterError::ArithmeticUnderflow {
                        operation: concat!($op_prefix, "::checked_sub").to_owned(),
                    }
                })
            }

            /// Checked multiplication by a scalar factor.
            ///
            /// # Arguments
            ///
            /// * `factor` - Scalar multiplier.
            ///
            /// # Returns
            ///
            /// Product wrapped in `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::ArithmeticOverflow`] if `self * factor > u64::MAX`.
            pub fn checked_mul(self, factor: u64) -> ArbiterResult<Self> {
                self.0.checked_mul(factor).map(Self).ok_or_else(|| {
                    ArbiterError::ArithmeticOverflow {
                        operation: concat!($op_prefix, "::checked_mul").to_owned(),
                    }
                })
            }

            /// Checked integer division by a scalar divisor.
            ///
            /// # Arguments
            ///
            /// * `divisor` - Scalar divisor.
            ///
            /// # Returns
            ///
            /// Quotient wrapped in `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::DivisionByZero`] if `divisor == 0`.
            pub fn checked_div(self, divisor: u64) -> ArbiterResult<Self> {
                self.0.checked_div(divisor).map(Self).ok_or_else(|| {
                    ArbiterError::DivisionByZero {
                        operation: concat!($op_prefix, "::checked_div").to_owned(),
                    }
                })
            }

            /// Checked integer remainder by a scalar divisor.
            ///
            /// # Arguments
            ///
            /// * `divisor` - Scalar divisor.
            ///
            /// # Returns
            ///
            /// Remainder wrapped in `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::DivisionByZero`] if `divisor == 0`.
            pub fn checked_rem(self, divisor: u64) -> ArbiterResult<Self> {
                self.0.checked_rem(divisor).map(Self).ok_or_else(|| {
                    ArbiterError::DivisionByZero {
                        operation: concat!($op_prefix, "::checked_rem").to_owned(),
                    }
                })
            }

            /// Saturating addition (clamps at `u64::MAX`).
            ///
            /// # Arguments
            ///
            /// * `rhs` - Quantity to add.
            ///
            /// # Returns
            ///
            /// Saturated sum.
            pub const fn saturating_add(self, rhs: Self) -> Self {
                Self(self.0.saturating_add(rhs.0))
            }

            /// Saturating subtraction (clamps at `0`).
            ///
            /// # Arguments
            ///
            /// * `rhs` - Quantity to subtract.
            ///
            /// # Returns
            ///
            /// Saturated difference.
            pub const fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }

            /// Computes the share of `self` relative to `total` in parts per billion (`10^9`).
            ///
            /// # Arguments
            ///
            /// * `total` - Denominator capacity.
            ///
            /// # Returns
            ///
            /// [`SharePartsPerBillion`] representing `(self * 1_000_000_000) / total`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::DivisionByZero`] if `total` is zero, or
            /// [`ArbiterError::ArithmeticOverflow`] if the resulting ratio exceeds `u64::MAX`.
            pub fn share_of(self, total: Self) -> ArbiterResult<SharePartsPerBillion> {
                SharePartsPerBillion::from_ratio(self.0, total.0)
            }
        }

        impl fmt::Display for $name {
            /// Formats the unit value with its unit suffix.
            ///
            /// # Arguments
            ///
            /// * `f` - The formatter.
            ///
            /// # Returns
            ///
            /// `fmt::Result`.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", self.0, $unit_suffix)
            }
        }
    };
}

define_u64_unit!(
    /// CPU compute capacity measured in millicores (`1000m = 1 hardware thread/core`).
    Millicores,
    "m",
    "Millicores"
);

/// Canonical alias for [`Millicores`] when distinguishing CPU compute millicores from [`GpuMillicores`].
pub type CpuMillicores = Millicores;

define_u64_unit!(
    /// GPU compute slice measured in millicores (`1000gm = 1 whole GPU compute engine`).
    GpuMillicores,
    "gm",
    "GpuMillicores"
);

define_u64_unit!(
    /// Discrete TPU chip count.
    TpuChips,
    "chips",
    "TpuChips"
);

define_u64_unit!(
    /// Memory or storage capacity measured in exact bytes.
    Bytes,
    "B",
    "Bytes"
);

define_u64_unit!(
    /// Network, PCIe, NVLink, ICI, or storage I/O bandwidth measured in bits per second.
    BandwidthBps,
    "bps",
    "BandwidthBps"
);

define_u64_unit!(
    /// Electrical power draw or cap measured in milliwatts (`1000mW = 1W`).
    PowerMilliwatts,
    "mW",
    "PowerMilliwatts"
);

/// Alias for [`PowerMilliwatts`] where watts-scale naming is referenced.
pub type Watts = PowerMilliwatts;

define_u64_unit!(
    /// Clock frequency measured in megahertz (`MHz`).
    FrequencyMegahertz,
    "MHz",
    "FrequencyMegahertz"
);

define_u64_unit!(
    /// Interconnect hop or probe latency measured in nanoseconds (`ns`).
    LatencyNanoseconds,
    "ns",
    "LatencyNanoseconds"
);

define_u64_unit!(
    /// Fractional share represented in parts per billion (`1_000_000_000 = 100%`).
    SharePartsPerBillion,
    "ppb",
    "SharePartsPerBillion"
);

define_u64_unit!(
    /// Discrete network packet count transmitted on a physical or virtual wire.
    PacketCount,
    "pkt",
    "PacketCount"
);

define_u64_unit!(
    /// Duration of a single simulation or scheduler tick in microseconds (`us`).
    TickDurationMicros,
    "us",
    "TickDurationMicros"
);

define_u64_unit!(
    /// Count of discrete simulation or benchmark ticks.
    BenchmarkTicks,
    "ticks",
    "BenchmarkTicks"
);

define_u64_unit!(
    /// Operation or commit latency measured in microseconds (`us`).
    LatencyMicros,
    "us",
    "LatencyMicros"
);

define_u64_unit!(
    /// Client-observed service blackhole / unavailability duration in milliseconds (`ms`).
    ClientDowntimeMillis,
    "ms",
    "ClientDowntimeMillis"
);

define_u64_unit!(
    /// Monotonically increasing database write-ahead log sequence number (`LSN`) or replication offset.
    LogSequenceNumber,
    "lsn",
    "LogSequenceNumber"
);

define_u64_unit!(
    /// Monotonically increasing Raft consensus election term (`0..=u64::MAX`).
    RaftTerm,
    "term",
    "RaftTerm"
);

define_u64_unit!(
    /// Monotonically increasing Raft write-ahead log entry index (`0..=u64::MAX`).
    RaftLogIndex,
    "idx",
    "RaftLogIndex"
);

define_u64_unit!(
    /// Monotonically increasing key-value storage modification revision (`0..=u64::MAX`).
    StorageRevision,
    "rev",
    "StorageRevision"
);

define_u64_unit!(
    /// Framework failover grace timeout in milliseconds (`ms`) before unregistered tasks are terminated.
    FailoverTimeoutMillis,
    "ms",
    "FailoverTimeoutMillis"
);

define_u64_unit!(
    /// Periodic Master or Agent heartbeat interval in discrete ticks.
    HeartbeatIntervalTicks,
    "ticks",
    "HeartbeatIntervalTicks"
);

define_u64_unit!(
    /// Resource offer time-to-live (`TTL`) duration in discrete ticks before automatic rescinding.
    OfferTtlTicks,
    "ticks",
    "OfferTtlTicks"
);

define_u64_unit!(
    /// Byte offset for paginated Mesos `READ_FILE` sandbox file reads.
    FileReadOffset,
    "B",
    "FileReadOffset"
);

define_u64_unit!(
    /// Maximum byte length for paginated Mesos `READ_FILE` sandbox file reads.
    FileReadLength,
    "B",
    "FileReadLength"
);

define_u64_unit!(
    /// Wall-clock or timeout duration measured in milliseconds (`ms`).
    MillisecondDuration,
    "ms",
    "MillisecondDuration"
);

define_u64_unit!(
    /// Wall-clock timestamp in milliseconds since the Unix epoch (`1970-01-01T00:00:00Z`).
    WallClockUnixMillis,
    "unix_ms",
    "WallClockUnixMillis"
);

/// Alias for [`BandwidthBps`] when describing hardware interconnect link bandwidth.
pub type InterconnectBandwidthBps = BandwidthBps;

/// Canonical alias for [`BandwidthBps`] (`BitsPerSecond`).
pub type BitsPerSecond = BandwidthBps;

/// Canonical alias for [`LatencyMicros`] (`Microseconds`).
pub type Microseconds = LatencyMicros;

/// Alias for [`RaftTerm`] when referring to generic consensus term numbers.
pub type TermNumber = RaftTerm;

/// Alias for [`RaftLogIndex`] when referring to generic write-ahead log entry indices.
pub type LogIndex = RaftLogIndex;

/// Strongly-typed 32-bit cyclic redundancy check (`CRC32`) checksum for WAL, snapshot, and `ARBW` frames.
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct Crc32Checksum(u32);

impl Crc32Checksum {
    /// Wraps a raw `u32` CRC32 checksum value.
    ///
    /// # Arguments
    ///
    /// * `value` - Raw 32-bit CRC32 value.
    ///
    /// # Returns
    ///
    /// Wrapped [`Crc32Checksum`].
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the underlying `u32` checksum value.
    ///
    /// # Returns
    ///
    /// Raw 32-bit CRC32 integer.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Verifies that `self` matches `expected`, returning an error on mismatch.
    ///
    /// # Arguments
    ///
    /// * `expected` - Expected [`Crc32Checksum`].
    /// * `context` - Frame or segment identifier for diagnostics.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the checksums match.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `self != expected`.
    pub fn verify(self, expected: Self, context: &str) -> ArbiterResult<()> {
        if self == expected {
            Ok(())
        } else {
            Err(ArbiterError::InvalidResourceQuantity {
                resource: format!("Crc32Checksum({context})"),
                quantity: u64::from(self.0),
                reason: format!(
                    "CRC32 mismatch: expected 0x{:08x}, found 0x{:08x}",
                    expected.0, self.0
                ),
            })
        }
    }
}

impl fmt::Display for Crc32Checksum {
    /// Formats the CRC32 checksum in lowercase hexadecimal (`crc32:0x...`).
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crc32:0x{:08x}", self.0)
    }
}

/// Strongly-typed control-plane and agent logging verbosity level (`SET_LOGGING_LEVEL` / `GET_LOGGING_LEVEL`).
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum LoggingLevel {
    /// Only fatal and error events (`0`).
    Error,
    /// Warning and error events (`1`, default).
    #[default]
    Warn,
    /// Informational, warning, and error events (`2`).
    Info,
    /// Verbose debug events (`3`).
    Debug,
    /// Wire-frame and tick-level trace events (`4`).
    Trace,
}

impl LoggingLevel {
    /// Converts a raw numeric level (`0..=4`) into a validated [`LoggingLevel`].
    ///
    /// # Arguments
    ///
    /// * `raw` - Numeric verbosity level (`0..=4`).
    ///
    /// # Returns
    ///
    /// Validated [`LoggingLevel`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `raw > 4`.
    pub fn from_u8(raw: u8) -> ArbiterResult<Self> {
        match raw {
            0 => Ok(Self::Error),
            1 => Ok(Self::Warn),
            2 => Ok(Self::Info),
            3 => Ok(Self::Debug),
            4 => Ok(Self::Trace),
            _ => Err(ArbiterError::InvalidResourceQuantity {
                resource: "LoggingLevel".to_owned(),
                quantity: u64::from(raw),
                reason: "logging level must be between 0 (Error) and 4 (Trace)".to_owned(),
            }),
        }
    }

    /// Returns the canonical numeric verbosity code (`0..=4`).
    ///
    /// # Returns
    ///
    /// Numeric level `u8`.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }

    /// Returns the canonical uppercase name of this logging level.
    ///
    /// # Returns
    ///
    /// Static uppercase label string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

impl fmt::Display for LoggingLevel {
    /// Formats the logging level as its canonical uppercase name.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated HTTP response status code (`100..=599`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct HttpStatusCode(u16);

impl Default for HttpStatusCode {
    /// Returns HTTP `200 OK` as the default status code.
    ///
    /// # Returns
    ///
    /// `HttpStatusCode(200)`.
    fn default() -> Self {
        Self::OK
    }
}

impl HttpStatusCode {
    /// HTTP `101 Switching Protocols` (WebSocket upgrade).
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    /// HTTP `200 OK`.
    pub const OK: Self = Self(200);
    /// HTTP `202 Accepted` (Mesos v1 one-way call acknowledgment).
    pub const ACCEPTED: Self = Self(202);
    /// HTTP `204 No Content`.
    pub const NO_CONTENT: Self = Self(204);
    /// HTTP `307 Temporary Redirect` (Master leader redirect).
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    /// HTTP `400 Bad Request`.
    pub const BAD_REQUEST: Self = Self(400);
    /// HTTP `401 Unauthorized`.
    pub const UNAUTHORIZED: Self = Self(401);
    /// HTTP `403 Forbidden`.
    pub const FORBIDDEN: Self = Self(403);
    /// HTTP `404 Not Found`.
    pub const NOT_FOUND: Self = Self(404);
    /// HTTP `409 Conflict`.
    pub const CONFLICT: Self = Self(409);
    /// HTTP `503 Service Unavailable`.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Validates and constructs an [`HttpStatusCode`] in `100..=599`.
    ///
    /// # Arguments
    ///
    /// * `code` - Raw HTTP status code (`100..=599`).
    ///
    /// # Returns
    ///
    /// Validated [`HttpStatusCode`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidRangeBounds`] if `code < 100` or `code > 599`.
    pub fn new(code: u16) -> ArbiterResult<Self> {
        if !(100..=599).contains(&code) {
            return Err(ArbiterError::InvalidRangeBounds {
                context: "HttpStatusCode".to_owned(),
                start: u64::from(code),
                end: 599,
            });
        }
        Ok(Self(code))
    }

    /// Returns the underlying `u16` HTTP status code.
    ///
    /// # Returns
    ///
    /// Raw `u16` status code.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns `true` if the status code is in the `2xx` success range (`200..=299`).
    ///
    /// # Returns
    ///
    /// `true` if `200 <= code <= 299`.
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 <= 299
    }
}

impl fmt::Display for HttpStatusCode {
    /// Formats the HTTP status code.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated POSIX / OS signal number (`1..=64`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct SignalNumber(i32);

impl Default for SignalNumber {
    /// Returns `SIGTERM` (`15`) as the default signal number.
    ///
    /// # Returns
    ///
    /// `SignalNumber(15)`.
    fn default() -> Self {
        Self::SIGTERM
    }
}

impl SignalNumber {
    /// `SIGHUP` (`1`) — configuration / trust bundle reload.
    pub const SIGHUP: Self = Self(1);
    /// `SIGINT` (`2`) — interactive interrupt.
    pub const SIGINT: Self = Self(2);
    /// `SIGKILL` (`9`) — immediate non-maskable termination.
    pub const SIGKILL: Self = Self(9);
    /// `SIGUSR1` (`10`) — Arbiter pre-preemption checkpoint warning signal.
    pub const SIGUSR1: Self = Self(10);
    /// `SIGTERM` (`15`) — graceful termination request.
    pub const SIGTERM: Self = Self(15);
    /// `SIGCONT` (`18`) — resume stopped process.
    pub const SIGCONT: Self = Self(18);
    /// `SIGSTOP` (`19`) — freeze process execution.
    pub const SIGSTOP: Self = Self(19);

    /// Validates and constructs a [`SignalNumber`] in `1..=64`.
    ///
    /// # Arguments
    ///
    /// * `sig` - Raw POSIX signal number (`1..=64`).
    ///
    /// # Returns
    ///
    /// Validated [`SignalNumber`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `sig < 1` or `sig > 64`.
    pub fn new(sig: i32) -> ArbiterResult<Self> {
        if !(1..=64).contains(&sig) {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "SignalNumber".to_owned(),
                quantity: u64::try_from(sig).unwrap_or(0),
                reason: "POSIX signal number must be in 1..=64".to_owned(),
            });
        }
        Ok(Self(sig))
    }

    /// Returns the underlying `i32` signal number.
    ///
    /// # Returns
    ///
    /// Raw `i32` signal number.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Display for SignalNumber {
    /// Formats the signal number with `SIG:` prefix.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIG:{}", self.0)
    }
}

/// Monotonically increasing replication timeline identifier (`>= 1`, incremented on each standby promotion).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct TimelineId(u64);

impl Default for TimelineId {
    /// Returns the initial valid [`TimelineId`] (`1`).
    ///
    /// # Returns
    ///
    /// `TimelineId(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl TimelineId {
    /// Constructs a validated [`TimelineId`] (must be `>= 1`).
    ///
    /// # Arguments
    ///
    /// * `timeline` - Raw timeline number (`>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`TimelineId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `timeline == 0`.
    pub fn new(timeline: u64) -> ArbiterResult<Self> {
        if timeline == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "TimelineId".to_owned(),
                quantity: 0,
                reason: "replication timeline ID must be >= 1".to_owned(),
            });
        }
        Ok(Self(timeline))
    }

    /// Returns the underlying `u64` timeline identifier.
    ///
    /// # Returns
    ///
    /// Raw `u64` timeline value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Increments the timeline ID by `1` using checked arithmetic.
    ///
    /// # Returns
    ///
    /// Next sequential [`TimelineId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if `self.0 == u64::MAX`.
    pub fn next(self) -> ArbiterResult<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| ArbiterError::ArithmeticOverflow {
                operation: "TimelineId::next".to_owned(),
            })
    }
}

impl fmt::Display for TimelineId {
    /// Formats the timeline ID with `tl:` prefix.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tl:{}", self.0)
    }
}

/// Validated count of clusters in a multicluster benchmark or federation (`>= 1`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct ClusterCount(u32);

impl Default for ClusterCount {
    /// Returns the default [`ClusterCount`] (`1`).
    ///
    /// # Returns
    ///
    /// `ClusterCount(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl ClusterCount {
    /// Creates a validated [`ClusterCount`] (`>= 1`).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of clusters (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`ClusterCount`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `count == 0`.
    pub fn new(count: u32) -> ArbiterResult<Self> {
        if count == 0 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "ClusterCount".to_owned(),
                reason: "cluster count must be >= 1".to_owned(),
            });
        }
        Ok(Self(count))
    }

    /// Returns the underlying `u32` cluster count.
    ///
    /// # Returns
    ///
    /// `u32` count.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ClusterCount {
    /// Formats the cluster count as an integer.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated count of nodes in a cluster or benchmark topology (`>= 1`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct NodeCount(u32);

impl Default for NodeCount {
    /// Returns the default HA quorum [`NodeCount`] (`3`).
    ///
    /// # Returns
    ///
    /// `NodeCount(3)`.
    fn default() -> Self {
        Self(3)
    }
}

impl NodeCount {
    /// Creates a validated [`NodeCount`] (`>= 1`).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of nodes (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`NodeCount`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `count == 0`.
    pub fn new(count: u32) -> ArbiterResult<Self> {
        if count == 0 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "NodeCount".to_owned(),
                reason: "node count must be >= 1".to_owned(),
            });
        }
        Ok(Self(count))
    }

    /// Creates a validated odd Raft/HA quorum [`NodeCount`] (`>= 3` and odd, e.g., `3`, `5`, `7`).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of quorum nodes (must be `>= 3` and odd).
    ///
    /// # Returns
    ///
    /// Validated [`NodeCount`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `count < 3` or `count % 2 == 0`.
    pub fn new_quorum(count: u32) -> ArbiterResult<Self> {
        if count < 3 || count % 2 == 0 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "NodeCount".to_owned(),
                reason: format!("HA quorum node count must be odd and >= 3 (got {count})"),
            });
        }
        Ok(Self(count))
    }

    /// Returns the underlying `u32` node count.
    ///
    /// # Returns
    ///
    /// `u32` count.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the majority quorum threshold `(N / 2) + 1`.
    ///
    /// # Returns
    ///
    /// Majority node count as `u32`.
    pub const fn quorum_majority(self) -> u32 {
        (self.0 / 2) + 1
    }

    /// Returns the maximum tolerated simultaneous node failures `(N - 1) / 2`.
    ///
    /// # Returns
    ///
    /// Fault tolerance `f` as `u32`.
    pub const fn fault_tolerance(self) -> u32 {
        (self.0 - 1) / 2
    }
}

impl fmt::Display for NodeCount {
    /// Formats the node count as an integer.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated count of workload tasks in a benchmark trace (`>= 1`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct WorkloadTaskCount(u32);

impl Default for WorkloadTaskCount {
    /// Returns the default [`WorkloadTaskCount`] (`1`).
    ///
    /// # Returns
    ///
    /// `WorkloadTaskCount(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl WorkloadTaskCount {
    /// Creates a validated [`WorkloadTaskCount`] (`>= 1`).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of workload tasks (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`WorkloadTaskCount`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidBenchmarkConfig`] if `count == 0`.
    pub fn new(count: u32) -> ArbiterResult<Self> {
        if count == 0 {
            return Err(ArbiterError::InvalidBenchmarkConfig {
                parameter: "WorkloadTaskCount".to_owned(),
                reason: "workload task count must be >= 1".to_owned(),
            });
        }
        Ok(Self(count))
    }

    /// Returns the underlying `u32` workload task count.
    ///
    /// # Returns
    ///
    /// `u32` count.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for WorkloadTaskCount {
    /// Formats the workload task count as an integer.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Deterministic 64-bit pseudo-random number generator seed for reproducible trace generation.
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct DeterministicPrngSeed(u64);

impl DeterministicPrngSeed {
    /// Constructs a new [`DeterministicPrngSeed`].
    ///
    /// # Arguments
    ///
    /// * `seed` - Raw 64-bit seed value.
    ///
    /// # Returns
    ///
    /// [`DeterministicPrngSeed`].
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Returns the inner `u64` seed value.
    ///
    /// # Returns
    ///
    /// Raw `u64` seed.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl SharePartsPerBillion {
    /// Computes `(numerator * 1_000_000_000) / denominator` using 128-bit intermediate integer math.
    ///
    /// # Arguments
    ///
    /// * `numerator` - Allocated or requested quantity.
    /// * `denominator` - Total capacity quantity (must be non-zero).
    ///
    /// # Returns
    ///
    /// Exact integer [`SharePartsPerBillion`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DivisionByZero`] if `denominator == 0`, or
    /// [`ArbiterError::ArithmeticOverflow`] if the quotient exceeds `u64::MAX`.
    pub fn from_ratio(numerator: u64, denominator: u64) -> ArbiterResult<Self> {
        if denominator == 0 {
            return Err(ArbiterError::DivisionByZero {
                operation: "SharePartsPerBillion::from_ratio".to_owned(),
            });
        }
        let scaled = u128::from(numerator) * u128::from(ONE_BILLION);
        let quotient = scaled / u128::from(denominator);
        let value = u64::try_from(quotient).map_err(|_| ArbiterError::ArithmeticOverflow {
            operation: "SharePartsPerBillion::from_ratio".to_owned(),
        })?;
        Ok(Self(value))
    }

    /// Computes a weighted share `(self * 10_000) / weight_bps` using 128-bit intermediate math.
    ///
    /// In Dominant Resource Fairness (HDRF), dividing a role's raw share by its weight
    /// normalizes shares across roles of different priority weights.
    ///
    /// # Arguments
    ///
    /// * `weight` - The role's [`WeightBasisPoints`].
    ///
    /// # Returns
    ///
    /// Weight-normalized [`SharePartsPerBillion`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if the normalized share exceeds `u64::MAX`.
    pub fn normalize_by_weight(self, weight: WeightBasisPoints) -> ArbiterResult<Self> {
        let scaled = u128::from(self.0) * 10_000_u128;
        let quotient = scaled / u128::from(weight.get());
        let value = u64::try_from(quotient).map_err(|_| ArbiterError::ArithmeticOverflow {
            operation: "SharePartsPerBillion::normalize_by_weight".to_owned(),
        })?;
        Ok(Self(value))
    }

    /// Computes a weighted share `(self * 10_000) / weight_bps`, saturating at `u64::MAX`.
    ///
    /// # Arguments
    ///
    /// * `weight` - The role's [`WeightBasisPoints`].
    ///
    /// # Returns
    ///
    /// Weight-normalized [`SharePartsPerBillion`].
    pub fn saturating_normalize_by_weight(self, weight: WeightBasisPoints) -> Self {
        let scaled = u128::from(self.0) * 10_000_u128;
        let quotient = scaled / u128::from(weight.get());
        Self(u64::try_from(quotient).unwrap_or(u64::MAX))
    }
}

/// Thermal sensor reading in millicelsius (`1000mC = 1 degree Celsius`).
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct TemperatureMilliCelsius(i64);

/// Alias for [`TemperatureMilliCelsius`] for concise domain signatures.
pub type MilliCelsius = TemperatureMilliCelsius;

impl TemperatureMilliCelsius {
    /// Constructs a new temperature reading in millicelsius.
    ///
    /// # Arguments
    ///
    /// * `value` - Temperature in millicelsius.
    ///
    /// # Returns
    ///
    /// New [`TemperatureMilliCelsius`].
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the raw signed millicelsius integer value.
    ///
    /// # Returns
    ///
    /// Signed 64-bit integer millicelsius.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Checked addition of two temperature values.
    ///
    /// # Arguments
    ///
    /// * `rhs` - Temperature delta to add.
    ///
    /// # Returns
    ///
    /// Resulting [`TemperatureMilliCelsius`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] on signed overflow.
    pub fn checked_add(self, rhs: Self) -> ArbiterResult<Self> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or_else(|| ArbiterError::ArithmeticOverflow {
                operation: "TemperatureMilliCelsius::checked_add".to_owned(),
            })
    }

    /// Checked subtraction of two temperature values.
    ///
    /// # Arguments
    ///
    /// * `rhs` - Temperature delta to subtract.
    ///
    /// # Returns
    ///
    /// Resulting [`TemperatureMilliCelsius`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticUnderflow`] on signed underflow.
    pub fn checked_sub(self, rhs: Self) -> ArbiterResult<Self> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or_else(|| ArbiterError::ArithmeticUnderflow {
                operation: "TemperatureMilliCelsius::checked_sub".to_owned(),
            })
    }
}

impl fmt::Display for TemperatureMilliCelsius {
    /// Formats the temperature with `mC` suffix.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}mC", self.0)
    }
}

/// Validated weight or fractional percentage in basis points (`1..=100_000`, where `10_000 = 100%`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct WeightBasisPoints(pub(crate) u64);

impl WeightBasisPoints {
    /// Standard unit weight (`10_000 bps = 1.0x`).
    pub const STANDARD: Self = Self(10_000);

    /// Constructs a validated [`WeightBasisPoints`] in `1..=MAX_BASIS_POINTS`.
    ///
    /// # Arguments
    ///
    /// * `bps` - Basis points value (must be in `1..=100_000`).
    ///
    /// # Returns
    ///
    /// Validated [`WeightBasisPoints`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidShareWeight`] if `bps == 0` or `bps > MAX_BASIS_POINTS`.
    pub fn new(bps: u64) -> ArbiterResult<Self> {
        if bps == 0 || bps > MAX_BASIS_POINTS {
            return Err(ArbiterError::InvalidShareWeight {
                weight_bps: bps,
                reason: format!("weight basis points must be in 1..={MAX_BASIS_POINTS}"),
            });
        }
        Ok(Self(bps))
    }

    /// Returns the raw basis points value.
    ///
    /// # Returns
    ///
    /// The `u64` basis points value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for WeightBasisPoints {
    /// Formats the weight with `bps` suffix.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}bps", self.0)
    }
}

/// Validated non-zero TCP/UDP/QUIC network port number (`1..=65535`).
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct PortNumber(pub(crate) u16);

impl Default for PortNumber {
    /// Returns the default valid [`PortNumber`] (`1`).
    ///
    /// # Returns
    ///
    /// `PortNumber(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl PortNumber {
    /// Creates a new validated [`PortNumber`].
    ///
    /// # Arguments
    ///
    /// * `port` - Port number (`1..=65535`).
    ///
    /// # Returns
    ///
    /// Validated [`PortNumber`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `port == 0`.
    pub fn new(port: u16) -> ArbiterResult<Self> {
        if port == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "PortNumber".to_owned(),
                quantity: 0,
                reason: "network port number must be between 1 and 65535".to_owned(),
            });
        }
        Ok(Self(port))
    }

    /// Returns the underlying `u16` port number.
    ///
    /// # Returns
    ///
    /// `u16` port number.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for PortNumber {
    /// Formats the port number as an integer.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Inclusive range of network ports `[start, end]` where `start <= end`.
#[must_use]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct PortRange {
    /// Inclusive lower bound port.
    pub(crate) start: PortNumber,
    /// Inclusive upper bound port.
    pub(crate) end: PortNumber,
}

impl PortRange {
    /// Creates a validated inclusive [`PortRange`].
    ///
    /// # Arguments
    ///
    /// * `start` - Starting [`PortNumber`].
    /// * `end` - Ending [`PortNumber`] (must be `>= start`).
    ///
    /// # Returns
    ///
    /// Validated [`PortRange`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidRangeBounds`] if `start > end`.
    pub fn new(start: PortNumber, end: PortNumber) -> ArbiterResult<Self> {
        if start.get() > end.get() {
            return Err(ArbiterError::InvalidRangeBounds {
                context: "PortRange".to_owned(),
                start: u64::from(start.get()),
                end: u64::from(end.get()),
            });
        }
        Ok(Self { start, end })
    }

    /// Returns the inclusive start port.
    ///
    /// # Returns
    ///
    /// Start [`PortNumber`].
    pub const fn start(self) -> PortNumber {
        self.start
    }

    /// Returns the inclusive end port.
    ///
    /// # Returns
    ///
    /// End [`PortNumber`].
    pub const fn end(self) -> PortNumber {
        self.end
    }

    /// Returns the number of ports in this inclusive range.
    ///
    /// # Returns
    ///
    /// Count of ports as `u64`.
    pub const fn count(self) -> u64 {
        (self.end.get() as u64 - self.start.get() as u64) + 1
    }

    /// Checks whether a given [`PortNumber`] falls within this range.
    ///
    /// # Arguments
    ///
    /// * `port` - Port to check.
    ///
    /// # Returns
    ///
    /// `true` if `start <= port <= end`.
    pub const fn contains_port(self, port: PortNumber) -> bool {
        port.get() >= self.start.get() && port.get() <= self.end.get()
    }

    /// Checks whether `other` is completely contained within `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - Sub-range to test.
    ///
    /// # Returns
    ///
    /// `true` if `self.start <= other.start && other.end <= self.end`.
    pub const fn contains_range(self, other: Self) -> bool {
        other.start.get() >= self.start.get() && other.end.get() <= self.end.get()
    }
}

impl fmt::Display for PortRange {
    /// Formats the port range as `start-end`.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// Normalized set of disjoint, sorted, non-adjacent [`PortRange`]s.
#[must_use]
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct PortSet {
    /// Sorted, coalesced, disjoint port ranges.
    ranges: Vec<PortRange>,
}

impl PortSet {
    /// Creates an empty [`PortSet`].
    ///
    /// # Returns
    ///
    /// An empty [`PortSet`].
    pub const fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Constructs a normalized [`PortSet`] from an arbitrary list of [`PortRange`]s.
    ///
    /// Overlapping and adjacent ranges are automatically coalesced.
    ///
    /// # Arguments
    ///
    /// * `input` - Vector of port ranges.
    ///
    /// # Returns
    ///
    /// Normalized [`PortSet`].
    pub fn from_ranges(mut input: Vec<PortRange>) -> Self {
        if input.is_empty() {
            return Self::empty();
        }
        input.sort_by_key(|r| (r.start().get(), r.end().get()));
        let mut merged: Vec<PortRange> = Vec::with_capacity(input.len());
        for range in input {
            if let Some(last) = merged.last_mut() {
                let last_end_plus_one = u32::from(last.end().get()) + 1;
                if u32::from(range.start().get()) <= last_end_plus_one {
                    let new_end = if range.end().get() > last.end().get() {
                        range.end()
                    } else {
                        last.end()
                    };
                    *last = PortRange {
                        start: last.start(),
                        end: new_end,
                    };
                    continue;
                }
            }
            merged.push(range);
        }
        Self { ranges: merged }
    }

    /// Returns the slice of normalized [`PortRange`]s.
    ///
    /// # Returns
    ///
    /// Slice `&[PortRange]`.
    pub fn ranges(&self) -> &[PortRange] {
        &self.ranges
    }

    /// Returns the total number of individual ports in the set.
    ///
    /// # Returns
    ///
    /// Total port count as `u64`.
    pub fn total_ports(&self) -> u64 {
        self.ranges.iter().map(|r| r.count()).sum()
    }

    /// Checks if the set contains every port in `other`.
    ///
    /// # Arguments
    ///
    /// * `other` - Subset candidate.
    ///
    /// # Returns
    ///
    /// `true` if every range in `other` is covered by a range in `self`.
    pub fn contains(&self, other: &Self) -> bool {
        other
            .ranges
            .iter()
            .all(|req| self.ranges.iter().any(|avail| avail.contains_range(*req)))
    }

    /// Returns the union of `self` and `other`.
    ///
    /// # Arguments
    ///
    /// * `other` - [`PortSet`] to merge with.
    ///
    /// # Returns
    ///
    /// Coalesced union [`PortSet`].
    pub fn union(&self, other: &Self) -> Self {
        let mut combined = Vec::with_capacity(self.ranges.len() + other.ranges.len());
        combined.extend_from_slice(&self.ranges);
        combined.extend_from_slice(&other.ranges);
        Self::from_ranges(combined)
    }

    /// Subtracts `other` from `self`, failing if `other` is not a subset of `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - [`PortSet`] to remove.
    ///
    /// # Returns
    ///
    /// Remaining [`PortSet`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InsufficientResources`] if `self` does not contain `other`.
    pub fn try_sub(&self, other: &Self) -> ArbiterResult<Self> {
        if !self.contains(other) {
            return Err(ArbiterError::InsufficientResources {
                resource: "ports".to_owned(),
                requested: other.total_ports(),
                available: self.total_ports(),
            });
        }
        let mut current = self.ranges.clone();
        for rem in &other.ranges {
            let mut next = Vec::with_capacity(current.len() + 1);
            for avail in current {
                if !avail.contains_range(*rem) {
                    next.push(avail);
                    continue;
                }
                if avail.start().get() < rem.start().get() {
                    let left_end = PortNumber(rem.start().get() - 1);
                    next.push(PortRange {
                        start: avail.start(),
                        end: left_end,
                    });
                }
                if avail.end().get() > rem.end().get() {
                    let right_start = PortNumber(rem.end().get() + 1);
                    next.push(PortRange {
                        start: right_start,
                        end: avail.end(),
                    });
                }
            }
            current = next;
        }
        Ok(Self { ranges: current })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_u64_units_checked_and_saturating_math() {
        let c1 = Millicores::new(1500);
        let c2 = Millicores::new(500);
        assert!(!c1.is_zero());
        assert!(Millicores::ZERO.is_zero());
        assert_eq!(c1.get(), 1500);
        assert_eq!(c1.to_string(), "1500m");

        assert_eq!(c1.checked_add(c2), Ok(Millicores::new(2000)));
        assert_eq!(c1.checked_sub(c2), Ok(Millicores::new(1000)));
        assert_eq!(c1.checked_mul(2), Ok(Millicores::new(3000)));
        assert_eq!(c1.checked_div(3), Ok(Millicores::new(500)));
        assert_eq!(c1.checked_rem(400), Ok(Millicores::new(300)));
        assert_eq!(c1.saturating_add(c2), Millicores::new(2000));
        assert_eq!(c2.saturating_sub(c1), Millicores::ZERO);

        assert!(Millicores::MAX.checked_add(Millicores::new(1)).is_err());
        assert!(c2.checked_sub(c1).is_err());
        assert!(Millicores::MAX.checked_mul(2).is_err());
        assert!(c1.checked_div(0).is_err());
        assert!(c1.checked_rem(0).is_err());

        let share = c2.share_of(Millicores::new(2000));
        assert_eq!(share, Ok(SharePartsPerBillion::new(250_000_000)));
        assert!(c2.share_of(Millicores::ZERO).is_err());
    }

    macro_rules! test_unit_type {
        ($fn_name:ident, $t:ty, $suffix:literal) => {
            #[test]
            fn $fn_name() {
                let a = <$t>::new(100);
                let b = <$t>::new(50);
                assert!(!a.is_zero());
                assert!(<$t>::ZERO.is_zero());
                assert_eq!(a.get(), 100);
                assert_eq!(a.to_string(), format!("100{}", $suffix));
                assert_eq!(a.checked_add(b), Ok(<$t>::new(150)));
                assert!(<$t>::MAX.checked_add(b).is_err());
                assert_eq!(a.checked_sub(b), Ok(<$t>::new(50)));
                assert!(b.checked_sub(a).is_err());
                assert_eq!(a.checked_mul(2), Ok(<$t>::new(200)));
                assert!(<$t>::MAX.checked_mul(2).is_err());
                assert_eq!(a.checked_div(2), Ok(<$t>::new(50)));
                assert!(a.checked_div(0).is_err());
                assert_eq!(a.checked_rem(30), Ok(<$t>::new(10)));
                assert!(a.checked_rem(0).is_err());
                assert_eq!(a.saturating_add(b), <$t>::new(150));
                assert_eq!(b.saturating_sub(a), <$t>::ZERO);
                assert_eq!(b.share_of(a), Ok(SharePartsPerBillion::new(500_000_000)));
            }
        };
    }

    test_unit_type!(test_gpu_millicores, GpuMillicores, "gm");
    test_unit_type!(test_tpu_chips, TpuChips, "chips");
    test_unit_type!(test_bytes, Bytes, "B");
    test_unit_type!(test_bandwidth_bps, BandwidthBps, "bps");
    test_unit_type!(test_power_milliwatts, PowerMilliwatts, "mW");
    test_unit_type!(test_frequency_megahertz, FrequencyMegahertz, "MHz");
    test_unit_type!(test_latency_nanoseconds, LatencyNanoseconds, "ns");
    test_unit_type!(test_share_parts_per_billion, SharePartsPerBillion, "ppb");
    test_unit_type!(test_packet_count, PacketCount, "pkt");
    test_unit_type!(test_tick_duration_micros, TickDurationMicros, "us");
    test_unit_type!(test_benchmark_ticks, BenchmarkTicks, "ticks");
    test_unit_type!(test_latency_micros, LatencyMicros, "us");
    test_unit_type!(test_client_downtime_millis, ClientDowntimeMillis, "ms");
    test_unit_type!(test_log_sequence_number, LogSequenceNumber, "lsn");
    test_unit_type!(test_raft_term, RaftTerm, "term");
    test_unit_type!(test_raft_log_index, RaftLogIndex, "idx");
    test_unit_type!(test_storage_revision, StorageRevision, "rev");
    test_unit_type!(test_failover_timeout_millis, FailoverTimeoutMillis, "ms");
    test_unit_type!(
        test_heartbeat_interval_ticks,
        HeartbeatIntervalTicks,
        "ticks"
    );
    test_unit_type!(test_offer_ttl_ticks, OfferTtlTicks, "ticks");
    test_unit_type!(test_file_read_offset, FileReadOffset, "B");
    test_unit_type!(test_file_read_length, FileReadLength, "B");
    test_unit_type!(test_millisecond_duration, MillisecondDuration, "ms");
    test_unit_type!(test_wall_clock_unix_millis, WallClockUnixMillis, "unix_ms");

    #[test]
    fn test_crc32_checksum_and_type_aliases() {
        let crc = Crc32Checksum::new(0xDEAD_BEEF);
        assert_eq!(crc.get(), 0xDEAD_BEEF);
        assert_eq!(crc.to_string(), "crc32:0xdeadbeef");
        assert!(crc.verify(Crc32Checksum::new(0xDEAD_BEEF), "wal").is_ok());
        assert!(crc.verify(Crc32Checksum::default(), "wal").is_err());

        let term: TermNumber = RaftTerm::new(3);
        let idx: LogIndex = RaftLogIndex::new(9);
        let bw: InterconnectBandwidthBps = BandwidthBps::new(100_000);
        let bps: BitsPerSecond = BandwidthBps::new(50_000);
        let us: Microseconds = LatencyMicros::new(180);
        assert_eq!(term.get(), 3);
        assert_eq!(idx.get(), 9);
        assert_eq!(bw.get(), 100_000);
        assert_eq!(bps.get(), 50_000);
        assert_eq!(us.get(), 180);
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&crc);
    }

    #[test]
    fn test_logging_level_conversions() {
        assert_eq!(LoggingLevel::default(), LoggingLevel::Warn);
        let levels = [
            (0_u8, LoggingLevel::Error, "ERROR"),
            (1_u8, LoggingLevel::Warn, "WARN"),
            (2_u8, LoggingLevel::Info, "INFO"),
            (3_u8, LoggingLevel::Debug, "DEBUG"),
            (4_u8, LoggingLevel::Trace, "TRACE"),
        ];
        for (code, expected, label) in levels {
            assert_eq!(LoggingLevel::from_u8(code), Ok(expected));
            assert_eq!(expected.as_u8(), code);
            assert_eq!(expected.as_str(), label);
            assert_eq!(expected.to_string(), label);
        }
        assert!(LoggingLevel::from_u8(5).is_err());
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&LoggingLevel::Trace);
    }

    #[test]
    fn test_http_status_code_and_signal_number() {
        assert_eq!(HttpStatusCode::default(), HttpStatusCode::OK);
        assert!(HttpStatusCode::OK.is_success());
        assert!(HttpStatusCode::ACCEPTED.is_success());
        assert!(!HttpStatusCode::SWITCHING_PROTOCOLS.is_success());
        assert!(!HttpStatusCode::BAD_REQUEST.is_success());
        assert!(HttpStatusCode::new(99).is_err());
        assert!(HttpStatusCode::new(600).is_err());
        let code = HttpStatusCode::new(204).unwrap_or_default();
        assert_eq!(code.get(), 204);
        assert_eq!(code.to_string(), "204");

        assert_eq!(SignalNumber::default(), SignalNumber::SIGTERM);
        assert!(SignalNumber::new(0).is_err());
        assert!(SignalNumber::new(-1).is_err());
        assert!(SignalNumber::new(65).is_err());
        let sig = SignalNumber::new(9).unwrap_or_default();
        assert_eq!(sig, SignalNumber::SIGKILL);
        assert_eq!(sig.get(), 9);
        assert_eq!(sig.to_string(), "SIG:9");

        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&(code, sig));
    }

    #[test]
    fn test_timeline_id_and_cluster_count() {
        assert_eq!(TimelineId::default().get(), 1);
        assert!(TimelineId::new(0).is_err());
        let tl1 = TimelineId::new(1).unwrap_or_default();
        assert_eq!(tl1.to_string(), "tl:1");
        let tl2 = tl1.next();
        assert_eq!(tl2, Ok(TimelineId(2)));
        assert!(TimelineId(u64::MAX).next().is_err());

        assert_eq!(ClusterCount::default().get(), 1);
        assert!(ClusterCount::new(0).is_err());
        let cc = ClusterCount::new(3).unwrap_or_default();
        assert_eq!(cc.get(), 3);
        assert_eq!(cc.to_string(), "3");
    }

    #[test]
    fn test_node_count_and_workload_task_count() {
        assert_eq!(NodeCount::default().get(), 3);
        assert!(NodeCount::new(0).is_err());
        assert!(NodeCount::new_quorum(2).is_err());
        assert!(NodeCount::new_quorum(4).is_err());
        let n3 = NodeCount::new_quorum(3).unwrap_or_default();
        let n5 = NodeCount::new_quorum(5).unwrap_or_default();
        let n7 = NodeCount::new_quorum(7).unwrap_or_default();
        assert_eq!(n3.get(), 3);
        assert_eq!(n3.quorum_majority(), 2);
        assert_eq!(n3.fault_tolerance(), 1);
        assert_eq!(n5.quorum_majority(), 3);
        assert_eq!(n5.fault_tolerance(), 2);
        assert_eq!(n7.quorum_majority(), 4);
        assert_eq!(n7.fault_tolerance(), 3);
        assert_eq!(NodeCount::new(10).unwrap_or_default().to_string(), "10");

        assert_eq!(WorkloadTaskCount::default().get(), 1);
        assert!(WorkloadTaskCount::new(0).is_err());
        let wc = WorkloadTaskCount::new(50).unwrap_or_default();
        assert_eq!(wc.get(), 50);
        assert_eq!(wc.to_string(), "50");

        let seed = DeterministicPrngSeed::new(42);
        assert_eq!(seed.get(), 42);
    }

    #[test]
    fn test_share_parts_per_billion_ratio_and_weight() {
        assert!(SharePartsPerBillion::from_ratio(10, 0).is_err());
        assert!(SharePartsPerBillion::from_ratio(u64::MAX, 1).is_err());

        let half = SharePartsPerBillion::new(500_000_000);
        let weight_double = WeightBasisPoints(20_000);
        assert_eq!(
            half.normalize_by_weight(weight_double),
            Ok(SharePartsPerBillion::new(250_000_000))
        );

        let weight_min = WeightBasisPoints(1);
        assert!(
            SharePartsPerBillion::MAX
                .normalize_by_weight(weight_min)
                .is_err()
        );
        assert_eq!(
            SharePartsPerBillion::MAX.saturating_normalize_by_weight(weight_min),
            SharePartsPerBillion::MAX
        );
        assert_eq!(
            half.saturating_normalize_by_weight(weight_double),
            SharePartsPerBillion::new(250_000_000)
        );
    }

    #[test]
    fn test_temperature_milli_celsius() {
        let t1 = TemperatureMilliCelsius::new(45_000);
        let t2 = TemperatureMilliCelsius::new(5_000);
        assert_eq!(t1.get(), 45_000);
        assert_eq!(t1.to_string(), "45000mC");
        assert_eq!(t1.checked_add(t2), Ok(TemperatureMilliCelsius::new(50_000)));
        assert_eq!(t1.checked_sub(t2), Ok(TemperatureMilliCelsius::new(40_000)));
        assert!(
            TemperatureMilliCelsius::new(i64::MAX)
                .checked_add(TemperatureMilliCelsius::new(1))
                .is_err()
        );
        assert!(
            TemperatureMilliCelsius::new(i64::MIN)
                .checked_sub(TemperatureMilliCelsius::new(1))
                .is_err()
        );
    }

    #[test]
    fn test_weight_basis_points() {
        assert!(WeightBasisPoints::new(0).is_err());
        assert!(WeightBasisPoints::new(MAX_BASIS_POINTS + 1).is_err());
        let w = WeightBasisPoints::new(10_000);
        assert_eq!(w, Ok(WeightBasisPoints::STANDARD));
        assert_eq!(WeightBasisPoints::STANDARD.get(), 10_000);
        assert_eq!(WeightBasisPoints::STANDARD.to_string(), "10000bps");
    }

    #[test]
    fn test_port_number_range_and_set() {
        assert_eq!(PortNumber::default().get(), 1);
        assert!(PortNumber::new(0).is_err());
        let p80 = PortNumber::new(80);
        assert_eq!(p80, Ok(PortNumber(80)));
        let p80_val = PortNumber(80);
        let p90_val = PortNumber(90);
        assert_eq!(p80_val.get(), 80);
        assert_eq!(p80_val.to_string(), "80");

        assert!(PortRange::new(p90_val, p80_val).is_err());
        let r1 = PortRange::new(p80_val, p90_val);
        assert!(r1.is_ok());
        let range_80_90 = PortRange {
            start: p80_val,
            end: p90_val,
        };
        assert_eq!(range_80_90.start(), p80_val);
        assert_eq!(range_80_90.end(), p90_val);
        assert_eq!(range_80_90.count(), 11);
        assert!(range_80_90.contains_port(PortNumber(85)));
        assert!(!range_80_90.contains_port(PortNumber(75)));
        assert!(!range_80_90.contains_port(PortNumber(95)));
        assert_eq!(range_80_90.to_string(), "80-90");

        let empty_set = PortSet::from_ranges(vec![]);
        assert_eq!(empty_set, PortSet::empty());
        assert_eq!(empty_set.total_ports(), 0);

        let r_a = PortRange {
            start: PortNumber(80),
            end: PortNumber(85),
        };
        let r_b = PortRange {
            start: PortNumber(86),
            end: PortNumber(90),
        };
        let r_c = PortRange {
            start: PortNumber(82),
            end: PortNumber(84),
        };
        let r_d = PortRange {
            start: PortNumber(100),
            end: PortNumber(105),
        };
        let set = PortSet::from_ranges(vec![r_d, r_b, r_a, r_c]);
        assert_eq!(set.ranges().len(), 2);
        assert_eq!(set.total_ports(), 11 + 6);

        let sub_req = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(82),
            end: PortNumber(88),
        }]);
        assert!(set.contains(&sub_req));

        let remainder = set.try_sub(&sub_req);
        assert!(remainder.is_ok());
        let rem_set = remainder.unwrap_or_default();
        assert_eq!(rem_set.total_ports(), (11 - 7) + 6);
        assert_eq!(rem_set.union(&sub_req), set);

        let exact_sub = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(100),
            end: PortNumber(105),
        }]);
        let rem2 = set.try_sub(&exact_sub).unwrap_or_default();
        assert_eq!(rem2.total_ports(), 11);

        let invalid_sub = PortSet::from_ranges(vec![PortRange {
            start: PortNumber(200),
            end: PortNumber(210),
        }]);
        assert!(set.try_sub(&invalid_sub).is_err());

        let all_units = (
            Millicores::ZERO,
            TimelineId::default(),
            ClusterCount::default(),
            NodeCount::default(),
            WorkloadTaskCount::default(),
            DeterministicPrngSeed::default(),
            TemperatureMilliCelsius::default(),
            WeightBasisPoints::STANDARD,
            PortNumber::default(),
            PortRange {
                start: PortNumber(80),
                end: PortNumber(90),
            },
            set,
        );
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&all_units);
    }

    proptest! {
        #[test]
        fn prop_millicores_add_sub_roundtrip(a in 0..=u64::MAX / 2, b in 0..=u64::MAX / 2) {
            let ma = Millicores::new(a);
            let mb = Millicores::new(b);
            let sum = ma.checked_add(mb);
            prop_assert!(sum.is_ok());
            let sum_val = sum.unwrap_or(Millicores::ZERO);
            prop_assert_eq!(sum_val.checked_sub(mb), Ok(ma));
        }
    }
}
