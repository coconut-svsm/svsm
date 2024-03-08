// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! A subset of the Microsoft hypervisor definitions used by the igvm crate.
//!
//! These types are defined in the Microsoft Hypervisor Top Level Funtional
//! Specification (TLFS), which can be found
//! [here](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs).

use core::fmt::Debug;
use open_enum::open_enum;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HvError {
    InvalidHypercallCode = 0x0002,
    InvalidHypercallInput = 0x0003,
    InvalidAlignment = 0x0004,
    InvalidParameter = 0x0005,
    AccessDenied = 0x0006,
    InvalidPartitionState = 0x0007,
    OperationDenied = 0x0008,
    UnknownProperty = 0x0009,
    PropertyValueOutOfRange = 0x000A,
    InsufficientMemory = 0x000B,
    PartitionTooDeep = 0x000C,
    InvalidPartitionId = 0x000D,
    InvalidVpIndex = 0x000E,
    NotFound = 0x0010,
    InvalidPortId = 0x0011,
    InvalidConnectionId = 0x0012,
    InsufficientBuffers = 0x0013,
    NotAcknowledged = 0x0014,
    InvalidVpState = 0x0015,
    Acknowledged = 0x0016,
    InvalidSaveRestoreState = 0x0017,
    InvalidSynicState = 0x0018,
    ObjectInUse = 0x0019,
    InvalidProximityDomainInfo = 0x001A,
    NoData = 0x001B,
    Inactive = 0x001C,
    NoResources = 0x001D,
    FeatureUnavailable = 0x001E,
    PartialPacket = 0x001F,
    ProcessorFeatureNotSupported = 0x0020,
    ProcessorCacheLineFlushSizeIncompatible = 0x0030,
    InsufficientBuffer = 0x0033,
    IncompatibleProcessor = 0x0037,
    InsufficientDeviceDomains = 0x0038,
    CpuidFeatureValidationError = 0x003C,
    CpuidXsaveFeatureValidationError = 0x003D,
    ProcessorStartupTimeout = 0x003E,
    SmxEnabled = 0x003F,
    InvalidLpIndex = 0x0041,
    InvalidRegisterValue = 0x0050,
    InvalidVtlState = 0x0051,
    NxNotDetected = 0x0055,
    InvalidDeviceId = 0x0057,
    InvalidDeviceState = 0x0058,
    PendingPageRequests = 0x0059,
    PageRequestInvalid = 0x0060,
    KeyAlreadyExists = 0x0065,
    DeviceAlreadyInDomain = 0x0066,
    InvalidCpuGroupId = 0x006F,
    InvalidCpuGroupState = 0x0070,
    OperationFailed = 0x0071,
    NotAllowedWithNestedVirtActive = 0x0072,
    InsufficientRootMemory = 0x0073,
    EventBufferAlreadyFreed = 0x0074,
    VtlAlreadyEnabled = 0x0086,
}

impl core::fmt::Display for HvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let error_str = match *self {
            HvError::InvalidHypercallCode => "Invalid hypercall code",
            HvError::InvalidHypercallInput => "Invalid hypercall input",
            HvError::InvalidAlignment => "Invalid alignment",
            HvError::InvalidParameter => "Invalid parameter",
            HvError::AccessDenied => "Access denied",
            HvError::InvalidPartitionState => "Invalid partition state",
            HvError::OperationDenied => "Operation denied",
            HvError::UnknownProperty => "Unknown property",
            HvError::PropertyValueOutOfRange => "Property value out of range",
            HvError::InsufficientMemory => "Insufficient memory",
            HvError::PartitionTooDeep => "Partition too deep",
            HvError::InvalidPartitionId => "Invalid partition ID",
            HvError::InvalidVpIndex => "Invalid VP index",
            HvError::NotFound => "Not found",
            HvError::InvalidPortId => "Invalid port ID",
            HvError::InvalidConnectionId => "Invalid connection ID",
            HvError::InsufficientBuffers => "Insufficient buffers",
            HvError::NotAcknowledged => "Not acknowledged",
            HvError::InvalidVpState => "Invalid VP state",
            HvError::Acknowledged => "Acknowledged",
            HvError::InvalidSaveRestoreState => "Invalid save restore state",
            HvError::InvalidSynicState => "Invalid SynIC state",
            HvError::ObjectInUse => "Object in use",
            HvError::InvalidProximityDomainInfo => "Invalid proximity domain info",
            HvError::NoData => "No data",
            HvError::Inactive => "Inactive",
            HvError::NoResources => "No resources",
            HvError::FeatureUnavailable => "Feature unavailable",
            HvError::PartialPacket => "Partial packet",
            HvError::ProcessorFeatureNotSupported => "Processor feature not supported",
            HvError::ProcessorCacheLineFlushSizeIncompatible => {
                "Processor cache line flush size incompatible"
            }
            HvError::InsufficientBuffer => "Insufficient buffer",
            HvError::IncompatibleProcessor => "Incompatible processor",
            HvError::InsufficientDeviceDomains => "Insufficient device domains",
            HvError::CpuidFeatureValidationError => "CPUID feature validation error",
            HvError::CpuidXsaveFeatureValidationError => "CPUID XSAVE feature validation error",
            HvError::ProcessorStartupTimeout => "Processor startup timeout",
            HvError::SmxEnabled => "SMX enabled",
            HvError::InvalidLpIndex => "Invalid LP index",
            HvError::InvalidRegisterValue => "Invalid register value",
            HvError::InvalidVtlState => "Invalid VTL state",
            HvError::NxNotDetected => "NX not detected",
            HvError::InvalidDeviceId => "Invalid device ID",
            HvError::InvalidDeviceState => "Invalid device state",
            HvError::PendingPageRequests => "Pending page requests",
            HvError::PageRequestInvalid => "Page request invalid",
            HvError::KeyAlreadyExists => "Key already exists",
            HvError::DeviceAlreadyInDomain => "Device already in domain",
            HvError::InvalidCpuGroupId => "Invalid CPU group ID",
            HvError::InvalidCpuGroupState => "Invalid CPU group state",
            HvError::OperationFailed => "Operation failed",
            HvError::NotAllowedWithNestedVirtActive => {
                "Not allowed with nested virtualization active"
            }
            HvError::InsufficientRootMemory => "Insufficient root memory",
            HvError::EventBufferAlreadyFreed => "Event buffer already freed",
            other => return write!(f, "Hypervisor error {:#06x}", other.0),
        };
        f.write_str(error_str)
    }
}

impl std::error::Error for HvError {}

/// A result type with error type [`HvError`].
pub type HvResult<T> = Result<T, HvError>;

/// A Virtual Trust Level (VTL) defined by Virtual Secure Mode (VSM).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Vtl {
    /// VTL0.
    Vtl0 = 0,
    /// VTL1.
    Vtl1 = 1,
    /// VTL2.
    Vtl2 = 2,
}

impl TryFrom<u8> for Vtl {
    type Error = HvError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Vtl0,
            1 => Self::Vtl1,
            2 => Self::Vtl2,
            _ => return Err(HvError::InvalidParameter),
        })
    }
}

impl From<Vtl> for u8 {
    fn from(value: Vtl) -> Self {
        value as u8
    }
}

/// An aligned u128 value.
#[repr(C, align(16))]
#[derive(Copy, Clone, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
pub struct AlignedU128([u8; 16]);

impl AlignedU128 {
    pub fn to_ne_bytes(&self) -> [u8; 16] {
        self.0
    }

    pub fn from_ne_bytes(val: [u8; 16]) -> Self {
        Self(val)
    }
}

impl Debug for AlignedU128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&u128::from_ne_bytes(self.0), f)
    }
}

impl From<u128> for AlignedU128 {
    fn from(v: u128) -> Self {
        Self(v.to_ne_bytes())
    }
}

impl From<u64> for AlignedU128 {
    fn from(v: u64) -> Self {
        (v as u128).into()
    }
}

impl From<u32> for AlignedU128 {
    fn from(v: u32) -> Self {
        (v as u128).into()
    }
}

impl From<u16> for AlignedU128 {
    fn from(v: u16) -> Self {
        (v as u128).into()
    }
}

impl From<u8> for AlignedU128 {
    fn from(v: u8) -> Self {
        (v as u128).into()
    }
}

impl From<AlignedU128> for u128 {
    fn from(v: AlignedU128) -> Self {
        u128::from_ne_bytes(v.0)
    }
}

/// A `HV_REGISTER_VALUE` that represents virtual processor registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct HvRegisterValue(pub AlignedU128);

impl HvRegisterValue {
    pub fn as_u128(&self) -> u128 {
        self.0.into()
    }

    pub fn as_u64(&self) -> u64 {
        self.as_u128() as u64
    }

    pub fn as_u32(&self) -> u32 {
        self.as_u128() as u32
    }

    pub fn as_u16(&self) -> u16 {
        self.as_u128() as u16
    }

    pub fn as_u8(&self) -> u8 {
        self.as_u128() as u8
    }

    pub fn as_table(&self) -> HvX64TableRegister {
        HvX64TableRegister::read_from_prefix(self.as_bytes()).unwrap()
    }

    pub fn as_segment(&self) -> HvX64SegmentRegister {
        HvX64SegmentRegister::read_from_prefix(self.as_bytes()).unwrap()
    }
}

impl From<u8> for HvRegisterValue {
    fn from(val: u8) -> Self {
        (val as u128).into()
    }
}

impl From<u16> for HvRegisterValue {
    fn from(val: u16) -> Self {
        (val as u128).into()
    }
}

impl From<u32> for HvRegisterValue {
    fn from(val: u32) -> Self {
        (val as u128).into()
    }
}

impl From<u64> for HvRegisterValue {
    fn from(val: u64) -> Self {
        (val as u128).into()
    }
}

impl From<u128> for HvRegisterValue {
    fn from(val: u128) -> Self {
        Self(val.into())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct HvX64TableRegister {
    pub pad: [u16; 3],
    pub limit: u16,
    pub base: u64,
}

impl From<HvX64TableRegister> for HvRegisterValue {
    fn from(val: HvX64TableRegister) -> Self {
        Self::read_from_prefix(val.as_bytes()).unwrap()
    }
}

impl From<HvRegisterValue> for HvX64TableRegister {
    fn from(val: HvRegisterValue) -> Self {
        Self::read_from_prefix(val.as_bytes()).unwrap()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct HvX64SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub attributes: u16,
}

impl From<HvX64SegmentRegister> for HvRegisterValue {
    fn from(val: HvX64SegmentRegister) -> Self {
        Self::read_from_prefix(val.as_bytes()).unwrap()
    }
}

impl From<HvRegisterValue> for HvX64SegmentRegister {
    fn from(val: HvRegisterValue) -> Self {
        Self::read_from_prefix(val.as_bytes()).unwrap()
    }
}

macro_rules! registers {
    ($name:ident {
        $(
            $(#[$vattr:meta])*
            $variant:ident = $value:expr
        ),*
        $(,)?
    }) => {
        #[open_enum]
        #[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u32)]
        pub enum $name {
            $($variant = $value,)*
            InstructionEmulationHints = 0x00000002,
            InternalActivityState = 0x00000004,

            // Guest Crash Registers
            GuestCrashP0  = 0x00000210,
            GuestCrashP1  = 0x00000211,
            GuestCrashP2  = 0x00000212,
            GuestCrashP3  = 0x00000213,
            GuestCrashP4  = 0x00000214,
            GuestCrashCtl = 0x00000215,

            PendingInterruption = 0x00010002,
            InterruptState = 0x00010003,
            PendingEvent0 = 0x00010004,
            PendingEvent1 = 0x00010005,

            VpRuntime = 0x00090000,
            GuestOsId = 0x00090002,
            VpIndex = 0x00090003,
            TimeRefCount = 0x00090004,
            CpuManagementVersion = 0x00090007,
            VpAssistPage = 0x00090013,
            VpRootSignalCount = 0x00090014,
            ReferenceTsc = 0x00090017,
            VpConfig = 0x00090018,
            Ghcb = 0x00090019,
            ReferenceTscSequence = 0x0009001A,
            GuestSchedulerEvent = 0x0009001B,

            Sint0 = 0x000A0000,
            Sint1 = 0x000A0001,
            Sint2 = 0x000A0002,
            Sint3 = 0x000A0003,
            Sint4 = 0x000A0004,
            Sint5 = 0x000A0005,
            Sint6 = 0x000A0006,
            Sint7 = 0x000A0007,
            Sint8 = 0x000A0008,
            Sint9 = 0x000A0009,
            Sint10 = 0x000A000A,
            Sint11 = 0x000A000B,
            Sint12 = 0x000A000C,
            Sint13 = 0x000A000D,
            Sint14 = 0x000A000E,
            Sint15 = 0x000A000F,
            Scontrol = 0x000A0010,
            Sversion = 0x000A0011,
            Sifp = 0x000A0012,
            Sipp = 0x000A0013,
            Eom = 0x000A0014,
            Sirbp = 0x000A0015,

            VsmCodePageOffsets = 0x000D0002,
            VsmVpStatus = 0x000D0003,
            VsmPartitionStatus = 0x000D0004,
            VsmVina = 0x000D0005,
            VsmCapabilities = 0x000D0006,
            VsmPartitionConfig = 0x000D0007,
            GuestVsmPartitionConfig = 0x000D0008,
            VsmVpSecureConfigVtl0 = 0x000D0010,
            VsmVpSecureConfigVtl1 = 0x000D0011,
            VsmVpSecureConfigVtl2 = 0x000D0012,
            VsmVpSecureConfigVtl3 = 0x000D0013,
            VsmVpSecureConfigVtl4 = 0x000D0014,
            VsmVpSecureConfigVtl5 = 0x000D0015,
            VsmVpSecureConfigVtl6 = 0x000D0016,
            VsmVpSecureConfigVtl7 = 0x000D0017,
            VsmVpSecureConfigVtl8 = 0x000D0018,
            VsmVpSecureConfigVtl9 = 0x000D0019,
            VsmVpSecureConfigVtl10 = 0x000D001A,
            VsmVpSecureConfigVtl11 = 0x000D001B,
            VsmVpSecureConfigVtl12 = 0x000D001C,
            VsmVpSecureConfigVtl13 = 0x000D001D,
            VsmVpSecureConfigVtl14 = 0x000D001E,
            VsmVpWaitForTlbLock = 0x000D0020,
        }
    };
}

registers! {
    HvX64RegisterName {
        DeliverabilityNotifications = 0x00010006,

        // X64 User-Mode Registers
        Rax = 0x00020000,
        Rcx = 0x00020001,
        Rdx = 0x00020002,
        Rbx = 0x00020003,
        Rsp = 0x00020004,
        Rbp = 0x00020005,
        Rsi = 0x00020006,
        Rdi = 0x00020007,
        R8 = 0x00020008,
        R9 = 0x00020009,
        R10 = 0x0002000a,
        R11 = 0x0002000b,
        R12 = 0x0002000c,
        R13 = 0x0002000d,
        R14 = 0x0002000e,
        R15 = 0x0002000f,
        Rip = 0x00020010,
        Rflags = 0x00020011,

        // X64 Floating Point and Vector Registers
        Xmm0 = 0x00030000,
        Xmm1 = 0x00030001,
        Xmm2 = 0x00030002,
        Xmm3 = 0x00030003,
        Xmm4 = 0x00030004,
        Xmm5 = 0x00030005,
        Xmm6 = 0x00030006,
        Xmm7 = 0x00030007,
        Xmm8 = 0x00030008,
        Xmm9 = 0x00030009,
        Xmm10 = 0x0003000A,
        Xmm11 = 0x0003000B,
        Xmm12 = 0x0003000C,
        Xmm13 = 0x0003000D,
        Xmm14 = 0x0003000E,
        Xmm15 = 0x0003000F,
        FpMmx0 = 0x00030010,
        FpMmx1 = 0x00030011,
        FpMmx2 = 0x00030012,
        FpMmx3 = 0x00030013,
        FpMmx4 = 0x00030014,
        FpMmx5 = 0x00030015,
        FpMmx6 = 0x00030016,
        FpMmx7 = 0x00030017,
        FpControlStatus = 0x00030018,
        XmmControlStatus = 0x00030019,

        // X64 Control Registers
        Cr0 = 0x00040000,
        Cr2 = 0x00040001,
        Cr3 = 0x00040002,
        Cr4 = 0x00040003,
        Cr8 = 0x00040004,
        Xfem = 0x00040005,
        // X64 Intermediate Control Registers
        IntermediateCr0 = 0x00041000,
        IntermediateCr4 = 0x00041003,
        IntermediateCr8 = 0x00041004,
        // X64 Debug Registers
        Dr0 = 0x00050000,
        Dr1 = 0x00050001,
        Dr2 = 0x00050002,
        Dr3 = 0x00050003,
        Dr6 = 0x00050004,
        Dr7 = 0x00050005,
        // X64 Segment Registers
        Es = 0x00060000,
        Cs = 0x00060001,
        Ss = 0x00060002,
        Ds = 0x00060003,
        Fs = 0x00060004,
        Gs = 0x00060005,
        Ldtr = 0x00060006,
        Tr = 0x00060007,
        // X64 Table Registers
        Idtr = 0x00070000,
        Gdtr = 0x00070001,
        // X64 Virtualized MSRs
        Tsc = 0x00080000,
        Efer = 0x00080001,
        KernelGsBase = 0x00080002,
        ApicBase = 0x00080003,
        Pat = 0x00080004,
        SysenterCs = 0x00080005,
        SysenterEip = 0x00080006,
        SysenterEsp = 0x00080007,
        Star = 0x00080008,
        Lstar = 0x00080009,
        Cstar = 0x0008000a,
        Sfmask = 0x0008000b,
        InitialApicId = 0x0008000c,
        // X64 Cache control MSRs
        MsrMtrrCap = 0x0008000d,
        MsrMtrrDefType = 0x0008000e,
        MsrMtrrPhysBase0 = 0x00080010,
        MsrMtrrPhysBase1 = 0x00080011,
        MsrMtrrPhysBase2 = 0x00080012,
        MsrMtrrPhysBase3 = 0x00080013,
        MsrMtrrPhysBase4 = 0x00080014,
        MsrMtrrPhysBase5 = 0x00080015,
        MsrMtrrPhysBase6 = 0x00080016,
        MsrMtrrPhysBase7 = 0x00080017,
        MsrMtrrPhysBase8 = 0x00080018,
        MsrMtrrPhysBase9 = 0x00080019,
        MsrMtrrPhysBaseA = 0x0008001a,
        MsrMtrrPhysBaseB = 0x0008001b,
        MsrMtrrPhysBaseC = 0x0008001c,
        MsrMtrrPhysBaseD = 0x0008001d,
        MsrMtrrPhysBaseE = 0x0008001e,
        MsrMtrrPhysBaseF = 0x0008001f,
        MsrMtrrPhysMask0 = 0x00080040,
        MsrMtrrPhysMask1 = 0x00080041,
        MsrMtrrPhysMask2 = 0x00080042,
        MsrMtrrPhysMask3 = 0x00080043,
        MsrMtrrPhysMask4 = 0x00080044,
        MsrMtrrPhysMask5 = 0x00080045,
        MsrMtrrPhysMask6 = 0x00080046,
        MsrMtrrPhysMask7 = 0x00080047,
        MsrMtrrPhysMask8 = 0x00080048,
        MsrMtrrPhysMask9 = 0x00080049,
        MsrMtrrPhysMaskA = 0x0008004a,
        MsrMtrrPhysMaskB = 0x0008004b,
        MsrMtrrPhysMaskC = 0x0008004c,
        MsrMtrrPhysMaskD = 0x0008004d,
        MsrMtrrPhysMaskE = 0x0008004e,
        MsrMtrrPhysMaskF = 0x0008004f,
        MsrMtrrFix64k00000 = 0x00080070,
        MsrMtrrFix16k80000 = 0x00080071,
        MsrMtrrFix16kA0000 = 0x00080072,
        MsrMtrrFix4kC0000 = 0x00080073,
        MsrMtrrFix4kC8000 = 0x00080074,
        MsrMtrrFix4kD0000 = 0x00080075,
        MsrMtrrFix4kD8000 = 0x00080076,
        MsrMtrrFix4kE0000 = 0x00080077,
        MsrMtrrFix4kE8000 = 0x00080078,
        MsrMtrrFix4kF0000 = 0x00080079,
        MsrMtrrFix4kF8000 = 0x0008007a,

        TscAux = 0x0008007B,
        Bndcfgs = 0x0008007C,
        DebugCtl = 0x0008007D,
        MCount = 0x0008007E,
        ACount = 0x0008007F,

        SgxLaunchControl0 = 0x00080080,
        SgxLaunchControl1 = 0x00080081,
        SgxLaunchControl2 = 0x00080082,
        SgxLaunchControl3 = 0x00080083,
        SpecCtrl = 0x00080084,
        PredCmd = 0x00080085,
        VirtSpecCtrl = 0x00080086,
        TscVirtualOffset = 0x00080087,
        TsxCtrl = 0x00080088,
        MsrMcUpdatePatchLevel = 0x00080089,
        Available1 = 0x0008008A,
        Xss = 0x0008008B,
        UCet = 0x0008008C,
        SCet = 0x0008008D,
        Ssp = 0x0008008E,
        Pl0Ssp = 0x0008008F,
        Pl1Ssp = 0x00080090,
        Pl2Ssp = 0x00080091,
        Pl3Ssp = 0x00080092,
        InterruptSspTableAddr = 0x00080093,
        TscVirtualMultiplier = 0x00080094,
        TscDeadline = 0x00080095,
        TscAdjust = 0x00080096,
        Pasid = 0x00080097,
        UmwaitControl = 0x00080098,
        Xfd = 0x00080099,
        XfdErr = 0x0008009A,

        Hypercall = 0x00090001,

        // Partition Timer Assist Registers
        EmulatedTimerPeriod = 0x00090030,
        EmulatedTimerControl = 0x00090031,
        PmTimerAssist = 0x00090032,
    }
}

registers! {
    HvArm64RegisterName {
        X0 = 0x00020000,
        X1 = 0x00020001,
        X2 = 0x00020002,
        X3 = 0x00020003,
        X4 = 0x00020004,
        X5 = 0x00020005,
        X6 = 0x00020006,
        X7 = 0x00020007,
        X8 = 0x00020008,
        X9 = 0x00020009,
        X10 = 0x0002000A,
        X11 = 0x0002000B,
        X12 = 0x0002000C,
        X13 = 0x0002000D,
        X14 = 0x0002000E,
        X15 = 0x0002000F,
        X16 = 0x00020010,
        X17 = 0x00020011,
        X18 = 0x00020012,
        X19 = 0x00020013,
        X20 = 0x00020014,
        X21 = 0x00020015,
        X22 = 0x00020016,
        X23 = 0x00020017,
        X24 = 0x00020018,
        X25 = 0x00020019,
        X26 = 0x0002001A,
        X27 = 0x0002001B,
        X28 = 0x0002001C,
        XFp = 0x0002001D,
        XLr = 0x0002001E,
        XSp = 0x0002001F, // alias for either El0/x depending on Cpsr.SPSel
        XSpEl0 = 0x00020020,
        XSpElx = 0x00020021,
        XPc = 0x00020022,
        Cpsr = 0x00020023,
        SctlrEl1 = 0x00040002,
        Ttbr0El1 = 0x00040005,
        Ttbr1El1 = 0x00040006,
        TcrEl1 = 0x00040007,
        EsrEl1 = 0x00040008,
        FarEl1 = 0x00040009,
        ElrEl1 = 0x00040015,
        MairEl1 = 0x0004000B,
        VbarEl1 = 0x0004000C,
    }
}
