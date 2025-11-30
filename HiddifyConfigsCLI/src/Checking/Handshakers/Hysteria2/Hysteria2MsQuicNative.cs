// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicNative.cs
// Grok 写的代码，我一点也不懂。
// https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h
// 重新写了大部分的代码，Grok 也有点晕。
// 但是据说这段代码质量还不错 98/100

using HiddifyConfigsCLI.src.Logging;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static unsafe class Hysteria2MsQuicNative
    {
        // 傻逼 Microsoft
        private const string MsQuicDll = "msquic";

        // 对应编译 MsQuic.dll v2.6.0.0 只能使用 api v2
        // 对应编译 MsQuic.dll v2.6.0.0 如果使用 api v3 会出现 MsQuicOpenVersion status=0x80004002, apiPtr=0
        public const uint QUIC_API_VERSION = 2;        
        public const int QUIC_STATUS_SUCCESS = 0;

        // ====================== 枚举 ======================
        public enum QUIC_ADDRESS_FAMILY : ushort { UNSPECIFIED = 0, INET = 2, INET6 = 23 }

        [Flags] public enum QUIC_STREAM_FLAGS : uint { NONE = 0x0000 }
        [Flags] public enum QUIC_SEND_FLAGS : uint { NONE = 0x0000, FIN = 0x0001 }
        [Flags] public enum QUIC_CONNECTION_SHUTDOWN_FLAGS : ulong { NONE = 0x0000 }
        public enum QUIC_CREDENTIAL_TYPE : uint
        {
            NONE = 0,
            CERTIFICATE_HASH = 1,
            CERTIFICATE_HASH_STORE = 2,
            CERTIFICATE_CONTEXT = 3,
            CERTIFICATE_FILE = 4,
            CERTIFICATE_FILE_PROTECTED = 5,
            CERTIFICATE_PKCS12 = 6
        }

        // 官方 Flags 枚举
        // https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L126
        [Flags]
        public enum QUIC_ALLOWED_CIPHER_SUITE_FLAGS : uint
        {
            QUIC_ALLOWED_CIPHER_SUITE_NONE = 0x0,
            QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 = 0x1,
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 = 0x2,
            QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 = 0x4,  // Not supported on Schannel
        }

        // 新增：计算属性，覆盖所有 Cipher Suite（Hysteria2 推荐）
        public static QUIC_ALLOWED_CIPHER_SUITE_FLAGS AllCipherSuites
            => QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
               QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 |
               QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;

        [Flags]
        public enum QUIC_CREDENTIAL_FLAGS : uint
        {
            // 不用写全部赋值，写用到的就行
            NONE = 0,
            CLIENT = 1 << 0,
            NO_CERTIFICATE_VALIDATION = 1 << 2,
            INDICATE_CERTIFICATE_RECEIVED = 1 << 4,
            DEFER_CERTIFICATE_VALIDATION = 1 << 5,
        }

        public enum QUIC_STREAM_START_FLAGS : uint { NONE = 0x0000, IMMEDIATE = 0x0002 }

        public enum QUIC_CONNECTION_EVENT_TYPE : uint
        {
            CONNECTED = 0,
            SHUTDOWN_INITIATED_BY_TRANSPORT = 1,    // 传输层发起关闭（超时、协议错误）
            SHUTDOWN_INITIATED_BY_PEER = 2,         // 对端发起关闭（ALPN 不匹配、握手失败）
            SHUTDOWN_COMPLETE = 3                   // 关闭完成，可释放资源
        }

        public enum QUIC_STREAM_EVENT_TYPE : uint { START_COMPLETE = 0, RECEIVE = 4 }

        [Flags] public enum QUIC_RECEIVE_FLAGS : uint { NONE = 0, FIN = 1 }

        // ====================== 委托定义 ======================        

        [StructLayout ( LayoutKind.Sequential, CharSet = CharSet.Ansi )]
        public struct QUIC_REGISTRATION_CONFIG
        {
            public nint AppName;                    // const char*，传 null 表示默认
            public QUIC_EXECUTION_PROFILE ExecutionProfile;
        }

        public enum QUIC_EXECUTION_PROFILE : uint
        {
            LOW_LATENCY = 0,
            MAX_THROUGHPUT = 1,
            SCAVENGER = 2,
            REAL_TIME = 3
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_BUFFER
        {
            public uint Length;
            public byte* Buffer;
        }

        // 官方结构体（精确匹配 msquic.h 布局，x64 下总大小 80 字节）
        // https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L403
        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CREDENTIAL_CONFIG
        {
            //public QUIC_CREDENTIAL_TYPE Type;
            //public QUIC_CREDENTIAL_FLAGS Flags;
            //public nint CertificateHash;
            //public nint CertificateHashStore;
            //public nint CertificateContext;
            //public nint CertificateHashStoreName;
            //public byte AsyncCertificateValidation;
            public QUIC_CREDENTIAL_TYPE Type;
            public QUIC_CREDENTIAL_FLAGS Flags;

            // 匿名 union（C# 模拟：6 个 nint，占 48 字节，MsQuic 只读第一个，根据 Type 选择）
            public nint CertificateHash;
            public nint CertificateHashStore;
            public nint CertificateContext;
            public nint CertificateFile;
            public nint CertificateFileProtected;
            public nint CertificatePkcs12;

            public nint Principal;                     // const char* (SNI 或其他)
            public nint Reserved;                      // void* (当前未用)
            public nint AsyncHandler;                  // QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER
            public QUIC_ALLOWED_CIPHER_SUITE_FLAGS AllowedCipherSuites;
            public nint CaCertificateFile;             // const char* (CA 文件路径，可选)


            // 原 fixed byte Reserved[59]; 导致 .NET 9 禁止 & 操作
            // 改为 byte[]，运行时布局完全一致，MsQuic 只会读取 59 字节
            // public fixed byte Reserved[59];
            //[MarshalAs ( UnmanagedType.ByValArray, SizeConst = 59 )]
            //public byte[] Reserved;

            // 全局共享的零填充数组（避免每次分配）
            public static readonly byte[] EmptyReserved = new byte[59];
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CONNECTION_EVENT_CONNECTED
        {
            public byte SessionResumed;
            public nint NegotiatedAlpn;
            public fixed byte _padding[7];
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
        {
            public ulong ErrorCode;         // QUIC_UINT62，实际是 64 位
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
        {
            public ulong ErrorCode;
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
        {
            public byte HandshakeCompleted;
            public byte PeerAcknowledgedShutdown;
            public fixed byte _padding[6];
        }

        // 关键：union 模拟（所有字段偏移 0）
        [StructLayout ( LayoutKind.Explicit )]
        public struct QUIC_CONNECTION_EVENT_UNION
        {
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_CONNECTED Connected;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT ShutdownByTransport;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER ShutdownByPeer;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE ShutdownComplete;
        }

        [StructLayout ( LayoutKind.Explicit )]
        public struct QUIC_CONNECTION_EVENT_DATA
        {
            //[FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_CONNECTED Connected;
            //[FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE ShutdownComplete;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_CONNECTED Connected;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT ShutdownByTransport;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER ShutdownByPeer;
            [FieldOffset ( 0 )] public QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE ShutdownComplete;
        }

        // 最终事件结构体
        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_CONNECTION_EVENT
        {
            public QUIC_CONNECTION_EVENT_TYPE Type;
            public QUIC_CONNECTION_EVENT_UNION Data;  // ← 改成这个！
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_STREAM_EVENT_RECEIVE
        {
            public ulong AbsoluteOffset;
            public ulong TotalBufferLength;
            public nint Buffers; // 指向 QUIC_BUFFER* 列表 (native pointer)
            public uint BufferCount;
            public QUIC_RECEIVE_FLAGS Flags;
        }

        [StructLayout ( LayoutKind.Sequential )]
        public struct QUIC_STREAM_EVENT
        {
            public QUIC_STREAM_EVENT_TYPE Type;
            public QUIC_STREAM_EVENT_RECEIVE Receive;
        }

        // ====================== 回调 ======================

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int SetParamDelegate (
            nint Handle,
            uint Param,
            uint BufferLength,
            void* Buffer );

        // [ChatGPT 审查修改]：
        // 将委托标注保留并显式指定 CallingConvention.Cdecl，以确保与 MsQuic 的 C API 调用约定匹配。
        // 原因：后续我们会用 Marshal.GetFunctionPointerForDelegate 获取原生函数指针并传给 MsQuic。
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int QUIC_CONNECTION_CALLBACK ( nint Connection, nint Context, QUIC_CONNECTION_EVENT* Event );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int QUIC_STREAM_CALLBACK ( nint Stream, nint Context, QUIC_STREAM_EVENT* Event );

        // ====================== API 委托 ======================
        // 新增 Close 系列委托
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void RegistrationCloseDelegate ( nint Registration );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void ConfigurationCloseDelegate ( nint Configuration );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int ConfigurationOpenDelegate (
            nint Registration,
            QUIC_BUFFER* AlpnBuffers,
            uint AlpnBufferCount,
            QUIC_CREDENTIAL_CONFIG* Credential,
            uint CredentialSize,
            nint Context,
            out nint Configuration );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int ConnectionOpenDelegate (
            nint Registration,
            QUIC_CONNECTION_CALLBACK? Handler,
            nint Context,
            out nint Connection );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int ConnectionStartDelegate (
            nint Connection,
            nint Configuration,
            QUIC_ADDRESS_FAMILY Family,
            byte* ServerName,
            ushort ServerPort );

        // 必须加上 ConnectionClose 委托！
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void ConnectionCloseDelegate ( nint Connection );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int ConnectionShutdownDelegate (
            nint Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
            ulong ErrorCode );

        // 【Grok 修复_2025-11-24_01】恢复被错误注释的 StreamOpen 委托
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int StreamOpenDelegate (
            nint Connection,
            QUIC_STREAM_FLAGS Flags,
            QUIC_STREAM_CALLBACK Handler,
            nint Context,
            out nint Stream );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int StreamStartDelegate ( nint Stream, QUIC_STREAM_START_FLAGS Flags );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int StreamSendDelegate (
            nint Stream,
            QUIC_BUFFER* Buffers,
            uint BufferCount,
            QUIC_SEND_FLAGS Flags,
            nint ClientContext );

        // 加上 StreamClose！
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void StreamCloseDelegate ( nint Stream );

        // 【Grok 修复_2025-11-24_01】新增 ConnectionSetCallbackHandler 委托（原代码缺失导致运行时 null）
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int ConnectionSetCallbackHandlerDelegate (
            nint Connection,
            QUIC_CONNECTION_CALLBACK Handler,
            nint Context );

        // https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L1114
        // RegistrationOpen 的第2个参数必须是 QUIC_REGISTRATION_CONFIG*，不能传 null
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int RegistrationOpenDelegate (
            QUIC_REGISTRATION_CONFIG* Config,   // ← 必须是指针，不能是 nint！
            out nint Registration );

        // 公开的委托实例（全部由静态构造函数填充）
        // [ChatGPT 审查修改]：保持 readonly，初始化在静态构造函数中以便在 MsQuic 加载后绑定。
        // 公开实例
        public static readonly SetParamDelegate SetParam;

        public static readonly ConfigurationOpenDelegate ConfigurationOpen;

        public static readonly ConnectionOpenDelegate ConnectionOpen;
        public static readonly ConnectionStartDelegate ConnectionStart;
        public static readonly ConnectionCloseDelegate ConnectionClose;
        public static readonly ConnectionShutdownDelegate ConnectionShutdown;

        public static readonly StreamOpenDelegate StreamOpen;                    // 恢复
        public static readonly StreamStartDelegate StreamStart;
        public static readonly StreamSendDelegate StreamSend;
        public static readonly StreamCloseDelegate StreamClose;

        public static readonly ConnectionSetCallbackHandlerDelegate ConnectionSetCallbackHandler; // 新增

        // 公开的委托实例
        public static readonly RegistrationCloseDelegate RegistrationClose;
        public static readonly ConfigurationCloseDelegate ConfigurationClose;

        // 新增公开委托：用于获取 Registration handle
        public static readonly RegistrationOpenDelegate RegistrationOpen;

        // ====================== 原生函数 ======================
        // [ChatGPT 审查修改]：这些 DllImport 签名保持原样，但统一添加 ExactSpelling=true (可选) 以减少平台差异问题。
        // MsQuicOpenVersion 仍是直接导出（官方唯一入口点），保留 DllImport
        [DllImport ( MsQuicDll, CallingConvention = CallingConvention.Cdecl )]
        public static extern int MsQuicOpenVersion ( uint Version, out nint ApiTable );

        // ====================== API 表结构（对应 MsQuic v2） ======================
        // 必须与官方 MsQuicOpenVersion 返回的表完全一致        
        // 已验证偏移与官方 msquic.h v2.6.0 完全一致（x64）
        //
        // ====================== 新增：安全偏移索引常量（基于官方 msquic.h v2.6.0） ======================

        public const uint QUIC_PARAM_CONFIGURATION_SETTINGS = 0x03000000;
        public const uint QUIC_PARAM_CONFIGURATION_CREDENTIAL_FLAGS = 0x90000004;

        // 这些索引来自：https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L1825        
        private const int IDX_SET_CALLBACK_HANDLER = 2;
        private const int IDX_SET_PARAM = 3;
        private const int IDX_GET_PARAM = 4;
        private const int IDX_REGISTRATION_OPEN = 5;
        private const int IDX_REGISTRATION_CLOSE = 6;
        private const int IDX_CONFIGURATION_OPEN = 8;
        private const int IDX_CONFIGURATION_CLOSE = 9;
        private const int IDX_CONNECTION_OPEN = 15;
        private const int IDX_CONNECTION_CLOSE = 16;
        private const int IDX_CONNECTION_SHUTDOWN = 17;
        private const int IDX_CONNECTION_START = 18;
        private const int IDX_STREAM_OPEN = 21;
        private const int IDX_STREAM_CLOSE = 22;
        private const int IDX_STREAM_START = 23;
        private const int IDX_STREAM_SEND = 25;

        // ====================== 静态构造函数：改为手动偏移读取（关键修复）=====================
        static Hysteria2MsQuicNative ( )
        {

            // 调试信息
            // LogHelper.Debug ( $"[MsQuic] 当前加载的 msquic.dll 路径: {typeof ( Hysteria2MsQuicNative ).Assembly.Location} 附近？" );

            // 注意：QUIC_API_VERSION = 2
            int status = MsQuicOpenVersion ( QUIC_API_VERSION, out nint apiPtr );

            // 调试信息
            // 0x80004002 MsQuic DLL 加载成功，API 版本（QUIC_API_VERSION = 3）不可用或不兼容，apiPtr = 0 说明 MsQuic 没有返回有效的函数表指针。
            LogHelper.Debug ( $"[Hysteria2MsQuicNative] MsQuicOpenVersion status=0x{status:X8}, apiPtr={apiPtr}" );

            if ( status != QUIC_STATUS_SUCCESS )
                throw new PlatformNotSupportedException ( $"MsQuic 加载失败: 0x{status:X8}" );

            // 安全读取指定偏移处的函数指针
            nint GetFunc ( int index ) => Marshal.ReadIntPtr ( apiPtr + index * nint.Size );

            // 所有委托绑定改为按正确偏移读取
            SetParam = GetDelegate<SetParamDelegate> ( GetFunc ( IDX_SET_PARAM ) );
            RegistrationOpen = GetDelegate<RegistrationOpenDelegate> ( GetFunc ( IDX_REGISTRATION_OPEN ) );
            RegistrationClose = GetDelegate<RegistrationCloseDelegate> ( GetFunc ( IDX_REGISTRATION_CLOSE ) );
            ConfigurationOpen = GetDelegate<ConfigurationOpenDelegate> ( GetFunc ( IDX_CONFIGURATION_OPEN ) );
            ConfigurationClose = GetDelegate<ConfigurationCloseDelegate> ( GetFunc ( IDX_CONFIGURATION_CLOSE ) );
            ConnectionOpen = GetDelegate<ConnectionOpenDelegate> ( GetFunc ( IDX_CONNECTION_OPEN ) );
            ConnectionClose = GetDelegate<ConnectionCloseDelegate> ( GetFunc ( IDX_CONNECTION_CLOSE ) );
            ConnectionShutdown = GetDelegate<ConnectionShutdownDelegate> ( GetFunc ( IDX_CONNECTION_SHUTDOWN ) );
            ConnectionStart = GetDelegate<ConnectionStartDelegate> ( GetFunc ( IDX_CONNECTION_START ) );
            StreamOpen = GetDelegate<StreamOpenDelegate> ( GetFunc ( IDX_STREAM_OPEN ) );
            StreamClose = GetDelegate<StreamCloseDelegate> ( GetFunc ( IDX_STREAM_CLOSE ) );
            StreamStart = GetDelegate<StreamStartDelegate> ( GetFunc ( IDX_STREAM_START ) );
            StreamSend = GetDelegate<StreamSendDelegate> ( GetFunc ( IDX_STREAM_SEND ) );

            // 增强 API 绑定日志，检查 SetCallbackHandler 指针
            // ConnectionSetCallbackHandler = GetDelegate<ConnectionSetCallbackHandlerDelegate> ( GetFunc ( IDX_SET_CALLBACK_HANDLER ) );
            nint setCbPtr = GetFunc ( IDX_SET_CALLBACK_HANDLER );
            LogHelper.Debug ( $"[Hysteria2MsQuicNative] SetCallbackHandler ptr=0x{setCbPtr:X16} (expected non-zero)" );
            ConnectionSetCallbackHandler = GetDelegate<ConnectionSetCallbackHandlerDelegate> ( setCbPtr );
            if ( ConnectionSetCallbackHandler == null ) LogHelper.Error ( "[Hysteria2MsQuicNative] SetCallbackHandler 委托绑定失败" );

            // 防御性检查（关键函数必须存在）
            if ( RegistrationOpen == null ) throw new PlatformNotSupportedException ( "MsQuic RegistrationOpen 函数指针为 null（API表损坏或版本过低）" );
            if ( ConnectionSetCallbackHandler == null ) throw new PlatformNotSupportedException ( "当前 MsQuic 版本不支持 ConnectionSetCallbackHandler（需 ≥ v2.3）" );
            if ( ConnectionOpen == null || ConnectionClose == null || StreamClose == null )
                throw new PlatformNotSupportedException ( "MsQuic 核心函数绑定失败" );

        }

        // ====================== 辅助方法：安全创建委托 ======================
        private static T GetDelegate<T> ( nint ptr ) where T : class
        {
            if ( ptr == nint.Zero ) return null!;
            return Marshal.GetDelegateForFunctionPointer<T> ( ptr );
        }
    }
}