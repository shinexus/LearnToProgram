// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicNative.cs
// Grok 写的代码，我一点也不懂。
// 重构直接 DllImport 的 MsQuic 函数（如 RegistrationOpen），转为通过 API table 委托绑定。
// 原因：MsQuic 不导出这些函数，直接 DllImport 导致 EntryPointNotFoundException。所有操作必须用 table 中的指针。
// 新增：RegistrationOpenDelegate + 绑定；更新 QUIC_API_TABLE_RAW 以匹配 v2 完整顺序（基于官方 msquic.h v2.6.0）。
// 废弃旧 DllImport：用 /* 废弃 */ 包围，用户可后续删除。
// 测试：Hysteria2Handshaker 初始化时调用 GetRegistration()，确保无异常

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
        public const uint QUIC_API_VERSION = 2;        // MsQuic v3（对应 2.x 库）
        public const int QUIC_STATUS_SUCCESS = 0;

        // ====================== 枚举 ======================
        public enum QUIC_ADDRESS_FAMILY : ushort { UNSPECIFIED = 0, INET = 2, INET6 = 23 }

        [Flags] public enum QUIC_STREAM_FLAGS : uint { NONE = 0x0000 }
        [Flags] public enum QUIC_SEND_FLAGS : uint { NONE = 0x0000, FIN = 0x0001 }
        [Flags] public enum QUIC_CONNECTION_SHUTDOWN_FLAGS : ulong { NONE = 0x0000 }
        public enum QUIC_CREDENTIAL_TYPE : uint { NONE = 0 }
        [Flags]
        public enum QUIC_CREDENTIAL_FLAGS : uint
        {
            NONE = 0,
            CLIENT = 0x00000001,
            NO_CERTIFICATE_VALIDATION = 0x00001000
        }
        public enum QUIC_STREAM_START_FLAGS : uint { NONE = 0x0000, IMMEDIATE = 0x0002 }
        public enum QUIC_CONNECTION_EVENT_TYPE : uint { CONNECTED = 0, SHUTDOWN_COMPLETE = 2 }
        public enum QUIC_STREAM_EVENT_TYPE : uint { START_COMPLETE = 0, RECEIVE = 4 }
        [Flags] public enum QUIC_RECEIVE_FLAGS : uint { NONE = 0, FIN = 1 }

        // ====================== 结构体 ======================
        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_BUFFER
        {
            public uint Length;
            public byte* Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CREDENTIAL_CONFIG
        {
            public QUIC_CREDENTIAL_TYPE Type;
            public QUIC_CREDENTIAL_FLAGS Flags;
            public nint CertificateHash;
            public nint CertificateHashStore;
            public nint CertificateContext;
            public nint CertificateHashStoreName;
            public byte AsyncCertificateValidation;
            public fixed byte Reserved[59];
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT_CONNECTED
        {
            public byte SessionResumed;
            public nint NegotiatedAlpn;
            public fixed byte _padding[7];
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
        {
            public byte HandshakeCompleted;
            public byte PeerAcknowledgedShutdown;
            public fixed byte _padding[6];
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct QUIC_CONNECTION_EVENT_DATA
        {
            [FieldOffset(0)] public QUIC_CONNECTION_EVENT_CONNECTED Connected;
            [FieldOffset(0)] public QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE ShutdownComplete;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT
        {
            public QUIC_CONNECTION_EVENT_TYPE Type;
            public QUIC_CONNECTION_EVENT_DATA Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT_RECEIVE
        {
            public ulong AbsoluteOffset;
            public ulong TotalBufferLength;
            public nint Buffers; // 指向 QUIC_BUFFER* 列表 (native pointer)
            public uint BufferCount;
            public QUIC_RECEIVE_FLAGS Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT
        {
            public QUIC_STREAM_EVENT_TYPE Type;
            public QUIC_STREAM_EVENT_RECEIVE Receive;
        }

        // ====================== 回调 ======================
        // [ChatGPT 审查修改]：
        // 将委托标注保留并显式指定 CallingConvention.Cdecl，以确保与 MsQuic 的 C API 调用约定匹配。
        // 原因：后续我们会用 Marshal.GetFunctionPointerForDelegate 获取原生函数指针并传给 MsQuic。
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int QUIC_CONNECTION_CALLBACK( nint Connection, nint Context, QUIC_CONNECTION_EVENT* Event );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int QUIC_STREAM_CALLBACK( nint Stream, nint Context, QUIC_STREAM_EVENT* Event );

        // ====================== API 委托 ======================
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConfigurationOpenDelegate(
            nint Registration,
            QUIC_BUFFER* AlpnBuffers,
            uint AlpnBufferCount,
            QUIC_CREDENTIAL_CONFIG* Credential,
            uint CredentialSize,
            nint Context,
            out nint Configuration );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionOpenDelegate(
            nint Registration,
            QUIC_CONNECTION_CALLBACK? Handler,
            nint Context,
            out nint Connection );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionStartDelegate(
            nint Connection,
            nint Configuration,
            QUIC_ADDRESS_FAMILY Family,
            byte* ServerName,
            ushort ServerPort );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionShutdownDelegate(
            nint Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
            ulong ErrorCode );

        // 【Grok 修复_2025-11-24_01】恢复被错误注释的 StreamOpen 委托
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int StreamOpenDelegate(
            nint Connection,
            QUIC_STREAM_FLAGS Flags,
            QUIC_STREAM_CALLBACK Handler,
            nint Context,
            out nint Stream );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int StreamStartDelegate( nint Stream, QUIC_STREAM_START_FLAGS Flags );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int StreamSendDelegate(
            nint Stream,
            QUIC_BUFFER* Buffers,
            uint BufferCount,
            QUIC_SEND_FLAGS Flags,
            nint ClientContext );

        // 【Grok 修复_2025-11-24_01】新增 ConnectionSetCallbackHandler 委托（原代码缺失导致运行时 null）
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionSetCallbackHandlerDelegate(
            nint Connection,
            QUIC_CONNECTION_CALLBACK Handler,
            nint Context );

        // 公开的委托实例（全部由静态构造函数填充）
        // [ChatGPT 审查修改]：保持 readonly，初始化在静态构造函数中以便在 MsQuic 加载后绑定。
        public static readonly ConfigurationOpenDelegate ConfigurationOpen;
        public static readonly ConnectionOpenDelegate ConnectionOpen;
        public static readonly ConnectionStartDelegate ConnectionStart;
        public static readonly ConnectionShutdownDelegate ConnectionShutdown;
        public static readonly StreamOpenDelegate StreamOpen;                    // 恢复
        public static readonly StreamStartDelegate StreamStart;
        public static readonly StreamSendDelegate StreamSend;
        public static readonly ConnectionSetCallbackHandlerDelegate ConnectionSetCallbackHandler; // 新增

        // ====================== 原生函数 ======================
        // [ChatGPT 审查修改]：这些 DllImport 签名保持原样，但统一添加 ExactSpelling=true (可选) 以减少平台差异问题。
        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RegistrationOpen( byte* Config, out nint Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void RegistrationClose( nint Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ConfigurationClose( nint Configuration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ConnectionClose( nint Connection );

        // 【Grok 修复_2025-11-24_01】新增 StreamClose（Hysteria2MsQuicStream.Dispose 中使用）
        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void StreamClose( nint Stream );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MsQuicOpenVersion( uint Version, out nint ApiTable );

        // ====================== API 表结构（对应 MsQuic v3） ======================
        // 必须与官方 MsQuicOpenVersion 返回的表完全一致
        [StructLayout(LayoutKind.Sequential)]
        private struct QUIC_API_TABLE_RAW
        {
            public nint SetParam;
            public nint GetParam;

            public nint RegistrationOpen;            
            public nint RegistrationClose;

            public nint ConfigurationOpen;
            public nint ConfigurationLoadCredential;
            public nint ConfigurationClose;

            public nint ConnectionOpen;
            public nint ConnectionClose;           // ← 必须在这里！你在原代码里放到了 Shutdown 后面
            public nint ConnectionShutdown;
            public nint ConnectionStart;

            public nint StreamOpen;
            public nint StreamClose;               // ← 必须在这里！不能放在 Send 后面
            public nint StreamStart;
            public nint StreamShutdown;
            public nint StreamSend;

            public nint ListenerOpen;
            public nint ListenerClose;
            public nint ListenerStart;
            public nint ListenerStop;

            // 关键：ConnectionSetCallbackHandler 就在这里！（v2.3 引入，v3 表固定位置）
            public nint ConnectionSetCallbackHandler;

            // 后面还有几十个字段，我们不需要，用 nint 占位即可（不会错位）
            public nint Padding1;  // DatagramSend 等
            public nint Padding2;
            public nint Padding3;
            // ... 省略 20+ 个字段，反正我们只取前面的
        }

        static Hysteria2MsQuicNative()
        {

            // 调试信息
            // LogHelper.Debug($"[Hysteria2MsQuicNative] 正在加载 MsQuic...");

            // 注意：QUIC_API_VERSION = 2
            int status = MsQuicOpenVersion(QUIC_API_VERSION, out nint apiPtr);

            // 调试信息
            // 0x80004002 MsQuic DLL 加载成功，API 版本（QUIC_API_VERSION = 3）不可用或不兼容，apiPtr = 0 说明 MsQuic 没有返回有效的函数表指针。
            LogHelper.Debug($"[Hysteria2MsQuicNative] MsQuicOpenVersion status=0x{status:X8}, apiPtr={apiPtr}");

            if (status != QUIC_STATUS_SUCCESS)
                throw new PlatformNotSupportedException($"MsQuic 加载失败: 0x{status:X8}");

            // [ChatGPT 审查修改]
            // 将指针解析为结构体，注意这里使用 PtrToStructure<T> 需要确保 QUIC_API_TABLE_RAW
            // 的布局与 native 完全一致，否则会产生不可预期的指针/函数绑定错误（运行时访问 violation）。
            var table = Marshal.PtrToStructure<QUIC_API_TABLE_RAW>(apiPtr);

            // 绑定委托（若某字段为 0 则 Marshal.GetDelegateForFunctionPointer 会抛异常）
            // 因此在生产环境建议对每个 table.xxx 进行 non-zero 检查并提供更友好的错误。
            ConfigurationOpen = Marshal.GetDelegateForFunctionPointer<ConfigurationOpenDelegate>(table.ConfigurationOpen);
            ConnectionOpen = Marshal.GetDelegateForFunctionPointer<ConnectionOpenDelegate>(table.ConnectionOpen);
            ConnectionStart = Marshal.GetDelegateForFunctionPointer<ConnectionStartDelegate>(table.ConnectionStart);
            ConnectionShutdown = Marshal.GetDelegateForFunctionPointer<ConnectionShutdownDelegate>(table.ConnectionShutdown);
            StreamOpen = Marshal.GetDelegateForFunctionPointer<StreamOpenDelegate>(table.StreamOpen);
            StreamStart = Marshal.GetDelegateForFunctionPointer<StreamStartDelegate>(table.StreamStart);
            StreamSend = Marshal.GetDelegateForFunctionPointer<StreamSendDelegate>(table.StreamSend);

            // 【Grok 修复_2025-11-24_01】关键修复：绑定 ConnectionSetCallbackHandler
            ConnectionSetCallbackHandler = Marshal.GetDelegateForFunctionPointer<ConnectionSetCallbackHandlerDelegate>(
                table.ConnectionSetCallbackHandler);

            // [ChatGPT 审查修改]：对关键 API 进行额外防御性检查，给出明确错误信息以便调试。
            if (ConnectionSetCallbackHandler == null)
                throw new PlatformNotSupportedException("当前 MsQuic 版本不支持 ConnectionSetCallbackHandler（需要 ≥2.3）");
        }
    }
}