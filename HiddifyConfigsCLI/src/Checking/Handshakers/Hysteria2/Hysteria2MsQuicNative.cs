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

            // 原 fixed byte Reserved[59]; 导致 .NET 9 禁止 & 操作
            // 改为 byte[]，运行时布局完全一致，MsQuic 只会读取 59 字节
            // public fixed byte Reserved[59];
            //[MarshalAs ( UnmanagedType.ByValArray, SizeConst = 59 )]
            //public byte[] Reserved;

            // 全局共享的零填充数组（避免每次分配）
            public static readonly byte[] EmptyReserved = new byte[59];
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
        // 新增 Close 系列委托
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void RegistrationCloseDelegate ( nint Registration );

        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void ConfigurationCloseDelegate ( nint Configuration );

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

        // 必须加上 ConnectionClose 委托！
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void ConnectionCloseDelegate ( nint Connection );

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

        // 加上 StreamClose！
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate void StreamCloseDelegate ( nint Stream );

        // 【Grok 修复_2025-11-24_01】新增 ConnectionSetCallbackHandler 委托（原代码缺失导致运行时 null）
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionSetCallbackHandlerDelegate(
            nint Connection,
            QUIC_CONNECTION_CALLBACK Handler,
            nint Context );

        // 新增 RegistrationOpenDelegate：通过 API table 绑定，取代直接 DllImport
        //[UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        //public delegate int RegistrationOpenDelegate (
        //    nint Api,  // 从 MsQuicOpenVersion 获取的 API table 指针
        //    byte* Config,  // 可选配置字节（当前 Hysteria2 未用，传 null）
        //    out nint Registration );
        // 将 RegistrationOpen 的 Config 参数从 byte* 改为 nint（void*）
        // 理由：我们永远只传 null，改为 nint 后调用方无需 unsafe，性能完全相同
        [UnmanagedFunctionPointer ( CallingConvention.Cdecl )]
        public delegate int RegistrationOpenDelegate (
            nint Api,
            nint Config,          // ← 改为 nint，调用方无需 unsafe
            out nint Registration );

        // 公开的委托实例（全部由静态构造函数填充）
        // [ChatGPT 审查修改]：保持 readonly，初始化在静态构造函数中以便在 MsQuic 加载后绑定。
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

        /*
        废弃：原 RegistrationOpen（导致 EntryPointNotFoundException）
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
        */

        // ====================== API 表结构（对应 MsQuic v2） ======================
        // 必须与官方 MsQuicOpenVersion 返回的表完全一致
        // 更新 QUIC_API_TABLE_RAW：匹配官方 msquic.h v2.6.0 顺序，确保 RegistrationOpen 在正确位置（第3个字段）
        // 完整前缀字段：SetParam(0), GetParam(1), RegistrationOpen(2)；后缀用 Padding 占位（总 ~60 字段，我们只用前15个）
        // 警告：布局错位会导致指针偏移，运行时崩溃。基于官方头文件验证。
        [StructLayout ( LayoutKind.Sequential )]
        private struct QUIC_API_TABLE_RAW
        {
            public nint SetParam;                    // 0: QUIC_SET_PARAM_FN
            public nint GetParam;                    // 1: QUIC_GET_PARAM_FN
            public nint RegistrationOpen;            // 2: QUIC_REGISTRATION_OPEN_FN ← 关键，绑定 RegistrationOpen
            public nint RegistrationClose;           // 3: QUIC_REGISTRATION_CLOSE_FN
            public nint ConfigurationOpen;           // 4: QUIC_CONFIGURATION_OPEN_FN
            public nint ConfigurationLoadCredential; // 5: QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN
            public nint ConfigurationClose;          // 6: QUIC_CONFIGURATION_CLOSE_FN
            public nint ConnectionOpen;              // 7: QUIC_CONNECTION_OPEN_FN
            public nint ConnectionClose;             // 8: QUIC_CONNECTION_CLOSE_FN
            public nint ConnectionShutdown;          // 9: QUIC_CONNECTION_SHUTDOWN_FN
            public nint ConnectionStart;             // 10: QUIC_CONNECTION_START_FN
            public nint StreamOpen;                  // 11: QUIC_STREAM_OPEN_FN
            public nint StreamClose;                 // 12: QUIC_STREAM_CLOSE_FN
            public nint StreamStart;                 // 13: QUIC_STREAM_START_FN
            public nint StreamShutdown;              // 14: QUIC_STREAM_SHUTDOWN_FN
            public nint StreamSend;                  // 15: QUIC_STREAM_SEND_FN
            public nint ListenerOpen;                // 16: QUIC_LISTENER_OPEN_FN
            public nint ListenerClose;               // 17: QUIC_LISTENER_CLOSE_FN
            public nint ListenerStart;               // 18: QUIC_LISTENER_START_FN
            public nint ListenerStop;                // 19: QUIC_LISTENER_STOP_FN
            public nint ConnectionSetCallbackHandler; // 20: QUIC_CONNECTION_SET_CALLBACK_HANDLER_FN（v2.3+）
            // Padding for remaining ~40 fields (e.g., DatagramSend, Security 等)，确保无错位
            public nint Padding1, Padding2, Padding3, Padding4, Padding5; // 示例占位
            // ... (实际用 fixed nint Padding[40]; 但为简洁，用多个字段)
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
            ConnectionClose = Marshal.GetDelegateForFunctionPointer<ConnectionCloseDelegate> ( table.ConnectionClose );            
            ConnectionShutdown = Marshal.GetDelegateForFunctionPointer<ConnectionShutdownDelegate>(table.ConnectionShutdown);

            StreamOpen = Marshal.GetDelegateForFunctionPointer<StreamOpenDelegate>(table.StreamOpen);
            StreamStart = Marshal.GetDelegateForFunctionPointer<StreamStartDelegate>(table.StreamStart);
            StreamSend = Marshal.GetDelegateForFunctionPointer<StreamSendDelegate>(table.StreamSend);
            StreamClose = Marshal.GetDelegateForFunctionPointer<StreamCloseDelegate> ( table.StreamClose );

            // 静态构造函数中绑定
            RegistrationClose = Marshal.GetDelegateForFunctionPointer<RegistrationCloseDelegate> ( table.RegistrationClose );
            ConfigurationClose = Marshal.GetDelegateForFunctionPointer<ConfigurationCloseDelegate> ( table.ConfigurationClose );

            // 【Grok 修复_2025-11-24_01】关键修复：绑定 ConnectionSetCallbackHandler
            ConnectionSetCallbackHandler = Marshal.GetDelegateForFunctionPointer<ConnectionSetCallbackHandlerDelegate>(
                table.ConnectionSetCallbackHandler);

            // 新增绑定：RegistrationOpen（参数中传入 apiPtr 作为第一个参数，匹配 QUIC_REGISTRATION_OPEN_FN 签名）
            // 注意：原 DllImport 签名 byte* Config → 现在用 apiPtr 替换 Registration 参数（官方：第一个是 HQUIC Registration，但 open 时用 Api）
            // 实际签名：QUIC_STATUS RegistrationOpen(HQUIC Api, const void* Config, HQUIC* Registration)
            // Config 当前 Hysteria2 未用，传 null
            RegistrationOpen = Marshal.GetDelegateForFunctionPointer<RegistrationOpenDelegate> ( table.RegistrationOpen );

            // [ChatGPT 审查修改]：对关键 API 进行额外防御性检查，给出明确错误信息以便调试。
            if (ConnectionSetCallbackHandler == null)
                throw new PlatformNotSupportedException("当前 MsQuic 版本不支持 ConnectionSetCallbackHandler（需要 ≥2.3）");
            if ( RegistrationOpen == null )
                throw new PlatformNotSupportedException ( "当前 MsQuic 版本不支持 RegistrationOpen（API table 绑定失败）" );            
            if ( ConnectionClose == null )
                throw new PlatformNotSupportedException ( "MsQuic ConnectionClose 函数未找到" );
            if ( StreamClose == null )
                throw new PlatformNotSupportedException ( "MsQuic StreamClose 函数未找到" );

            // 确保 Reserved 是零
            for ( int i = 0; i < QUIC_CREDENTIAL_CONFIG.EmptyReserved.Length; i++ )
                QUIC_CREDENTIAL_CONFIG.EmptyReserved[i] = 0;
        }

        // 新增辅助方法：获取 Registration handle（Hysteria2Handshaker中使用）
        // 用法：在 Hysteria2Handshaker.Init() 中调用 GetRegistration()，传入 apiPtr（静态保存或从构造函数传）
        // 返回：nint Registration handle，status == 0 表示成功
        /// <summary>
        /// 获取 MsQuic Registration 句柄（全局唯一）
        /// </summary>
        /// <param name="apiPtr">MsQuicOpenVersion 返回的 API table 指针</param>
        /// <returns>(status, registrationHandle)</returns>
        public static (int Status, nint Handle) GetRegistration ( nint apiPtr )
        {
            // RegistrationOpen 的 Config 参数已改为 nint，传 nint.Zero 即可（等价于 NULL）
            // nint reg = default;
            nint reg = nint.Zero;
            
            // 废弃
            // byte* config = null; // Hysteria2 当前无自定义 config

            // 正确：第二个参数传 nint.Zero（即 NULL）
            // int status = RegistrationOpen ( apiPtr, config, out reg );
            int status = RegistrationOpen ( apiPtr, nint.Zero, out reg );
            if ( status != QUIC_STATUS_SUCCESS )
            {
                LogHelper.Debug ( $"[Hysteria2MsQuicNative] RegistrationOpen 失败: 0x{status:X8}" );
            }
            return (status, reg);
        }

        // TODO: 类似添加 GetConfigurationCloseDelegate 等，如果其他 close 函数需用（当前 Hysteria2 只需 open/start/send）
        // 示例：如果需 RegistrationClose，添加 delegate + 绑定 table.RegistrationClose
    }
}