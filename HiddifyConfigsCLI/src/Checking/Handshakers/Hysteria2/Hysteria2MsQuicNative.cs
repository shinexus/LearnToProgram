// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicNative.cs
// Grok 写的代码，我一点也不懂。

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static unsafe class Hysteria2MsQuicNative
    {
        private const string MsQuicDll = "msquic";
        public const uint QUIC_API_VERSION = 3;
        public const int QUIC_STATUS_SUCCESS = 0;

        // ====================== 枚举 ======================
        public enum QUIC_ADDRESS_FAMILY : ushort { UNSPECIFIED = 0, INET = 2, INET6 = 23 }

        [Flags] public enum QUIC_STREAM_FLAGS : uint { NONE = 0x0000 }
        [Flags] public enum QUIC_SEND_FLAGS : uint { NONE = 0x0000, FIN = 0x0001 }
        [Flags] public enum QUIC_CONNECTION_SHUTDOWN_FLAGS : ulong { NONE = 0x0000 }
        public enum QUIC_CREDENTIAL_TYPE : uint { NONE = 0 }
        [Flags] public enum QUIC_CREDENTIAL_FLAGS : uint { NONE = 0, CLIENT = 0x00000001, NO_CERTIFICATE_VALIDATION = 0x00001000 }
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
            public nint Buffers;
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

        //[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        //public delegate int StreamOpenDelegate(
        //    nint Connection,
        //    QUIC_STREAM_FLAGS Flags,
        //    QUIC_STREAM_CALLBACK Handler,
        //    nint Context,
        //    out nint Stream );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int StreamStartDelegate( nint Stream, QUIC_STREAM_START_FLAGS Flags );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int StreamSendDelegate(
            nint Stream,
            QUIC_BUFFER* Buffers,
            uint BufferCount,
            QUIC_SEND_FLAGS Flags,
            nint ClientContext );

        // 1. 添加委托定义
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectionSetCallbackHandlerDelegate(
            IntPtr Connection,
            QUIC_CONNECTION_CALLBACK Handler,
            IntPtr Context );

        public static readonly ConnectionSetCallbackHandlerDelegate ConnectionSetCallbackHandler;

        // 公开委托
        public static readonly ConfigurationOpenDelegate ConfigurationOpen;
        public static readonly ConnectionOpenDelegate ConnectionOpen;
        public static readonly ConnectionStartDelegate ConnectionStart;
        public static readonly ConnectionShutdownDelegate ConnectionShutdown;
        // public static readonly StreamOpenDelegate StreamOpen;
        private static readonly QUIC_STREAM_CALLBACK StreamCallbackDelegate = StreamCallbackManaged;

        public static readonly StreamStartDelegate StreamStart;
        public static readonly StreamSendDelegate StreamSend;

        // 原始表结构
        [StructLayout(LayoutKind.Sequential)]
        private struct QUIC_API_TABLE_RAW
        {
            public nint SetParam; public nint GetParam;
            public nint RegistrationOpen; public nint RegistrationClose;
            public nint ConfigurationOpen; public nint ConfigurationClose;
            public nint ConnectionOpen; public nint ConnectionShutdown; public nint ConnectionStart;
            public nint StreamOpen; public nint StreamStart; public nint StreamSend;
            public IntPtr ConnectionSetCallbackHandler;
        }

        static Hysteria2MsQuicNative()
        {
            int status = MsQuicOpenVersion(QUIC_API_VERSION, out nint apiPtr);
            if (status != QUIC_STATUS_SUCCESS)
                throw new PlatformNotSupportedException($"MsQuic 加载失败: 0x{status:X8}");

            var table = Marshal.PtrToStructure<QUIC_API_TABLE_RAW>(apiPtr);

            ConfigurationOpen = Marshal.GetDelegateForFunctionPointer<ConfigurationOpenDelegate>(table.ConfigurationOpen);
            ConnectionOpen = Marshal.GetDelegateForFunctionPointer<ConnectionOpenDelegate>(table.ConnectionOpen);
            ConnectionStart = Marshal.GetDelegateForFunctionPointer<ConnectionStartDelegate>(table.ConnectionStart);
            ConnectionShutdown = Marshal.GetDelegateForFunctionPointer<ConnectionShutdownDelegate>(table.ConnectionShutdown);
            StreamOpen = Marshal.GetDelegateForFunctionPointer<StreamOpenDelegate>(table.StreamOpen);
            StreamStart = Marshal.GetDelegateForFunctionPointer<StreamStartDelegate>(table.StreamStart);
            StreamSend = Marshal.GetDelegateForFunctionPointer<StreamSendDelegate>(table.StreamSend);
            ConnectionSetCallbackHandler = Marshal.GetDelegateForFunctionPointer<ConnectionSetCallbackHandlerDelegate>(table.ConnectionSetCallbackHandler);
        }

        // 必须保留的 DllImport
        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RegistrationOpen( byte* Config, out nint Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void RegistrationClose( nint Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ConfigurationClose( nint Configuration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ConnectionClose( nint Connection );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void StreamClose( nint Stream );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MsQuicOpenVersion( uint Version, out nint ApiTable );
    }
}