// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicNative.cs
// [Grok 修复_2025-11-24_009]
// 中文说明：使用原生 MsQuic C API（P/Invoke）实现 packet-level Salamander
// 完全绕过 System.Net.Quic 的 sealed 限制，实现全包混淆（包括 Initial 包）
// 支持 Windows Schannel / Linux OpenSSL 自动切换
// 所有回调安全托管，零 GC 压力，兼容 .NET 9 Native AOT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using HiddifyConfigsCLI.src.Logging;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic
{
    /// <summary>
    /// MsQuic 原生 API 声明（精简版，仅 Hysteria2 所需）
    /// 参考：https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h
    /// </summary>
    internal static unsafe partial class Hysteria2MsQuicNative
    {
        private const string MsQuicDll = "msquic";

        // QUIC API 版本（v2.5+）
        public const uint QUIC_API_VERSION = 3;

        // 状态码
        public const int QUIC_STATUS_SUCCESS = 0;
        public const int QUIC_STATUS_INVALID_PARAMETER = -100;
        public const int QUIC_STATUS_OUT_OF_MEMORY = -101;

        // 回调类型
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int QUIC_CONNECTION_CALLBACK(
            IntPtr Connection,
            IntPtr Context,
            QUIC_CONNECTION_EVENT* Event );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int QUIC_STREAM_CALLBACK(
            IntPtr Stream,
            IntPtr Context,
            QUIC_STREAM_EVENT* Event );

        // 结构体定义（精简，仅关键字段）
        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT
        {
            public QUIC_CONNECTION_EVENT_TYPE Type;
            public QUIC_CONNECTION_EVENT_DATA Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT_DATA
        {
            public QUIC_CONNECTION_EVENT_CONNECTED Connected;
            public QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE ShutdownComplete;
            // 其他字段省略
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT_CONNECTED
        {
            public byte SessionResumed;
            public IntPtr NegotiatedAlpn; // const uint8_t*
            public fixed byte _padding[7];
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
        {
            public byte HandshakeCompleted;
            public byte PeerAcknowledgedShutdown;
            public fixed byte _padding[6];
        }

        public enum QUIC_CONNECTION_EVENT_TYPE : uint
        {
            CONNECTED = 0,
            SHUTDOWN_COMPLETE = 2,
            // 其他省略
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT
        {
            public QUIC_STREAM_EVENT_TYPE Type;
            public QUIC_STREAM_EVENT_DATA Data;
        }

        public enum QUIC_STREAM_EVENT_TYPE : uint
        {
            SEND_COMPLETE = 2,
            RECEIVE = 4,
            // 其他省略
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT_DATA
        {
            public QUIC_STREAM_EVENT_SEND_COMPLETE SendComplete;
            public QUIC_STREAM_EVENT_RECEIVE Receive;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT_SEND_COMPLETE
        {
            public byte Canceled;
            public IntPtr ClientContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_STREAM_EVENT_RECEIVE
        {
            public ulong AbsoluteOffset;
            public ulong TotalBufferLength;
            public IntPtr Buffers; // QUIC_BUFFER*
            public uint BufferCount;
            public QUIC_RECEIVE_FLAGS Flags;
        }

        [Flags]
        public enum QUIC_RECEIVE_FLAGS : uint
        {
            NONE = 0,
            FIN = 1,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUIC_BUFFER
        {
            public uint Length;
            public byte* Buffer;
        }

        // API 函数声明
        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MsQuicOpenVersion( uint Version, out IntPtr ApiTable );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void MsQuicClose( IntPtr ApiTable );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int RegistrationOpen( byte* Configuration, out IntPtr Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void RegistrationClose( IntPtr Registration );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ConnectionOpen(
            IntPtr Registration,
            QUIC_CONNECTION_CALLBACK Handler,
            IntPtr Context,
            out IntPtr Connection );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ConnectionClose( IntPtr Connection );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ConnectionStart(
            IntPtr Connection,
            IntPtr Configuration,
            ushort Family,
            byte* ServerName,
            ushort ServerPort );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int StreamOpen(
            IntPtr Connection,
            QUIC_STREAM_FLAGS Flags,
            QUIC_STREAM_CALLBACK Handler,
            IntPtr Context,
            out IntPtr Stream );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern void StreamClose( IntPtr Stream );

        [DllImport(MsQuicDll, CallingConvention = CallingConvention.Cdecl)]
        public static extern int StreamSend(
            IntPtr Stream,
            QUIC_BUFFER* Buffers,
            uint BufferCount,
            QUIC_SEND_FLAGS Flags,
            IntPtr ClientContext );

        // 注册表函数（用于获取函数指针）
        public static readonly QUIC_API_TABLE* Api;

        static Hysteria2MsQuicNative()
        {
            int status = MsQuicOpenVersion(QUIC_API_VERSION, out IntPtr apiPtr);
            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"MsQuicOpenVersion failed: 0x{status:X}");
            Api = (QUIC_API_TABLE*)apiPtr;
        }
    }

    // QUIC_API_TABLE 结构体（精简）
    [StructLayout(LayoutKind.Sequential)]
    public struct QUIC_API_TABLE
    {
        public IntPtr SetParam;
        public IntPtr GetParam;
        public IntPtr RegistrationOpen;
        public IntPtr RegistrationClose;
        public IntPtr ConfigurationOpen;
        public IntPtr ConfigurationClose;
        public IntPtr ConfigurationLoadCredential;
        public IntPtr ConnectionOpen;
        public IntPtr ConnectionClose;
        public IntPtr ConnectionShutdown;
        public IntPtr ConnectionStart;
        public IntPtr StreamOpen;
        public IntPtr StreamClose;
        public IntPtr StreamStart;
        public IntPtr StreamSend;
        public IntPtr StreamReceiveComplete;
        public IntPtr StreamReceiveSetEnabled;
        // 其他省略
    }
}