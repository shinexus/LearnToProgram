// NativeCallbacks.cs
// 主类零污染、零 unsafe 标记、最高性能
// 同时暴露托管 delegate 和原生函数指针，防止 GC 回收

using System;
using System.Runtime.InteropServices;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class NativeCallbacks
    {
        // 托管 delegate（与 MsQuic 回调签名完全一致）
        // 这些 field 对外公开供 Hysteria2MsQuicNative.*Delegate 类型的函数调用（比如 ConnectionOpen）直接使用。
        public static readonly QUIC_CONNECTION_CALLBACK ConnectionDelegate;
        public static readonly QUIC_STREAM_CALLBACK StreamDelegate;

        // 也同时保留原生函数指针（有些 API 接受函数指针 IntPtr）
        public static readonly nint ConnectionPtr;
        public static readonly nint StreamPtr;

        static NativeCallbacks()
        {
            unsafe
            {
                // 绑定到各自 Connection/Stream 静态方法（方法签名必须匹配 QUIC_*_CALLBACK）
                ConnectionDelegate = Hysteria2MsQuicConnection.ConnectionCallbackStatic;
                StreamDelegate = Hysteria2MsQuicStream.StreamCallbackStatic;
            }

            // 转换为原生函数指针（可选，两者同时保留以便分别使用）
            ConnectionPtr = Marshal.GetFunctionPointerForDelegate(ConnectionDelegate);
            StreamPtr = Marshal.GetFunctionPointerForDelegate(StreamDelegate);

            // 确保 GC 不会回收委托（静态 field 本身已保持根，但 KeepAlive 更保险）
            GC.KeepAlive(ConnectionDelegate);
            GC.KeepAlive(StreamDelegate);
        }

        /// <summary>
        /// 显式 pin（可选），在初始化后调用可以再次确保委托长期存活。
        /// </summary>
        public static void Pin()
        {
            GC.KeepAlive(ConnectionDelegate);
            GC.KeepAlive(StreamDelegate);
        }
    }
}