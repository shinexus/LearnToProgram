// NativeCallbacks.cs
// 主类零污染、零 unsafe 标记、最高性能

using HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2;
using System.Runtime.InteropServices;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class NativeCallbacks
    {
        // 托管委托（与 MsQuic 委托定义完全一致）
        private static readonly QUIC_CONNECTION_CALLBACK _connectionDelegate;
        private static readonly QUIC_STREAM_CALLBACK _streamDelegate;

        // 公开的原生函数指针（供托管代码使用）
        public static readonly nint ConnectionPtr;
        public static readonly nint StreamPtr;

        static NativeCallbacks()
        {
            // 创建托管委托实例
            _connectionDelegate = Hysteria2MsQuicConnection.ConnectionCallbackStatic;
            _streamDelegate = Hysteria2MsQuicStream.StreamCallbackStatic;

            // 转换为原生函数指针（MsQuic 唯一接受的方式）
            ConnectionPtr = Marshal.GetFunctionPointerForDelegate(_connectionDelegate);
            StreamPtr = Marshal.GetFunctionPointerForDelegate(_streamDelegate);
        }

        // 重要：防止 GC 回收委托
        public static void Pin()
        {
            // 调用此方法可防止委托被回收（可选，static 根通常已足够）
            GC.KeepAlive(_connectionDelegate);
            GC.KeepAlive(_streamDelegate);
        }
    }
}