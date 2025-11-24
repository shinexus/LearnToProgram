// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2CipherSuiteProvider.cs
using System.Net.Security;
using System.Security.Authentication;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class Hysteria2CipherSuiteProvider
    {
        public static IReadOnlyList<TlsCipherSuite> GetSuites( string? fingerprint )
        {
            return fingerprint?.ToLowerInvariant() switch
            {
                "firefox" => new TlsCipherSuite[]
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                },

                "random" => new TlsCipherSuite[]
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                }.Shuffle(),

                _ => new TlsCipherSuite[] // Chrome 131 默认顺序
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                }
            };
        }
    }

    internal static class RandomExtensions
    {
        public static T[] Shuffle<T>( this T[] array )
        {
            var copy = (T[])array.Clone();
            for (int i = copy.Length - 1; i > 0; i--)
            {
                int j = Random.Shared.Next(i + 1);
                (copy[j], copy[i]) = (copy[i], copy[j]);
            }
            return copy;
        }
    }
}