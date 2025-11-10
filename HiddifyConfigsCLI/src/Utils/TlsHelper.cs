// TlsHelper.cs
// 负责：统一 TLS 配置（VLESS/Trojan/Hysteria2 共用）
// 命名空间：HiddifyConfigsCLI.src.Utils
// [Grok Rebuild] 2025-11-10：消除重复，集中管理
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace HiddifyConfigsCLI.src.Utils;

/// <summary>
/// TLS 配置助手：统一 SslClientAuthenticationOptions 创建
/// </summary>
internal static class TlsHelper
{
    /// <summary>
    /// 创建标准 TLS 配置
    /// </summary>
    /// <param name="sni">SNI 域名</param>
    /// <param name="skipCertVerify">是否跳过证书验证</param>
    /// <returns>配置好的 SslClientAuthenticationOptions</returns>
    public static SslClientAuthenticationOptions CreateSslOptions( string sni, bool skipCertVerify )
    {
        var opts = new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        if (skipCertVerify)
        {
            // 【Grok 安全警告】仅用于测试节点，生产环境慎用
            opts.RemoteCertificateValidationCallback =
                ( sender, cert, chain, errors ) => true;
        }

        return opts;
    }
}