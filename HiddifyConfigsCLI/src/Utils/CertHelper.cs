// CertHelper.cs
// 统一 skip-cert-verify 解析逻辑

using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Utils;

/// <summary>
/// 证书验证助手：统一 skip-cert-verify 解析
/// </summary>
internal static class CertHelper
{
    /// <summary>
    /// 从 ExtraParams 提取 skip-cert-verify 状态
    /// 支持：skip_cert_verify=true / allowInsecure=1
    /// </summary>
    public static bool GetSkipCertVerify( IReadOnlyDictionary<string, string>? extra )
    {
        if (extra == null) return false;
        return extra.GetValueOrDefault("skip_cert_verify") == "true" ||
               extra.GetValueOrDefault("allowInsecure") == "1";
    }
}