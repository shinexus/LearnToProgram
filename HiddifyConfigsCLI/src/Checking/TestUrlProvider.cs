// src/Checking/TestUrlProvider.cs
// 从 InternetTester.cs 拆分类，负责提供随机或自定义测试 URL
// [ChatGPT 审查修改]：保留原 DefaultTestUrls + GetTestUrl 方法

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;

namespace HiddifyConfigsCLI.src.Checking
{
    internal static class TestUrlProvider
    {
        /// <summary>
        /// 默认测试 URL 池
        /// [ChatGPT 审查修改]：保留原 DefaultTestUrls
        /// </summary>
        private static readonly string[] DefaultTestUrls =
        {
            "https://cp.cloudflare.com/generate_204",
            "https://www.google.com/generate_204",
            "https://connectivitycheck.gstatic.com/generate_204",
            "https://detectportal.firefox.com/success.txt",
            "https://www.msftconnecttest.com/connecttest.txt",
            "https://www.youtube.com/generate_204",
            "https://clients3.google.com/generate_204",
            "https://play.googleapis.com/generate_204"
        };

        /// <summary>
        /// 返回测试 URL（随机或自定义）
        /// [ChatGPT 审查修改]：原 GetTestUrl 逻辑迁移至此
        /// </summary>
        public static string GetTestUrl( RunOptions opts )
        {
            if (!string.IsNullOrWhiteSpace(opts.TestUrl) && opts.TestUrl != "random")
            {
                if (Uri.TryCreate(opts.TestUrl, UriKind.Absolute, out var u) &&
                    (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    return opts.TestUrl;
                }

                LogHelper.Warn($"[配置错误] TestUrl 无效，已回退随机: {opts.TestUrl}");
            }

            return DefaultTestUrls[Random.Shared.Next(DefaultTestUrls.Length)];
        }
    }
}