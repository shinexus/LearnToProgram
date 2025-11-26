// Program.cs
// CLI 项目入口：.NET 8 + VS 2022
// 使用 CommandLineParser 2.9.1 解析参数
// 命名空间：HiddifyConfigsCLI.src

using CommandLine;
using CommandLine.Text;
using HiddifyConfigsCLI.src.Checking;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Parsing;
using HiddifyConfigsCLI.src.Processing;
using HiddifyConfigsCLI.src.Sources.Telegram;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace HiddifyConfigsCLI.src;

internal class Program
{
    // ──────────────────────────────────────────────────────────────
    // MsQuic 强制加载（终极版）—— 支持 native/ 目录 + runtimes/ 回退
    // ──────────────────────────────────────────────────────────────
    static Program()
    {
        // 程序一启动就先把我们自己的完整版 msquic.dll 接管掉
        EnsureMsQuicLoaded();
    }

    /// <summary>
    /// 强制加载项目根目录 native\win-x64\msquic.dll（本地 + GitHub Actions 通用）
    /// </summary>
    internal static void EnsureMsQuicLoaded()
    {
        // 1. 优先从项目根目录的 native 目录加载（最推荐的放置方式）
        string candidate1 = Path.Combine(AppContext.BaseDirectory, "native", "win-x64", "msquic.dll");

        // 2. 回退到旧的 runtimes 路径（兼容以前的项目）
        string candidate2 = Path.Combine(AppContext.BaseDirectory, "runtimes", "win-x64", "native", "msquic.dll");

        string dllPath = File.Exists(candidate1) ? candidate1 : candidate2;

        if (!File.Exists(dllPath))
            throw new FileNotFoundException($"[MsQuic] 未找到完整版 msquic.dll，请放入以下任一位置：\n   {candidate1}\n   {candidate2}");

        IntPtr handle = NativeLibrary.Load(dllPath);
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException($"[MsQuic] 加载失败：{dllPath}");

        var ver = FileVersionInfo.GetVersionInfo(dllPath);
        Console.WriteLine($"[MsQuic 终极接管] 已加载：{dllPath}");
        Console.WriteLine($"[MsQuic] 版本 {ver.FileVersion} —— 0x80004002 永别了！");

        // 全局拦截：以后任何 DllImport("msquic") 都强制走我们自己的句柄
        NativeLibrary.SetDllImportResolver(
            Assembly.GetExecutingAssembly(),
            ( libName, _, __ ) => libName.Equals("msquic", StringComparison.OrdinalIgnoreCase) ? handle : IntPtr.Zero);
    }


    // 以下是业务代码
    // [新增] 全局配置对象，解析后保存，供所有模块使用
    public static RunOptions? Options { get; private set; }

    private static async Task<int> Main( string[] args )
    {
        //强制工作目录为项目根
        var projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
        Directory.SetCurrentDirectory(projectRoot);
        
        // LogHelper.Info($"[调试] 工作目录: {Directory.GetCurrentDirectory()}");

        var parser = new Parser(config =>
        {
            config.HelpWriter = null;
            config.CaseInsensitiveEnumValues = true;
            config.AutoVersion = false;
        });

        var result = parser.ParseArguments<RunOptions>(args);

        // 统一构建帮助文本
        var helpText = HelpText.AutoBuild(result, h =>
        {
            h.Heading = "HiddifyConfigsCLI - 协议链接验证工具";
            h.Copyright = "© 2025 JimTsui & shinexus. All rights reserved.";
            h.AddPreOptionsLine("用法: dotnet run [options]");
            h.AddPostOptionsLine("\n支持本地文件或远程 URL 作为输入。");
            h.AddPreOptionsLine("");
            h.AddPreOptionsLine("出网测试参数：");
            h.AddPreOptionsLine(" --test-url <url> 指定出网测试目标地址（如 http://www.google.com）");
            h.AddPreOptionsLine(" 若未指定，将随机使用 Cloudflare、Google 等通用地址");
            h.AddPostOptionsLine("");
            h.AddPostOptionsLine("==========================================================");
            h.AddPostOptionsLine(" 感谢 Grok（xAI）提供技术支持与实现指导！ ");
            h.AddPostOptionsLine("==========================================================");
            return h;
        }, e => e);

        return await result.MapResult(
            // ────────────────────── 解析成功分支 ──────────────────────
            async options =>
            {
                if (args.Length == 0)
                {
                    Console.WriteLine(helpText);
                    return 1;
                }

                Options = options;
                LogHelper.Init(options.EnableLog, options.Verbose);

                if (string.IsNullOrEmpty(options.TestUrl) && options.EnableInternetCheck)
                {
                    LogHelper.Info("[出网测试] 未指定 --test-url，将随机使用 Cloudflare、Google 等通用地址");
                }
                else if (!string.IsNullOrEmpty(options.TestUrl))
                {
                    LogHelper.Info($"[出网测试] 使用自定义地址: {options.TestUrl}");
                }

                return await RunAsync(options);
            },
            // ────────────────────── 解析失败分支 ──────────────────────
            errs =>
            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach (var err in errs)
                {
                    Console.WriteLine(err.ToString());
                }
                Console.ResetColor();
                Console.WriteLine();
                Console.WriteLine(helpText);
                return Task.FromResult(1);
            });
    }

    private static async Task<int> RunAsync( RunOptions opts )
    {
        try
        {
            LogHelper.Info($"开始执行：输入={opts.Input} 输出={opts.Output}");

            // ───────────── 如果指定 --proxy，则打印 Host:Port ─────────────
            if (!string.IsNullOrEmpty(opts.Proxy))
            {
                LogHelper.Info($"[代理模式] 使用代理: {opts.Proxy}");
                var parts = opts.Proxy.Split(':', 2);
                if (parts.Length == 2)
                {
                    var host = parts[0];
                    var port = parts[1];
                    // Console.WriteLine($"{host}:{port}");
                }
                else
                {
                    // Console.WriteLine(opts.Proxy);
                }

                // 如果仅打印代理，不执行其他逻辑，可直接返回
                // return 0;
            }

            // ==================== 1. 下载 + 提取（含 Telegram） ====================
            var rawLinks = new List<string>();

            // 1.1 传统输入源
            // var traditionalLinks = await DoParse.DownloadAndExtractAsync(opts);            
            if (!opts.EnableTelegram)
            {
                var traditionalLinks = await DoParse.DownloadAndExtractAsync(opts);
                
                LogHelper.Info($"[传统源] 提取到 {traditionalLinks.Count} 条原始链接");
                rawLinks.AddRange(traditionalLinks);
            }
            
            // LogHelper.Info($"[传统源] 提取到 {traditionalLinks.Count} 条原始链接");

            // 1.2 Telegram 源（开关控制）
            if (opts.EnableTelegram)
            {
                var configPath = opts.TelegramConfigPath ?? "config/TelegramConfig.json";
                if (!File.Exists(configPath))
                {
                    LogHelper.Error($"[Telegram] 配置文件未找到: {configPath}");
                }
                else
                {
                    var json = File.ReadAllText(configPath);
                    var telegramConfig = JsonSerializer.Deserialize<TelegramConfig>(json)!;
                    telegramConfig.Validate();

                    LogHelper.Info($"[Telegram] 加载配置: {telegramConfig.Channels.Count} 个频道");

                    var fetcher = new TelegramFetcher(telegramConfig, opts);
                    var telegramLinks = await fetcher.FetchAllAsync();

                    rawLinks.AddRange(telegramLinks);
                    LogHelper.Info($"[Telegram] 提取到 {telegramLinks.Count} 条原始链接");
                }
            }

            // 去重
            rawLinks = rawLinks.Distinct().ToList();
            LogHelper.Info($"[合并后] 总计 {rawLinks.Count} 条原始链接");

            if (rawLinks.Count == 0)
            {
                LogHelper.Warn("无有效链接，提前退出");
                return 0;
            }

            // ==================== 2. 解析 ====================
            var parsed = rawLinks
                .Select(ProtocolParser.Parse)
                .OfType<NodeInfoBase>()
                .ToList();

            LogHelper.Info($"成功解析 {parsed.Count} 条结构化节点");

            // ==================== 3. 连通性检测 ====================
            List<NodeInfoBase> valid = opts.NoCheck
                ? parsed
                : await ConnectivityChecker.CheckAsync(parsed, opts);

            if (opts.NoCheck)
                LogHelper.Info("跳过连通性检测");
            else
                LogHelper.Info($"连通性检测完成，有效节点 {valid.Count} 条（已通过协议握手 + 出网测试）");

            // ==================== 4. 去重 + 排序 ====================
            var processed = ResultProcessor.Process(valid, opts.Sort);
            LogHelper.Info($"去重排序后剩余 {processed.Count} 条");

            // ==================== 5. 保存文件 ====================
            await FileSaver.SaveAsync(processed, opts);
            LogHelper.Info("所有文件已生成");

            return 0;
        }
        catch (Exception ex)
        {
            LogHelper.Error("程序异常终止", ex);
            Console.WriteLine($"\n[错误] {ex.Message}\n堆栈: {ex.StackTrace}");
            return 1;
        }
        finally
        {
            LogHelper.Flush();
        }
    }
}