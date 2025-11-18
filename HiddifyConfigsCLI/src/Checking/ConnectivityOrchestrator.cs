// src/Checking/ConnectivityOrchestrator.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace HiddifyConfigsCLI.src.Checking;

/// <summary>
/// 【并发编排器】负责：并发控制、进度报告、结果收集
/// </summary>
internal class ConnectivityOrchestrator
{
    private readonly RunOptions _opts;
    private readonly SemaphoreSlim _semaphore;
    private readonly ConcurrentBag<NodeInfoBase> _valid = new();
    private int _completed;

    public ConnectivityOrchestrator( RunOptions opts )
    {
        _opts = opts;
        _semaphore = new SemaphoreSlim(opts.Parallel);
    }

    /// <summary>
    /// 执行完整检测流程
    /// </summary>
    public async Task<List<NodeInfoBase>> RunAsync( List<NodeInfoBase> nodes )
    {
        LogHelper.Info($"开始连通性检测，共 {nodes.Count} 个节点（并发: {_opts.Parallel}，检测超时: {_opts.Timeout}s）");

        // 【Grok 提炼】DNS 解析外移
        var dnsCache = await DnsResolver.ResolveAsync(nodes);
        if (dnsCache.Count == 0)
        {
            LogHelper.Warn("DNS 解析失败，所有节点跳过");
            return [];
        }

        // 【Grok 提炼】并行检测
        // var tasks = nodes.Select(node => Task.Run(() => TestNodeAsync(node, dnsCache)));
        // 需要传递 nodes
        var total = nodes.Count;
        var tasks = nodes.Select(node => Task.Run(() => TestNodeAsync(node, dnsCache, total)));
        await Task.WhenAll(tasks);

        var result = _valid.ToList();
        LogHelper.Info($"连通性检测完成，有效节点 {result.Count} 条（已通过协议握手 + 出网测试）");
        return result;
    }

    /// <summary>
    /// 单个节点检测（并发安全）
    /// </summary>
    private async Task TestNodeAsync( NodeInfoBase node, Dictionary<string, IPAddress> dnsCache, int total )
    {
        var extra = node.ExtraParams ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var transportType = extra.GetValueOrDefault("transport_type") ?? "";
        
        await _semaphore.WaitAsync();
        var sw = Stopwatch.StartNew();

        try
        {
            // 【Grok 提炼】握手检测外移
            // if (!await HandshakeTester.TryHandshakeAsync(node, dnsCache, _opts.Timeout, _opts))
            
            //var (success, latency, stream) = await HandshakeTester.TryHandshakeAsync(node, dnsCache, _opts.Timeout, _opts);
            //if (!success)
            //    return;
            // 【Grok 修复_2025-11-17_020】正确调用新签名
            var (success, latency, stream) = await HandshakeTester.TryHandshakeAsync(
                node, dnsCache, _opts.Timeout, _opts).ConfigureAwait(false);

            if (!success)
                return;

            // Hysteria2 不需要出网测试
            // ws | httpupgrade 传输也不需要出网测试
            if (node.Type == "hysteria2" ||
                transportType.Equals("ws", StringComparison.OrdinalIgnoreCase) == true ||
                transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase) == true)
{
                // var n = node with { Latency = latency };
                // _valid.Add(n);
                node.Latency = latency;
                _valid.Add(node);
                if (_opts.Verbose) LogHelper.Info($"[可用] {node} | {latency.TotalMilliseconds:F0}ms");
                return;
            }

            if (stream == null)
            {
                LogHelper.Warn($"[注意] {node} | 握手成功但流为空，跳过出网测试");
                return;
            }

            bool internetOk = true;
            if (_opts.EnableInternetCheck)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_opts.Timeout));

                // 关键：出网测试必须传入 effectiveSni
                // 由于 HandshakeTester 现在会把 effectiveSni 放进 node 的一个临时属性（推荐做法）
                // 这里我们直接从 node 取（如果 HandshakeTester 没写，我们加一个扩展属性）
                string effectiveSni = node.EffectiveSni ?? node.Host;
                internetOk = await InternetTester.CheckInternetAsync(node, stream, effectiveSni, _opts, cts.Token);
                if (!internetOk)
                {
                    LogHelper.Warn($"[注意] {node} | 协议握手通过，但无法出网");
                    return;
                }
            }

            // var validNode = node with { Latency = sw.Elapsed };
            // _valid.Add(validNode);

            // 记录可用节点
            // node.Latency = sw.Elapsed;
            node.Latency = latency;
            _valid.Add(node);

            // if (_opts.Verbose) LogHelper.Info($"[可用] {validNode} | {sw.Elapsed.TotalMilliseconds:F0}ms");
            if (_opts.Verbose) LogHelper.Info($"[可用] {node} | {sw.Elapsed.TotalMilliseconds:F0}ms");
        }
        finally
        {
            _semaphore.Release();
            ReportProgress(total);
        }
    }

    /// <summary>
    /// 进度报告（每10%或最后）
    /// </summary>
    private void ReportProgress( int total )
    {
        var current = Interlocked.Increment(ref _completed);
        if (current % Math.Max(10, total / 10) == 0 || current == total)
        {
            var percent = (int)(current * 100.0 / total);
            LogHelper.Info($"[进度] [{current}/{total}] {percent}%");
        }
    }
}