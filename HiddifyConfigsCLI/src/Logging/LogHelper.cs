// LogHelper.cs
// 负责：统一日志输出（控制台 + 文件轮转）
// 命名空间：HiddifyConfigsCLI

using System;
using System.IO;
using System.Text;

namespace HiddifyConfigsCLI;

internal static class LogHelper
{
    private static readonly object _lock = new();
    private static StreamWriter? _logWriter;
    private static bool _verbose;

    private const long MaxFileSize = 1 * 1024 * 1024; // 1MB
    private const int MaxRetainedFiles = 5;
    private const string LogFileName = "cliLog.log";

    /// <summary>
    /// 初始化日志系统
    /// </summary>
    /// <param name="enableLog">是否写入文件</param>
    /// <param name="verbose">是否启用详细模式（控制台输出 DEBUG）</param>
    public static void Init( bool enableLog, bool verbose )
    {
        _verbose = verbose;

        if (!enableLog) return;

        var logPath = Path.Combine(AppContext.BaseDirectory, LogFileName);
        RotateIfNeeded(logPath);

        try
        {
            _logWriter = new StreamWriter(logPath, append: true, Encoding.UTF8)
            {
                AutoFlush = true
            };
            Info("日志系统已启用");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] 无法创建日志文件: {logPath} | {ex.Message}");
        }
    }

    /// <summary>
    /// 日志轮转（超过 1MB 自动归档）
    /// </summary>
    private static void RotateIfNeeded( string path )
    {
        if (!File.Exists(path)) return;

        var info = new FileInfo(path);
        if (info.Length < MaxFileSize) return;

        try
        {
            // 归档：log.5 → 删除，log.4 → log.5，...，log → log.1
            for (int i = MaxRetainedFiles - 1; i >= 1; i--)
            {
                var oldPath = $"{path}.{i}";
                var newPath = i == 1 ? path : $"{path}.{i + 1}";
                if (File.Exists(oldPath))
                    File.Move(oldPath, newPath, overwrite: true);
            }
            File.Move(path, $"{path}.1", overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] 日志轮转失败: {ex.Message}");
        }
    }

    // ================================
    // 公共日志方法
    // ================================

    public static void Info( string msg ) => Write("INFO", msg);
    public static void Warn( string msg ) => Write("WARN", msg);
    public static void Error( string msg, Exception? ex = null ) => Write("ERROR", msg, ex);        
    public static void Verbose( string msg ) => Write("VERBOSE", msg);
    public static void Debug( string msg )
    {
        if (_verbose)
            Write("DEBUG", msg);
    }

    // ================================
    // 内部写入逻辑
    // ================================

    private static void Write( string level, string msg, Exception? ex = null )
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var line = $"[{timestamp}] [{level}] {msg}";
        if (ex != null)
            line += $" | {ex.GetType().Name}: {ex.Message}";

        lock (_lock)
        {
            // 始终输出到控制台（除非是 DEBUG 且未启用 verbose）
            if (level != "DEBUG" || _verbose)
                Console.WriteLine(line);

            try
            {
                _logWriter?.WriteLine(line);
            }
            catch
            {
                // 防止日志写入失败导致程序崩溃
            }
        }
    }

    /// <summary>
    /// 刷新日志缓冲区（程序退出前调用）
    /// </summary>
    public static void Flush()
    {
        try
        {
            _logWriter?.Flush();
            _logWriter?.Dispose();
            _logWriter = null;
        }
        catch { /* ignore */ }
    }
}