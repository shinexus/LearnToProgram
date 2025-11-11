// LogHelper.cs
// 负责：统一日志输出（控制台 + 文件轮转）
// 命名空间：HiddifyConfigsCLI.src.Logging
// [Grok 修复] 2025-11-11：修复日志输出逻辑，符合 --verbose / --log 设计
using System;
using System.IO;
using System.Text;

namespace HiddifyConfigsCLI.src.Logging;

internal static class LogHelper
{
    private static readonly object _lock = new();
    private static StreamWriter? _logWriter;
    private static bool _logToFile = false;   // 由 --log 控制
    private static bool _verbose = false;     // 由 --verbose 控制

    private const long MaxFileSize = 1 * 1024 * 1024; // 1MB
    private const int MaxRetainedFiles = 5;
    private const string LogFileName = "cliLog.log";

    /// <summary>
    /// 初始化日志系统
    /// </summary>
    /// <param name="logToFile">是否写入文件（--log）</param>
    /// <param name="verbose">是否启用详细模式（--verbose）</param>
    public static void Init( bool logToFile, bool verbose )
    {
        _logToFile = logToFile;
        _verbose = verbose;

        if (!_logToFile) return;

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
    // 公共日志方法（逻辑修复）
    // ================================
    public static void Info( string msg ) => Write("INFO", msg, shouldConsole: _verbose);
    public static void Warn( string msg ) => Write("WARN", msg, shouldConsole: _verbose);
    public static void Error( string msg, Exception? ex = null ) => Write("ERROR", msg, ex, shouldConsole: true); // Error 始终输出控制台
    public static void Verbose( string msg ) => Write("VERBOSE", msg, shouldConsole: _verbose);
    public static void Debug( string msg ) => Write("DEBUG", msg, shouldConsole: _verbose);

    // ================================
    // 内部写入逻辑（核心修复）
    // ================================
    private static void Write( string level, string msg, Exception? ex = null, bool shouldConsole = false )
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var line = $"[{timestamp}] [{level}] {msg}";
        if (ex != null)
            line += $" | {ex.GetType().Name}: {ex.Message}";

        lock (_lock)
        {
            // [控制台输出逻辑] 
            if (shouldConsole || level == "ERROR")
            {
                Console.WriteLine(line);
            }

            // [文件输出逻辑] 仅由 _logToFile 控制
            if (_logToFile)
            {
                try
                {
                    _logWriter?.WriteLine(line);
                }
                catch
                {
                    // 防止崩溃
                }
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