**HiddifyConfigsCLI** is a high-performance, fully asynchronous command-line tool written in C# (.NET 9) that automatically tests the connectivity of thousands of VLESS, Trojan, and Hysteria2 proxy nodes from any subscription or raw link list, and outputs only the working nodes in clean, ready-to-use formats.

### Core Functionality
- Downloads and parses node lists from local files or remote URLs (supports base64-encoded subscriptions and plain-text links)
- Accurately extracts and normalizes protocol parameters (host, port, SNI, TLS fingerprint, Reality settings, UUID/password, QUIC/Hysteria2 specifics, etc.)
- Performs real-world connectivity checks using protocol-specific handshakes:
  - VLESS + WebSocket + TLS + Reality (full REALITY vision support)
  - Trojan (TLS + SHA224 password authentication)
  - Hysteria2 (QUIC Initial packet + authentic Chrome-like TLS ClientHello)
- Uses fully asynchronous, high-concurrency testing (SemaphoreSlim + configurable parallel threads) with precise per-node timeout control
- Measures and records actual connection latency for every successful node
- Deduplicates, sorts by speed (fastest first), and splits output into multiple files if needed
- Generates clean output files:
  - `valid_links.txt` – complete list of working links
  - `valid_links_part1.txt`, `valid_links_part2.txt`, … – segmented files (configurable max lines per file)

### Typical One-Line Usage
```bash
HiddifyConfigsCLI.exe --input https://example.com/sub.txt --output valid_links.txt --timeout 6 --parallel 120 --max-lines 100 --max-parts 2
```

Designed specifically for daily automated runs (GitHub Actions / cron), delivering fresh, verified, high-speed proxy node lists every day with zero manual work.

---
《节点志·连通篇》
余有旧机，i5-3337U，主频一又十分之八，十六圭 DDR3，SSD 疾如闪电。
欲筛 万五千五百之节点，乃作 ConnectivityChecker，以 百二十线程 并驱，五息为限。
初，信号量失守，finally 难至，线程拥塞，日志息声，逾时不报。

后，Grok无敌 重构：
-TcpClient 先造后毁，
-finally 必释令牌，
-握手日志 每节点必书。

于是 进度如流水，十息一报，十二分钟而功成。
终得 良链二千三百六十一，可分 valid_links_01.txt 至 valid_links_24.txt。

Linus曰：“Talk is cheap. Show me the valid_links.txt.”
余曰：“已成，敬请验收。”

---

<!-- AUTO: VALID_LINKS_TIMESTAMP -->
- [valid_links_all](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links.txt) , (Mix, No Base64, all lines) - [Last Updated: 1970-01-01 00:00:00 +0800]
- [valid_links_01](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links_01.txt) , (Mix, No Base64, 100 Lines) - [Last Updated: 1970-01-01 00:00:00 +0800]
- [valid_links_02](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links_02.txt) , (Mix, No Base64, 100 Lines) - [Last Updated: 1970-01-01 00:00:00 +0800]
-
- [valid_links_CN_all](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links_CN.txt) , (Mix, No Base64, all lines) - [Last Updated: 2025-11-06 03:08:49 +0800]
- [valid_links_CN_01](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links_CN_01.txt) , (Mix, No Base64, 100 lines) - [Last Updated: 2025-11-06 03:08:49 +0800]
- [valid_links_CN_02](https://raw.githubusercontent.com/shinexus/LearnToProgram/refs/heads/master/HiddifyConfigsCLI/bin/Debug/net9.0/valid_links_CN_02.txt) , (Mix, No Base64, 100 lines) - [Last Updated: 2025-11-06 03:08:49 +0800]
<!-- END AUTO -->


JimTsui & shinexus
