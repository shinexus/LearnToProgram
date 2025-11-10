# refactor.ps1
# 一键重构 HiddifyConfigsCLI 项目结构
# 作者：顶尖程序员 Grok
# 运行前：关闭 Visual Studio 2022

Write-Host "Starting project restructuring..." -ForegroundColor Green

# 1. Create directories
$dirs = @(
    "src\Core",
    "src\Parsing",
    "src\Checking",
    "src\Processing",
    "src\Logging",
    "src\Sources",
    "config",
    "cache",
    "cache\telegram",
    "tests",
    ".github\workflows"
)
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Cyan
    }
}

# 2. Move files
$moves = @{
    "NodeInfo.cs"           = "src\Core"
    "RunOption.cs"          = "src\Core"
    "GuidExtensions.cs"     = "src\Core"

    "DoParse.cs"            = "src\Parsing"
    "ProtocolParser.cs"     = "src\Parsing"
    "RegexPatterns.cs"      = "src\Parsing"
    "WebSocketRequestBuilder.cs" = "src\Parsing"

    "ConnectivityChecker.cs"= "src\Checking"
    "InternetTester.cs"     = "src\Checking"

    "ResultProcessor.cs"    = "src\Processing"
    "FileSaver.cs"          = "src\Processing"

    "LogHelper.cs"          = "src\Logging"

    "Program.cs"            = "src"

    "urls.txt"              = "config"

    "one.txt"               = "tests"
    "vless.txt"              = "tests"
    "vless_test"            = "tests"
}

foreach ($file in $moves.Keys) {
    $src = $file
    $dst = $moves[$file]
    if (Test-Path $src) {
        Move-Item -Path $src -Destination $dst -Force
        Write-Host "Moved: $src -> $dst" -ForegroundColor Yellow
    } else {
        Write-Host "Skipped: $src (not found)" -ForegroundColor Gray
    }
}

# 3. Update .csproj
$csproj = "HiddifyConfigsCLI.csproj"
if (Test-Path $csproj) {
    $content = @'
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="src\**\*.cs" />
  </ItemGroup>

</Project>
'@
    Set-Content -Path $csproj -Value $content.Trim() -Encoding UTF8
    Write-Host "Updated $csproj" -ForegroundColor Green
}

# 4. Create .gitignore
$gitignore = @'
# .NET
bin/
obj/
*.csproj.user

# Cache
cache/

# VS
.vscode/
*.vspscc
*.vssscc

# Test output
tests/output/
valid_links.txt
'@
Set-Content -Path ".gitignore" -Value $gitignore.Trim() -Encoding UTF8
Write-Host "Created .gitignore" -ForegroundColor Green

# 5. Create TelegramConfig.json template
$telegramConfig = @'
{
  "channels": [
    "v2Line",
    "vpnfail_v2ray",
    "free_v2ray"
  ],
  "maxMessagesPerChannel": 50,
  "requestDelayMs": 2000,
  "parallelChannels": 5,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "cacheDir": "cache/telegram",
  "enableCache": true,
  "timeoutSeconds": 15
}
'@
Set-Content -Path "config\TelegramConfig.json" -Value $telegramConfig.Trim() -Encoding UTF8
Write-Host "Created config\TelegramConfig.json" -ForegroundColor Green

Write-Host "`nRestructuring complete!" -ForegroundColor Magenta
Write-Host "Next steps:"
Write-Host "   1. Open VS 2022 -> Open HiddifyConfigsCLI.csproj"
Write-Host "   2. Press Ctrl + . to fix namespaces"
Write-Host "   3. Run 'dotnet build' to verify"
Write-Host ""