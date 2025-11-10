# create-telegram.ps1
# One-click create Telegram module skeleton

Write-Host "Creating Telegram module..." -ForegroundColor Green

# Create directory
New-Item -ItemType Directory -Path "src\Sources\Telegram" -Force | Out-Null

# Create placeholder files
@"
namespace HiddifyConfigsCLI.Sources.Telegram;

// POCO config class
public class TelegramConfig
{
    // TODO: To be implemented
}
"@ | Set-Content -Path "src\Sources\Telegram\TelegramConfig.cs" -Encoding UTF8

@"
namespace HiddifyConfigsCLI.Sources.Telegram;

// Cache management
public class TelegramCache
{
    // TODO: To be implemented
}
"@ | Set-Content -Path "src\Sources\Telegram\TelegramCache.cs" -Encoding UTF8

@"
namespace HiddifyConfigsCLI.Sources.Telegram;

// Main fetching logic
public class TelegramFetcher
{
    // TODO: To be implemented
}
"@ | Set-Content -Path "src\Sources\Telegram\TelegramFetcher.cs" -Encoding UTF8

Write-Host "Telegram module skeleton created!" -ForegroundColor Magenta
Write-Host "Path: src/Sources/Telegram/"