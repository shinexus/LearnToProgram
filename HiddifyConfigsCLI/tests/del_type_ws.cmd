@echo off
setlocal enabledelayedexpansion

rem === 要处理的文件 ===
set "file=test.txt"

rem === 备份原文件（可选，建议保留）===
if exist "%file%.bak" del "%file%.bak"
copy "%file%" "%file%.bak" >nul

rem === 方法一：用 findstr 取反匹配，直接生成新文件（最快最稳）===
rem 说明：/V 表示只输出不匹配的行，/I 不区分大小写，/L 按字面量匹配
findstr /V /I /L "type=ws" "%file%" > "%file%.tmp"

rem === 替换原文件 ===
move /Y "%file%.tmp" "%file%" >nul

echo.
echo [Success] 已删除 test.txt 中所有包含 "type=ws" 的行（不区分大小写）
echo [Info] 原文件已备份为 %file%.bak
echo [Info] 当前文件剩余行数： 
find /c /v "" "%file%"

endlocal
pause