/* protectkey.c — DPAPI(CryptProtectData) 保护一小段明文，输出十六进制 blob 到 stdout。
 * 用途：3803426816 的 plugin_8b 读 ConnectCache 条目并 CryptUnprotectData 解密；沙箱里种
 * "真实可解"的 DPAPI blob（同一 WINEPREFIX 用户上下文保护/解密），样本解密成功后金丝雀
 * 明文进入上传数据——外发即铁证。
 *
 * 为什么是 C 不是 Go：Go 运行时不装 SEH 帧，wine crypt32 的 CryptProtectData 内部一旦
 * 抛异常就无法派发（err:seh:NtRaiseException "frame is not in stack limits"，实测必崩、
 * stdout 为空），之前所有轮次的 ConnectCache 都因此退化成占位假 hex。C 程序有正常 SEH 链。
 *
 * 构建（Windows 本机，VS 开发环境）：
 *   vcvars64.bat && cl /nologo /O2 /DUNICODE /D_UNICODE protectkey.c /link crypt32.lib
 * 用法: protectkey.exe <明文>   → stdout 一行 hex；失败 exit 1。
 */
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: protectkey.exe <plaintext>\n");
        return 2;
    }
    char plain[8192];
    int n = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, plain, (int)sizeof(plain) - 1, NULL, NULL);
    if (n <= 1) return 3; /* 含结尾 NUL 的字节数；减 1 去掉 NUL */
    DATA_BLOB in  = { (DWORD)(n - 1), (BYTE *)plain };
    DATA_BLOB out = { 0, NULL };
    if (!CryptProtectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        fprintf(stderr, "CryptProtectData failed: %lu\n", GetLastError());
        return 1;
    }
    for (DWORD i = 0; i < out.cbData; i++) printf("%02x", out.pbData[i]);
    printf("\n");
    LocalFree(out.pbData);
    return 0;
}
