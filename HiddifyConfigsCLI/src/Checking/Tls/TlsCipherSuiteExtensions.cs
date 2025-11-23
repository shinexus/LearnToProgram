using System.Net.Security;

// TlsCipherSuite 扩展：随机 shuffle cipher 列表（random 指纹）
public static class TlsCipherSuiteExtensions
{
    public static TlsCipherSuite[] Shuffle( this TlsCipherSuite[] suites )
    {
        var random = Random.Shared;
        for (int i = suites.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (suites[i], suites[j]) = (suites[j], suites[i]);
        }
        return suites;
    }
}