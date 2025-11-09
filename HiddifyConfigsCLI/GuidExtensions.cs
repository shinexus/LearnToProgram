using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI
{
    public static class GuidExtensions
    {
        /// <summary>
        /// 兼容 .NET 6/7/8：返回大端序 UUID 字节数组（VLESS 协议要求）
        /// </summary>
        public static byte[] ToByteArrayBigEndian( this Guid guid )
        {
            var bytes = guid.ToByteArray();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return bytes;
        }
    }
}
