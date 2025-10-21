using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HiddifyConfigs
{
    public class Test
    {
        public void DoTest()
        {
            IProgress<string> p = new System.Progress<string>(s => Console.WriteLine(s));
            p.Report("这是一个测试：IProgress<string> p = new System.Progress<string>(s => Console.WriteLine(s));");
        }
    }
}
