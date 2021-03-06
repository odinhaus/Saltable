﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Altus.Saltable
{
    public class Program
    {
        public static void Main(params string[] args)
        {
            string test = "I'm in love with being queen.";
            
            Console.WriteLine("Encrypt: " + test);
            Console.WriteLine("Decrypt: " + Altus.Saltable.Class1.BoxUnbox(test));
            for (int i = 1; i < 25; i++)
            {
                int messageSize = (int)Math.Pow(2, i);
                Console.WriteLine("Encrypt Rate (" + messageSize + "): " + Altus.Saltable.Class1.EncryptRateTest(messageSize) * messageSize + " bytes/sec");
            }
            Console.ReadLine();
        }
    }
}
