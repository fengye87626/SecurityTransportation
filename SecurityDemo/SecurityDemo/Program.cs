using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SecurityDemo
{
    class Program
    {
        static CngKey aliceKey;
        static CngKey bobKey;
        static byte[] alicePubKeyBlob;
        static byte[] bobPubKeyBlob;

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            CreateKey();
            byte[] encrytpedData = AliceSendData("123");
            BobReceiveData(encrytpedData);
            Console.ReadKey();
        }

        public static void CreateKey()
        {
            aliceKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            bobKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            alicePubKeyBlob = aliceKey.Export(CngKeyBlobFormat.EccPublicBlob);
            bobPubKeyBlob = bobKey.Export(CngKeyBlobFormat.EccPublicBlob);
        }

        private static byte[] AliceSendData(string msg)
        {
            Console.WriteLine(string.Format("Alice Send Msg: {0}", msg));
            byte[] rawdata = Encoding.UTF8.GetBytes(msg);
            byte[] encryptedData = null;
            using (var aliceAlgorithm = new ECDiffieHellmanCng(aliceKey))
            using (CngKey bobPubKey = CngKey.Import(bobPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] symmkey = aliceAlgorithm.DeriveKeyMaterial(bobPubKey);

                Console.WriteLine(string.Format("Alice Create this symmtric key with {0}", Convert.ToBase64String(symmkey)));

                var aes = new AesCryptoServiceProvider();
                aes.Key = symmkey;
                aes.GenerateIV();
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    cs.Write(rawdata, 0, rawdata.Length);
                    cs.Close();
                    encryptedData = ms.ToArray();
                }
                aes.Clear();
            }

            Console.WriteLine(Convert.ToBase64String(encryptedData));
            return encryptedData;
        }

        private static void BobReceiveData(byte[] encryptData)
        {
            byte[] rawdata = null;
            var aes = new AesCryptoServiceProvider();
            int nBytes = aes.BlockSize >> 3; // bit to Byte, need to devide 8
            byte[] iv = new byte[nBytes];

            for (int i = 0; i < iv.Length; i++)
                iv[i] = encryptData[i];
            using (var bobAlgorithm = new ECDiffieHellmanCng(bobKey))
            using (CngKey alicePubKey = CngKey.Import(alicePubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] symmKey = bobAlgorithm.DeriveKeyMaterial(alicePubKey);
                Console.WriteLine(Convert.ToBase64String(symmKey));
                aes.Key = symmKey;
                aes.IV = iv;
            }
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            using (MemoryStream ms = new MemoryStream())
            {
                var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);
                cs.Write(encryptData, nBytes, encryptData.Length - nBytes);
                cs.Close();
                rawdata = ms.ToArray();
                Console.WriteLine(Encoding.UTF8.GetString(rawdata));
            }
            aes.Clear();
        }
    }

}
