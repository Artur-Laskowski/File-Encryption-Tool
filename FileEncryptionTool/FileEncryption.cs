using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Windows;

namespace FileEncryptionTool
{
    static class FileEncryption
    {
        public delegate void ProgressUpdate(int i);
        static public ProgressUpdate pu;
        static public byte[] key;
        static public byte[] iv;
        static public CipherMode mode;
        static public int bufferSize;
        static public int keySize;
        static public int blockSize;

        static public bool EncryptFile(string inputFile, string outputFile)
        {
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.KeySize = keySize;
                    aesAlg.Mode = mode;
                    aesAlg.BlockSize = blockSize;
                    aesAlg.Key = key;
                    aesAlg.IV = iv;

                    MessageBox.Show(String.Format("Starting encryption, params:\nkeySize: {0}\nblockSize: {1}\nmode: {2}", keySize, blockSize, mode.ToString()));

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    byte[] buffer = new byte[bufferSize];
                    using (Stream output = File.Open(outputFile, FileMode.Append))
                    {
                        using (CryptoStream cs = new CryptoStream(output, encryptor, CryptoStreamMode.Write))
                        {
                            using (BinaryWriter bw = new BinaryWriter(cs))
                            {
                                using (Stream input = File.OpenRead(inputFile))
                                {
                                    int count = 0;
                                    double i = 0;
                                    long totalSize = input.Length / bufferSize;
                                    while ((count = input.Read(buffer, 0, bufferSize)) > 0)
                                    {
                                        bw.Write(buffer, 0, count);
                                        i++;
                                        pu((int)(i / totalSize * 100.0));
                                    }
                                }
                            }
                        }
                    }
                }
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        static public bool DecryptFile(string inputFile, string outputFile)
        {
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = iv;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] buffer = new byte[256];
                    using (Stream output = File.Open(outputFile, FileMode.Create))
                    {
                        using (CryptoStream cs = new CryptoStream(output, decryptor, CryptoStreamMode.Write))
                        {
                            using (BinaryWriter bw = new BinaryWriter(cs))
                            {
                                using (Stream input = File.OpenRead(inputFile))
                                {
                                    int count = 0;
                                    while ((count = input.Read(buffer, 0, 256)) > 0)
                                        bw.Write(buffer, 0, count);
                                }
                            }
                        }
                    }
                }
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }
    }
}
