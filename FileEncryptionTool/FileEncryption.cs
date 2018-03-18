using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Windows;
using System.Xml.Linq;

namespace FileEncryptionTool
{
    static class FileEncryption
    {
        public delegate void ProgressUpdate(int i);
        static public ProgressUpdate pu;
        static private string algorithmName = "AES";
        static public byte[] key;
        static public byte[] iv;
        static public CipherMode mode;
        static public int bufferSize;
        static public int keySize;
        static public int blockSize;
        static public List<User> targetUsers;
        static public User currentUser;
        static public string password;

        static public void InitializeEncryption(string inputFile, string outputFile)
        {
            //TODO add error checking for block below
            XDocument xdoc = new XDocument(
                new XElement("EncryptedFileHeader",
                    new XElement("Algorithm", algorithmName),
                    new XElement("KeySize", keySize.ToString()),
                    new XElement("BlockSize", blockSize.ToString()),
                    new XElement("CipherMode", mode.ToString()),
                    new XElement("IV", string.Join("", iv)),
                    new XElement("ApprovedUsers",
                        from user in targetUsers
                        select new XElement("User",
                            new XElement("Email", user.Email),
                            //TODO add sessionKey encryption
                            //new XElement("SessionKey", RSA.encrypt(FileEncryption.key, user.getPublicKey()))
                            new XElement("SessionKey", string.Join("", key))
                        )
                    )
                )
            );

            using (StreamWriter writer = new StreamWriter(outputFile, false))
            {
                xdoc.Save(writer);
                writer.Write("\r\nDATA\r\n");
            }

            if (EncryptFile(inputFile, outputFile))
                MessageBox.Show("Pomyślnie zapisano do pliku");
        }

        static public void InitializeDecryption(string inputFile, string outputFile)
        {
            //read the header to memory
            using (MemoryStream ms = new MemoryStream())
            {
                using (StreamReader s = File.OpenText(inputFile))
                {
                    while (!s.EndOfStream)
                    {
                        var l = s.ReadLine();
                        if (l.Contains("DATA"))
                            break;

                        ms.Write(Encoding.ASCII.GetBytes(l.ToCharArray()), 0, l.Length);
                    }
                }

                //write settings from header
                ms.Position = 0;
                XDocument xdoc = XDocument.Load(ms);
                var root = xdoc.Element("EncryptedFileHeader");
                algorithmName = root.Element("Algorithm").Value;
                keySize = Int32.Parse(root.Element("KeySize").Value);
                blockSize = Int32.Parse(root.Element("BlockSize").Value);
                Enum.TryParse(root.Element("CipherMode").Value, out mode);
                iv = root.Element("IV").Value.Select(s => Byte.Parse(s.ToString())).ToArray();

                //TODO add searching the user in this list and decrypting the session key
                var usersAndKeys = root.Element("ApprovedUsers").Elements().Select(element => new Tuple<string, string>(element.Element("Email").Value, element.Element("SessionKey").Value)).ToList();
                /*
                foreach (var user in usersAndKeys)
                {
                    if (user.Item1 == currentUser.Email)
                    {
                        key = RSA.decrypt(user.Item2.Select(s => Byte.Parse(s.ToString())).ToArray(), currentUser.getPrivateKey(password));
                        break;
                    }
                }*/
            }
            

            if (DecryptFile(inputFile, outputFile))
                MessageBox.Show("Pomyślnie rozszyfrowano plik");
        }

        static private bool EncryptFile(string inputFile, string outputFile)
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

                    MessageBox.Show(String.Format("Rozpoczynanie szyfrowania, parametry:\nrozmiar klucza: {0}\nrozmiar bloku: {1}\ntryb: {2}", keySize, blockSize, mode.ToString()));

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
                                        pu((int)(i / totalSize * 100.0)); //calling progress update delegate (progress bar function)
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
            }
            return false;
        }

        static private bool DecryptFile(string inputFile, string outputFile)
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

                    MessageBox.Show(String.Format("Starting decryption, params:\nkeySize: {0}\nblockSize: {1}\nmode: {2}", keySize, blockSize, mode.ToString()));

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] buffer = new byte[bufferSize];

                    using (Stream output = File.Open(outputFile, FileMode.Create))
                    {
                        using (CryptoStream cs = new CryptoStream(output, decryptor, CryptoStreamMode.Write))
                        {
                            using (BinaryWriter bw = new BinaryWriter(cs))
                            {
                                using (Stream input = File.OpenRead(inputFile))
                                {
                                    //keep reading until we hit data label (we don't want to decrypt header)
                                    //TODO put it into nice function
                                    bool found = false;
                                    while (!found)
                                    {
                                        if (input.ReadByte() == 'D' &&
                                            input.ReadByte() == 'A' &&
                                            input.ReadByte() == 'T' &&
                                            input.ReadByte() == 'A' &&
                                            input.ReadByte() == '\r' &&
                                            input.ReadByte() == '\n'
                                            )
                                        {
                                            found = true;
                                        }
                                    }
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
    }
}
