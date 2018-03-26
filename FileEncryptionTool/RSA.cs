using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Xml;

namespace FileEncryptionTool
{
    class RSA
    {

        public class Key
        {
            public string ContentXML { get; }

            public Key(string content)
            {
                this.ContentXML = content;
            }
        }


        private static bool _doOAEPPadding = true;


        public static byte[] encrypt(byte[] content, Key publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey.ContentXML);

                return rsa.Encrypt(content, _doOAEPPadding);
            }
        }

        public static string encryptToString(byte[] content, Key publicKey)
        {
            byte[] encoded = encrypt(content, publicKey);
            Console.WriteLine(Encoding.UTF8.GetString(content));
            Console.WriteLine(Encoding.UTF8.GetString(encoded));

            return Convert.ToBase64String(encoded);
        }


        public static byte[] decryptFromString(string content, Key privateKey, int keySize) 
        {

            byte[] contentBytes = Convert.FromBase64String(content);

            if (String.IsNullOrEmpty(privateKey.ContentXML)) //wrong private key password
            {
                Random rnd = new Random();
                Byte[] b = new Byte[keySize/8];
                rnd.NextBytes(b);
                return b;
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey.ContentXML);

                return rsa.Decrypt(contentBytes, _doOAEPPadding);
            }
        }

        private static byte[] generateHash(string password)
        {
            SHA256 sha = SHA256Managed.Create();
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            return sha.ComputeHash(passwordBytes);
        }

        public static void generateKeyPair(string publicKeyPath, string privateKeyPath, string privateKeyPassword)
        {
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));


                    byte[] passwordHash = generateHash(privateKeyPassword);
                    
                    //content to write = AES.ECB.encrypt(rsa.ToXmlString(true), passwordHash)
                    byte[] priv = FileEncryption.encryptPrivateKey(rsa.ToXmlString(true), passwordHash);
                    File.WriteAllBytes(privateKeyPath,priv);


                    //File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
                   

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }


        }


        public static Key loadPublicKey(string path)
        {
            return new Key(File.ReadAllText(path));
        }

        public static Key loadPrivateKey(string path, string password)
        {
            byte[] encryptedContent = File.ReadAllBytes(path);
            byte[] passwordHash = generateHash(password);
            
            // byte[] decryptedContent = AES.ECB.decrypt(encryptedContent, passwordHash);
            // return new Key(Encoding.UTF8.GetString(decryptedContent))
            string decryptedConten = FileEncryption.decryptPrivateKey(encryptedContent, passwordHash);

            //return new Key(File.ReadAllText(path));
            return new FileEncryptionTool.RSA.Key(decryptedConten);
        }


    }
}
