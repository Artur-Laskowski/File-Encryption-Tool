using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.ComponentModel;
using System.Windows.Threading;
using System.Security.Cryptography;

namespace FileEncryptionTool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string _algorithmName;
        private int _keySize;
        private int _blockSize;
        private string _cipherModeName;
        private string _ivName;

        private int _bytesLengthANU = 100;

        private List<User> _users = User.loadUsers();

        public MainWindow()
        {
            InitializeComponent();
            FileEncryption.pu = (
                (int i) => encryptionProgressBar.Dispatcher.Invoke(
                    () => encryptionProgressBar.Value = i,
                    DispatcherPriority.Background
                )
            );
        }

        private void Update_RNG(List<Point> coords)
        {
            //TODO: add option for choosing which rng methods to use

            //use coordinates entered by user
            List<byte> bytes = new List<byte>();
            foreach (var p in coords)
            {
                bytes.Add(Convert.ToByte(p.X));
                bytes.Add(Convert.ToByte(p.Y));
            }

            //get system time
            bytes.AddRange(BitConverter.GetBytes(DateTime.Now.ToBinary()));

            //get system uptime
            using (var uptime = new PerformanceCounter("System", "System Up Time"))
            {
                uptime.NextValue();       //Call this an extra time before reading its value
                bytes.AddRange(BitConverter.GetBytes(uptime.NextValue()));
            }

            //get random number from Australian National University's Quantum RNG Server
            //TODO: add variable length
            //TODO: add error checking (check for success value in API return, lack of connection)

            string result = new WebClient().DownloadString(string.Format("https://qrng.anu.edu.au/API/jsonI.php?length={0}&type=uint8", _bytesLengthANU));
            var m = Regex.Match(result, "\"data\":\\[(?<rnd>[0-9,]*?)\\]", RegexOptions.Singleline); //parse JSON with regex

            if (m.Success)
            {
                var g = m.Groups["rnd"];
                if (g != null && g.Success)
                {
                    string[] values = g.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var v in values)
                        bytes.Add(Byte.Parse(v));
                }
            }


            rng_result.Text = bytes.ToString();
        }

        private byte[] GetAnuBytes(int length)
        {
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++)
                bytes[i] = (byte)(i + 1);
            return bytes;
            using (var wc = new WebClient())
            {
                string result = wc.DownloadString(string.Format("https://qrng.anu.edu.au/API/jsonI.php?length={0}&type=uint8", length));
                var m = Regex.Match(result, "\"data\":\\[(?<rnd>[0-9,]*?)\\]", RegexOptions.Singleline); //parse JSON with regex

                if (m.Success)
                {
                    var g = m.Groups["rnd"];
                    if (g != null && g.Success)
                    {
                        string[] values = g.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        for (int i = 0; i < values.Length; i++)
                            bytes[i] = Byte.Parse(values[i]);
                    }
                }
                return bytes;
            }
        }

        private byte GetSelectedCipherMode()
        {
            if (modeECB.IsChecked == true)
                return 2;
            if (modeCBC.IsChecked == true)
                return 1;
            if (modeCFB.IsChecked == true)
                return 4;
            if (modeOFB.IsChecked == true)
                return 3;
            return 2;
        }

        private void inputFile_Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                inputFile_TextBox.Text = openFileDialog.FileName;
        }

        private void outputFile_Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                outputFile_TextBox.Text = openFileDialog.FileName;
        }

        private void generateRandomNumber_Button_Click(object sender, RoutedEventArgs e)
        {
            RNG_Window win2 = new RNG_Window(Update_RNG);
            win2.ShowDialog();
        }
        
        private void encryptFile_Button_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(inputFile_TextBox.Text))
            {
                MessageBox.Show("Nie wybrano pliku wejściowego!");
                return;
            }
            try { Path.GetFullPath(inputFile_TextBox.Text); }
            catch
            {
                MessageBox.Show("Folder źródłowy nie istnieje!");
                return;
            }
            if (!File.Exists(inputFile_TextBox.Text))
            {
                MessageBox.Show("Plik źródłowy nie istnieje!");
                return;
            }

            string outputPath;
            try { outputPath = inputFile_TextBox.Text.Substring(0, outputFile_TextBox.Text.LastIndexOf("\\")); }
            catch (Exception ex)
            {
                MessageBox.Show("Niepoprawna ścieżka pliku docelowego!");
                return;
            }
            try { Path.GetFullPath(outputFile_TextBox.Text); }
            catch
            {
                MessageBox.Show("Folder docelowy nie istnieje!");
                return;
            }

            CipherMode cipherMode = (CipherMode)GetSelectedCipherMode();

            _algorithmName = "AES";
            _keySize = 256;
            _blockSize = Int32.Parse(blockSize_TextBox.Text);
            _cipherModeName = cipherMode.ToString();
            _ivName = "ivName";
            _users = new List<User>
            {
                new User("user@gmail.com", "123123123123123")
            };

            FileEncryption.mode = cipherMode;
            FileEncryption.keySize = _keySize;
            FileEncryption.key = GetAnuBytes(_keySize >> 3);
            FileEncryption.bufferSize = 1 << 15;
            FileEncryption.blockSize = _blockSize;
            FileEncryption.iv = GetAnuBytes(_blockSize >> 3);


            //TODO add error checking for block below
            XDocument xdoc = new XDocument(
                new XElement("EncryptedFileHeader",
                    new XElement("Algorightm", _algorithmName),
                    new XElement("KeySize", _keySize.ToString()),
                    new XElement("BlockSize", _blockSize.ToString()),
                    new XElement("CipherMode", _cipherModeName),
                    new XElement("IV", _ivName),
                    new XElement("ApprovedUsers",
                        from user in _users
                        select new XElement("User",
                            new XElement("Email", user.Email)
                            //TODO add sessionKey encryption
                            //new XElement("SessionKey", RSA.encrypt(sessionKey, user.getPublicKey()))
                        )
                    )
                )
            );

            string pathAndFileName = outputFile_TextBox.Text;
            
            string path = pathAndFileName.Substring(0, pathAndFileName.LastIndexOf("\\"));
            try
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Nie można utworzyć folderu docelowego!");
                return;
            }

            using (StreamWriter writer = new StreamWriter(pathAndFileName, false))
            {
                xdoc.Save(writer);
                writer.Write("\nDATA\n");
            }

            if (FileEncryption.EncryptFile(inputFile_TextBox.Text, outputFile_TextBox.Text))
                MessageBox.Show("Pomyślnie zapisano do pliku");
        }
    }
}
