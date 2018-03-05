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

        private List<User> _users;

        private class User
        {
            public User(string email, string sessionKey)
            {
                _email = email;
                _sessionKey = sessionKey;
            }

            public string _email;
            public string _sessionKey; //TODO change type (?)
        }

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                outputFileName.Text = openFileDialog.FileName;
        }

        private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            RNG_Window win2 = new RNG_Window(Update_RNG);
            win2.ShowDialog();
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

        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            _algorithmName = "algoName";
            _keySize = 32;
            _blockSize = 128;
            _cipherModeName = "cipherName";
            _ivName = "ivName";
            _users = new List<User>();
            _users.Add(new User("user@gmail.com", "123123123123123"));


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
                            new XElement("Email", user._email),
                            new XElement("SessionKey", user._sessionKey)
                        )
                    )
                )
            );
            //TODO add creating directory if doesn't exist
            string directory = (Directory.Exists(outputFileName.Text) ? outputFileName.Text : @"C:\test\default.xml");
            using (StreamWriter writer = new StreamWriter(directory, false))
            {
                xdoc.Save(writer);
                writer.Write(rng_result.Text);
                MessageBox.Show("Pomyślnie zapisano do pliku");
            }

        }
    }
}
