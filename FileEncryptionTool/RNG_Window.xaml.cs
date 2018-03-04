using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace FileEncryptionTool
{
    /// <summary>
    /// Interaction logic for RNG_Window.xaml
    /// </summary>
    public partial class RNG_Window : Window
    {
        public delegate void CallbackDelegate(List<Point> coords);
        CallbackDelegate callback_func;
        List<Point> _coords;
        int clicks = 0;

        public RNG_Window(CallbackDelegate func)
        {
            InitializeComponent();
            callback_func = func;

            _coords = new List<Point>();
        }


        private void canvas1_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            clicksCounter.Content = (++clicks).ToString() + " / 8";
            _coords.Add(e.GetPosition(canvas1));

            if (_coords.Count == 8)
            {
                callback_func(_coords);
                this.Close();
            }
        }
    }
}
