using Microsoft.Win32;
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
using System.Windows.Navigation;
using System.Windows.Shapes;
using Sentrio;
using System.IO;

namespace Locker
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private string[] EFilesToOperate = new string[0];
        private string[] DFilesToOperate = new string[0];

        private void EBrowseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog
            {
                CheckFileExists = true,
                CheckPathExists = true,
                Multiselect = true,
                Title = "Select a file to encrypt."
                // add possibility to encrypt multiple files at the same time
            };

            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                if (ofd.FileNames.Length == 1) EFilePath.Text = ofd.FileName;
                else EFilePath.Text = "Multiples files...";
                EFilesToOperate = ofd.FileNames;
            }
            else if (result == false)
            {
                EFilePath.Text = "";
                EFilesToOperate = new string[0];
            }
        }

        private async void EEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (EFilesToOperate.Length == 0)
            {
                MessageBox.Show("No file(s) selected, aborting.", "Encryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }

            foreach (string File in EFilesToOperate)
            {
                if (string.IsNullOrWhiteSpace(File) || !Uri.TryCreate(File, UriKind.Absolute, out Uri useless))
                {
                    MessageBox.Show("The file path specified is invalid, aborting.", "Encryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return;
                }
            }

            if (string.IsNullOrWhiteSpace(EPassword.Password) || string.IsNullOrWhiteSpace(EPasswordConfirm.Password))
            {
                MessageBox.Show("Password and confirmation cannot be empty or whitespace, aborting.", "Encryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }
            else if (EPassword.Password != EPasswordConfirm.Password)
            {
                MessageBox.Show("Password and confirmation does not match, aborting.", "Encryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }

            // disable ui elements
            EncryptTab.IsEnabled = false;
            DecryptTab.IsEnabled = false;
            EBrowseButton.IsEnabled = false;
            EFilePath.IsEnabled = false;
            EPassword.IsEnabled = false;
            EPasswordConfirm.IsEnabled = false;
            EEncryptButton.IsEnabled = false;

            EFileCountLabel.Content = $"0/{EFilesToOperate.Length}";
            EProgressBar.Value = 0;
            EProgressBar.Maximum = EFilesToOperate.Length;
            for (int i = 0; i < EFilesToOperate.Length; ++i)
            {
                string File = EFilesToOperate[i];
                EFileCountLabel.Content = $"{i + 1}/{EFilesToOperate.Length}";
                EProgressBar.Value = i;
                await CryptoWorks.Encrypt(File, File + ".lok", EPassword.Password);
                if (System.IO.File.Exists(File + ".lok")) System.IO.File.Delete(File);
            }
            MessageBox.Show("Operation completed.", "Encryption", MessageBoxButton.OK, MessageBoxImage.Information);
            EFileCountLabel.Content = $"";
            EProgressBar.Value = 0;

            // enable ui elements
            EncryptTab.IsEnabled = true;
            DecryptTab.IsEnabled = true;
            EBrowseButton.IsEnabled = true;
            EFilePath.IsEnabled = true;
            EPassword.IsEnabled = true;
            EPasswordConfirm.IsEnabled = true;
            EEncryptButton.IsEnabled = true;
        }

        private void DBrowseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog
            {
                CheckFileExists = true,
                CheckPathExists = true,
                Multiselect = true,
                Title = "Select a file to decrypt.",
                Filter = "Locked Files (*.lok)|*.lok"
                // add possibility to encrypt multiple files at the same time
            };

            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                if (ofd.FileNames.Length == 1) DFilePath.Text = ofd.FileName;
                else DFilePath.Text = "Multiple files...";
                DFilesToOperate = ofd.FileNames;
            }
            else if (result == false)
            {
                DFilePath.Text = "";
                DFilesToOperate = new string[0];
            }
        }

        private async void DDecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (DFilesToOperate.Length == 0)
            {
                MessageBox.Show("No file(s) selected, aborting.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }

            foreach (string File in DFilesToOperate)
            {
                if (string.IsNullOrWhiteSpace(File) || !Uri.TryCreate(File, UriKind.Absolute, out Uri useless))
                {
                    MessageBox.Show("The file path specified is invalid, aborting.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return;
                }
            }
            if (string.IsNullOrWhiteSpace(DPassword.Password))
            {
                MessageBox.Show("Password cannot be empty or whitespace, aborting.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                return;
            }

            // disable ui elements
            EncryptTab.IsEnabled = false;
            DecryptTab.IsEnabled = false;
            DBrowseButton.IsEnabled = false;
            DFilePath.IsEnabled = false;
            DPassword.IsEnabled = false;
            DDecryptButton.IsEnabled = false;

            int decrypted = 0;
            DFileCountLabel.Content = $"0/{DFilesToOperate.Length}";
            DProgressBar.Value = 0;
            DProgressBar.Maximum = DFilesToOperate.Length;
            for (int i = 0; i < DFilesToOperate.Length; ++i)
            {
                string File = DFilesToOperate[i];
                DFileCountLabel.Content = $"{i + 1}/{DFilesToOperate.Length}";
                DProgressBar.Value = i;
                //await Task.Run(new Action(async () =>
                //{
                try
                {
                    await CryptoWorks.Decrypt(File, File.Substring(0, File.Length - 4), DPassword.Password);
                    if (System.IO.File.Exists(File.Substring(0, File.Length - 4))) System.IO.File.Delete(File);
                    decrypted += 1;
                }
                catch (HMACNotEqualException)
                {
                    MessageBox.Show($"The given password does not unlock ({File}), aborting.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Error);
                    if (System.IO.File.Exists(File.Substring(0, File.Length - 4))) System.IO.File.Delete(File.Substring(0, File.Length - 4));
                    break;
                }
                catch (FormatException)
                {
                    MessageBox.Show($"The file ({File}) is not in the correct format, aborting.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Error);
                    if (System.IO.File.Exists(File.Substring(0, File.Length - 4))) System.IO.File.Delete(File.Substring(0, File.Length - 4));
                    break;
                }
                //}));
            }
            if (decrypted == DFilesToOperate.Length) MessageBox.Show("Operation completed.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Information);
            else MessageBox.Show($"Some files ({DFilesToOperate.Length - decrypted}/{DFilesToOperate.Length}) were not decrypted.", "Decryption", MessageBoxButton.OK, MessageBoxImage.Error);
            DFileCountLabel.Content = $"";
            DProgressBar.Value = 0;

            // disable ui elements
            EncryptTab.IsEnabled = true;
            DecryptTab.IsEnabled = true;
            DBrowseButton.IsEnabled = true;
            DFilePath.IsEnabled = true;
            DPassword.IsEnabled = true;
            DDecryptButton.IsEnabled = true;
        }

        private void EPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) EEncryptButton_Click(null, null);
        }

        private void EPasswordConfirm_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) EEncryptButton_Click(null, null);
        }

        private void DPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) DDecryptButton_Click(null, null);
        }
    }
}
