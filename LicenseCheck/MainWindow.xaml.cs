using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using License;
using Newtonsoft.Json;

namespace LicenseCheck
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            txtMachineCode.Text = GetMachineCode();
            txtExpiryDate.Text = GetExpiryDate();
        }

        private string GetMachineCode()
        {
            return Status.GetHardwareID(true, true, false, true);
        }

        private string GetExpiryDate()
        {
            if (!Status.Licensed)
            {
                return "未激活";
            }

            if (Status.Evaluation_Lock_Enabled)
            {
                return "试用版本，第二天凌晨0点失效";
            }

            if (Status.Expiration_Date_Lock_Enable)
            {
                return Status.Expiration_Date.ToString("yyyy-MM-dd HH:mm:ss");
            }

            return "未激活";
        }

        private string GetExpiryDateByReq()
        {
            var (result, licenseInfo) = auth();
            if (result != 0 || licenseInfo == null)
            {
                return "未激活";
            }

            return licenseInfo.PaidUpTo.ToString("yyyy-MM-dd HH:mm:ss");
        }

        private class LicenseInfo
        {
            public string LicenseeName { get; set; }
            public string HardwareID { get; set; }
            public DateTime PaidUpTo { get; set; }
        }

        private static (int, LicenseInfo) auth()
        {
            try
            {
                string dataString = "";
                var hardwareId = Status.GetHardwareID(true, true, false, true);
                WebClient wc = new WebClient();
                using (StreamReader reader = new StreamReader(wc.OpenRead(
                                                                  "https://gitee.com/hearthstone-hearthbuddy/Hearthbuddy-account/raw/main/accounts/" +
                                                                  hardwareId) ??
                                                              throw new InvalidOperationException()))
                {
                    dataString = reader.ReadToEnd();
                }

                var licenseParts = dataString.Split('-');
                if (licenseParts.Length < 2)
                    return (-1, null);
                var licensePart = Encoding.UTF8.GetString(Convert.FromBase64String(licenseParts[0]));
                var deserializeObject = JsonConvert.DeserializeObject<LicenseInfo>(licensePart);
                if (deserializeObject == null || string.IsNullOrEmpty(deserializeObject.HardwareID) ||
                    !string.Equals(deserializeObject.HardwareID, hardwareId) ||
                    deserializeObject.PaidUpTo < DateTime.Now)
                {
                    return (-1, null);
                }

                if (RsaSignCheck(licenseParts[0], licenseParts[1]))
                {
                    return (0, deserializeObject);
                }

                return (1, null);
            }
            catch (Exception)
            {
                return (-1, null);
            }
        }

        /// <summary>
        /// 签名验证
        /// </summary>
        /// <param name="str">待验证的字符串</param>
        /// <param name="sign">加签之后的字符串</param>
        /// <returns>签名是否符合</returns>
        private static bool RsaSignCheck(string str, string sign)
        {
            try
            {
                string xmlPublicKey = "RSA_HOLDER";
                byte[] data = Convert.FromBase64String(str);
                byte[] signature = Convert.FromBase64String(sign);

                // 导入公钥
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(xmlPublicKey);
                    return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch
            {
                return false;
            }
        }
    }
}