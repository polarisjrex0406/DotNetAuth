using System.Security.Cryptography;

namespace DotNetAuth.Helpers
{
    public static class OtpGenerator
    {
        private static readonly int _otpLength = 6;
        private static readonly int _maxOtpValue = (int)Math.Pow(10, _otpLength);

        public static string GenerateCode()
        {
            byte[] buffer = new byte[4];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
                int randomNumber = BitConverter.ToInt32(buffer, 0) % _maxOtpValue;
                randomNumber = randomNumber < 0 ? randomNumber * -1 : randomNumber;
                return randomNumber.ToString().PadLeft(_otpLength, '0');
            }
        }

        public static bool VerifyCode(string providedOtp, string expectedOtp)
        {
            return string.Equals(providedOtp, expectedOtp, StringComparison.Ordinal);
        }
    }
}
