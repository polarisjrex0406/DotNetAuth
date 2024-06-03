namespace DotNetAuth.Helpers
{
    public class AppSettings
    {
        public string SecretKey { get; set; } = string.Empty;
        public int IntExpireHour { get; set; } = 0;
    }
}
