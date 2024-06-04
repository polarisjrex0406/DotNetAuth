using Microsoft.AspNetCore.Identity;

namespace DotNetAuth.Helpers
{
    // Custom email sender that displays OTP on console
    public class ConsoleOtpEmailSender : IEmailSender<IdentityUser>
    {
        public Task SendConfirmationLinkAsync(IdentityUser user, string email, string confirmationLink)
        {
            Console.WriteLine($"Confirmation link for user {user.Id}: {confirmationLink}");
            return Task.CompletedTask;
        }

        public Task SendPasswordResetLinkAsync(IdentityUser user, string email, string passwordResetLink)
        {
            Console.WriteLine($"Password reset link for user {user.Id}: {passwordResetLink}");
            return Task.CompletedTask;
        }

        public Task SendPasswordResetCodeAsync(IdentityUser user, string email, string passwordResetCode)
        {
            Console.WriteLine($"Password reset code for user {user.Id}: {passwordResetCode}");
            return Task.CompletedTask;
        }
    }
}
