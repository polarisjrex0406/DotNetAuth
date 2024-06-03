using DotNetAuth.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.AspNetCore.Identity.Data;
using System.Diagnostics;

namespace DotNetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IDistributedCache _distributedCache;
        private readonly AppSettings _appSettings;

        public AccountController(
            IHttpContextAccessor httpContextAccessor,
            IDistributedCache distributedCache,
            IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
            _httpContextAccessor = httpContextAccessor;
            _distributedCache = distributedCache;
        }

        private string? CurrentUserId(string purpose)
        {
            var tokenPurpose = HttpContext.User.FindFirst("Purpose");
            if (tokenPurpose != null)
            {
                if (purpose == tokenPurpose.Value)
                {
                    string? userId = null;
                    var userInfo = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
                    if (userInfo != null)
                    {
                        userId = userInfo.Value;
                    }
                    return userId;
                }
            }
            return null;
        }

        private async Task StoreOtp(string emailOrPhone, string otpCode)
        {
            // Check if there's an existing OTP for the same email
            string existingOtpKey = $"OTP_{emailOrPhone}";
            string existingOtp = await _distributedCache.GetStringAsync(existingOtpKey);
            if (!string.IsNullOrEmpty(existingOtp))
            {
                // Delete the existing OTP
                await _distributedCache.RemoveAsync(existingOtpKey);
            }

            // Save the new OTP to the cache
            await _distributedCache.SetStringAsync(existingOtpKey, otpCode, new DistributedCacheEntryOptions
            {
                // Set the expiration time for the OTP (e.g., 5 minutes)
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
            });
        }

        private async Task<string?> LoadOtp(string emailOrPhone)
        {
            // Load the OTP from the cache
            string otpKey = $"OTP_{emailOrPhone}";
            string storedOtp = await _distributedCache.GetStringAsync(otpKey);
            // Remove the OTP from the cache
            await _distributedCache.RemoveAsync(otpKey);
            return storedOtp;
        }

        private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
    TypedResults.ValidationProblem(new Dictionary<string, string[]> {
            { errorCode, [errorDescription] }
    });

        private static ValidationProblem CreateValidationProblem(IdentityResult result)
        {
            // We expect a single error code and description in the normal case.
            // This could be golfed with GroupBy and ToDictionary, but perf! :P
            Debug.Assert(!result.Succeeded);
            var errorDictionary = new Dictionary<string, string[]>(1);

            foreach (var error in result.Errors)
            {
                string[] newDescriptions;

                if (errorDictionary.TryGetValue(error.Code, out var descriptions))
                {
                    newDescriptions = new string[descriptions.Length + 1];
                    Array.Copy(descriptions, newDescriptions, descriptions.Length);
                    newDescriptions[descriptions.Length] = error.Description;
                }
                else
                {
                    newDescriptions = [error.Description];
                }

                errorDictionary[error.Code] = newDescriptions;
            }

            return TypedResults.ValidationProblem(errorDictionary);
        }

        [HttpPost]
        [Route("register")]
        public async Task<object> Register([FromBody] RegisterDto model, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();

            var user = new IdentityUser
            {
                Email = model.Email,
                UserName = model.UserName
            };
            if (!model.PhoneNumber.IsNullOrEmpty()) user.PhoneNumber = model.PhoneNumber;

            var res = await userManager.CreateAsync(user);
            if (res.Succeeded)
            {
                if (model.Password is not null)
                {
                    var result = await userManager.AddPasswordAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        return Ok(new
                        {
                            success = true,
                            message = "Successfully registered new user"
                        });
                    }
                }
                else
                {
                    return Ok(new
                    {
                        success = true,
                        message = "Successfully registered new user"
                    });
                }
            }
            return BadRequest(new
            {
                success = false,
                message = "Failed registering new user"
            });
        }

        [HttpPost]
        [Route("checkEmail")]
        public async Task<object> CheckEmail([FromBody] string email, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var appUser = await userManager.FindByEmailAsync(email);
            if (appUser == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
            else
            {
                // Check if the user has already gone through the MFA (2FA) process
                if (await userManager.GetTwoFactorEnabledAsync(appUser) && appUser.PhoneNumberConfirmed)
                {
                    // If the user has already completed the MFA, do not allow them to submit their credentials again
                    return Unauthorized(new
                    {
                        success = false,
                        action = "MFACompleted",
                        message = "You have already completed the MFA process. Please proceed with the next step."
                    });
                }
                if (await userManager.HasPasswordAsync(appUser))
                {
                    string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "LoginWithPassword");
                    return Ok(new
                    {
                        success = true,
                        action = "TypePassword",
                        message = "Please input password.",
                        accessToken = token
                    });
                }
                else
                {
                    // Send OTP to verification email
                    string otpCode = OtpGenerator.GenerateCode();
                    Console.WriteLine($"Sent {otpCode} to {appUser.Email}");
                    await StoreOtp(appUser.Email, otpCode);
                    string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmEmail");
                    return Ok(new
                    {
                        success = true,
                        action = "ConfirmEmail",
                        message = "Please verify email.",
                        accessToken = token
                    });
                }
            }
        }

        [HttpPost]
        [Route("login")]
        [Authorize(Policy = "LoginWithPasswordPolicy")]
        public async Task<object> LoginWithPassword([FromBody] string password, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var userId = CurrentUserId("LoginWithPassword");
            if (userId == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }

            var appUser = await userManager.FindByIdAsync(userId);
            if (appUser == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
            else
            {
                // Check if the user has already gone through the MFA (2FA) process
                if (await userManager.GetTwoFactorEnabledAsync(appUser) && appUser.PhoneNumberConfirmed)
                {
                    // If the user has already completed the MFA, do not allow them to submit their credentials again
                    return Unauthorized(new
                    {
                        success = false,
                        action = "MFACompleted",
                        message = "You have already completed the MFA process. Please proceed with the next step."
                    });
                }

                var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();                
                var result = await signInManager.PasswordSignInAsync(appUser, password, false, false);
                string token;
                
                if (result.RequiresTwoFactor)
                {
                    if (userManager.GetPhoneNumberAsync(appUser) != null)
                    {
                        // Send OTP to verification email
                        string otpCode = OtpGenerator.GenerateCode();
                        Console.WriteLine($"Sent {otpCode} to {appUser.PhoneNumber}");
                        await StoreOtp(appUser.PhoneNumber, otpCode);
                        token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmSms");
                        return Ok(new
                        {
                            success = false,
                            action = "Type2faOtp",
                            message = "Input OTP for 2FA.",
                            accessToken = token
                        });
                    }
                    else
                    {
                        token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "CapturePhoneNumber");
                        return Ok(new
                        {
                            success = false,
                            action = "Type2faPhone",
                            message = "Input phone number.",
                            accessToken = token
                        });
                    }
                }

                if (!result.Succeeded)
                {
                    return Unauthorized(new
                    {
                        success = false,
                        action = "RetypePassword",
                        message = result.ToString(),
                    });
                }

                token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "AccessUserData");
                return Ok(new
                {
                    success = true,
                    action = "Done",
                    message = "Successfully login.",
                    accessToken = token
                });
            }
        }

        [HttpPost]
        [Route("forgotPassword")]
        public async Task<object> ForgotPassword([FromQuery] string email, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var appUser = await userManager.FindByEmailAsync(email);
            
            if (appUser is not null && await userManager.IsEmailConfirmedAsync(appUser))
            {
                // Send OTP to verification email
                string otpCode = OtpGenerator.GenerateCode();
                Console.WriteLine($"Sent {otpCode} to {appUser.Email}");
                await StoreOtp(appUser.Email, otpCode);
                string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmEmail");

                return Ok(new
                {
                    success = true,
                    action = "ConfirmEmail",
                    message = "Please verify email.",
                    accessToken = token
                });
            }
            else
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
        }

        [HttpGet]
        [Route("confirmEmail")]
        [Authorize(Policy = "ConfirmEmailPolicy")]
        public async Task<object> ConfirmEmail([FromQuery] string code, [FromServices] IServiceProvider sp)
        {
            var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();
            var userId = CurrentUserId("ConfirmEmail");
            if (userId == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var appUser = await userManager.FindByIdAsync(userId);
            if (appUser == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
            else
            {
                var result = await LoadOtp(appUser.Email);
                if (result == code)
                {
                    appUser.EmailConfirmed = true;
                    await userManager.UpdateAsync(appUser);
                    string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "CreatePassword");
                    return Ok(new
                    {
                        success = true,
                        action = "CreatePassword",
                        message = "Create or reset password.",
                        accessToken = token
                    });
                }
                else
                {
                    return NotFound(new
                    {
                        success = false,
                        action = "ResendCode",
                        message = "Resend code again."
                    });
                }
            }
        }

        [HttpPost]
        [Route("createPassword")]
        [Authorize(Policy = "CreatePasswordPolicy")]
        public async Task<object> CreatePassword([FromBody] string password, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var userId = CurrentUserId("CreatePassword");
            if (userId == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }

            var appUser = await userManager.FindByIdAsync(userId);
            if (appUser == null)
            {
                return NotFound(new
                {
                    success = false,
                    action = "RetypeEmail",
                    message = "Email is not recognised. Please try again."
                });
            }
            else
            {
                if (await userManager.HasPasswordAsync(appUser))
                {
                    await userManager.RemovePasswordAsync(appUser);
                }
                var resultAddPswd = await userManager.AddPasswordAsync(appUser, password);
                if (resultAddPswd.Succeeded)
                {
                    var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();
                    var resultSignIn = await signInManager.PasswordSignInAsync(appUser, password, false, false);
                    string token;
                    if (resultSignIn.RequiresTwoFactor)
                    {
                        if (userManager.GetPhoneNumberAsync(appUser) != null)
                        {
                            // Send OTP to verification email
                            string otpCode = OtpGenerator.GenerateCode();
                            Console.WriteLine($"Sent {otpCode} to {appUser.PhoneNumber}");
                            await StoreOtp(appUser.PhoneNumber, otpCode);
                            token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmSms");
                            return Ok(new
                            {
                                success = false,
                                action = "Type2faOtp",
                                message = "Input OTP for 2FA.",
                                accessToken = token
                            });
                        }
                        else
                        {
                            token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "CapturePhoneNumber");
                            return Ok(new
                            {
                                success = false,
                                action = "Type2faPhone",
                                message = "Input phone number.",
                                accessToken = token
                            });
                        }
                    }

                    if (!resultSignIn.Succeeded)
                    {
                        return Unauthorized(new
                        {
                            success = false,
                            action = "RetypePassword",
                            message = resultSignIn.ToString(),
                        });
                    }
                    token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "AccessUserData");
                    return Ok(new
                    {
                        success = true,
                        action = "Done",
                        message = "Successfully login.",
                        accessToken = token
                    });
                }
                return Unauthorized(new
                {
                    success = false,
                    action = "RetypePassword",
                    message = "Error while creating password",
                });
            }
        }

        [HttpPost]
        [Route("capturePhoneNumber")]
        [Authorize(Policy = "CapturePhoneNumberPolicy")]
        public async Task<object> CapturePhoneNumber([FromBody] string phoneNumber, [FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var userId = CurrentUserId("CapturePhoneNumber");
            if (userId != null)
            {
                var appUser = await userManager.FindByIdAsync(userId);
                if (appUser != null)
                {
                    var result = await userManager.SetPhoneNumberAsync(appUser, phoneNumber);
                    if (result.Succeeded)
                    {
                        // Send OTP to verification email
                        string otpCode = OtpGenerator.GenerateCode();
                        Console.WriteLine($"Sent {otpCode} to {appUser.PhoneNumber}");
                        await StoreOtp(appUser.PhoneNumber, otpCode);
                        string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmSms");
                        return Ok(new
                        {
                            success = false,
                            action = "Type2faOtp",
                            message = "Input OTP for 2FA.",
                            accessToken = token
                        });
                    }
                }
            }
            return NotFound(new
            {
                success = false,
                action = "RetypeEmail",
                message = "Email is not recognised. Please try again."
            });
        }

        [HttpPost]
        [Route("resendSms")]
        [Authorize(Policy = "ConfirmSmsPolicy")]
        public async Task<object> resendSms([FromServices] IServiceProvider sp)
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var userId = CurrentUserId("ConfirmSms");
            if (userId != null)
            {
                var appUser = await userManager.FindByIdAsync(userId);
                if (appUser != null)
                {
                    // Send OTP to verification email
                    string otpCode = OtpGenerator.GenerateCode();
                    Console.WriteLine($"Sent {otpCode} to {appUser.PhoneNumber}");
                    await StoreOtp(appUser.PhoneNumber, otpCode);
                    string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "ConfirmSms");
                    return Ok(new
                    {
                        success = false,
                        action = "Type2faOtp",
                        message = "Input OTP for 2FA.",
                        accessToken = token
                    });
                }
            }
            return NotFound(new
            {
                success = false,
                action = "RetypeEmail",
                message = "Email is not recognised. Please try again."
            });
        }

        [HttpGet]
        [Route("confirmSms")]
        [Authorize(Policy = "ConfirmSmsPolicy")]
        public async Task<object> ConfirmSms([FromQuery] string code, [FromServices] IServiceProvider sp)
        {
            var userId = CurrentUserId("ConfirmSms");
            if (userId != null)
            {
                var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
                var appUser = await userManager.FindByIdAsync(userId);
                if (appUser != null)
                {
                    var result = await LoadOtp(appUser.PhoneNumber);
                    if (result == code)
                    {
                        appUser.PhoneNumberConfirmed = true;
                        await userManager.UpdateAsync(appUser);
                        var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();
                        var enable2fa = await userManager.GetTwoFactorEnabledAsync(appUser);
                        if (!enable2fa)
                        {
                            var resultEnable2fa = await userManager.SetTwoFactorEnabledAsync(appUser, false);
                            enable2fa = resultEnable2fa.Succeeded;
                        }
                        if (enable2fa)
                        {
                            var resultSignIn = await signInManager.TwoFactorAuthenticatorSignInAsync(result, false, false);
                            string token = JWTHelper.GenerateJsonWebToken(appUser, _appSettings, "AccessUserData");
                            return Ok(new
                            {
                                success = true,
                                action = "Done",
                                message = "Successfully login.",
                                accessToken = token
                            });
                        }
                    }
                }
            }
            return NotFound(new
            {
                success = false,
                action = "ResendCode",
                message = "Resend code again."
            });
        }

        [HttpPost]
        [Route("enable2fa")]
        [Authorize(Policy = "AccessUserDataPolicy")]
        public async Task<object> Enable2fa([FromBody] TwoFactorRequest tfaRequest, [FromServices] IServiceProvider sp)
        {
            var userId = CurrentUserId("AccessUserData");
            var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            if (userId is null)
            {
                return BadRequest();
            }
            if (await userManager.FindByIdAsync(userId) is not { } user)
            {
                return NotFound();
            }

            if (tfaRequest.Enable == true)
            {
                if (tfaRequest.ResetSharedKey)
                {
                    return CreateValidationProblem("CannotResetSharedKeyAndEnable",
                        "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
                }
                else if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
                {
                    return CreateValidationProblem("RequiresTwoFactor",
                        "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
                }
/*                else if (!await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
                {
                    return CreateValidationProblem("InvalidTwoFactorCode",
                        "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
                }*/

                await userManager.SetTwoFactorEnabledAsync(user, true);
            }
            else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
            {
                await userManager.SetTwoFactorEnabledAsync(user, false);
            }

            if (tfaRequest.ResetSharedKey)
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
            }

            string[]? recoveryCodes = null;
            if (tfaRequest.ResetRecoveryCodes || (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
            {
                var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                recoveryCodes = recoveryCodesEnumerable?.ToArray();
            }

            if (tfaRequest.ForgetMachine)
            {
                await signInManager.ForgetTwoFactorClientAsync();
            }

            var key = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                key = await userManager.GetAuthenticatorKeyAsync(user);

                if (string.IsNullOrEmpty(key))
                {
                    throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
                }
            }

            return Ok(new TwoFactorResponse
            {
                SharedKey = key,
                RecoveryCodes = recoveryCodes,
                RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
                IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
                IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user),
            });
        }

        public class RegisterDto
        {
            [Required]
            public string Email { get; init; } = string.Empty;
            public string? Password { get; init; }
            [Required]
            public string? UserName { get; init; }
            public string? PhoneNumber { get; init; }
        }

        public class LoginDto
        {
            public string Email { get; init; }
            public string Password { get; init; }
        }
    }
}
