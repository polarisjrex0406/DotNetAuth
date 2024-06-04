using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DotNetAuth.Helpers
{
    public class JWTHelper
    {
        /*
         * Helper method, for generating Json Web Token
         * 
         * install Nuget System.IdentityModel.Tokens.Jwt
         */
        public static string GenerateJsonWebToken(IdentityUser user, AppSettings settings, string purpose)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(settings.SecretKey);
            var date = DateTime.Now;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // makes the properties of the user to be the claim identity, parding user into the token
                Subject = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim("Purpose", purpose)
                }),

                // Set the token expiry to a day - This value is only to show
                Expires = DateTime.Now.AddHours(1),
                NotBefore = date,

                // setting the signing credentials
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };

            // create the token
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public static string? DecodeJsonWebTokenToUser(string jsonWebToken, string SecretKey, string purpose)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(SecretKey);
                tokenHandler.ValidateToken(jsonWebToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,

                    // set clockskew to zero so token expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;

                // Logging Purpose
                Console.WriteLine("Cookie was issued at " + jwtToken.IssuedAt);
                Console.WriteLine("Cookie was valid to " + jwtToken.ValidTo);

                string tokenPurpose = jwtToken.Claims.First(x => x.Type == "purpose").Value;
                if (tokenPurpose.Equals(purpose))
                {
                    string id = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
                    // Return the decoded user from the token
                    return id;
                }
                else return null;
            }
            catch
            {
                return null;
            }
        }
    }

    public class JwtPurposeRequirement : IAuthorizationRequirement
    {
        public string RequiredPurpose { get; }

        public JwtPurposeRequirement(string requiredPurpose)
        {
            RequiredPurpose = requiredPurpose;
        }
    }

    public class JwtPurposeAuthorizationHandler : AuthorizationHandler<JwtPurposeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtPurposeRequirement requirement)
        {
            var purposeClaim = context.User.FindFirst("Purpose");
            if (purposeClaim != null && purposeClaim.Value == requirement.RequiredPurpose)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }

            return Task.CompletedTask;
        }
    }

}
