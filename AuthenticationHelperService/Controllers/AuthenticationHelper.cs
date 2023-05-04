using AuthenticationHelperService.Interfaces;
using AuthenticationHelperService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationHelperService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationHelper : ControllerBase, IAuthenticationHelper
    {
        private readonly byte[] _key;

        public AuthenticationHelper(string key)
        {
            _key = Convert.FromBase64String(key);
        }

        [HttpPost]
        [Route("generate-token")]
        public string GenerateToken(UserDto user)
        {
            // Create token
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.username),
                new Claim(ClaimTypes.Role, user.role)
            };

            var key = new SymmetricSecurityKey(_key);
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: "yourdomain.com",
                audience: "yourdomain.com",
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost]
        [Route("create-password-hash")]
        public PasswordHashDto CreatePasswordHash(string password)
        {
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(20);

            return new PasswordHashDto { passwordHash = hash, passwordSalt = salt };
        }


        [HttpPost]
        [Route("verify-password-hash")]
        public bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, storedSalt, 10000, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(20);

            for (int i = 0; i < 20; i++)
            {
                if (storedHash[i] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
