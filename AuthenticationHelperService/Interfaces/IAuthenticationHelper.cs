using AuthenticationHelperService.Models;

namespace AuthenticationHelperService.Interfaces
{
    public interface IAuthenticationHelper
    {
        /* * Return the JWT token for the user. * Based on the user's username and role. */
        Task<string> GenerateToken(UserDto user);
        /* * Create a password hash and salt for the user. */
        Task<PasswordHashDto> CreatePasswordHash(string password);
        /* * Verify the password hash and salt for the user. */
        Task<bool> VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt);
    }

}
