using AuthenticationHelperService.Models;

namespace AuthenticationHelperService.Interfaces
{
    public interface IAuthenticationHelper
    {
        /* * Return the JWT token for the user. * Based on the user's username and role. */
        string GenerateToken(UserDto user);
        /* * Create a password hash and salt for the user. */
        PasswordHashDto CreatePasswordHash(string password);
        /* * Verify the password hash and salt for the user. */
        bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt);
    }

}
