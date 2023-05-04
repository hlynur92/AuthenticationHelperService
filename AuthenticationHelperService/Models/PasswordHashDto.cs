namespace AuthenticationHelperService.Models
{
    public class PasswordHashDto
    {
        public byte[] passwordHash { get; set; }
        public byte[] passwordSalt { get; set; }
    }

}
