namespace jwtAuthentication.Models
{
    public class Users
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
    }
}
