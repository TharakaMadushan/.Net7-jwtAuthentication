using jwtAuthentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static Users users = new Users();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult<Users> Register (UserDTO request)
        {
            string PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            users.Username = request.Username;
            users.PasswordHash = PasswordHash;

            return Ok(users);
        }

        [HttpPost("login")]
        public ActionResult<Users> Login (UserDTO request)
        {
            if (users.Username != request.Username)
            {
                return BadRequest("User Not Found!");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, users.PasswordHash))
            {
                return BadRequest("Password Invalid!");
            }

            string token = CreateToken(users);

            return Ok(token);
        }

        private string CreateToken(Users users)
        {
            List<Claim> claims = new List<Claim>
            {new Claim(ClaimTypes.Name, users.Username)};

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;

        }
    }
}
