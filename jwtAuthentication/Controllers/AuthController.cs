using jwtAuthentication.Models;
using jwtAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
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
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMyName()
        {
            return Ok(_userService.GetMyName());

            //var userName = User?.Identity?.Name;
            //var roleClaims = User?.FindAll(ClaimTypes.Role);
            //var roles = roleClaims?.Select(c => c.Value).ToList();
            //var roles2 = User?.Claims
            //    .Where(c => c.Type == ClaimTypes.Role)
            //    .Select(c => c.Value)
            //    .ToList();
            //return Ok(new { userName, roles, roles2 });
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
            {
                new Claim(ClaimTypes.Name, users.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User")
            };

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
