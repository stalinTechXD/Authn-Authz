using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authn_Authz.Controllers
{
    /// <summary>
    /// Demonstrates authentication (AuthN): verifying who a user is and
    /// issuing a signed JWT that later requests use to prove their identity.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        // In-memory demo user store. NEVER store plain-text passwords in a real app.
        private static readonly List<DemoUser> Users =
        [
            new("admin", "admin123", "Admin", "IT"),
            new("hruser", "hr123", "User", "HR"),
            new("john", "john123", "User", "Sales")
        ];

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Validates credentials and returns a signed JWT on success.
        /// </summary>
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var user = Users.FirstOrDefault(u =>
                u.Username == request.Username && u.Password == request.Password);

            if (user is null)
            {
                // 401: authentication failed.
                return Unauthorized(new { message = "Invalid username or password." });
            }

            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        /// <summary>
        /// Decodes a JWT WITHOUT contacting any server-side session store.
        /// This shows the "stateless" nature of JWT: everything the server needs
        /// is carried inside the token itself and protected by the signature.
        /// </summary>
        [HttpGet("decode")]
        public IActionResult Decode()
        {
            // Reads the "Authorization: Bearer <token>" header.
            var authHeader = Request.Headers.Authorization.ToString();
            if (string.IsNullOrWhiteSpace(authHeader) ||
                !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new { message = "Provide a token via 'Authorization: Bearer <token>'." });
            }

            var rawToken = authHeader["Bearer ".Length..].Trim();

            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(rawToken))
            {
                return BadRequest(new { message = "The provided value is not a valid JWT." });
            }

            var jwt = handler.ReadJwtToken(rawToken);

            return Ok(new
            {
                header = jwt.Header,                                   // alg / typ
                payload = jwt.Claims.ToDictionary(c => c.Type, c => c.Value), // claims
                issuedAt = jwt.ValidFrom,
                expiresAt = jwt.ValidTo,
                note = "The server did NOT look up any session. It only reads/verifies the token."
            });
        }

        private string GenerateJwtToken(DemoUser user)
        {
            var jwtSection = _configuration.GetSection("Jwt");

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Username),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Role, user.Role),
                new("department", user.Department),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSection["Key"]!));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiryMinutes = int.Parse(jwtSection["ExpiryMinutes"] ?? "60");

            var token = new JwtSecurityToken(
                issuer: jwtSection["Issuer"],
                audience: jwtSection["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private record DemoUser(string Username, string Password, string Role, string Department);
    }

    public record LoginRequest(string Username, string Password);
}
