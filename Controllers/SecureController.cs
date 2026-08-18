using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authn_Authz.Controllers
{
    /// <summary>
    /// Demonstrates authorization (AuthZ): controlling what an authenticated
    /// user is allowed to do using [Authorize], roles, and policies.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class SecureController : ControllerBase
    {
        // No [Authorize] -> anyone can call this, even anonymous users.
        [HttpGet("public")]
        public IActionResult PublicEndpoint()
        {
            return Ok(new { message = "This is public. No token required." });
        }

        // [Authorize] -> any authenticated user with a valid token.
        [Authorize]
        [HttpGet("profile")]
        public IActionResult Profile()
        {
            var username = User.Identity?.Name;
            var role = User.FindFirstValue(ClaimTypes.Role);
            var department = User.FindFirstValue("department");

            return Ok(new
            {
                message = "You are authenticated.",
                username,
                role,
                department
            });
        }

        // Role-based authorization: only users in the "Admin" role.
        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new { message = "Welcome, admin! You have Admin role access." });
        }

        // Policy-based authorization: uses the "AdminOnly" policy from Program.cs.
        [Authorize(Policy = "AdminOnly")]
        [HttpGet("admin-policy")]
        public IActionResult AdminPolicy()
        {
            return Ok(new { message = "Access granted via the AdminOnly policy." });
        }

        // Claim-based policy: only users whose "department" claim is "HR".
        [Authorize(Policy = "HrDepartment")]
        [HttpGet("hr")]
        public IActionResult HrOnly()
        {
            return Ok(new { message = "Welcome to the HR area." });
        }
    }
}
