using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Przytulisko.Entities;
using Przytulisko.Models;
using Przytulisko.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Przytulisko.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register (UserDto request)
        {
            var user = authService.RegisterAsync(request);
            if(user==null)
            {
                return BadRequest("Username already exists");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var result = authService.LoginAsync(request);
            if (result == null)
            {
                return Unauthorized("Invalid username or password");
            }
            return Ok(result);
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokensAsync(request);
            if (result is null||result.AccessToken is null||result.RefreshToken is null)
            {
                return Unauthorized("Invalid refresh token");
            }
            return Ok(result);
        }
        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpount()
        {
            return Ok("You are authenticated!");
        }
        [Authorize(Roles ="Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpount()
        {
            return Ok("You are an Admin!");
        }
    }
}
