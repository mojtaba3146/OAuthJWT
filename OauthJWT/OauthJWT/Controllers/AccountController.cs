using Microsoft.AspNetCore.Mvc;
using OauthJWT.Context;
using OauthJWT.Entities;
using OauthJWT.Models;
using OauthJWT.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OauthJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IJwtService _jwtService;
        private readonly ApplicationDbContext _context;

        public AccountController(IJwtService jwtService,
            ApplicationDbContext context)
        {
            _jwtService = jwtService;
            _context = context;
        }

        [HttpPost("[action]")]
        public async Task<IActionResult> AuthToken([FromBody] AuthRequest authRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthRespond { IsSuccess = false, Reason = "USERNAME AND PASS Problem" });
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress!.ToString();
            var authResponse = await _jwtService.GetTokenAsync(authRequest, ipAddress);
            if (authResponse == null)
                return Unauthorized();
            return Ok(authResponse);
        }

        [HttpPost("[action]")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthRespond { IsSuccess = false, Reason = "Token Must Be Provided" });
            }
            var ipAddress = HttpContext.Connection.RemoteIpAddress!.ToString();
            var expiredToken = GetJwtToken(refreshTokenRequest.ExpiredToken);
            var refreshToken = _context.UserRefreshTokens.FirstOrDefault(x => x.IsInvalidated == false &&
            x.Token == refreshTokenRequest.ExpiredToken &&
            x.RefreshToken == refreshTokenRequest.RefreshToken &&
            x.IpAddress == ipAddress);

            AuthRespond respond = ValidateDetails(expiredToken, refreshToken);
            if(!respond.IsSuccess)
                return BadRequest(respond);

            refreshToken!.IsInvalidated = true;
            _context.UserRefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            var userName = expiredToken.Claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)!.Value;
            var authResponse = await _jwtService
                .GetRefreshTokenAsync(ipAddress, refreshToken.UserId, userName);

            return Ok(authResponse);

        }

        private AuthRespond ValidateDetails(JwtSecurityToken expiredToken,
            UserRefreshToken? refreshToken)
        {
            if (refreshToken == null)
                return new AuthRespond { IsSuccess = false, Reason = "Invali Dteails" };
            if (expiredToken.ValidTo > DateTime.UtcNow)
                return new AuthRespond { IsSuccess = false, Reason = "Token Is Valid" };
            if (!refreshToken.IsActive)
                return new AuthRespond { IsSuccess = false, Reason = "Refresh Token Expired" };
            return new AuthRespond { IsSuccess = true };
        }

        private JwtSecurityToken GetJwtToken(string expiredToken)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            return handler.ReadJwtToken(expiredToken);
        }
    }
}
