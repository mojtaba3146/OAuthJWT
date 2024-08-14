using Microsoft.AspNetCore.Mvc;
using OauthJWT.Models;
using OauthJWT.Services;

namespace OauthJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public AccountController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpPost("[action]")]
        public async Task<IActionResult> AuthToken([FromBody]AuthRequest authRequest)
        {
            var token = await _jwtService.GetTokenAsync(authRequest);
            if (token == null) 
                return Unauthorized();
            return Ok(new AuthRespond { Token = token});
        }
    }
}
