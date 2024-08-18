using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OauthJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class NamesController : ControllerBase
    {
        [HttpGet("[action]")]
        [Authorize]
        public async Task<IActionResult> GetNames()
        {
            var names = await 
                Task.FromResult(new List<string>() { "Adam","Goli"});
            return Ok(names);
        }
    }
}
