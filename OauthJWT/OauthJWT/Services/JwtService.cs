using Microsoft.IdentityModel.Tokens;
using OauthJWT.Context;
using OauthJWT.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OauthJWT.Services
{
    public class JwtService : IJwtService
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public JwtService(ApplicationDbContext context,
            IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<string> GetTokenAsync(AuthRequest request)
        {
            var user = _context.Users.FirstOrDefault(_ => _.UserName.Equals(request.UserName)&&
            _.Password.Equals(request.Password));

            if (user == null) 
            {
                return await Task.FromResult<string>(null);
            }

            var jwtKey = _configuration.GetValue<string>("JwtSettings:Key");
            var keyBytes = Encoding.ASCII.GetBytes(jwtKey!);

            var tokenHandler = new JwtSecurityTokenHandler();

            var descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, request.UserName)
                    //new Claim(ClaimTypes.Role, request.UserName),
                }),
                Expires = DateTime.UtcNow.AddSeconds(120),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256)
            }; 

            var token = tokenHandler.CreateToken(descriptor);

            return await Task.FromResult(tokenHandler.WriteToken(token));
        }
    }
}
