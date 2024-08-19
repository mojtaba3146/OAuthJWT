using Microsoft.IdentityModel.Tokens;
using OauthJWT.Context;
using OauthJWT.Entities;
using OauthJWT.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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

        public async Task<AuthRespond> GetTokenAsync(AuthRequest request, string ipAddress)
        {
            var user = _context.Users.FirstOrDefault(_ => _.UserName.Equals(request.UserName) &&
            _.Password.Equals(request.Password));

            if (user == null)
            {
                return await Task.FromResult<AuthRespond>(null);
            }

            string stringToken = GenerateToken(user.UserName);
            string refreshToken = GenerateRefreshToken();
            await SaveTokenDetails(ipAddress, user.UserId,
                stringToken, refreshToken);

            return new AuthRespond { Token = stringToken, RefreshToken = refreshToken, IsSuccess = true };
        }

        public async Task<AuthRespond> GetRefreshTokenAsync(string ipAddress,
            int userId, string userName)
        {
            var refreshToken = GenerateRefreshToken();
            var accessToken = GenerateToken(userName);
            await SaveTokenDetails(ipAddress, userId,
               accessToken, refreshToken);

            return new AuthRespond { Token = accessToken, RefreshToken = refreshToken, IsSuccess = true };
        }

        private string GenerateToken(string username)
        {
            var jwtKey = _configuration.GetValue<string>("JwtSettings:Key");
            var keyBytes = Encoding.ASCII.GetBytes(jwtKey!);

            var tokenHandler = new JwtSecurityTokenHandler();

            var descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, username)
                    //new Claim(ClaimTypes.Role, request.UserName),
                }),
                Expires = DateTime.UtcNow.AddSeconds(120),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(descriptor);

            var stringToken = tokenHandler.WriteToken(token);
            return stringToken;
        }

        private string GenerateRefreshToken()
        {
            var byteArray = new byte[64];
            RandomNumberGenerator.Fill(byteArray); // Fills the array with cryptographically strong random bytes
            return Convert.ToBase64String(byteArray);
        }

        private async Task SaveTokenDetails(string ipAddress, int userId,
           string stringToken, string refreshToken)
        {
            var userRefreshToken = new UserRefreshToken
            {
                CreatedDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddMinutes(5),
                IpAddress = ipAddress,
                IsInvalidated = false,
                RefreshToken = refreshToken,
                Token = stringToken,
                UserId = userId
            };

            await _context.UserRefreshTokens.AddAsync(userRefreshToken);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> IsTokenValid(string accessToken,
            string ipAddress)
        {
            var isValid = _context.UserRefreshTokens.FirstOrDefault(x => x.Token == accessToken&&
            x.IpAddress == ipAddress) != null;

            return await Task.FromResult(isValid);
        }
    }
}
