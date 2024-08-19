using OauthJWT.Models;

namespace OauthJWT.Services
{
    public interface IJwtService
    {
        Task<AuthRespond> GetTokenAsync(AuthRequest request, string ipAddress);
        Task<AuthRespond> GetRefreshTokenAsync(string ipAddress, int userId, string userName);
        Task<bool> IsTokenValid(string accessToken, string ipAddress);
    }
}
