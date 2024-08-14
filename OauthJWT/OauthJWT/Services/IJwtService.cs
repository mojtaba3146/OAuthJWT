using OauthJWT.Models;

namespace OauthJWT.Services
{
    public interface IJwtService
    {
        Task<string> GetTokenAsync(AuthRequest request);
    }
}
