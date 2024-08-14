using Microsoft.EntityFrameworkCore;
using OauthJWT.Entities;

namespace OauthJWT.Context
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options)
            :base(options) 
        {
            
        }

        public DbSet<User> Users { get; set; }
    }
}
