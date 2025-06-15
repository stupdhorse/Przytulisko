using Microsoft.EntityFrameworkCore;
using Przytulisko.Entities;

namespace Przytulisko.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
