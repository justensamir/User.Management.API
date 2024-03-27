using System.Runtime.CompilerServices;
using User.Management.API.Models.Data;
using User.Management.API.Repositories.Services;

namespace User.Management.API.Repositories
{
    public class UserRepository : GenericRepository<ApplicationUser>, IUserRepository
    {
        public UserRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<ApplicationUser?> Get(string id)
        {
            return await context.Users.FindAsync(id);
        }
    }
}
