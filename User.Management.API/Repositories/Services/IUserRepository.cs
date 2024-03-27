using User.Management.API.Models.Data;

namespace User.Management.API.Repositories.Services
{
    public interface IUserRepository : IGenericRepository<ApplicationUser>
    {
        Task<ApplicationUser?> Get(string id);
    }
}
