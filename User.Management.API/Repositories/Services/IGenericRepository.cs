using User.Management.API.Models.Data;

namespace User.Management.API.Repositories.Services
{
    public interface IGenericRepository<T> where T : class
    {
        Task<IEnumerable<T>> GetAll();
        Task<T?> Get(int id);
        Task Add(T entity);
        Task Update(T entity);
        Task Delete(T entity);
    }
}
