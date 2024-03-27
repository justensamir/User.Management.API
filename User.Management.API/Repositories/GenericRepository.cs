using Microsoft.EntityFrameworkCore;
using User.Management.API.Models.Data;
using User.Management.API.Repositories.Services;

namespace User.Management.API.Repositories
{
    public class GenericRepository<T> : IGenericRepository<T>  where T : class
    {
        protected ApplicationDbContext context;
        public GenericRepository(ApplicationDbContext context)
        {
            this.context = context;
        }

        public async Task Add(T entity)
        {
            await context.Set<T>().AddAsync(entity);
            await context.SaveChangesAsync();
        }

        public async Task Delete(T entity)
        {
            context.Set<T>().Remove(entity);
            await context.SaveChangesAsync();
        }

        public async Task<T?> Get(int id)
        {
            return await context.Set<T>().FindAsync(id);
        }

        public async Task<IEnumerable<T>> GetAll()
        {
            return await context.Set<T>().AsNoTracking().ToListAsync();
        }

        public async Task Update(T entity)
        {
            context.Set<T>().Update(entity);
            await context.SaveChangesAsync();
        }
    }
}
