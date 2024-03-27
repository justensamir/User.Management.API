using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using User.Management.API.Models.Token;

namespace User.Management.API.Models.Data
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50)]
        public string FristName { get; set; }
        
        [MaxLength(50)]
        public string LastName { get; set; }

        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
