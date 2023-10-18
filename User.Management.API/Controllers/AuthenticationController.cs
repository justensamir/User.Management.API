using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.SignUp;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }

        /// <summary>
        /// Register Users Info
        /// </summary>
        /// <param name="registerUser"> User Data</param>
        /// <param name="role">User Role</param>
        /// <returns></returns>

        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Register(RegisterUser registerUser, string role)
        {
            // Check user Exist
            var UserExist = await userManager.FindByEmailAsync(registerUser.Email);
            
            if (UserExist != null) return Forbid("User already exists!");
            
            if(!await roleManager.RoleExistsAsync(role)) return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Role does not Exist." });


            // Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
            };


            var result = await userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                // Add role to user
                await userManager.AddToRoleAsync(user, role);
                
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User Created Successfully" });
            }
            
                
                return  StatusCode(StatusCodes.Status500InternalServerError,
                    new Response{Status = "Error", Message="User Failed to Ceare"});

        }
    }
}
