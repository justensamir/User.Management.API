using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata.Ecma335;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly IEmailService emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailService emailService)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            this.emailService = emailService;
        }

        

        [HttpPost("Register")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Register(RegisterUser registerUser, string role)
        {
            // Check user Exist
            var userByEmailExist = await userManager.FindByEmailAsync(registerUser.Email);
            if (userByEmailExist != null)
            {
                return StatusCode(
                       StatusCodes.Status403Forbidden,
                       "This Email already exists!");
            }

            var userByNameExist = await userManager.FindByNameAsync(registerUser.UserName);
            if (userByNameExist != null)
            {
                return StatusCode(
                       StatusCodes.Status403Forbidden,
                       "This Username already exists!");
            }

            if (!await roleManager.RoleExistsAsync(role))
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Role does not Exist." });
            }


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
                await userManager.AddToRoleAsync(user, role);
            
                await CreateConfirmationEmailAsync(user);

                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = $"User Created & Email Sent to {user.Email} Successfully" });
            }
            
                
            return  StatusCode(StatusCodes.Status500InternalServerError,
                    new Response{Status = "Error", Message="User Failed to Create"});

        }

        [HttpGet("SendMail")]
        public async Task<IActionResult> TestEmail()
        {
            var message = new Message(new string[] { "smyr4916@gmail.com", 
                                                     "moo.samir2000@gmail.com"}, 
                                                     "Test Email Service", 
                                                     "<h1>Hello Every One <span style=\"color: red;\">❤❤<span></h1>");
            
            await emailService.SendMessage(message);
            return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email Sent Successfully" });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var result = await userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return Ok("Email Confirmed Successfully");
                }
            }
            return BadRequest("Invalid Email Or Token");
        }

        private async Task CreateConfirmationEmailAsync(IdentityUser user)
        {
            // Add Token
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
            var message = new Message(new string[] { user.Email! }, "Confiramtion Email", confirmationLink!);
            await emailService.SendMessage(message);
        }
    }
}
