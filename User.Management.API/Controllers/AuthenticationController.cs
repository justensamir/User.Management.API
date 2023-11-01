using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
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
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration configuration;
        private readonly IEmailService emailService;

        public AuthenticationController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
            this.emailService = emailService;
        }

        

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterUser registerUser, string role)
        {
            // Check user Exist by Email
            var userByEmailExist = await userManager.FindByEmailAsync(registerUser.Email);
            if (userByEmailExist != null)
            {
                return StatusCode(
                       StatusCodes.Status403Forbidden,
                       "This Email already exists!");
            }
            // Check user Exist by Username
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

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            var user = await userManager.FindByNameAsync(loginModel.Username);
            if(user != null && await userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                if (!user.EmailConfirmed) return StatusCode(StatusCodes.Status403Forbidden, "Email not Confirmed");

                if(user.TwoFactorEnabled)
                {
                    await signInManager.SignOutAsync();
                    await signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

                    var otp = await userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    Message message = new (new string[] { user.Email }, "OTP Confirmation",otp);
                    await emailService.SendMessage(message);
                    return StatusCode(
                        StatusCodes.Status200OK,
                        new { Status = "Success", Message = $"OTP Sent to {user.Email} Successfully" });
                }
                // Add token
                var userRoles = await userManager.GetRolesAsync(user);

                // Create Claims
                var claimsForToken = new List<Claim>
                {
                    new Claim("sub", user.Id.ToString()),
                    new Claim("email", user.Email),
                    new Claim("username", user.UserName)
                };
                foreach (var role in userRoles)
                {
                    claimsForToken.Add(new Claim("role", role));
                }


                var token = GenerateJWT(claimsForToken);

                return Ok(new { 
                    token = new JwtSecurityTokenHandler().WriteToken(token).ToString(),
                    expiration = token.ValidTo 
                });
            }
            return Unauthorized("Invalid username or password!!");
        }

        [HttpPost("Login-2FAC")]
        public async Task<IActionResult> Login2FAC(string username, string otp)
        {
            var user = await userManager.FindByNameAsync(username);
            if(user != null && otp != null)
            {
                var result = await signInManager.TwoFactorSignInAsync("Email", otp, false, true);
                if(result.Succeeded)
                {
                    var userRoles = await userManager.GetRolesAsync(user);
                    // Create Claims
                    var claimsForToken = new List<Claim>
                    {
                        new Claim("sub", user.Id.ToString()),
                        new Claim("email", user.Email),
                        new Claim("username", user.UserName)
                    };
                    foreach (var role in userRoles)
                    {
                        claimsForToken.Add(new Claim("role", role));
                    }


                    var token = GenerateJWT(claimsForToken);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token).ToString(),
                        expiration = token.ValidTo
                    });
                }
            }
            return NotFound("Invalid Username or OTP");
        }

        private JwtSecurityToken GenerateJWT(List<Claim> claims)
        {
            var key = configuration["Authentication:SecretForKey"];
            // Step 2: Create Token
            var securityKey = new SymmetricSecurityKey(
                Encoding.ASCII.GetBytes(key)
                );
            // Step 2.1: Create 
            var signinCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            
            // Step 2.4 create token
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: configuration["Authentication:Issuer"],
                audience: configuration["Authentication:Audience"],
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(20),
                signingCredentials: signinCredentials
                );

            return jwtSecurityToken;
        }
    }
}
