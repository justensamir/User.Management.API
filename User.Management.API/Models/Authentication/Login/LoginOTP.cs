using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.Login
{
    public class LoginOTP
    {
        [Required]
        public string Username { get; set; } = null!;
        [Required]
        public string OTP { get; set; } = null!;
    }
}
