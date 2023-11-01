using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]

    public class AdminController : ControllerBase
    {
        [HttpGet("employees")]
        public IActionResult Employees()
        {
            return Ok(new List<string>
            {
                "Mohamed",
                "Samir",
                "Alaa"
            });
        }   
    }
}
