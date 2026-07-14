using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class HealthController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new
        {
            service = "EndpointSecurity.Api",
            status = "Healthy",
            version = "1.0.0",
            utcTime = DateTime.UtcNow
        });
    }
}
