using EndpointSecurity.Application.Devices;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/devices")]
public sealed class DevicesController(
    IDeviceService deviceService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<DeviceResponse>>> GetAll(
        CancellationToken cancellationToken)
    {
        var devices = await deviceService.GetAllAsync(
            cancellationToken);

        return Ok(devices);
    }

    [HttpPost("register")]
    public async Task<ActionResult<DeviceResponse>> Register(
        RegisterDeviceRequest request,
        CancellationToken cancellationToken)
    {
        var device = await deviceService.RegisterAsync(
            request,
            cancellationToken);

        return StatusCode(
            StatusCodes.Status201Created,
            device);
    }
}
