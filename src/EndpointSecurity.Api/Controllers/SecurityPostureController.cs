using EndpointSecurity.Application.SecurityPosture;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/security-posture")]
public sealed class SecurityPostureController(
    ISecurityPostureService securityPostureService)
    : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<SecurityPostureResponse>> Submit(
        SubmitSecurityPostureRequest request,
        CancellationToken cancellationToken)
    {
        var result = await securityPostureService.SubmitAsync(
            request,
            cancellationToken);

        return StatusCode(
            StatusCodes.Status201Created,
            result);
    }

    [HttpGet("{deviceId:guid}/latest")]
    public async Task<ActionResult<SecurityPostureResponse>> GetLatest(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var result = await securityPostureService.GetLatestAsync(
            deviceId,
            cancellationToken);

        return result is null
            ? NotFound()
            : Ok(result);
    }
}
