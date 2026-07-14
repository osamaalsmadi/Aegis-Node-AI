using EndpointSecurity.Application.Telemetry;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/telemetry")]
public sealed class TelemetryController(
    IEndpointTelemetryService telemetryService)
    : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<EndpointTelemetryResponse>> Submit(
        SubmitEndpointTelemetryRequest request,
        CancellationToken cancellationToken)
    {
        var result = await telemetryService.SubmitAsync(
            request,
            cancellationToken);

        return StatusCode(
            StatusCodes.Status201Created,
            result);
    }

    [HttpGet("{deviceId:guid}/latest")]
    public async Task<ActionResult<EndpointTelemetryResponse>> GetLatest(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var result = await telemetryService.GetLatestAsync(
            deviceId,
            cancellationToken);

        return result is null
            ? NotFound()
            : Ok(result);
    }
}
