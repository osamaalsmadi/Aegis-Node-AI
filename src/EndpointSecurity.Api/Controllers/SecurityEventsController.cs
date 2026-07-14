using EndpointSecurity.Application.SecurityEvents;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/security-events")]
public sealed class SecurityEventsController(
    IWindowsSecurityEventService securityEventService)
    : ControllerBase
{
    [HttpPost("batch")]
    public async Task<ActionResult<
        IReadOnlyList<WindowsSecurityEventResponse>>>
        SubmitBatch(
            SubmitWindowsSecurityEventBatchRequest request,
            CancellationToken cancellationToken)
    {
        var result =
            await securityEventService.SubmitBatchAsync(
                request,
                cancellationToken);

        return StatusCode(
            StatusCodes.Status201Created,
            result);
    }

    [HttpGet("devices/{deviceId:guid}")]
    public async Task<ActionResult<
        IReadOnlyList<WindowsSecurityEventResponse>>>
        GetRecent(
            Guid deviceId,
            [FromQuery] int limit,
            CancellationToken cancellationToken)
    {
        var result =
            await securityEventService.GetRecentAsync(
                deviceId,
                limit <= 0 ? 200 : limit,
                cancellationToken);

        return Ok(result);
    }

    [HttpGet("devices/{deviceId:guid}/summary")]
    public async Task<ActionResult<
        WindowsSecurityEventSummaryResponse>>
        GetSummary(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var result =
            await securityEventService.GetSummaryAsync(
                deviceId,
                cancellationToken);

        return Ok(result);
    }
}
