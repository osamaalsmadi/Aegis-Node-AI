using EndpointSecurity.Application.Findings;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/findings")]
public sealed class FindingsController(
    IFindingManagementService findingService)
    : ControllerBase
{
    [HttpPost("{findingId:guid}/review")]
    public async Task<ActionResult<FindingReviewResponse>>
        Review(
            Guid findingId,
            ReviewFindingRequest request,
            CancellationToken cancellationToken)
    {
        var result = await findingService.ReviewAsync(
            findingId,
            request,
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("devices/{deviceId:guid}/reviews")]
    public async Task<
        ActionResult<IReadOnlyList<FindingReviewResponse>>>
        GetHistory(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var result = await findingService.GetHistoryAsync(
            deviceId,
            cancellationToken);

        return Ok(result);
    }
}
